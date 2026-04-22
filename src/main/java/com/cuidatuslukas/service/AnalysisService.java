package com.cuidatuslukas.service;

import com.cuidatuslukas.dto.AnalysisFactor;
import com.cuidatuslukas.dto.AnalysisResponse;
import com.cuidatuslukas.model.CitizenReport;
import com.cuidatuslukas.model.RiskLevel;
import com.cuidatuslukas.model.ScamPlatform;
import com.cuidatuslukas.repository.CitizenReportRepository;
import com.cuidatuslukas.repository.ScamPlatformRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Motor principal de análisis de riesgo — 8 capas de detección.
 *
 * PUNTUACIÓN (0-100, cap en 100):
 *  Capa 1 — CMF Chile:
 *    API no configurada:                  +20
 *    No autorizado:                       +40
 *    Autorizado:                          +0  (fuerza SAFE si no hay amenaza confirmada)
 *
 *  Capa 2 — Antigüedad de dominio:
 *    < 30 días:                           +35
 *    30-90 días:                          +25
 *    90-365 días:                         +10
 *    ≥ 365 días:                          +0
 *
 *  Capa 3 — Patrón del nombre de dominio:
 *    Término forex/trading:               +25
 *    Término inversión:                   +15
 *    Término cripto:                      +15
 *    TLD de alto riesgo:                  +10-25
 *    Suplantación de marca conocida:      +45  (fuerza CRITICAL)
 *    Guiones excesivos (≥3):              +10
 *
 *  Capa 4 — Google Safe Browsing:
 *    MALWARE / SOCIAL_ENGINEERING:        +50  (fuerza CRITICAL)
 *    UNWANTED_SOFTWARE:                   +30
 *    POTENTIALLY_HARMFUL_APPLICATION:     +20
 *
 *  Capa 5 — Contenido de la página web:
 *    Forex + rendimientos garantizados:   +30
 *    Rendimientos garantizados solos:     +25
 *    Forex solo:                          +15
 *    MLM / pirámide:                      +20
 *    Cripto-estafa:                       +15
 *
 *  Capa 6 — VirusTotal (70+ motores):
 *    ≥ 5 motores malicioso:               +45
 *    2-4 motores maliciosos:              +30
 *    1 motor malicioso:                   +10
 *    Sospechoso (sin malicious):          +5
 *
 *  Capa 7 — Lista negra local:            +50  (fuerza CRITICAL)
 *
 *  Capa 8 — Reportes ciudadanos:
 *    > 10 reportes:                       +20
 *    > 5 reportes:                        +12
 *    > 0 reportes:                        +5
 *
 * NIVELES: 0-20 → SAFE | 21-50 → CAUTION | 51+ → CRITICAL
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

    private final CmfService cmfService;
    private final WhoisService whoisService;
    private final DomainPatternService domainPatternService;
    private final GoogleSafeBrowsingService safeBrowsingService;
    private final ContentAnalysisService contentAnalysisService;
    private final VirusTotalService virusTotalService;
    private final ScamPlatformRepository scamPlatformRepository;
    private final CitizenReportRepository citizenReportRepository;

    private static final Pattern RUT_PATTERN =
            Pattern.compile("^\\d{1,2}\\.?\\d{3}\\.?\\d{3}-[\\dkK]$");
    private static final Pattern URL_PATTERN =
            Pattern.compile("^(https?://)?[\\w\\-]+(\\.[\\w\\-]+)+(/.*)?$");

    // ── Entrada pública ───────────────────────────────────────────────────────

    public AnalysisResponse analizar(String rawQuery) {
        String query = rawQuery.trim();
        String queryType = detectarTipo(query);
        log.info("Analizando '{}' (tipo: {})", query, queryType);

        List<AnalysisFactor> factors = new ArrayList<>();
        int score = 0;

        // ── Capa 1: CMF Chile ─────────────────────────────────────────────────
        CmfService.CmfResult cmf = cmfService.verificar(query);
        score += evaluarCmf(cmf, factors);

        // ── Capas 2-6 solo aplican a URLs ────────────────────────────────────
        WhoisService.WhoisResult whois = WhoisService.WhoisResult.unknown(query);
        DomainPatternService.DomainPatternResult domainPattern = DomainPatternService.DomainPatternResult.noAplica();
        GoogleSafeBrowsingService.SafeBrowsingResult safeBrowsing = GoogleSafeBrowsingService.SafeBrowsingResult.noDisponible();
        ContentAnalysisService.ContentAnalysisResult content = ContentAnalysisService.ContentAnalysisResult.noDisponible();
        VirusTotalService.VirusTotalResult virustotal = VirusTotalService.VirusTotalResult.noDisponible();

        if ("URL".equals(queryType)) {
            // Capa 2: antigüedad de dominio
            whois = whoisService.consultarDominio(query);
            score += evaluarDominio(whois, factors);

            // Capa 3: patrón del nombre de dominio
            domainPattern = domainPatternService.analizar(query);
            score += evaluarPatronDominio(domainPattern, factors);

            // Capa 4: Google Safe Browsing
            safeBrowsing = safeBrowsingService.verificar(query);
            score += evaluarSafeBrowsing(safeBrowsing, factors);

            // Capa 5: contenido de la página web
            content = contentAnalysisService.analizar(query);
            score += evaluarContenido(content, factors);

            // Capa 6: VirusTotal
            virustotal = virusTotalService.analizar(query);
            score += evaluarVirusTotal(virustotal, factors);

        } else {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description("No aplica para esta búsqueda (RUT o nombre). Ingrese una URL para verificar.")
                    .badge("UNKNOWN").safe(true).build());
        }

        // ── Capa 7: lista negra local ─────────────────────────────────────────
        List<ScamPlatform> scamsEncontrados = scamPlatformRepository.searchAll(query);
        boolean knownScam = !scamsEncontrados.isEmpty();
        if (knownScam) score += 50;
        factors.add(buildListaNegraFactor(knownScam, scamsEncontrados));

        // ── Capa 8: reportes ciudadanos ───────────────────────────────────────
        long reportCount = citizenReportRepository.countByQuery(query);
        score += evaluarReportesCiudadanos((int) reportCount, factors);

        // ── Nivel de riesgo final ─────────────────────────────────────────────
        score = Math.min(score, 100);
        boolean isSafeBrowsingThreat = safeBrowsing.isThreat();
        RiskLevel riskLevel = calcularNivel(score, knownScam, domainPattern.isImpersonating(),
                                            cmf.authorized(), isSafeBrowsingThreat);

        // ── Testimonios ───────────────────────────────────────────────────────
        List<String> testimonials = obtenerTestimonios(query);

        return AnalysisResponse.builder()
                .query(query)
                .queryType(queryType)
                .riskLevel(riskLevel)
                .riskScore(score)
                .cmfAuthorized(cmf.authorized())
                .cmfEntityName(cmf.entityName())
                .cmfEntityType(cmf.entityType())
                .domainAgeDays(whois.domainAgeDays())
                .domainRegistrationDate(whois.registrationDate())
                .communityReports((int) reportCount)
                .knownScam(knownScam)
                .testimonials(testimonials)
                .contentKeywordsDetected(content.detectedKeywords())
                .factors(factors)
                .summary(generarResumen(riskLevel, query, cmf, domainPattern, safeBrowsing, content, virustotal))
                .build();
    }

    // ── Tipo de consulta ──────────────────────────────────────────────────────

    private String detectarTipo(String query) {
        if (RUT_PATTERN.matcher(query).matches()) return "RUT";
        if (URL_PATTERN.matcher(query).matches()) return "URL";
        return "NOMBRE";
    }

    // ── Evaluadores ──────────────────────────────────────────────────────────

    private int evaluarCmf(CmfService.CmfResult cmf, List<AnalysisFactor> factors) {
        if ("UNKNOWN".equals(cmf.entityType())) {
            factors.add(AnalysisFactor.builder()
                    .title("¿Está regulado por la CMF Chile?")
                    .description("No se pudo verificar en este momento. Configure CMF_API_KEY para activar la consulta.")
                    .badge("UNKNOWN").safe(false)
                    .detail("Regístrate gratis en api.cmfchile.cl")
                    .build());
            return 20;
        }
        if (cmf.authorized()) {
            factors.add(AnalysisFactor.builder()
                    .title("¿Está regulado por la CMF Chile?")
                    .description("Entidad autorizada: " + cmf.entityName() + " (" + cmf.entityType() + ")")
                    .badge("OK").safe(true)
                    .detail("Figura en los registros oficiales de la Comisión para el Mercado Financiero.")
                    .build());
            return 0;
        }
        factors.add(AnalysisFactor.builder()
                .title("¿Está regulado por la CMF Chile?")
                .description("No se encontraron registros de esta entidad en la base de datos de la CMF.")
                .badge("CRITICAL").safe(false)
                .detail("Solo opere con entidades autorizadas. Verifique en cmfchile.cl")
                .build());
        return 40;
    }

    private int evaluarDominio(WhoisService.WhoisResult whois, List<AnalysisFactor> factors) {
        if (whois.domainAgeDays() == null) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description("No fue posible determinar la fecha de registro del dominio.")
                    .badge("UNKNOWN").safe(false).build());
            return 10;
        }
        long dias = whois.domainAgeDays();
        if (dias < 30) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 1 mes). Extremadamente sospechoso.", dias))
                    .badge("CRITICAL").safe(false)
                    .detail("Las estafas usan dominios recién creados. Registro: " + whois.registrationDate())
                    .build());
            return 35;
        }
        if (dias < 90) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 3 meses).", dias))
                    .badge("ALERT").safe(false)
                    .detail("Registro: " + whois.registrationDate()).build());
            return 25;
        }
        if (dias < 365) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 1 año).", dias))
                    .badge("ALERT").safe(false)
                    .detail("Registro: " + whois.registrationDate()).build());
            return 10;
        }
        factors.add(AnalysisFactor.builder()
                .title("Antigüedad del dominio web")
                .description(String.format("Dominio con %d días de antigüedad (%d años). Sin señales de alerta por antigüedad.",
                        dias, dias / 365))
                .badge("OK").safe(true)
                .detail("Registro: " + whois.registrationDate()).build());
        return 0;
    }

    private int evaluarPatronDominio(DomainPatternService.DomainPatternResult pattern, List<AnalysisFactor> factors) {
        if (pattern.riskIndicators().isEmpty()) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del nombre de dominio")
                    .description("El nombre de dominio no presenta palabras clave sospechosas ni patrones de riesgo.")
                    .badge("OK").safe(true).build());
            return 0;
        }
        String badge = pattern.isImpersonating() ? "CRITICAL"
                     : pattern.riskScore() >= 25  ? "CRITICAL"
                     : "ALERT";
        factors.add(AnalysisFactor.builder()
                .title("Análisis del nombre de dominio")
                .description(String.join(" | ", pattern.riskIndicators()))
                .badge(badge).safe(false)
                .detail("Los dominios fraudulentos incluyen términos de forex, inversión o suplantan marcas conocidas.")
                .build());
        return pattern.riskScore();
    }

    private int evaluarSafeBrowsing(GoogleSafeBrowsingService.SafeBrowsingResult gsb, List<AnalysisFactor> factors) {
        if (!gsb.available()) {
            factors.add(AnalysisFactor.builder()
                    .title("Google Safe Browsing")
                    .description("API no configurada — se activará automáticamente con el perfil local.")
                    .badge("UNKNOWN").safe(false).build());
            return 0;
        }
        if (!gsb.isThreat()) {
            factors.add(AnalysisFactor.builder()
                    .title("Google Safe Browsing")
                    .description("URL verificada: no aparece en la base de datos de amenazas de Google.")
                    .badge("OK").safe(true).build());
            return 0;
        }
        List<String> types = gsb.threatTypes();
        String tipos = String.join(", ", types.stream()
                .map(this::traducirTipoGsb).toList());
        factors.add(AnalysisFactor.builder()
                .title("Google Safe Browsing")
                .description("¡AMENAZA CONFIRMADA por Google! Clasificado como: " + tipos)
                .badge("CRITICAL").safe(false)
                .detail("Google bloquea activamente este sitio en Chrome y otros navegadores.")
                .build());

        boolean esSevero = types.stream()
                .anyMatch(t -> t.equals("MALWARE") || t.equals("SOCIAL_ENGINEERING"));
        return esSevero ? 50 : 30;
    }

    private int evaluarContenido(ContentAnalysisService.ContentAnalysisResult content, List<AnalysisFactor> factors) {
        if (!content.fetchSuccess()) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del contenido de la página")
                    .description("No fue posible acceder al contenido del sitio para su análisis.")
                    .badge("UNKNOWN").safe(false)
                    .detail("El sitio puede estar caído, bloqueado o requerir JavaScript.").build());
            return 0;
        }
        if (content.riskScore() == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del contenido de la página")
                    .description("No se detectaron palabras clave asociadas a estafas financieras en el contenido del sitio.")
                    .badge("OK").safe(true).build());
            return 0;
        }
        String badge = content.riskScore() >= 25 ? "CRITICAL" : "ALERT";
        String keywords = content.detectedKeywords().isEmpty() ? ""
                : " Detectado: " + String.join(", ", content.detectedKeywords().stream().limit(5).toList()) + ".";
        factors.add(AnalysisFactor.builder()
                .title("Análisis del contenido de la página")
                .description(buildDescripcionContenido(content) + keywords)
                .badge(badge).safe(false)
                .detail("El contenido del sitio contiene lenguaje típico de fraudes financieros.")
                .build());
        return content.riskScore();
    }

    private int evaluarVirusTotal(VirusTotalService.VirusTotalResult vt, List<AnalysisFactor> factors) {
        switch (vt.status()) {
            case "SIN_API_KEY" -> {
                factors.add(AnalysisFactor.builder()
                        .title("VirusTotal (70+ motores)")
                        .description("API key no configurada — se activará automáticamente con el perfil local.")
                        .badge("UNKNOWN").safe(false).build());
                return 0;
            }
            case "NO_DISPONIBLE" -> {
                factors.add(AnalysisFactor.builder()
                        .title("VirusTotal (70+ motores)")
                        .description("No fue posible consultar VirusTotal en este momento.")
                        .badge("UNKNOWN").safe(false).build());
                return 0;
            }
            case "EN_ANALISIS" -> {
                factors.add(AnalysisFactor.builder()
                        .title("VirusTotal (70+ motores)")
                        .description("URL enviada a VirusTotal para análisis. En la próxima consulta habrá resultados disponibles.")
                        .badge("UNKNOWN").safe(false)
                        .detail("Este sitio aún no tenía análisis previo en VirusTotal.").build());
                return 0;
            }
            default -> {
                // COMPLETADO — procesar resultados
            }
        }

        if (vt.malicious() == 0 && vt.suspicious() == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("VirusTotal (70+ motores)")
                    .description(String.format("Limpio: %d motores lo clasifican como seguro, ninguno como malicioso.", vt.harmless()))
                    .badge("OK").safe(true)
                    .detail(String.format("Total motores consultados: %d", vt.total())).build());
            return 0;
        }

        String badge;
        int pts;
        if (vt.malicious() >= 5) { badge = "CRITICAL"; pts = 45; }
        else if (vt.malicious() >= 2) { badge = "CRITICAL"; pts = 30; }
        else if (vt.malicious() == 1) { badge = "ALERT"; pts = 10; }
        else { badge = "ALERT"; pts = 5; } // solo suspicious

        factors.add(AnalysisFactor.builder()
                .title("VirusTotal (70+ motores)")
                .description(String.format(
                        "%d motor(es) lo detectan como MALICIOSO y %d como SOSPECHOSO (de %d motores analizados).",
                        vt.malicious(), vt.suspicious(), vt.total()))
                .badge(badge).safe(false)
                .detail("VirusTotal agrega resultados de más de 70 motores antivirus y de reputación web.")
                .build());
        return pts;
    }

    private AnalysisFactor buildListaNegraFactor(boolean found, List<ScamPlatform> plataformas) {
        if (!found) {
            return AnalysisFactor.builder()
                    .title("Lista negra de estafas conocidas")
                    .description("No figura en nuestra base de datos de plataformas fraudulentas conocidas.")
                    .badge("OK").safe(true).build();
        }
        ScamPlatform p = plataformas.get(0);
        return AnalysisFactor.builder()
                .title("Lista negra de estafas conocidas")
                .description("¡ALERTA! Esta plataforma está registrada en nuestra base de datos de fraudes: " + p.getDescription())
                .badge("CRITICAL").safe(false)
                .detail("Fuente: " + p.getSource()).build();
    }

    private int evaluarReportesCiudadanos(int count, List<AnalysisFactor> factors) {
        if (count == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("Reportes de la comunidad")
                    .description("Sin denuncias ciudadanas registradas en nuestra plataforma.")
                    .badge("OK").safe(true).build());
            return 0;
        }
        String badge = count > 10 ? "CRITICAL" : "ALERT";
        factors.add(AnalysisFactor.builder()
                .title("Reportes de la comunidad")
                .description(String.format("%d denuncia(s) ciudadana(s) asociada(s) a esta entidad.", count))
                .badge(badge).safe(false)
                .detail("Cada reporte representa una persona que fue contactada por esta entidad.").build());
        if (count > 10) return 20;
        if (count > 5)  return 12;
        return 5;
    }

    // ── Nivel de riesgo final ─────────────────────────────────────────────────

    private RiskLevel calcularNivel(int score, boolean knownScam, boolean isImpersonating,
                                    boolean cmfAuthorized, boolean isSafeBrowsingThreat) {
        // CMF autorizado es evidencia fuerte de legitimidad, salvo amenaza confirmada
        if (cmfAuthorized && !knownScam && !isSafeBrowsingThreat) return RiskLevel.SAFE;

        if (knownScam || isImpersonating || isSafeBrowsingThreat || score >= 51) return RiskLevel.CRITICAL;
        if (score >= 21) return RiskLevel.CAUTION;
        return RiskLevel.SAFE;
    }

    // ── Testimonios ───────────────────────────────────────────────────────────

    private List<String> obtenerTestimonios(String query) {
        List<CitizenReport> reportes = citizenReportRepository.findTestimoniosByQuery(query);
        return reportes.stream()
                .limit(5)
                .map(r -> "\"" + r.getDetails() + "\"")
                .toList();
    }

    // ── Resumen ejecutivo ─────────────────────────────────────────────────────

    private String generarResumen(RiskLevel nivel, String query,
                                  CmfService.CmfResult cmf,
                                  DomainPatternService.DomainPatternResult domainPattern,
                                  GoogleSafeBrowsingService.SafeBrowsingResult safeBrowsing,
                                  ContentAnalysisService.ContentAnalysisResult content,
                                  VirusTotalService.VirusTotalResult vt) {
        return switch (nivel) {
            case SAFE -> String.format(
                    "'%s' parece una entidad legítima: está registrada en la CMF (%s) y no presenta señales de alerta.",
                    query, cmf.entityName() != null ? cmf.entityName() : "entidad regulada");

            case CAUTION -> {
                if (content.hasForexIndicators())
                    yield String.format("'%s' ofrece servicios de trading/forex. Verifique su regulación en la CMF antes de invertir.", query);
                yield String.format("'%s' presenta señales de alerta. Extreme cautela antes de realizar cualquier transferencia.", query);
            }

            case CRITICAL -> {
                if (safeBrowsing.isThreat())
                    yield String.format("¡ALERTA MÁXIMA! '%s' está bloqueado por Google por ser peligroso (%s). No ingrese datos personales.",
                            query, String.join(", ", safeBrowsing.threatTypes().stream().map(this::traducirTipoGsb).toList()));
                if (domainPattern.isImpersonating())
                    yield String.format("¡ALERTA MÁXIMA! '%s' está suplantando la identidad de una institución conocida. No ingrese datos.", query);
                if ("COMPLETADO".equals(vt.status()) && vt.malicious() >= 3)
                    yield String.format("¡ALERTA ROJA! '%s' fue detectado como malicioso por %d motores en VirusTotal. No acceda a este sitio.", query, vt.malicious());
                if (content.hasForexIndicators() && content.hasHighYieldPromises())
                    yield String.format("¡ALERTA ROJA! '%s' es un sitio de forex con promesas de rendimientos garantizados — estafa confirmada. No transfiera dinero.", query);
                if (content.hasMlmIndicators())
                    yield String.format("¡ALERTA ROJA! '%s' opera como esquema piramidal o MLM. No invierta ni reclute a conocidos.", query);
                yield String.format("¡ALERTA ROJA! '%s' presenta múltiples características de fraude. No transfiera dinero. Reporte a la CMF.", query);
            }

            default -> String.format(
                    "No fue posible determinar el riesgo de '%s' con certeza. Consulte directamente con la CMF.", query);
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String buildDescripcionContenido(ContentAnalysisService.ContentAnalysisResult c) {
        if (c.hasForexIndicators() && c.hasHighYieldPromises())
            return "¡ALERTA! El sitio ofrece trading de forex con rendimientos garantizados — señal clásica de estafa.";
        if (c.hasMlmIndicators())
            return "El sitio presenta estructura de esquema multinivel (pirámide o MLM).";
        if (c.hasHighYieldPromises())
            return "El sitio promete rendimientos garantizados o sin riesgo — esto es siempre una señal de alerta.";
        if (c.hasForexIndicators())
            return "El sitio ofrece servicios de forex o trading de divisas sin evidencia de regulación.";
        if (c.hasCryptoScamIndicators())
            return "El sitio promete ganancias garantizadas con criptomonedas — patrón de estafa frecuente.";
        return "El sitio contiene lenguaje asociado a fraudes financieros.";
    }

    private String traducirTipoGsb(String type) {
        return switch (type) {
            case "MALWARE"                        -> "Malware";
            case "SOCIAL_ENGINEERING"             -> "Phishing/Engaño";
            case "UNWANTED_SOFTWARE"              -> "Software no deseado";
            case "POTENTIALLY_HARMFUL_APPLICATION"-> "Aplicación potencialmente dañina";
            default -> type;
        };
    }
}
