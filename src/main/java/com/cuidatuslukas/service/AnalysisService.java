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
 * Motor principal de análisis de riesgo — 6 capas de detección.
 *
 * Algoritmo de puntuación (0-100, cap en 100):
 *  CMF no configurada:              +20 pts
 *  CMF: entidad no autorizada:      +40 pts
 *  Dominio < 30 días:               +35 pts
 *  Dominio 30-90 días:              +25 pts
 *  Dominio 90-365 días:             +10 pts
 *  Patrón de dominio sospechoso:    +15-25 pts
 *  Suplantación de marca:           +45 pts (fuerza CRITICAL)
 *  TLD de alto riesgo:              +10-25 pts
 *  Contenido: forex + garantías:    +30 pts
 *  Contenido: garantías solas:      +25 pts
 *  Contenido: forex solo:           +15 pts
 *  Contenido: MLM/pirámide:         +20 pts
 *  Contenido: cripto-estafa:        +15 pts
 *  En lista negra local:            +50 pts (fuerza CRITICAL)
 *  Reportes ciudadanos >10:         +20 pts
 *  Reportes ciudadanos >5:          +12 pts
 *  Reportes ciudadanos >0:          +5  pts
 *
 * Niveles:  0-20 → SAFE  |  21-50 → CAUTION  |  51+ → CRITICAL
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

    private final CmfService cmfService;
    private final WhoisService whoisService;
    private final DomainPatternService domainPatternService;
    private final ContentAnalysisService contentAnalysisService;
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

        // ── 1. Verificación CMF ───────────────────────────────────────────────
        CmfService.CmfResult cmfResult = cmfService.verificar(query);
        score += evaluarCmf(cmfResult, factors);

        // ── 2. Antigüedad del dominio ─────────────────────────────────────────
        WhoisService.WhoisResult whoisResult = WhoisService.WhoisResult.unknown(query);
        DomainPatternService.DomainPatternResult domainPattern = DomainPatternService.DomainPatternResult.noAplica();
        ContentAnalysisService.ContentAnalysisResult contentResult = ContentAnalysisService.ContentAnalysisResult.noDisponible();

        if ("URL".equals(queryType)) {
            whoisResult = whoisService.consultarDominio(query);
            score += evaluarDominio(whoisResult, factors);

            // ── 3. Patrón del nombre de dominio ──────────────────────────────
            domainPattern = domainPatternService.analizar(query);
            score += evaluarPatronDominio(domainPattern, factors);

            // ── 4. Contenido de la página web ─────────────────────────────────
            contentResult = contentAnalysisService.analizar(query);
            score += evaluarContenido(contentResult, factors);

        } else {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description("No aplica para esta búsqueda (RUT o nombre). Ingrese una URL para verificar.")
                    .badge("UNKNOWN")
                    .safe(true)
                    .build());
        }

        // ── 5. Lista negra local ──────────────────────────────────────────────
        List<ScamPlatform> scamsEncontrados = scamPlatformRepository.searchAll(query);
        boolean knownScam = !scamsEncontrados.isEmpty();
        if (knownScam) score += 50;
        factors.add(buildListaNegraFactor(knownScam, scamsEncontrados));

        // ── 6. Reportes ciudadanos ────────────────────────────────────────────
        long reportCount = citizenReportRepository.countByQuery(query);
        score += evaluarReportesCiudadanos((int) reportCount, factors);

        // ── Nivel de riesgo final ─────────────────────────────────────────────
        score = Math.min(score, 100);
        RiskLevel riskLevel = calcularNivel(score, knownScam, domainPattern.isImpersonating());

        // ── Testimonios ───────────────────────────────────────────────────────
        List<String> testimonials = obtenerTestimonios(query);

        // ── Respuesta ─────────────────────────────────────────────────────────
        return AnalysisResponse.builder()
                .query(query)
                .queryType(queryType)
                .riskLevel(riskLevel)
                .riskScore(score)
                .cmfAuthorized(cmfResult.authorized())
                .cmfEntityName(cmfResult.entityName())
                .cmfEntityType(cmfResult.entityType())
                .domainAgeDays(whoisResult.domainAgeDays())
                .domainRegistrationDate(whoisResult.registrationDate())
                .communityReports((int) reportCount)
                .knownScam(knownScam)
                .testimonials(testimonials)
                .contentKeywordsDetected(contentResult.detectedKeywords())
                .factors(factors)
                .summary(generarResumen(riskLevel, query, cmfResult, domainPattern, contentResult, (int) reportCount))
                .build();
    }

    // ── Tipo de consulta ──────────────────────────────────────────────────────

    private String detectarTipo(String query) {
        if (RUT_PATTERN.matcher(query).matches()) return "RUT";
        if (URL_PATTERN.matcher(query).matches()) return "URL";
        return "NOMBRE";
    }

    // ── Evaluadores de factores ───────────────────────────────────────────────

    private int evaluarCmf(CmfService.CmfResult cmf, List<AnalysisFactor> factors) {
        if ("UNKNOWN".equals(cmf.entityType())) {
            factors.add(AnalysisFactor.builder()
                    .title("¿Está regulado por la CMF Chile?")
                    .description("No se pudo verificar en este momento. Configure CMF_API_KEY para activar la consulta en tiempo real.")
                    .badge("UNKNOWN")
                    .safe(false)
                    .detail("Regístrate gratis en api.cmfchile.cl")
                    .build());
            return 20;
        }
        if (cmf.authorized()) {
            factors.add(AnalysisFactor.builder()
                    .title("¿Está regulado por la CMF Chile?")
                    .description("Entidad autorizada: " + cmf.entityName() + " (" + cmf.entityType() + ")")
                    .badge("OK")
                    .safe(true)
                    .detail("Figura en los registros oficiales de la Comisión para el Mercado Financiero.")
                    .build());
            return 0;
        }
        factors.add(AnalysisFactor.builder()
                .title("¿Está regulado por la CMF Chile?")
                .description("No se encontraron registros de esta entidad en la base de datos de la CMF.")
                .badge("CRITICAL")
                .safe(false)
                .detail("Solo opere con entidades autorizadas. Verifique en cmfchile.cl")
                .build());
        return 40;
    }

    private int evaluarDominio(WhoisService.WhoisResult whois, List<AnalysisFactor> factors) {
        if (whois.domainAgeDays() == null) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description("No fue posible determinar la fecha de registro del dominio.")
                    .badge("UNKNOWN")
                    .safe(false)
                    .build());
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
                    .detail("Registro: " + whois.registrationDate())
                    .build());
            return 25;
        }
        if (dias < 365) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 1 año).", dias))
                    .badge("ALERT").safe(false)
                    .detail("Registro: " + whois.registrationDate())
                    .build());
            return 10;
        }
        factors.add(AnalysisFactor.builder()
                .title("Antigüedad del dominio web")
                .description(String.format("Dominio con %d días de antigüedad (%d años). Sin señales de alerta por antigüedad.",
                        dias, dias / 365))
                .badge("OK").safe(true)
                .detail("Registro: " + whois.registrationDate())
                .build());
        return 0;
    }

    private int evaluarPatronDominio(DomainPatternService.DomainPatternResult pattern, List<AnalysisFactor> factors) {
        if (pattern.riskIndicators().isEmpty()) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del nombre de dominio")
                    .description("El nombre de dominio no presenta palabras clave sospechosas ni patrones de riesgo.")
                    .badge("OK").safe(true)
                    .build());
            return 0;
        }

        String badge = pattern.isImpersonating() ? "CRITICAL"
                     : pattern.riskScore() >= 25  ? "CRITICAL"
                     : "ALERT";

        String descripcion = String.join(" | ", pattern.riskIndicators());

        factors.add(AnalysisFactor.builder()
                .title("Análisis del nombre de dominio")
                .description(descripcion)
                .badge(badge)
                .safe(false)
                .detail("Los dominios fraudulentos frecuentemente incluyen términos de forex, inversión o suplantan marcas conocidas.")
                .build());

        return pattern.riskScore();
    }

    private int evaluarContenido(ContentAnalysisService.ContentAnalysisResult content, List<AnalysisFactor> factors) {
        if (!content.fetchSuccess()) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del contenido de la página")
                    .description("No fue posible acceder al contenido del sitio para su análisis.")
                    .badge("UNKNOWN").safe(false)
                    .detail("El sitio puede estar caído, bloqueado o requerir JavaScript.")
                    .build());
            return 0;
        }

        if (content.riskScore() == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("Análisis del contenido de la página")
                    .description("No se detectaron palabras clave asociadas a estafas financieras en el contenido del sitio.")
                    .badge("OK").safe(true)
                    .build());
            return 0;
        }

        String badge = content.riskScore() >= 25 ? "CRITICAL" : "ALERT";
        String keywords = content.detectedKeywords().isEmpty() ? ""
                : " Detectado: " + String.join(", ", content.detectedKeywords().stream().limit(5).toList()) + ".";

        String descripcion = buildDescripcionContenido(content) + keywords;

        factors.add(AnalysisFactor.builder()
                .title("Análisis del contenido de la página")
                .description(descripcion)
                .badge(badge).safe(false)
                .detail("El contenido del sitio contiene lenguaje típico de fraudes financieros.")
                .build());

        return content.riskScore();
    }

    private String buildDescripcionContenido(ContentAnalysisService.ContentAnalysisResult c) {
        if (c.hasForexIndicators() && c.hasHighYieldPromises())
            return "¡ALERTA! El sitio ofrece trading de forex o divisas con rendimientos garantizados — señal clásica de estafa.";
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

    private AnalysisFactor buildListaNegraFactor(boolean found, List<ScamPlatform> plataformas) {
        if (!found) {
            return AnalysisFactor.builder()
                    .title("Lista negra de estafas conocidas")
                    .description("No figura en nuestra base de datos de plataformas fraudulentas conocidas.")
                    .badge("OK").safe(true)
                    .build();
        }
        ScamPlatform p = plataformas.get(0);
        return AnalysisFactor.builder()
                .title("Lista negra de estafas conocidas")
                .description("¡ALERTA! Esta plataforma está registrada en nuestra base de datos de fraudes: " + p.getDescription())
                .badge("CRITICAL").safe(false)
                .detail("Fuente: " + p.getSource())
                .build();
    }

    private int evaluarReportesCiudadanos(int count, List<AnalysisFactor> factors) {
        if (count == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("Reportes de la comunidad")
                    .description("Sin denuncias ciudadanas registradas en nuestra plataforma.")
                    .badge("OK").safe(true)
                    .build());
            return 0;
        }
        String badge = count > 10 ? "CRITICAL" : "ALERT";
        factors.add(AnalysisFactor.builder()
                .title("Reportes de la comunidad")
                .description(String.format("%d denuncia(s) ciudadana(s) asociada(s) a esta entidad.", count))
                .badge(badge).safe(false)
                .detail("Cada reporte representa una persona que fue contactada por esta entidad.")
                .build());
        if (count > 10) return 20;
        if (count > 5)  return 12;
        return 5;
    }

    // ── Nivel de riesgo ───────────────────────────────────────────────────────

    private RiskLevel calcularNivel(int score, boolean knownScam, boolean isImpersonating) {
        if (knownScam || isImpersonating || score >= 51) return RiskLevel.CRITICAL;
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
                                  ContentAnalysisService.ContentAnalysisResult content,
                                  int reportes) {
        return switch (nivel) {
            case SAFE -> String.format(
                    "'%s' parece una entidad legítima: está registrada en la CMF (%s) y no presenta señales de alerta.",
                    query, cmf.entityName() != null ? cmf.entityName() : "entidad regulada");

            case CAUTION -> {
                if (content.hasForexIndicators())
                    yield String.format("'%s' ofrece servicios de trading/forex. Verifique su regulación en la CMF antes de invertir.", query);
                yield String.format("'%s' presenta señales de alerta. Se recomienda extrema cautela antes de realizar cualquier transferencia.", query);
            }

            case CRITICAL -> {
                if (domainPattern.isImpersonating())
                    yield String.format("¡ALERTA MÁXIMA! '%s' está suplantando la identidad de una institución conocida. No ingrese datos personales.", query);
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
}
