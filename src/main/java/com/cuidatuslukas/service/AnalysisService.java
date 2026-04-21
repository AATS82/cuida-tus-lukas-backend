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
 * Motor principal de análisis de riesgo.
 *
 * Algoritmo de puntuación (0-100):
 *  - No figura en CMF:         +40 pts
 *  - Dominio < 30 días:        +35 pts
 *  - Dominio 30-90 días:       +25 pts
 *  - Dominio 90-365 días:      +10 pts
 *  - Reportes ciudadanos >10:  +20 pts
 *  - Reportes ciudadanos >5:   +12 pts
 *  - Reportes ciudadanos >0:   +5  pts
 *  - En lista negra local:     +50 pts (fuerza CRITICAL)
 *
 * Niveles:  0-20 → SAFE  |  21-50 → CAUTION  |  51+ → CRITICAL
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

    private final CmfService cmfService;
    private final WhoisService whoisService;
    private final ScamPlatformRepository scamPlatformRepository;
    private final CitizenReportRepository citizenReportRepository;

    // RUT chileno: 12.345.678-9 o 12345678-9
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

        // ── 2. Antigüedad del dominio (solo si es URL) ────────────────────────
        WhoisService.WhoisResult whoisResult = WhoisService.WhoisResult.unknown(query);
        if ("URL".equals(queryType)) {
            whoisResult = whoisService.consultarDominio(query);
            score += evaluarDominio(whoisResult, factors);
        } else {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description("No aplica para esta búsqueda (RUT o nombre). Ingrese una URL para verificar.")
                    .badge("UNKNOWN")
                    .safe(true)
                    .build());
        }

        // ── 3. Lista negra local ──────────────────────────────────────────────
        List<ScamPlatform> scamsEncontrados = scamPlatformRepository.searchAll(query);
        boolean knownScam = !scamsEncontrados.isEmpty();
        if (knownScam) score += 50;
        factors.add(buildListaNegraFactor(knownScam, scamsEncontrados));

        // ── 4. Reportes ciudadanos ────────────────────────────────────────────
        long reportCount = citizenReportRepository.countByQuery(query);
        score += evaluarReportesCiudadanos((int) reportCount, factors);

        // ── Nivel de riesgo final ─────────────────────────────────────────────
        score = Math.min(score, 100);
        RiskLevel riskLevel = calcularNivel(score, knownScam);

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
                .factors(factors)
                .summary(generarResumen(riskLevel, query, cmfResult, whoisResult, (int) reportCount))
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
                    .detail("Registra tu API key gratis en api.cmfchile.cl")
                    .build());
            return 20; // penalización parcial por incertidumbre
        }

        if (cmf.authorized()) {
            factors.add(AnalysisFactor.builder()
                    .title("¿Está regulado por la CMF Chile?")
                    .description(String.format("Entidad autorizada: %s (%s)", cmf.entityName(), cmf.entityType()))
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
                    .badge("CRITICAL")
                    .safe(false)
                    .detail("Las estafas usan dominios recién creados. Registro: " + whois.registrationDate())
                    .build());
            return 35;
        }
        if (dias < 90) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 3 meses).", dias))
                    .badge("ALERT")
                    .safe(false)
                    .detail("Registro: " + whois.registrationDate())
                    .build());
            return 25;
        }
        if (dias < 365) {
            factors.add(AnalysisFactor.builder()
                    .title("Antigüedad del dominio web")
                    .description(String.format("Dominio registrado hace %d días (menos de 1 año).", dias))
                    .badge("ALERT")
                    .safe(false)
                    .detail("Registro: " + whois.registrationDate())
                    .build());
            return 10;
        }

        factors.add(AnalysisFactor.builder()
                .title("Antigüedad del dominio web")
                .description(String.format("Dominio con %d días de antigüedad (%d años). Sin señales de alerta por antigüedad.",
                        dias, dias / 365))
                .badge("OK")
                .safe(true)
                .detail("Registro: " + whois.registrationDate())
                .build());
        return 0;
    }

    private AnalysisFactor buildListaNegraFactor(boolean found, List<ScamPlatform> plataformas) {
        if (!found) {
            return AnalysisFactor.builder()
                    .title("Lista negra de estafas conocidas")
                    .description("No figura en nuestra base de datos de plataformas fraudulentas conocidas.")
                    .badge("OK")
                    .safe(true)
                    .build();
        }
        ScamPlatform p = plataformas.get(0);
        return AnalysisFactor.builder()
                .title("Lista negra de estafas conocidas")
                .description("¡ALERTA! Esta plataforma está registrada en nuestra base de datos de fraudes: " + p.getDescription())
                .badge("CRITICAL")
                .safe(false)
                .detail("Fuente: " + p.getSource())
                .build();
    }

    private int evaluarReportesCiudadanos(int count, List<AnalysisFactor> factors) {
        if (count == 0) {
            factors.add(AnalysisFactor.builder()
                    .title("Reportes de la comunidad")
                    .description("Sin denuncias ciudadanas registradas en nuestra plataforma.")
                    .badge("OK")
                    .safe(true)
                    .build());
            return 0;
        }

        String badge = count > 10 ? "CRITICAL" : count > 5 ? "ALERT" : "ALERT";
        factors.add(AnalysisFactor.builder()
                .title("Reportes de la comunidad")
                .description(String.format("%d denuncia(s) ciudadana(s) asociada(s) a esta entidad.", count))
                .badge(badge)
                .safe(false)
                .detail("Cada reporte representa una persona que fue contactada por esta entidad.")
                .build());

        if (count > 10) return 20;
        if (count > 5)  return 12;
        return 5;
    }

    // ── Nivel de riesgo ───────────────────────────────────────────────────────

    private RiskLevel calcularNivel(int score, boolean knownScam) {
        if (knownScam || score >= 51) return RiskLevel.CRITICAL;
        if (score >= 21)              return RiskLevel.CAUTION;
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
                                  WhoisService.WhoisResult whois,
                                  int reportes) {
        return switch (nivel) {
            case SAFE -> String.format(
                    "'%s' parece una entidad legítima: está registrada en la CMF (%s) y no presenta señales de alerta.",
                    query, cmf.entityName() != null ? cmf.entityName() : "entidad regulada");
            case CAUTION -> String.format(
                    "'%s' presenta señales de alerta. Se recomienda extrema cautela antes de realizar cualquier transferencia.",
                    query);
            case CRITICAL -> String.format(
                    "¡ALERTA ROJA! '%s' presenta múltiples características de fraude. No transfiera dinero. Reporte a la CMF.",
                    query);
            default -> String.format(
                    "No fue posible determinar el riesgo de '%s' con certeza. Consulte directamente con la CMF.", query);
        };
    }
}
