package com.cuidatuslukas.dto;

import com.cuidatuslukas.model.RiskLevel;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AnalysisResponse {

    /** Término analizado (URL, RUT o nombre) */
    private String query;

    /** Tipo detectado: URL | RUT | NOMBRE */
    private String queryType;

    /** Nivel de riesgo final */
    private RiskLevel riskLevel;

    /** Puntuación 0-100 (uso interno / debug) */
    private int riskScore;

    // ── Resultado CMF ──────────────────────────────────────────────────────────

    /** ¿Figura en los registros CMF? */
    private boolean cmfAuthorized;

    /** Nombre oficial según CMF (si existe) */
    private String cmfEntityName;

    /** Tipo de entidad CMF: Banco, AGF, Corredor, etc. */
    private String cmfEntityType;

    // ── Resultado WHOIS / RDAP ─────────────────────────────────────────────────

    /** Edad del dominio en días (null si no aplica o no se pudo obtener) */
    private Long domainAgeDays;

    /** Fecha de registro del dominio (ISO 8601) */
    private String domainRegistrationDate;

    // ── Comunidad ─────────────────────────────────────────────────────────────

    /** Cantidad de denuncias ciudadanas que coinciden */
    private int communityReports;

    /** ¿Está en la lista negra local? */
    private boolean knownScam;

    /** Fragmentos de testimonios de afectados */
    private List<String> testimonials;

    // ── Factores detallados ────────────────────────────────────────────────────

    /** Lista de factores evaluados con su badge de riesgo */
    private List<AnalysisFactor> factors;

    /** Resumen ejecutivo en español */
    private String summary;
}
