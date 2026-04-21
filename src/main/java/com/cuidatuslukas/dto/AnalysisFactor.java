package com.cuidatuslukas.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AnalysisFactor {

    /** Título del factor: "¿Está regulado por la CMF?" */
    private String title;

    /** Descripción detallada del resultado */
    private String description;

    /** CRITICAL | ALERT | OK | UNKNOWN */
    private String badge;

    /** true = sin riesgo, false = factor de riesgo */
    private boolean safe;

    /** Nota adicional informativa */
    private String detail;
}
