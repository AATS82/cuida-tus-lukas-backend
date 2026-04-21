package com.cuidatuslukas.dto;

import com.cuidatuslukas.model.Alert;
import com.cuidatuslukas.model.RiskLevel;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AlertDto {

    private Long id;
    private String name;
    private String description;
    private RiskLevel riskLevel;
    private String icon;
    private String url;
    private LocalDateTime createdAt;
    private String tiempoRelativo;

    public static AlertDto from(Alert a) {
        return AlertDto.builder()
                .id(a.getId())
                .name(a.getName())
                .description(a.getDescription())
                .riskLevel(a.getRiskLevel())
                .icon(a.getIcon())
                .url(a.getUrl())
                .createdAt(a.getCreatedAt())
                .tiempoRelativo(calcularTiempoRelativo(a.getCreatedAt()))
                .build();
    }

    private static String calcularTiempoRelativo(LocalDateTime createdAt) {
        if (createdAt == null) return "";
        long minutos = java.time.Duration.between(createdAt, LocalDateTime.now()).toMinutes();
        if (minutos < 60) return "Hace " + minutos + " minutos";
        long horas = minutos / 60;
        if (horas < 24) return "Hace " + horas + (horas == 1 ? " hora" : " horas");
        long dias = horas / 24;
        if (dias == 1) return "Ayer";
        if (dias < 7) return "Hace " + dias + " días";
        return "Hace " + (dias / 7) + (dias / 7 == 1 ? " semana" : " semanas");
    }
}
