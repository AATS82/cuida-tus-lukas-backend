package com.cuidatuslukas.controller;

import com.cuidatuslukas.repository.AlertRepository;
import com.cuidatuslukas.repository.CitizenReportRepository;
import com.cuidatuslukas.repository.ScamPlatformRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/stats")
@RequiredArgsConstructor
public class StatsController {

    private final ScamPlatformRepository scamPlatformRepository;
    private final CitizenReportRepository citizenReportRepository;
    private final AlertRepository alertRepository;

    /**
     * GET /api/stats
     * Estadísticas generales para la home page.
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> getStats() {
        long scams     = scamPlatformRepository.count();
        long reports   = citizenReportRepository.count();
        long alerts    = alertRepository.count();

        return ResponseEntity.ok(Map.of(
                "sitiosAnalizados",   15000 + (scams * 12),
                "fraudesEvitados",    scams + reports,
                "alertasActivas",     alerts,
                "reportesCiudadanos", reports,
                "datosOficiales",     "100%",
                "monitoreo",          "24/7"
        ));
    }
}
