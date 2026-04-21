package com.cuidatuslukas.controller;

import com.cuidatuslukas.dto.AlertDto;
import com.cuidatuslukas.service.AlertService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertService alertService;

    /**
     * GET /api/alerts/recent
     * Últimas 10 alertas para la home page.
     */
    @GetMapping("/recent")
    public ResponseEntity<List<AlertDto>> getRecentAlerts() {
        return ResponseEntity.ok(alertService.getRecentAlerts());
    }

    /**
     * GET /api/alerts
     * Historial completo de alertas.
     */
    @GetMapping
    public ResponseEntity<List<AlertDto>> getAllAlerts() {
        return ResponseEntity.ok(alertService.getAllAlerts());
    }
}
