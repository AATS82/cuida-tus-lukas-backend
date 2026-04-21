package com.cuidatuslukas.controller;

import com.cuidatuslukas.dto.ReportRequest;
import com.cuidatuslukas.model.CitizenReport;
import com.cuidatuslukas.service.ReportService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    /**
     * POST /api/reports
     * Envía un reporte ciudadano anónimo.
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> submitReport(@Valid @RequestBody ReportRequest request) {
        CitizenReport saved = reportService.guardarReporte(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "success", true,
                "message", "Reporte enviado. Gracias por proteger a la comunidad.",
                "id", saved.getId()
        ));
    }
}
