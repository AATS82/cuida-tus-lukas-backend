package com.cuidatuslukas.controller;

import com.cuidatuslukas.dto.AnalysisRequest;
import com.cuidatuslukas.dto.AnalysisResponse;
import com.cuidatuslukas.service.AnalysisService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/analysis")
@RequiredArgsConstructor
public class AnalysisController {

    private final AnalysisService analysisService;

    /**
     * POST /api/analysis/analyze
     * Body: { "query": "inversiones-global-x.com" }
     */
    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResponse> analyze(@Valid @RequestBody AnalysisRequest request) {
        AnalysisResponse response = analysisService.analizar(request.getQuery());
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/analysis/analyze?q=...
     * Alternativa GET para uso directo desde el browser/frontend.
     */
    @GetMapping("/analyze")
    public ResponseEntity<AnalysisResponse> analyzeGet(@RequestParam("q") String query) {
        if (query == null || query.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        AnalysisResponse response = analysisService.analizar(query);
        return ResponseEntity.ok(response);
    }
}
