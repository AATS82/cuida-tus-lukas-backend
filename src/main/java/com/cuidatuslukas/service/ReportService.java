package com.cuidatuslukas.service;

import com.cuidatuslukas.dto.ReportRequest;
import com.cuidatuslukas.model.CitizenReport;
import com.cuidatuslukas.model.RiskLevel;
import com.cuidatuslukas.model.ScamPlatform;
import com.cuidatuslukas.repository.AlertRepository;
import com.cuidatuslukas.repository.CitizenReportRepository;
import com.cuidatuslukas.repository.ScamPlatformRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

    private final CitizenReportRepository reportRepository;
    private final ScamPlatformRepository scamPlatformRepository;
    private final AlertRepository alertRepository;

    @Transactional
    public CitizenReport guardarReporte(ReportRequest req) {
        CitizenReport report = CitizenReport.builder()
                .platformName(req.getPlatformName())
                .rutAccount(req.getRutAccount())
                .details(req.getDetails())
                .channels(req.getChannels())
                .build();

        CitizenReport saved = reportRepository.save(report);
        log.info("Reporte ciudadano guardado: id={}, plataforma='{}'", saved.getId(), saved.getPlatformName());

        // Auto-escalar: si ya hay 3+ reportes de la misma plataforma,
        // agregarla automáticamente a la lista negra local
        long totalReportes = reportRepository.countByQuery(req.getPlatformName());
        if (totalReportes >= 3 && !scamPlatformRepository.existsByName(req.getPlatformName())) {
            ScamPlatform scam = ScamPlatform.builder()
                    .name(req.getPlatformName())
                    .rutRuc(req.getRutAccount())
                    .description("Agregado automáticamente por acumulación de " + totalReportes + " reportes ciudadanos.")
                    .riskLevel(RiskLevel.CRITICAL)
                    .source("CITIZEN_REPORT")
                    .build();
            scamPlatformRepository.save(scam);
            log.info("Plataforma '{}' agregada a lista negra automáticamente ({} reportes)",
                    req.getPlatformName(), totalReportes);
        }

        return saved;
    }

    public long contarReportes() {
        return reportRepository.count();
    }
}
