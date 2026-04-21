package com.cuidatuslukas.seed;

import com.cuidatuslukas.model.*;
import com.cuidatuslukas.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Carga datos de ejemplo al iniciar si las tablas están vacías.
 * No destruye datos existentes en produción.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final ScamPlatformRepository scamRepo;
    private final AlertRepository alertRepo;
    private final CitizenReportRepository reportRepo;

    @Override
    public void run(ApplicationArguments args) {
        seedScamPlatforms();
        seedAlerts();
        seedCitizenReports();
    }

    // ── Plataformas fraudulentas conocidas ────────────────────────────────────

    private void seedScamPlatforms() {
        if (scamRepo.count() > 0) return;
        log.info("Seeding scam platforms...");

        scamRepo.saveAll(List.of(
            ScamPlatform.builder()
                .name("Inversiones Global-X")
                .url("inversiones-global-x.com")
                .description("Esquema Ponzi detectado vía grupos de WhatsApp. Promete 20% mensual sin respaldo legal.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("CMF_ALERT")
                .build(),
            ScamPlatform.builder()
                .name("CryptoChile Pro")
                .url("cryptochile-pro.cl")
                .description("Plataforma de trading sin respaldo legal. Bloqueo de retiros reportado por más de 50 usuarios.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("CITIZEN_REPORT")
                .build(),
            ScamPlatform.builder()
                .name("Ahorro Directo CL")
                .url("ahorrodirecto.cl")
                .description("Uso indebido del logo de BancoEstado y CMF. Suplantación de identidad institucional confirmada.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("CMF_ALERT")
                .build(),
            ScamPlatform.builder()
                .name("FX Capital Chile")
                .url("fxcapital-chile.com")
                .description("Sin registro en CMF. Opera desde el extranjero prometiendo 15% semanal en Forex.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("ADMIN")
                .build(),
            ScamPlatform.builder()
                .name("Yield Masters CL")
                .url("yieldmasters.cl")
                .description("Captación masiva a través de influencers falsos en Instagram y TikTok.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("CITIZEN_REPORT")
                .build(),
            ScamPlatform.builder()
                .name("InvertirYa.cl")
                .url("invertirya.cl")
                .description("Dominio registrado hace 45 días. Copia el diseño de un banco legítimo chileno.")
                .riskLevel(RiskLevel.CRITICAL)
                .source("ADMIN")
                .build()
        ));

        log.info("Scam platforms seeded: {}", scamRepo.count());
    }

    // ── Alertas recientes ─────────────────────────────────────────────────────

    private void seedAlerts() {
        if (alertRepo.count() > 0) return;
        log.info("Seeding alerts...");

        alertRepo.saveAll(List.of(
            Alert.builder()
                .name("Inversiones Global-X")
                .description("Detectado como esquema Ponzi a través de grupos de WhatsApp. Prometen 20% mensual.")
                .riskLevel(RiskLevel.CRITICAL)
                .icon("warning")
                .url("inversiones-global-x.com")
                .build(),
            Alert.builder()
                .name("CryptoChile Pro")
                .description("Plataforma de trading sin respaldo legal. Bloqueo de retiros reportado por 50+ usuarios.")
                .riskLevel(RiskLevel.CRITICAL)
                .icon("block")
                .url("cryptochile-pro.cl")
                .build(),
            Alert.builder()
                .name("Ahorro Directo CL")
                .description("Uso indebido de logo de BancoEstado y CMF. Suplantación de identidad institucional.")
                .riskLevel(RiskLevel.CRITICAL)
                .icon("dangerous")
                .url("ahorrodirecto.cl")
                .build(),
            Alert.builder()
                .name("FX Capital Chile")
                .description("Sin registro CMF. Opera desde el extranjero con promesas de ganancias Forex.")
                .riskLevel(RiskLevel.CRITICAL)
                .icon("warning")
                .url("fxcapital-chile.com")
                .build(),
            Alert.builder()
                .name("Yield Masters CL")
                .description("Captación masiva en redes sociales con influencers falsos.")
                .riskLevel(RiskLevel.CRITICAL)
                .icon("block")
                .url("yieldmasters.cl")
                .build()
        ));

        log.info("Alerts seeded: {}", alertRepo.count());
    }

    // ── Reportes ciudadanos de ejemplo ────────────────────────────────────────

    private void seedCitizenReports() {
        if (reportRepo.count() > 0) return;
        log.info("Seeding citizen reports...");

        reportRepo.saveAll(List.of(
            CitizenReport.builder()
                .platformName("Inversiones Global-X")
                .details("Me prometieron rentabilidad diaria y no pude retirar mi dinero. Perdí $500.000.")
                .channels(List.of("WHATSAPP"))
                .build(),
            CitizenReport.builder()
                .platformName("Inversiones Global-X")
                .details("Usan fotos de personalidades chilenas para atraer gente por redes sociales.")
                .channels(List.of("INSTAGRAM"))
                .build(),
            CitizenReport.builder()
                .platformName("CryptoChile Pro")
                .details("Después de invertir $1.000.000 me bloquearon la cuenta sin devolverme nada.")
                .channels(List.of("TELEGRAM"))
                .build(),
            CitizenReport.builder()
                .platformName("CryptoChile Pro")
                .details("Me contactaron prometiendo duplicar mi dinero en 30 días.")
                .channels(List.of("WHATSAPP", "INSTAGRAM"))
                .build(),
            CitizenReport.builder()
                .platformName("Ahorro Directo CL")
                .details("El sitio parece exactamente igual al BancoEstado. Me engañaron con el logo.")
                .channels(List.of("EMAIL"))
                .build()
        ));

        log.info("Citizen reports seeded: {}", reportRepo.count());
    }
}
