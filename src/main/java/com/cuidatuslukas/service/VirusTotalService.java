package com.cuidatuslukas.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Consulta VirusTotal API v3 para verificar la reputación de una URL
 * contra más de 70 motores antivirus y de reputación web.
 *
 * Gratis: 500 consultas/día, máx 4 por minuto.
 * Registrar en: https://www.virustotal.com/gui/join-us
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VirusTotalService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.virustotal.api-key:}")
    private String apiKey;

    @Value("${app.virustotal.base-url:https://www.virustotal.com/api/v3}")
    private String baseUrl;

    public record VirusTotalResult(
            int malicious,
            int suspicious,
            int harmless,
            int total,
            String status   // COMPLETADO | EN_ANALISIS | NO_DISPONIBLE | SIN_API_KEY
    ) {
        public static VirusTotalResult noDisponible() {
            return new VirusTotalResult(0, 0, 0, 0, "NO_DISPONIBLE");
        }
        public static VirusTotalResult sinApiKey() {
            return new VirusTotalResult(0, 0, 0, 0, "SIN_API_KEY");
        }
        public static VirusTotalResult enAnalisis() {
            return new VirusTotalResult(0, 0, 0, 0, "EN_ANALISIS");
        }
    }

    @Cacheable(value = "virusTotalResults", key = "#url.toLowerCase().trim()")
    public VirusTotalResult analizar(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            log.debug("VirusTotal API key no configurada");
            return VirusTotalResult.sinApiKey();
        }

        String normalizedUrl = url.startsWith("http") ? url : "https://" + url;
        String urlId = calcularUrlId(normalizedUrl);

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);

            ResponseEntity<String> response = restTemplate.exchange(
                    baseUrl + "/urls/" + urlId,
                    HttpMethod.GET, new HttpEntity<>(headers), String.class
            );

            return parsearRespuesta(response.getBody());

        } catch (HttpClientErrorException.NotFound e) {
            log.info("URL no encontrada en VirusTotal, enviando para análisis: {}", normalizedUrl);
            submitUrl(normalizedUrl);
            return VirusTotalResult.enAnalisis();

        } catch (Exception e) {
            log.warn("Error consultando VirusTotal para {}: {}", url, e.getMessage());
            return VirusTotalResult.noDisponible();
        }
    }

    private VirusTotalResult parsearRespuesta(String body) throws Exception {
        JsonNode stats = objectMapper.readTree(body)
                .path("data").path("attributes").path("last_analysis_stats");

        if (stats.isMissingNode()) return VirusTotalResult.noDisponible();

        int malicious  = stats.path("malicious").asInt(0);
        int suspicious = stats.path("suspicious").asInt(0);
        int harmless   = stats.path("harmless").asInt(0);
        int undetected = stats.path("undetected").asInt(0);
        int total      = malicious + suspicious + harmless + undetected;

        log.info("VirusTotal: malicious={}, suspicious={}, harmless={}, total={}",
                malicious, suspicious, harmless, total);

        return new VirusTotalResult(malicious, suspicious, harmless, total, "COMPLETADO");
    }

    // URL id = base64url(url) sin padding "=" — estándar de VirusTotal v3
    private String calcularUrlId(String url) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));
    }

    private void submitUrl(String url) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("url", url);

            restTemplate.exchange(
                    baseUrl + "/urls",
                    HttpMethod.POST, new HttpEntity<>(body, headers), String.class
            );
            log.info("URL enviada a VirusTotal para análisis: {}", url);
        } catch (Exception e) {
            log.warn("Error enviando URL a VirusTotal: {}", e.getMessage());
        }
    }
}
