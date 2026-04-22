package com.cuidatuslukas.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Consulta Google Safe Browsing API v4 para detectar URLs maliciosas,
 * phishing, malware y software no deseado.
 *
 * Gratis: 10.000 consultas/día.
 * Activar en: https://console.cloud.google.com → "Safe Browsing API"
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleSafeBrowsingService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.google-safe-browsing.api-key:}")
    private String apiKey;

    @Value("${app.google-safe-browsing.url:https://safebrowsing.googleapis.com/v4/threatMatches:find}")
    private String apiUrl;

    public record SafeBrowsingResult(
            boolean isThreat,
            List<String> threatTypes,
            boolean available
    ) {
        public static SafeBrowsingResult safe() {
            return new SafeBrowsingResult(false, List.of(), true);
        }
        public static SafeBrowsingResult noDisponible() {
            return new SafeBrowsingResult(false, List.of(), false);
        }
        public static SafeBrowsingResult amenaza(List<String> types) {
            return new SafeBrowsingResult(true, types, true);
        }
    }

    @Cacheable(value = "safeBrowsingResults", key = "#url.toLowerCase().trim()")
    public SafeBrowsingResult verificar(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            log.debug("Google Safe Browsing API key no configurada");
            return SafeBrowsingResult.noDisponible();
        }

        String normalizedUrl = url.startsWith("http") ? url : "https://" + url;

        try {
            Map<String, Object> body = Map.of(
                    "client", Map.of("clientId", "cuida-tus-lukas", "clientVersion", "1.0"),
                    "threatInfo", Map.of(
                            "threatTypes",      List.of("MALWARE", "SOCIAL_ENGINEERING",
                                                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                            "platformTypes",    List.of("ANY_PLATFORM"),
                            "threatEntryTypes", List.of("URL"),
                            "threatEntries",    List.of(Map.of("url", normalizedUrl))
                    )
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            ResponseEntity<String> response = restTemplate.exchange(
                    apiUrl + "?key=" + apiKey,
                    HttpMethod.POST,
                    new HttpEntity<>(objectMapper.writeValueAsString(body), headers),
                    String.class
            );

            return parsearRespuesta(response.getBody());

        } catch (Exception e) {
            log.warn("Error consultando Google Safe Browsing para {}: {}", url, e.getMessage());
            return SafeBrowsingResult.noDisponible();
        }
    }

    private SafeBrowsingResult parsearRespuesta(String body) throws Exception {
        if (body == null || body.isBlank() || "{}".equals(body.trim())) {
            return SafeBrowsingResult.safe();
        }

        JsonNode matches = objectMapper.readTree(body).path("matches");
        if (matches.isMissingNode() || !matches.isArray() || matches.isEmpty()) {
            return SafeBrowsingResult.safe();
        }

        List<String> types = new ArrayList<>();
        for (JsonNode match : matches) {
            String type = match.path("threatType").asText();
            if (!type.isBlank() && !types.contains(type)) types.add(type);
        }

        log.warn("Google Safe Browsing: AMENAZA detectada — tipos: {}", types);
        return SafeBrowsingResult.amenaza(types);
    }
}
