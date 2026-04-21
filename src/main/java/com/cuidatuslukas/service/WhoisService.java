package com.cuidatuslukas.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Determina la antigüedad de un dominio usando:
 *  1. RDAP de NIC.cl  (dominios .cl, sin API key)
 *  2. RDAP genérico   (rdap.org, redirige al registro correcto, sin API key)
 *  3. WhoisXML API    (fallback con API key opcional, 500 gratis/mes)
 *
 * Un dominio muy nuevo (<90 días) es una señal de alerta frecuente en estafas.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WhoisService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.whois.api-key:}")
    private String whoisApiKey;

    @Value("${app.whois.xml-url}")
    private String whoisXmlUrl;

    @Value("${app.whois.rdap-url}")
    private String rdapUrl;

    @Value("${app.whois.rdap-cl-url}")
    private String rdapClUrl;

    // ── Resultado encapsulado ─────────────────────────────────────────────────

    public record WhoisResult(Long domainAgeDays, String registrationDate, String domain) {
        public static WhoisResult unknown(String domain) {
            return new WhoisResult(null, null, domain);
        }
    }

    // ── Extracción de dominio ─────────────────────────────────────────────────

    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("(?:https?://)?(?:www\\.)?([a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9](?:\\.[a-zA-Z]{2,})+)");

    public String extractDomain(String url) {
        if (url == null || url.isBlank()) return null;
        Matcher m = DOMAIN_PATTERN.matcher(url.toLowerCase().trim());
        if (!m.find()) return null;
        // Reducir al dominio registrable (últimas dos partes): paygo.com.ng → paygo.com.ng
        // Elimina subdominios: officebnking.paygo.com.ng → paygo.com.ng
        String full = m.group(1);
        String[] parts = full.split("\\.");
        if (parts.length > 2) {
            // Detecta TLDs compuestos conocidos: co.uk, com.ar, com.ng, net.cl, etc.
            String last2 = parts[parts.length - 2] + "." + parts[parts.length - 1];
            boolean isCompoundTld = last2.matches("(com|net|org|gov|edu|co|ac)\\.[a-z]{2}");
            int keep = isCompoundTld ? 3 : 2;
            if (parts.length > keep) {
                String[] registrable = new String[keep];
                System.arraycopy(parts, parts.length - keep, registrable, 0, keep);
                return String.join(".", registrable);
            }
        }
        return full;
    }

    /**
     * Obtiene la edad del dominio extraído de la URL.
     */
    @Cacheable(value = "whoisResults", key = "#url.toLowerCase().trim()")
    public WhoisResult consultarDominio(String url) {
        String domain = extractDomain(url);
        if (domain == null) {
            log.debug("No se pudo extraer dominio de: {}", url);
            return WhoisResult.unknown(url);
        }

        // 1. RDAP NIC.cl para dominios .cl
        if (domain.endsWith(".cl")) {
            WhoisResult r = consultarRdapCl(domain);
            if (r.domainAgeDays() != null) return r;
        }

        // 2. RDAP genérico
        WhoisResult r = consultarRdapGenerico(domain);
        if (r.domainAgeDays() != null) return r;

        // 3. WhoisXML (si hay API key)
        if (whoisApiKey != null && !whoisApiKey.isBlank()) {
            return consultarWhoisXml(domain);
        }

        log.warn("No se pudo obtener antigüedad de dominio: {}", domain);
        return WhoisResult.unknown(domain);
    }

    // ── RDAP NIC.cl ──────────────────────────────────────────────────────────

    private WhoisResult consultarRdapCl(String domain) {
        try {
            String url = rdapClUrl + "/" + domain;
            String response = restTemplate.getForObject(url, String.class);
            return parsearRdapResponse(response, domain);
        } catch (Exception e) {
            log.debug("RDAP NIC.cl falló para {}: {}", domain, e.getMessage());
            return WhoisResult.unknown(domain);
        }
    }

    // ── RDAP Genérico (rdap.org) ──────────────────────────────────────────────

    private WhoisResult consultarRdapGenerico(String domain) {
        try {
            String url = rdapUrl + "/" + domain;
            String response = restTemplate.getForObject(url, String.class);
            return parsearRdapResponse(response, domain);
        } catch (Exception e) {
            log.debug("RDAP genérico falló para {}: {}", domain, e.getMessage());
            return WhoisResult.unknown(domain);
        }
    }

    /**
     * Parsea la respuesta RDAP (RFC 7483).
     * Busca el evento "registration" en el array "events".
     */
    private WhoisResult parsearRdapResponse(String json, String domain) throws Exception {
        if (json == null || json.isBlank()) return WhoisResult.unknown(domain);

        JsonNode root = objectMapper.readTree(json);
        JsonNode events = root.get("events");
        if (events == null || !events.isArray()) return WhoisResult.unknown(domain);

        for (JsonNode event : events) {
            String action = getTextSafe(event, "eventAction");
            if ("registration".equalsIgnoreCase(action)) {
                String dateStr = getTextSafe(event, "eventDate");
                return calcularEdad(dateStr, domain);
            }
        }
        return WhoisResult.unknown(domain);
    }

    // ── WhoisXML API (fallback) ───────────────────────────────────────────────

    private WhoisResult consultarWhoisXml(String domain) {
        try {
            String url = String.format("%s?apiKey=%s&domainName=%s&outputFormat=JSON",
                    whoisXmlUrl, whoisApiKey, domain);
            String response = restTemplate.getForObject(url, String.class);
            if (response == null) return WhoisResult.unknown(domain);

            JsonNode root = objectMapper.readTree(response);
            JsonNode record = root.get("WhoisRecord");
            if (record == null) return WhoisResult.unknown(domain);

            String dateStr = getTextSafe(record, "createdDateNormalized");
            if (dateStr.isBlank()) {
                JsonNode registry = record.get("registryData");
                if (registry != null) dateStr = getTextSafe(registry, "createdDateNormalized");
            }

            return calcularEdad(dateStr, domain);
        } catch (Exception e) {
            log.warn("WhoisXML falló para {}: {}", domain, e.getMessage());
            return WhoisResult.unknown(domain);
        }
    }

    // ── Utilidades ────────────────────────────────────────────────────────────

    private WhoisResult calcularEdad(String dateStr, String domain) {
        if (dateStr == null || dateStr.isBlank()) return WhoisResult.unknown(domain);
        try {
            LocalDate registrationDate = ZonedDateTime.parse(dateStr).toLocalDate();
            long dias = ChronoUnit.DAYS.between(registrationDate, LocalDate.now());
            return new WhoisResult(dias, registrationDate.toString(), domain);
        } catch (Exception e) {
            log.debug("No se pudo parsear fecha '{}': {}", dateStr, e.getMessage());
            return WhoisResult.unknown(domain);
        }
    }

    private String getTextSafe(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull()) ? n.asText("") : "";
    }
}
