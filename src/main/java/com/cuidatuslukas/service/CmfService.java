package com.cuidatuslukas.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

/**
 * Consulta la API pública de la CMF Chile para verificar si una entidad
 * está autorizada a captar dinero del público.
 *
 * Registra tu API key gratuita en: https://api.cmfchile.cl
 * Si no hay API key configurada, devuelve resultado DESCONOCIDO (no falso negativo).
 *
 * Endpoints consultados:
 *  - /bancos                      — Bancos
 *  - /agf                         — Administradoras Generales de Fondos
 *  - /corredoresbolsa             — Corredores de Bolsa
 *  - /companias_seguros_vida      — Seguros de Vida
 *  - /companias_seguros_generales — Seguros Generales
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CmfService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.cmf.api-key:}")
    private String apiKey;

    @Value("${app.cmf.base-url}")
    private String baseUrl;

    // ── Resultado encapsulado ─────────────────────────────────────────────────

    public record CmfResult(boolean authorized, String entityName, String entityType) {
        public static CmfResult unauthorized() {
            return new CmfResult(false, null, null);
        }
        public static CmfResult unknown() {
            return new CmfResult(false, null, "UNKNOWN");
        }
        public static CmfResult authorized(String name, String type) {
            return new CmfResult(true, name, type);
        }
    }

    // ── API Endpoints de la CMF ───────────────────────────────────────────────

    private static final String[] ENDPOINTS = {
        "/bancos",
        "/agf",
        "/corredoresbolsa",
        "/companias_seguros_vida",
        "/companias_seguros_generales"
    };

    private static final String[] ENTITY_TYPES = {
        "Banco",
        "Administradora General de Fondos (AGF)",
        "Corredor de Bolsa",
        "Compañía de Seguros de Vida",
        "Compañía de Seguros Generales"
    };

    /**
     * Verifica si una entidad está autorizada por la CMF.
     * @param query RUT (ej: "97004000-5") o nombre parcial (ej: "Banco de Chile")
     */
    @Cacheable(value = "cmfResults", key = "#query.toLowerCase().trim()")
    public CmfResult verificar(String query) {
        if (apiKey == null || apiKey.isBlank()) {
            log.warn("CMF_API_KEY no configurada — omitiendo verificación CMF para: {}", query);
            return CmfResult.unknown();
        }

        String queryNorm = query.toLowerCase().trim()
                .replace(".", "")
                .replace("-", "");

        for (int i = 0; i < ENDPOINTS.length; i++) {
            String endpoint = ENDPOINTS[i];
            String tipo = ENTITY_TYPES[i];
            try {
                Optional<String> resultado = buscarEnEndpoint(endpoint, queryNorm, tipo);
                if (resultado.isPresent()) {
                    return CmfResult.authorized(resultado.get(), tipo);
                }
            } catch (Exception e) {
                log.warn("Error consultando CMF endpoint {}: {}", endpoint, e.getMessage());
            }
        }

        return CmfResult.unauthorized();
    }

    private Optional<String> buscarEnEndpoint(String endpoint, String queryNorm, String tipo) throws Exception {
        String url = String.format("%s%s?apikey=%s&formato=json", baseUrl, endpoint, apiKey);
        String response = restTemplate.getForObject(url, String.class);

        if (response == null || response.isBlank()) return Optional.empty();

        JsonNode root = objectMapper.readTree(response);

        // La CMF devuelve el array dentro de una clave con el nombre del recurso
        // Ej: {"Bancos": [...]}  |  {"AGF": [...]}
        JsonNode array = root.isArray() ? root : root.elements().next();

        if (array == null || !array.isArray()) return Optional.empty();

        for (JsonNode entity : array) {
            String nombre = getTextSafe(entity, "Nombre");
            String rut    = getTextSafe(entity, "RUT")
                    .replace(".", "")
                    .replace("-", "");

            String nombreNorm = nombre.toLowerCase()
                    .replace(".", "")
                    .replace("-", "");

            if (rut.contains(queryNorm) || queryNorm.contains(rut) ||
                nombreNorm.contains(queryNorm) || queryNorm.contains(nombreNorm)) {
                log.info("CMF match encontrado en {}: {} [{}]", tipo, nombre, rut);
                return Optional.of(nombre);
            }
        }

        return Optional.empty();
    }

    private String getTextSafe(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull()) ? n.asText("") : "";
    }
}
