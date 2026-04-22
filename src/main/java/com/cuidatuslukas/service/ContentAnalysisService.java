package com.cuidatuslukas.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analiza el contenido HTML de una página web buscando señales de estafa:
 * keywords de forex/trading, promesas de rendimientos garantizados,
 * esquemas MLM y tácticas de presión.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ContentAnalysisService {

    private final RestTemplate restTemplate;

    private static final List<String> FOREX_KEYWORDS = List.of(
            "forex", "divisas", "par de divisas", "trading de divisas",
            "metatrader", "mt4", "mt5", "pip", "spread", "apalancamiento",
            "leverage", "broker de forex", "mercado de divisas"
    );

    private static final List<String> INVESTMENT_SCAM_KEYWORDS = List.of(
            "garantizado", "guaranteed", "100% seguro", "sin riesgo", "risk free",
            "rentabilidad diaria", "ganancia diaria", "daily profit",
            "retorno garantizado", "ganancias aseguradas", "sin pérdidas",
            "multiplica tu dinero", "duplica tu inversión", "inversión segura",
            "nunca pierdas", "retiro inmediato", "withdraw instantly"
    );

    private static final List<String> CRYPTO_SCAM_KEYWORDS = List.of(
            "bitcoin garantizado", "crypto garantizado", "staking garantizado",
            "yield farming garantizado", "rendimiento en bitcoin",
            "gana bitcoin", "earn bitcoin daily"
    );

    private static final List<String> MLM_KEYWORDS = List.of(
            "multinivel", "multi-nivel", "mlm", "network marketing",
            "comisión por referido", "comisión de referido", "plan de compensación",
            "recluta miembros", "recluta nuevos", "downline", "upline",
            "gana por referir", "gana invitando"
    );

    private static final List<String> URGENCY_KEYWORDS = List.of(
            "actúa ahora", "act now", "oferta limitada", "limited offer",
            "últimas plazas", "cupos limitados", "no pierdas esta oportunidad",
            "solo hoy", "tiempo limitado", "regístrate ya", "únete ahora"
    );

    // Detecta patrones como "20% diario", "5% mensual", "200% ROI"
    private static final Pattern HIGH_YIELD_PATTERN = Pattern.compile(
            "(\\d+[,.]?\\d*)\\s*%\\s*(diario|mensual|semanal|daily|monthly|weekly|al\\s*mes|al\\s*día|roi|anual|annual)",
            Pattern.CASE_INSENSITIVE
    );

    public record ContentAnalysisResult(
            int riskScore,
            List<String> detectedKeywords,
            boolean hasForexIndicators,
            boolean hasHighYieldPromises,
            boolean hasCryptoScamIndicators,
            boolean hasMlmIndicators,
            boolean fetchSuccess
    ) {
        public static ContentAnalysisResult noDisponible() {
            return new ContentAnalysisResult(0, List.of(), false, false, false, false, false);
        }
    }

    @Cacheable(value = "contentResults", key = "#url.toLowerCase().trim()")
    public ContentAnalysisResult analizar(String url) {
        String normalizedUrl = url.startsWith("http") ? url : "https://" + url;

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36");
            headers.set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
            headers.set("Accept-Language", "es-CL,es;q=0.9,en;q=0.8");

            ResponseEntity<String> response = restTemplate.exchange(
                    normalizedUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class
            );

            String body = response.getBody();
            if (body == null || body.isBlank()) return ContentAnalysisResult.noDisponible();

            String text = limpiarHtml(body);
            return analizarTexto(text);

        } catch (Exception e) {
            log.warn("No se pudo obtener contenido de {}: {}", url, e.getMessage());
            return ContentAnalysisResult.noDisponible();
        }
    }

    private String limpiarHtml(String html) {
        String text = html.toLowerCase()
                .replaceAll("(?s)<script[^>]*>.*?</script>", " ")
                .replaceAll("(?s)<style[^>]*>.*?</style>", " ")
                .replaceAll("<[^>]+>", " ")
                .replaceAll("&[a-z]{2,6};", " ")
                .replaceAll("\\s+", " ")
                .trim();
        // Limitar a 60k caracteres para evitar problemas de memoria
        return text.length() > 60_000 ? text.substring(0, 60_000) : text;
    }

    private ContentAnalysisResult analizarTexto(String text) {
        List<String> detected = new ArrayList<>();

        boolean hasForex    = detectar(text, FOREX_KEYWORDS, detected);
        boolean hasHighYield = detectar(text, INVESTMENT_SCAM_KEYWORDS, detected)
                             | detectarHighYield(text, detected);
        boolean hasCrypto   = detectar(text, CRYPTO_SCAM_KEYWORDS, detected);
        boolean hasMlm      = detectar(text, MLM_KEYWORDS, detected);
        detectar(text, URGENCY_KEYWORDS, detected);

        int score = 0;
        if (hasForex && hasHighYield) score += 30;  // Forex + garantías = estafa clásica
        else if (hasHighYield)        score += 25;
        else if (hasForex)            score += 15;
        if (hasMlm)                   score += 20;
        if (hasCrypto)                score += 15;

        return new ContentAnalysisResult(
                Math.min(score, 30), detected,
                hasForex, hasHighYield, hasCrypto, hasMlm, true
        );
    }

    private boolean detectar(String text, List<String> keywords, List<String> detected) {
        boolean found = false;
        for (String kw : keywords) {
            if (text.contains(kw)) {
                if (!detected.contains(kw)) detected.add(kw);
                found = true;
            }
        }
        return found;
    }

    private boolean detectarHighYield(String text, List<String> detected) {
        Matcher m = HIGH_YIELD_PATTERN.matcher(text);
        if (m.find()) {
            String match = m.group().trim();
            if (!detected.contains(match)) detected.add("Rendimiento prometido: \"" + match + "\"");
            return true;
        }
        return false;
    }
}
