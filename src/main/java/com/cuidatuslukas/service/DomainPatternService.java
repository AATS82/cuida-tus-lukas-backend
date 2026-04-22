package com.cuidatuslukas.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Analiza el nombre de dominio en busca de patrones de fraude:
 * keywords de forex/inversión/cripto, TLDs de alto riesgo,
 * suplantación de marcas conocidas y estructura sospechosa.
 */
@Slf4j
@Service
public class DomainPatternService {

    private static final List<String> FOREX_DOMAIN_KEYWORDS = List.of(
            "forex", "4rex", "forx", "fxtrading", "fxpro",
            "trading", "trader", "tradebot", "autotrader", "trade-"
    );

    private static final List<String> INVESTMENT_DOMAIN_KEYWORDS = List.of(
            "invest", "inversion", "inversiones", "profit", "profits",
            "earn", "earning", "money", "dinero", "capital", "fund",
            "yields", "dividend", "ganancia", "rentabilidad", "rendimiento",
            "returns", "wealth", "millonario", "millionaire", "richness",
            "ganancias", "beneficio", "beneficios"
    );

    private static final List<String> CRYPTO_DOMAIN_KEYWORDS = List.of(
            "crypto", "bitcoin", "btc", "ethereum", "eth", "coin",
            "token", "defi", "nft", "blockchain", "binance", "usdt"
    );

    // Marcas conocidas en Chile — detecta suplantación de identidad
    private static final List<String> KNOWN_BRANDS_CL = List.of(
            "bancoestado", "banco-estado", "bci", "santander", "scotiabank",
            "itau", "falabella", "ripley", "sii", "previred",
            "coopeuch", "tenpo", "fintual", "cmfchile", "bcentral",
            "chilecompra", "registro-civil", "afp", "isapre"
    );

    // Dominios oficiales de marcas — exceptuados del chequeo de suplantación
    private static final List<String> OFFICIAL_DOMAINS = List.of(
            "bancoestado.cl", "bci.cl", "santander.cl", "scotiabank.cl",
            "itau.cl", "falabella.com", "ripley.cl", "sii.cl",
            "previred.com", "coopeuch.cl", "tenpo.cl", "fintual.com",
            "cmfchile.cl", "bcentral.cl", "chilecompra.cl"
    );

    // TLDs con mayor índice de uso en dominios fraudulentos
    private static final Map<String, Integer> TLD_RISK_SCORES = Map.ofEntries(
            Map.entry("xyz", 20), Map.entry("top", 20), Map.entry("club", 15),
            Map.entry("online", 15), Map.entry("site", 15), Map.entry("icu", 20),
            Map.entry("tk", 25), Map.entry("ml", 20), Map.entry("ga", 20),
            Map.entry("cf", 20), Map.entry("buzz", 15), Map.entry("vip", 15),
            Map.entry("shop", 10), Map.entry("store", 10), Map.entry("live", 10),
            Map.entry("fun", 15), Map.entry("win", 20), Map.entry("click", 15)
    );

    public record DomainPatternResult(
            int riskScore,
            List<String> riskIndicators,
            boolean hasForexKeyword,
            boolean hasInvestmentKeyword,
            boolean hasCryptoKeyword,
            boolean isImpersonating,
            int tldRiskScore
    ) {
        public static DomainPatternResult noAplica() {
            return new DomainPatternResult(0, List.of(), false, false, false, false, 0);
        }
    }

    public DomainPatternResult analizar(String url) {
        String domain = extraerDominio(url);
        String domLower = domain.toLowerCase();

        List<String> indicators = new ArrayList<>();
        int score = 0;
        boolean hasForex = false;
        boolean hasInvest = false;
        boolean hasCrypto = false;
        boolean isImpersonating = false;

        // 1. Keywords de forex/trading en el nombre de dominio
        for (String kw : FOREX_DOMAIN_KEYWORDS) {
            if (domLower.contains(kw)) {
                hasForex = true;
                indicators.add("Término de trading en el dominio: '" + kw + "'");
                score += 25;
                break;
            }
        }

        // 2. Keywords de inversión en el nombre de dominio
        for (String kw : INVESTMENT_DOMAIN_KEYWORDS) {
            if (domLower.contains(kw)) {
                hasInvest = true;
                indicators.add("Término de inversión en el dominio: '" + kw + "'");
                score += 15;
                break;
            }
        }

        // 3. Keywords de criptomonedas en el nombre de dominio
        for (String kw : CRYPTO_DOMAIN_KEYWORDS) {
            if (domLower.contains(kw)) {
                hasCrypto = true;
                indicators.add("Término de criptomonedas en el dominio: '" + kw + "'");
                score += 15;
                break;
            }
        }

        // 4. TLD de alto riesgo
        String tld = extraerTld(domLower);
        int tldRisk = TLD_RISK_SCORES.getOrDefault(tld, 0);
        if (tldRisk > 0) {
            indicators.add("TLD de alto riesgo: '." + tld + "'");
            score += tldRisk;
        }

        // 5. Suplantación de marca conocida
        for (String brand : KNOWN_BRANDS_CL) {
            if (domLower.contains(brand) && OFFICIAL_DOMAINS.stream().noneMatch(domLower::equals)) {
                isImpersonating = true;
                indicators.add("¡POSIBLE SUPLANTACIÓN de marca conocida: '" + brand + "'!");
                score += 45;
                break;
            }
        }

        // 6. Guiones excesivos (3+) — patrón común en dominios fraudulentos
        long hyphens = domLower.chars().filter(c -> c == '-').count();
        if (hyphens >= 3) {
            indicators.add("Dominio con " + hyphens + " guiones (estructura inusual)");
            score += 10;
        }

        return new DomainPatternResult(score, indicators, hasForex, hasInvest, hasCrypto, isImpersonating, tldRisk);
    }

    private String extraerDominio(String url) {
        String d = url.replaceAll("(?i)https?://", "").split("/")[0].toLowerCase();
        if (d.startsWith("www.")) d = d.substring(4);
        return d;
    }

    private String extraerTld(String domain) {
        String[] parts = domain.split("\\.");
        return parts.length > 0 ? parts[parts.length - 1] : "";
    }
}
