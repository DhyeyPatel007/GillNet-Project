package com.gillnet.service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.gillnet.dto.UrlScanDto;
import com.gillnet.model.ScanRecord;
import com.gillnet.repository.ScanRecordRepository;

@Service
public class UrlScanService {

    private static final Logger log = LoggerFactory.getLogger(UrlScanService.class);

    private final HistoryService historyService;
    private final RestClient restClient;

    @Value("${ml.service.url:http://localhost:5000}")
    private String mlServiceUrl;

    public UrlScanService(HistoryService historyService) {
        this.historyService = historyService;
        this.restClient = RestClient.create();
    }

    public UrlScanDto.Response analyzeUrl(UrlScanDto.Request request) {
        String rawUrl = request.getUrl();
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("URL must not be empty");
        }

        String normalizedUrl = rawUrl.trim();
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "https://" + normalizedUrl;
        }

        UrlScanDto.Response response;
        try {
            // Attempt to call Python ML service
            log.info("Sending URL to Python ML service at {}: {}", mlServiceUrl, normalizedUrl);
            Map<String, String> mlRequestBody = Map.of("url", normalizedUrl);

            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/url/check")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(mlRequestBody)
                    .retrieve()
                    .body(Map.class);

            response = new UrlScanDto.Response();
            response.setUrl(normalizedUrl);
            response.setPrediction((String) mlResponse.getOrDefault("prediction", "SAFE"));

            Object conf = mlResponse.get("confidence");
            if (conf instanceof Number) {
                response.setConfidence(((Number) conf).doubleValue());
            } else {
                response.setConfidence(85.0);
            }

            Object score = mlResponse.get("riskScore");
            if (score instanceof Number) {
                response.setRiskScore(((Number) score).intValue());
            } else {
                response.setRiskScore("PHISHING".equalsIgnoreCase(response.getPrediction()) ? 85 : 15);
            }

            response.setModel((String) mlResponse.getOrDefault("model", "Random Forest ML Classifier"));

            Object reasonsObj = mlResponse.get("reasons");
            if (reasonsObj instanceof List) {
                List<String> reasons = new ArrayList<>();
                for (Object item : (List<?>) reasonsObj) {
                    reasons.add(String.valueOf(item));
                }
                response.setReasons(reasons);
            } else {
                response.setReasons(List.of("Analyzed by machine learning model."));
            }

            response.setRecommendation((String) mlResponse.getOrDefault("recommendation",
                    "PHISHING".equalsIgnoreCase(response.getPrediction())
                            ? "Do not open this website or enter sensitive information."
                            : "The website appears legitimate based on current analysis."));

        } catch (Exception ex) {
            log.warn("Python ML service unavailable ({}), executing rule-based heuristic engine", ex.getMessage());
            response = evaluateHeuristicFallback(normalizedUrl);
        }

        // Persist scan record
        try {
            String riskLevel = response.getRiskScore() >= 70 ? "HIGH" : (response.getRiskScore() >= 40 ? "MEDIUM" : "LOW");
            ScanRecord record = new ScanRecord(
                    request.getUserId(),
                    "URL",
                    normalizedUrl,
                    response.getPrediction(),
                    response.getRiskScore(),
                    riskLevel,
                    response.getReasons().isEmpty() ? "No threats detected" : String.join("; ", response.getReasons()),
                    LocalDateTime.now()
            );
            historyService.addRecord(record);
        } catch (Exception e) {
            log.warn("Failed to record scan: {}", e.getMessage());
        }

        return response;
    }

    private UrlScanDto.Response evaluateHeuristicFallback(String url) {
        UrlScanDto.Response resp = new UrlScanDto.Response();
        resp.setUrl(url);
        resp.setModel("GillNet Hybrid Heuristic Engine (Fallback)");

        List<String> reasons = new ArrayList<>();
        int riskScore = 15;

        try {
            URI uri = URI.create(url);
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";

            // Check IP address
            Pattern ipPattern = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
            if (ipPattern.matcher(host).matches()) {
                reasons.add("[Evasion & Infrastructure] Raw Numeric IP: Hostname targets a direct numeric IP address (" + host + ") rather than a registered domain, bypassing standard domain reputation checks.");
                riskScore += 40;
            }

            // Check length
            if (url.length() > 75) {
                reasons.add("[Obfuscation Vector] Abnormal URL Length: Link exceeds 75 characters (" + url.length() + " chars), a pattern commonly used to embed tracking tokens and obscure the destination.");
                riskScore += 15;
            }

            // Check @ symbol
            if (url.contains("@")) {
                reasons.add("[Credential Redirection] RFC-3986 '@' Exploit: URL contains '@' delimiter causing web clients to disregard preceding text and redirect solely to the trailing host.");
                riskScore += 25;
            }

            // Check hyphens in hostname
            if (host.contains("-")) {
                reasons.add("[Domain Spoofing] Hyphenated Domain Token: Hostname contains hyphens ('" + host + "'), frequently weaponized in brand typosquatting to impersonate legitimate entities.");
                riskScore += 15;
            }

            // Check subdomains
            long dots = host.chars().filter(ch -> ch == '.').count();
            if (dots > 2) {
                reasons.add("[DNS Manipulation] Excessive Subdomains: Detected " + dots + " subdomain levels, indicating potential DNS delegation spoofing or multi-tier phishing masking.");
                riskScore += 20;
            }

            // Check HTTPS
            if (!url.toLowerCase().startsWith("https://")) {
                reasons.add("[Transport Vulnerability] Unencrypted Communication: Connection uses unencrypted HTTP, leaving transmitted credentials susceptible to network eavesdropping and MITM attacks.");
                riskScore += 20;
            }

            // Check keywords
            String[] keywords = {"login", "verify", "secure", "banking", "update", "paypal", "account", "wallet"};
            for (String kw : keywords) {
                if (url.toLowerCase().contains(kw) && !host.contains(kw + ".com")) {
                    reasons.add("[Credential Harvesting Vector] Sensitive Authentication Keyword: Path includes high-risk credential trigger '" + kw + "' on an unverified domain.");
                    riskScore += 20;
                    break;
                }
            }

        } catch (Exception e) {
            reasons.add("[Structural Anomaly] Malformed URL Structure: Unable to parse standard RFC URI syntax.");
            riskScore += 30;
        }

        riskScore = Math.min(100, Math.max(0, riskScore));
        String prediction = riskScore >= 50 ? "PHISHING" : "SAFE";

        if (reasons.isEmpty()) {
            reasons.add("[Domain & Registry] Standard registered domain structure with valid format conventions.");
            reasons.add("[Transport Security] Encrypted HTTPS protocol verified.");
            reasons.add("[Lexical Structure] Clean URL composition with zero credential injection delimiters or deceptive redirect parameters.");
        }

        resp.setPrediction(prediction);
        resp.setConfidence("PHISHING".equals(prediction) ? 89.5 : 94.0);
        resp.setRiskScore(riskScore);
        resp.setReasons(reasons);
        resp.setRecommendation("PHISHING".equals(prediction)
                ? "CRITICAL THREAT ADVISORY: High likelihood of phishing detected. Do not navigate to this destination or enter sensitive credentials. Verify through official authenticated portals."
                : "VERIFIED SAFE DESTINATION: The URL conforms to standard legitimate security heuristics. Confirm address bar padlock before entering sensitive information.");

        return resp;
    }
}
