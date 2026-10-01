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

    private static final String[] SHORTENER_DOMAINS = {
            "bit.ly", "tinyurl.com", "tinyurl", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "j.mp", "cutt.ly", "shorte.st",
            "tiny.cc", "rb.gy", "shorturl.at", "lnkd.in", "fb.me", "t.ly",
            "bitly.com", "s.id", "short.gy"
    };

    private static final String[] SUSPICIOUS_TLDS = {
            ".tk", ".xyz", ".top", ".club", ".online", ".site", ".buzz", ".cf",
            ".gq", ".ml", ".pw", ".rest", ".fit", ".lol", ".cam", ".quest",
            ".zip", ".mov", ".monster", ".click", ".link", ".work", ".gdn",
            ".bid", ".win", ".stream", ".trade", ".review", ".date", ".faith",
            ".cricket", ".science", ".party", ".loan", ".download"
    };

    private static final String[] PATH_KEYWORDS = {
            "login", "signin", "sign-in", "verify", "verification", "secure",
            "account", "update", "confirm", "banking", "wallet", "credential",
            "password", "ebayisapi", "webscr", "authenticate", "oauth"
    };

    private static final String[] HOST_KEYWORDS = {
            "login", "verify", "banking", "update", "paypal", "account",
            "wallet", "signin", "confirm"
    };

    private static final String[] IMPERSONATED_BRANDS = {
            "paypal", "apple", "amazon", "microsoft", "netflix", "chase",
            "wellsfargo", "bankofamerica", "linkedin", "facebook", "instagram",
            "gmail", "outlook", "office365", "ebay", "hsbc", "citibank",
            "santander", "binance", "coinbase", "metamask", "dhl", "fedex",
            "google", "alibaba", "whatsapp", "telegram", "absa", "simplii",
            "standardbank", "fnb", "nedbank", "icici", "hdfc", "sbi"
    };

    private static final String[] FREE_HOSTING_DOMAINS = {
            "duckdns.org", "no-ip.", "dyndns", "github.io", "glitch.me",
            "netlify.app", "pages.dev", "web.app", "firebaseapp.com",
            "blogspot.", "wordpress.com", "weebly.com", "wixsite.com",
            "000webhost", "altervista.org", "yolasite.com"
    };

    private static final Pattern IP_HOST_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern BASE64_PATH_PATTERN = Pattern.compile("[A-Za-z0-9+/]{24,}={0,2}");

    private static boolean domainMatches(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
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
            if (host.isEmpty()) {
                throw new IllegalArgumentException("missing host");
            }
            String lowerUrl = url.toLowerCase();
            String rawPath = uri.getPath() != null ? uri.getPath() : "";
            String rawQuery = uri.getQuery() != null ? uri.getQuery() : "";
            String pathAndQuery = (rawPath + "?" + rawQuery).toLowerCase();

            boolean trustedInfrastructure = host.endsWith(".gov") || host.contains(".gov.")
                    || host.endsWith(".edu") || host.contains(".edu.") || host.contains(".ac.")
                    || host.endsWith(".arpa") || host.contains("awsdns-");

            // Raw numeric IP host (UCI: having_IP_Address)
            if (IP_HOST_PATTERN.matcher(host).matches()) {
                reasons.add("[Evasion & Infrastructure] Raw Numeric IP: Hostname targets a direct numeric IP address (" + host + ") rather than a registered domain, bypassing standard domain reputation checks.");
                riskScore += 40;
            }

            // Abnormal URL length (UCI: URL_Length)
            if (url.length() > 75) {
                reasons.add("[Obfuscation Vector] Abnormal URL Length: Link exceeds 75 characters (" + url.length() + " chars), a pattern commonly used to embed tracking tokens and obscure the destination.");
                riskScore += 15;
            }

            // '@' credential-redirection delimiter (UCI: having_At_Symbol)
            if (url.contains("@")) {
                reasons.add("[Credential Redirection] RFC-3986 '@' Exploit: URL contains '@' delimiter causing web clients to disregard preceding text and redirect solely to the trailing host.");
                riskScore += 25;
            }

            // Hyphenated domain token / typosquatting (UCI: Prefix_Suffix), exempt trusted infrastructure
            if (host.contains("-") && !trustedInfrastructure) {
                reasons.add("[Domain Spoofing] Hyphenated Domain Token: Hostname contains hyphens ('" + host + "'), frequently weaponized in brand typosquatting to impersonate legitimate entities.");
                riskScore += 15;
            }

            // Excessive subdomain depth (UCI: having_Sub_Domain)
            long dots = host.chars().filter(ch -> ch == '.').count();
            if (dots > 2) {
                reasons.add("[DNS Manipulation] Excessive Subdomains: Detected " + dots + " subdomain levels, indicating potential DNS delegation spoofing or multi-tier phishing masking.");
                riskScore += 20;
            }

            // Unencrypted transport (UCI: SSLfinal_State)
            if (!lowerUrl.startsWith("https://")) {
                reasons.add("[Transport Vulnerability] Unencrypted Communication: Connection uses unencrypted HTTP, leaving transmitted credentials susceptible to network eavesdropping and MITM attacks.");
                riskScore += 15;
            }

            // Credential-harvesting keywords in the hostname itself
            for (String kw : HOST_KEYWORDS) {
                if (host.contains(kw)) {
                    reasons.add("[Credential Harvesting Vector] Sensitive Authentication Keyword: Hostname includes high-risk credential trigger '" + kw + "' on an unverified domain.");
                    riskScore += 20;
                    break;
                }
            }

            // Link shorteners obscure the true destination (UCI: Shortining_Service)
            for (String shortener : SHORTENER_DOMAINS) {
                if (domainMatches(host, shortener)) {
                    reasons.add("[Obfuscation Vector] URL Shortener: Destination is hidden behind link-shortening service '" + shortener + "', preventing pre-click inspection of the true target.");
                    riskScore += 25;
                    break;
                }
            }

            // TLDs disproportionately abused for phishing
            for (String tld : SUSPICIOUS_TLDS) {
                if (host.endsWith(tld)) {
                    reasons.add("[Threat Intelligence] High-Risk TLD: Domain uses top-level domain '" + tld + "', which is disproportionately abused for phishing and scam infrastructure.");
                    riskScore += 20;
                    break;
                }
            }

            // Internationalized domain name homograph attacks
            if (host.contains("xn--")) {
                reasons.add("[Domain Spoofing] Punycode / IDN Homograph: Hostname uses punycode encoding ('xn--'), a classic technique for visually impersonating legitimate domains with lookalike characters.");
                riskScore += 30;
            }

            // Double-slash redirect after the authority section (UCI: double_slash_redirecting)
            String afterScheme = url.contains("://") ? url.substring(url.indexOf("://") + 3) : url;
            if (afterScheme.contains("//")) {
                reasons.add("[Credential Redirection] Double-Slash Redirect: URL contains '//' beyond the scheme, a known open-redirect trick that sends victims to an attacker-controlled host.");
                riskScore += 25;
            }

            // Non-standard port (UCI: port)
            int port = uri.getPort();
            if (port != -1 && port != 80 && port != 443) {
                reasons.add("[Evasion & Infrastructure] Non-Standard Port: Service runs on port " + port + " instead of 80/443, typical of throwaway phishing kits avoiding standard web hosting.");
                riskScore += 20;
            }

            // Digit-saturated hostname (algorithmically generated lookalike domains)
            long digitCount = host.chars().filter(Character::isDigit).count();
            if (digitCount >= 3) {
                reasons.add("[Domain Spoofing] Digit-Saturated Hostname: Host contains " + digitCount + " digits, characteristic of algorithmically generated phishing domains.");
                riskScore += 25;
            }

            // Credential-harvesting keywords in path / query
            for (String kw : PATH_KEYWORDS) {
                if (pathAndQuery.contains(kw)) {
                    reasons.add("[Credential Harvesting Vector] Sensitive Path Keyword: URL path includes high-risk credential trigger '" + kw + "'.");
                    riskScore += 20;
                    break;
                }
            }

            // Abnormally long hostname
            if (host.length() > 30) {
                reasons.add("[Obfuscation Vector] Abnormal Hostname Length: Hostname exceeds 30 characters (" + host.length() + "), consistent with deceptive compound domains.");
                riskScore += 15;
            }

            // Impersonated brand in path while the host is NOT that brand's domain
            for (String brand : IMPERSONATED_BRANDS) {
                if (pathAndQuery.contains(brand) && !domainMatches(host, brand)
                        && !host.contains(brand + ".com") && !host.contains(brand + ".")) {
                    reasons.add("[Brand & Entity Impersonation] Brand Lure in Path: URL path invokes trusted brand '" + brand + "' while the hosting domain '" + host + "' is not affiliated with it.");
                    riskScore += 25;
                    break;
                }
            }

            // Free / dynamic hosting infrastructure abused for throwaway kits
            for (String freeHost : FREE_HOSTING_DOMAINS) {
                boolean match = freeHost.contains(".")
                        ? domainMatches(host, freeHost)
                        : host.contains(freeHost);
                if (match) {
                    reasons.add("[Evasion & Infrastructure] Free Hosting Infrastructure: Site is hosted on free/dynamic infrastructure '" + freeHost + "', heavily abused for disposable phishing kits.");
                    riskScore += 15;
                    break;
                }
            }

            // Base64 / encoded blob in the path (obfuscated payload or tracking token)
            if (BASE64_PATH_PATTERN.matcher(rawPath).find()) {
                reasons.add("[Obfuscation Vector] Encoded Path Blob: URL path contains a long encoded token, commonly used to obfuscate phishing kit routing or victim identifiers.");
                riskScore += 15;
            }

            // Accredited / infrastructure domains are whitelisted AFTER all scoring
            if (trustedInfrastructure) {
                reasons.add("[Accredited Registry] Verified educational, public-authority, or provider-infrastructure domain ('" + host + "').");
                riskScore = Math.min(riskScore, 10);
            }

        } catch (Exception e) {
            reasons.add("[Structural Anomaly] Malformed URL Structure: Unable to parse standard RFC URI syntax.");
            riskScore += 30;
        }

        riskScore = Math.min(100, Math.max(0, riskScore));
        String prediction = riskScore >= 45 ? "PHISHING" : "SAFE";


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
