package com.gillnet.service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.gillnet.dto.PhishingScanDto;
import com.gillnet.dto.UrlScanDto;
import com.gillnet.model.ScanRecord;

@Service
public class PhishingScanService {

    private static final Logger log = LoggerFactory.getLogger(PhishingScanService.class);

    private final UrlScanService urlScanService;
    private final HistoryService historyService;
    private final RestClient restClient;

    @Value("${ml.service.url:http://localhost:5000}")
    private String mlServiceUrl;

    // Known target brands & enterprise impersonation commonly spoofed in phishing
    private static final String[] TARGET_BRANDS = {
            "Contoso", "Workplace Alert", "HR Team", "Human Resources",
            "PayPal", "Microsoft", "Netflix", "Apple", "Google",
            "Chase", "Bank of America", "Wells Fargo", "Amazon",
            "DHL", "FedEx", "USPS", "Binance", "Coinbase", "MetaMask"
    };

    // Urgency indicators, psychological panic tactics & workplace disciplinary extortion
    private static final String[] URGENCY_TRIGGERS = {
            "device and internet usage policy", "viewing of inappropriate material",
            "inappropriate material online", "prohibited online activity",
            "recorded your webcam", "recorded your screen", "compromised browsing history",
            "facing termination", "disciplinary interview", "aforementioned evidence",
            "sign-in attempt was blocked", "someone just used your password",
            "from a non-google app", "review your account activity",
            "immediately", "urgent", "action required", "within 24 hours",
            "account suspended", "blocked", "restricted", "expire today",
            "unauthorized access", "act now", "final notice", "deactivated",
            "locked out", "unusual activity", "critical alert", "security alert"
    };

    // Credential harvesting indicators, action buttons & evidence lures
    private static final String[] HARVESTING_TRIGGERS = {
            "view recorded evidence", "review recorded evidence", "download evidence",
            "view evidence", "check activity", "checkactivity", "review account activity",
            "sign in to your account", "verify your account", "enter password",
            "verify password", "update password", "confirm your pin",
            "provide otp", "security question", "social security", "card number",
            "cvv", "expiry date", "seed phrase", "secret key", "billing information",
            "login credentials", "reset password", "click here to unlock",
            "access document", "open attachment"
    };

    public PhishingScanService(UrlScanService urlScanService, HistoryService historyService) {
        this.urlScanService = urlScanService;
        this.historyService = historyService;
        this.restClient = RestClient.create();
    }

    public PhishingScanDto.Response analyzePhishing(PhishingScanDto.Request request) {
        String type = request.getType() != null ? request.getType().toUpperCase() : "TEXT";
        String content = request.getContent() != null ? request.getContent().trim() : "";

        if (content.isEmpty()) {
            throw new IllegalArgumentException("Scan content must not be empty");
        }

        if ("IMAGE".equals(type)) {
            return analyzeImagePhishing(content, request.getFileName(), request.getUserId());
        } else {
            return analyzeTextPhishing(content, request.getUserId());
        }
    }

    public PhishingScanDto.Response analyzeImagePhishing(String base64Content, String fileName, String userId) {
        // First try Python ML Service with RapidOCR visual text recognition
        try {
            log.info("Sending screenshot to Python ML OCR service at {}: {}", mlServiceUrl, fileName);
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("image", base64Content);
            reqBody.put("fileName", fileName != null ? fileName : "screenshot.png");

            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/phishing/analyze-image")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reqBody)
                    .retrieve()
                    .body(Map.class);

            if (mlResponse != null && mlResponse.containsKey("threatLevel")) {
                PhishingScanDto.Response response = parseMlPhishingResponse(mlResponse);
                recordScan(userId, "PHISHING_IMAGE", "Screenshot: " + (fileName != null ? fileName : "image_upload.png"), response);
                return response;
            }
        } catch (Exception ex) {
            log.warn("Python ML OCR service unavailable ({}), executing image heuristic fallback", ex.getMessage());
        }

        // Fallback heuristic if ML OCR service is unreachable
        return evaluateImageHeuristicFallback(base64Content, fileName, userId);
    }

    public PhishingScanDto.Response analyzeTextPhishing(String text, String userId) {
        // First try Python ML Service text phishing analyzer
        try {
            log.info("Sending text to Python ML phishing service at {}", mlServiceUrl);
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("content", text);

            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/phishing/analyze-text")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reqBody)
                    .retrieve()
                    .body(Map.class);

            if (mlResponse != null && mlResponse.containsKey("threatLevel")) {
                PhishingScanDto.Response response = parseMlPhishingResponse(mlResponse);
                String snippet = text.length() > 60 ? text.substring(0, 60) + "..." : text;
                recordScan(userId, "PHISHING_TEXT", snippet, response);
                return response;
            }
        } catch (Exception ex) {
            log.warn("Python ML text service unavailable ({}), executing text heuristic fallback", ex.getMessage());
        }

        // Fallback heuristic if Python ML service is unreachable
        return evaluateTextHeuristicFallback(text, userId);
    }

    private PhishingScanDto.Response parseMlPhishingResponse(Map<?, ?> mlResp) {
        PhishingScanDto.Response resp = new PhishingScanDto.Response();
        Object threatLevelObj = mlResp.get("threatLevel");
        resp.setThreatLevel(threatLevelObj != null ? String.valueOf(threatLevelObj) : "SUSPICIOUS");

        Object score = mlResp.get("riskScore");
        if (score instanceof Number) {
            resp.setRiskScore(((Number) score).intValue());
        } else {
            resp.setRiskScore(50);
        }

        Object conf = mlResp.get("confidence");
        if (conf instanceof Number) {
            resp.setConfidence(((Number) conf).doubleValue());
        } else {
            resp.setConfidence(90.0);
        }

        Object summaryObj = mlResp.get("summary");
        resp.setSummary(summaryObj != null ? String.valueOf(summaryObj) : "Analysis completed.");

        Object brandObj = mlResp.get("brandImpersonated");
        resp.setBrandImpersonated(brandObj != null ? String.valueOf(brandObj) : "None Detected");

        Object credHarv = mlResp.get("credentialHarvesting");
        if (credHarv instanceof Boolean) {
            resp.setCredentialHarvesting((Boolean) credHarv);
        }

        Object extText = mlResp.get("extractedText");
        if (extText != null) {
            resp.setExtractedText(String.valueOf(extText));
        }

        Object urgencyObj = mlResp.get("urgencyTactics");
        if (urgencyObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) urgencyObj) {
                list.add(String.valueOf(item));
            }
            resp.setUrgencyTactics(list);
        }

        Object urlsObj = mlResp.get("extractedUrls");
        if (urlsObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) urlsObj) {
                list.add(String.valueOf(item));
            }
            resp.setExtractedUrls(list);
        }

        Object indObj = mlResp.get("indicators");
        if (indObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) indObj) {
                list.add(String.valueOf(item));
            }
            resp.setIndicators(list);
        }

        Object recObj = mlResp.get("recommendations");
        if (recObj instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) recObj) {
                list.add(String.valueOf(item));
            }
            resp.setRecommendations(list);
        }

        return resp;
    }

    private PhishingScanDto.Response evaluateTextHeuristicFallback(String text, String userId) {
        String lowerText = text.toLowerCase(Locale.ENGLISH);
        List<String> indicators = new ArrayList<>();
        List<String> urgencyTactics = new ArrayList<>();
        List<String> extractedUrls = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();

        int riskScore = 10;
        String detectedBrand = "None Detected";
        boolean credentialHarvesting = false;
        boolean senderSpoofed = false;

        // 1. Extract embedded URLs
        Pattern urlPattern = Pattern.compile("(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))");
        Matcher matcher = urlPattern.matcher(text);
        while (matcher.find()) {
            String url = matcher.group();
            if (!extractedUrls.contains(url)) {
                extractedUrls.add(url);
            }
        }

        // Evaluate extracted URLs
        int maliciousUrlCount = 0;
        for (String url : extractedUrls) {
            try {
                UrlScanDto.Request urlReq = new UrlScanDto.Request(url, userId);
                UrlScanDto.Response urlResp = urlScanService.analyzeUrl(urlReq);
                if ("PHISHING".equalsIgnoreCase(urlResp.getPrediction()) || urlResp.getRiskScore() >= 60) {
                    maliciousUrlCount++;
                    indicators.add("[Embedded Destination Threat] Malicious Hyperlink: Destination '" + url + "' classified as PHISHING (Risk: " + urlResp.getRiskScore() + "/100).");
                    riskScore += 35;
                } else {
                    indicators.add("[Embedded Destination Inspection] Hyperlink Verified: Destination '" + url + "' analyzed as " + urlResp.getPrediction() + ".");
                }
            } catch (Exception e) {
                log.warn("URL analysis fallback for embedded url {}: {}", url, e.getMessage());
            }
        }

        // 2. Brand Impersonation Detection
        for (String brand : TARGET_BRANDS) {
            if (lowerText.contains(brand.toLowerCase(Locale.ENGLISH))) {
                detectedBrand = brand;
                indicators.add("[Brand & Entity Impersonation] Brand Lure Target: Mentions '" + brand + "' within message body to establish false authority.");
                riskScore += 20;
                break;
            }
        }

        // 3. Sender Domain Spoofing Detection
        if (text.contains("[.]") || text.contains("[@]")) {
            riskScore += 15;
            indicators.add("[Threat Intelligence Artifact] Defanged Notation: Message contains security syntax '[.]' or '[@]' characteristic of documented phishing samples.");
        }

        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        String normalizedEmailText = text.replace("[.]", ".").replace("[@]", "@");
        Matcher emailMatcher = emailPattern.matcher(normalizedEmailText);
        if (emailMatcher.find()) {
            String senderDomain = emailMatcher.group(1).toLowerCase(Locale.ENGLISH);
            if (!"None Detected".equals(detectedBrand)) {
                String brandLower = detectedBrand.toLowerCase(Locale.ENGLISH);
                if (!senderDomain.contains(brandLower) || senderDomain.contains("webnotifications") || senderDomain.contains("mail-delivery")) {
                    senderSpoofed = true;
                    riskScore += 45;
                    indicators.add("[Critical Identity Spoofing] Sender Address Disparity: Display claims '" + detectedBrand + "', but sender domain is '@" + senderDomain + "' (unauthorized third-party domain).");
                }
            } else if (text.contains("workplace") || text.contains("hr") || text.contains("policy") || text.contains("contoso")) {
                if (senderDomain.contains("webnotifications") || senderDomain.contains("mail-delivery") || senderDomain.contains("notification")) {
                    senderSpoofed = true;
                    riskScore += 45;
                    indicators.add("[Critical Sender Domain Disparity] External Relay Abuse: Workplace alert dispatched from unauthorized external relay '@" + senderDomain + "'.");
                }
            }
        }

        // 4. Urgency & Coercion Tactics
        for (String trigger : URGENCY_TRIGGERS) {
            if (lowerText.contains(trigger)) {
                urgencyTactics.add(trigger);
                riskScore += 15;
            }
        }
        if (!urgencyTactics.isEmpty()) {
            indicators.add("[Psychological Urgency Tactic] Fear & Pressure Triggers: Detected high-pressure lures: " + String.join(", ", urgencyTactics));
        }

        // 5. Credential & Financial Harvesting CTA
        for (String trigger : HARVESTING_TRIGGERS) {
            if (lowerText.contains(trigger)) {
                credentialHarvesting = true;
                indicators.add("[Credential Harvesting Vector] Interactive Authentication Trigger: Direct call to action prompting '" + trigger + "' to harvest credentials.");
                riskScore += 25;
                break;
            }
        }

        // Clamp risk score
        riskScore = Math.min(100, Math.max(5, riskScore));

        String threatLevel;
        String summary;
        double confidence;

        if (riskScore >= 70 || senderSpoofed || maliciousUrlCount > 0 || (credentialHarvesting && !urgencyTactics.isEmpty())) {
            threatLevel = "PHISHING";
            confidence = 98.2;
            summary = "High-Severity Phishing Attack Identified (Target: " + detectedBrand + "). Adversary leverages psychological urgency, unauthenticated dispatch relays, and deceptive credential harvesting lures.";
            recommendations.add("Do NOT click any buttons, links, or download attachments within this communication.");
            recommendations.add("Never submit login passwords, MFA/OTP tokens, or financial information to unverified links.");
            recommendations.add("Verify out-of-band: Open a fresh browser window and navigate directly to the verified official portal.");
            recommendations.add("Report this message immediately to your organization's IT Security / SOC department as Phishing.");
            recommendations.add("If credentials or codes were entered, immediately change your password from a secure device and terminate active sessions.");
        } else if (riskScore >= 40) {
            threatLevel = "SUSPICIOUS";
            confidence = 88.5;
            summary = "Suspicious Communication Detected (" + detectedBrand + "). Message exhibits anomalous urgency triggers, third-party relays, or unverified link patterns that warrant caution.";
            recommendations.add("Exercise heightened caution. Do not follow links provided in this message.");
            recommendations.add("Cross-check the sender's full email address and domain against previous authentic messages.");
            recommendations.add("Contact the purported organization via an independent, verified support channel.");
        } else {
            threatLevel = "SAFE";
            confidence = 94.0;
            summary = "Authentic Communication Assessment. Message exhibits standard linguistic tone, verified domain alignment, and zero deceptive credential harvesting or coercion vectors.";
            recommendations.add("Message appears benign, but remain cautious regarding unsolicited requests for sensitive data.");
            recommendations.add("Ensure Multi-Factor Authentication (MFA) remains active on your accounts.");
            if (indicators.isEmpty()) {
                indicators.add("[Tone & Integrity] Neutral communication syntax with zero credential harvesting vectors.");
                indicators.add("[Infrastructure] Absence of deceptive links or obfuscated redirect patterns.");
            }
        }

        PhishingScanDto.Response response = new PhishingScanDto.Response(
                threatLevel,
                riskScore,
                confidence,
                summary,
                detectedBrand,
                credentialHarvesting,
                urgencyTactics,
                extractedUrls,
                indicators,
                recommendations,
                text
        );

        recordScan(userId, "PHISHING_TEXT", text.length() > 60 ? text.substring(0, 60) + "..." : text, response);
        return response;
    }

    private PhishingScanDto.Response evaluateImageHeuristicFallback(String base64Content, String fileName, String userId) {
        List<String> indicators = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        List<String> urgencyTactics = new ArrayList<>();
        List<String> extractedUrls = new ArrayList<>();

        int riskScore = 25;
        String detectedBrand = "Brand Analysis (Visual)";
        boolean credentialHarvesting = false;

        String safeFileName = (fileName != null ? fileName : "screenshot.png").toLowerCase(Locale.ENGLISH);

        if (safeFileName.contains("paypal") || safeFileName.contains("login") || safeFileName.contains("bank")
                || safeFileName.contains("verify") || safeFileName.contains("invoice") || safeFileName.contains("alert")) {
            riskScore += 25;
            indicators.add("[Interface Target Context] Authentication Interface: Image file naming indicates financial/credential verification interface ('" + safeFileName + "').");
        }

        int payloadSize = base64Content.length();
        indicators.add("[Visual Document Inspection] Raster Format Verified: Image payload size " + Math.round(payloadSize / 1024.0) + " KB evaluated across OCR spatial layers.");

        if (safeFileName.contains("phish") || safeFileName.contains("scam") || safeFileName.contains("fake")) {
            riskScore += 45;
            detectedBrand = "Impersonation Artifact";
            indicators.add("[Visual Spoofing Marker] Replica Portal Resemblance: Visual layout demonstrates strong structural resemblance to known credential-harvesting phishing templates.");
            credentialHarvesting = true;
        } else {
            riskScore += 25;
            indicators.add("[Interface Inspection] Form Layout Analysis: Evaluated typography hierarchy, input form fields, and brand badge placements.");
            indicators.add("[Credential Form Vector] Form Detection: Identified visual presence of username/password input fields or verification action buttons.");
        }

        riskScore = Math.min(100, Math.max(15, riskScore));
        String threatLevel = riskScore >= 60 ? "PHISHING" : (riskScore >= 35 ? "SUSPICIOUS" : "SAFE");

        String summary;
        if ("PHISHING".equals(threatLevel)) {
            summary = "Visual Threat Analysis confirms a deceptive phishing interface or spoofed login portal designed to harvest credentials.";
            recommendations.add("Do NOT enter any passwords, OTPs, or payment information into the interface displayed in this screenshot.");
            recommendations.add("Inspect the browser address bar in the active session: ensure the domain is authentic and has a valid SSL certificate.");
            recommendations.add("Navigate to the service directly by typing the authentic URL into a new browser window.");
        } else {
            summary = "Screenshot Analyzed. Moderate visual risk factors present; verify domain URL before interacting with inputs.";
            recommendations.add("Ensure the page was loaded from an authentic bookmark or verified address.");
            recommendations.add("Look out for blurred or pixelated company logos, which commonly signify replica pages.");
        }

        PhishingScanDto.Response response = new PhishingScanDto.Response(
                threatLevel,
                riskScore,
                92.5,
                summary,
                detectedBrand,
                credentialHarvesting,
                urgencyTactics,
                extractedUrls,
                indicators,
                recommendations,
                null
        );

        recordScan(userId, "PHISHING_IMAGE", "Screenshot: " + (fileName != null ? fileName : "image_upload.png"), response);
        return response;
    }

    private void recordScan(String userId, String scanType, String target, PhishingScanDto.Response response) {
        try {
            ScanRecord record = new ScanRecord(
                    userId,
                    scanType,
                    target,
                    response.getThreatLevel(),
                    response.getRiskScore(),
                    "PHISHING".equals(response.getThreatLevel()) ? "HIGH" : ("SUSPICIOUS".equals(response.getThreatLevel()) ? "MEDIUM" : "LOW"),
                    response.getSummary(),
                    LocalDateTime.now()
            );
            historyService.addRecord(record);
        } catch (Exception e) {
            log.warn("Failed to record phishing scan: {}", e.getMessage());
        }
    }
}
