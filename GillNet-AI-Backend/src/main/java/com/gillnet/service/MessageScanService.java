package com.gillnet.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.gillnet.dto.MessageScanDto;
import com.gillnet.model.ScanRecord;

@Service
public class MessageScanService {

    private static final Logger log = LoggerFactory.getLogger(MessageScanService.class);

    private final HistoryService historyService;
    private final RestClient restClient;

    @Value("${ml.service.url:http://localhost:5000}")
    private String mlServiceUrl;

    public MessageScanService(HistoryService historyService) {
        this.historyService = historyService;
        this.restClient = RestClient.create();
    }

    public MessageScanDto.Response analyzeMessage(MessageScanDto.Request request) {
        String message = request.getMessage();
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Message must not be empty");
        }

        // 1. First attempt inference via Python ML NLP Model Service
        try {
            log.info("Sending message to Python ML NLP service at {}", mlServiceUrl);
            Map<String, String> reqBody = Map.of("message", message);
            Map mlResponse = restClient.post()
                    .uri(mlServiceUrl + "/api/v1/message/check")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(reqBody)
                    .retrieve()
                    .body(Map.class);

            if (mlResponse != null && mlResponse.containsKey("classification")) {
                MessageScanDto.Response response = new MessageScanDto.Response();
                Object classObj = mlResponse.get("classification");
                response.setClassification(classObj != null ? String.valueOf(classObj) : "SCAM");

                Object score = mlResponse.get("riskScore");
                response.setRiskScore(score instanceof Number ? ((Number) score).intValue() : 80);

                Object levelObj = mlResponse.get("riskLevel");
                response.setRiskLevel(levelObj != null ? String.valueOf(levelObj) : "HIGH");

                Object expObj = mlResponse.get("explanation");
                response.setExplanation(expObj != null ? String.valueOf(expObj) : "Analysis complete.");

                Object recObj = mlResponse.get("recommendation");
                response.setRecommendation(recObj != null ? String.valueOf(recObj) : "Stay vigilant.");

                Object indObj = mlResponse.get("indicators");
                if (indObj instanceof List) {
                    List<String> list = new ArrayList<>();
                    for (Object item : (List<?>) indObj) {
                        list.add(String.valueOf(item));
                    }
                    response.setIndicators(list);
                }

                recordScan(request.getUserId(), message, response);
                return response;
            }
        } catch (Exception ex) {
            log.warn("Python ML message check unavailable ({}), executing rule-based heuristic engine", ex.getMessage());
        }

        // 2. Comprehensive Fallback Heuristics
        return evaluateMessageFallback(message, request.getUserId());
    }

    private MessageScanDto.Response evaluateMessageFallback(String message, String userId) {
        String text = message.toLowerCase(Locale.ENGLISH);
        List<String> indicators = new ArrayList<>();
        int riskScore = 10;

        // A. Enterprise & HR Spear-Phishing
        if (text.contains("device and internet usage policy") || text.contains("viewing of inappropriate material")
                || text.contains("contoso") || text.contains("workplace alert") || text.contains("hr team")) {
            indicators.add("[Social Engineering & Authority Spoofing] Enterprise Spear-Phishing: Pretext exploits workplace hierarchy and employee acceptable use policy to compel obedience.");
            riskScore += 40;
        }

        // B. Evidence / Action Lures
        if (text.contains("view recorded evidence") || text.contains("review evidence") || text.contains("download evidence")) {
            indicators.add("[Credential Harvesting & Exploit Vector] Malicious Evidence Lure: Deceptive link enticing recipient to view fabricated evidence proof or open an exploit payload.");
            riskScore += 35;
        }

        // C. Urgency / Threat Triggers
        String[] urgencyKeywords = {
            "immediately", "urgent", "action required", "within 24 hours",
            "account suspended", "blocked", "restricted", "expire today",
            "unauthorized access", "act now", "final notice", "deactivated"
        };
        for (String kw : urgencyKeywords) {
            if (text.contains(kw)) {
                indicators.add("[Psychological Urgency Tactic] High Pressure Coercion: Message uses artificial time urgency ('" + kw + "') to force immediate, unconsidered action.");
                riskScore += 25;
                break;
            }
        }

        // D. Sensitive Credentials / OTP Requests
        String[] credentialKeywords = {
            "otp", "one-time password", "verification code", "pin", "cvv",
            "password", "secret phrase", "seed phrase", "social security", "ssn"
        };
        for (String kw : credentialKeywords) {
            if (text.contains(kw)) {
                indicators.add("[Credential Harvesting Vector] Sensitive Authentication Secret: Explicit request for confidential authentication data ('" + kw + "'). Legitimate entities never request passwords or OTPs via text.");
                riskScore += 35;
                break;
            }
        }

        // E. Financial / Prize / Reward Scams
        String[] financialKeywords = {
            "lottery", "won", "winner", "cash prize", "million dollars", "inheritance",
            "refund", "claim your prize", "wire transfer", "crypto", "bitcoin", "gift card"
        };
        for (String kw : financialKeywords) {
            if (text.contains(kw)) {
                indicators.add("[Financial Bait] Advance Fee / Reward Trap: Unrealistic monetary promise or prize notification ('" + kw + "') intended to extract personal funds or data.");
                riskScore += 25;
                break;
            }
        }

        // F. Impersonation of Reputable Institutions
        String[] impersonations = {
            "bank", "paypal", "netflix", "amazon", "apple support", "microsoft support",
            "irs", "tax department", "fedex", "ups delivery", "postal service", "dhl"
        };
        for (String imp : impersonations) {
            if (text.contains(imp)) {
                indicators.add("[Brand & Entity Impersonation] Authority Pretence: Claims representation of prominent brand or agency ('" + imp + "') to establish unearned credibility.");
                riskScore += 20;
                break;
            }
        }

        // G. Suspicious Link Patterns
        Pattern urlPattern = Pattern.compile("(https?://\\S+|bit\\.ly/\\S+|tinyurl\\.com/\\S+|t\\.co/\\S+|\\S+\\.(xyz|top|pw|club|online|tk)/\\S*)");
        if (urlPattern.matcher(message).find()) {
            indicators.add("[Embedded Destination Threat] Unverified External Hyperlink: Contains external link or shortened redirect commonly utilized in credential phishing campaigns.");
            riskScore += 25;
        }

        // H. Defanged syntax
        if (message.contains("[.]") || message.contains("[@]")) {
            indicators.add("[Threat Intelligence Artifact] Defanged Notation: Message contains security syntax '[.]' or '[@]' characteristic of documented threat intelligence samples.");
            riskScore += 20;
        }

        riskScore = Math.min(100, riskScore);

        String classification;
        String riskLevel;
        String explanation;
        String recommendation;

        if (riskScore >= 65) {
            classification = "SCAM";
            riskLevel = "HIGH";
            explanation = "High-Severity Social Engineering & Phishing Vector Identified. The communication employs coordinated psychological manipulation, brand impersonation, and credential capture lures.";
            recommendation = "CRITICAL: Do NOT click any links, do NOT reply, and never submit OTPs or credentials. Block the sender and report this message to security.";
        } else if (riskScore >= 40) {
            classification = "SUSPICIOUS";
            riskLevel = "MEDIUM";
            explanation = "Suspicious Communication Detected. Contains unverified urgency indicators or external redirect references that warrant independent verification.";
            recommendation = "Exercise caution. Do not follow links provided in this message. Confirm validity through official authenticated portals.";
        } else {
            classification = "SAFE";
            riskLevel = "LOW";
            explanation = "Authentic Communication Assessment. No overt social-engineering coercion, urgent threats, or deceptive credential harvesting traps detected.";
            recommendation = "Message appears benign. Maintain standard security vigilance regarding unsolicited requests.";
            if (indicators.isEmpty()) {
                indicators.add("[Tone & Integrity] Neutral conversational syntax with zero credential harvesting vectors.");
                indicators.add("[Infrastructure] Absence of deceptive links or obfuscated redirect patterns.");
            }
        }

        MessageScanDto.Response response = new MessageScanDto.Response(
                classification,
                riskScore,
                riskLevel,
                indicators,
                explanation,
                recommendation
        );

        recordScan(userId, message, response);
        return response;
    }

    private void recordScan(String userId, String message, MessageScanDto.Response response) {
        try {
            String sanitizedSnippet = message.length() > 60 ? message.substring(0, 60) + "..." : message;
            ScanRecord record = new ScanRecord(
                    userId,
                    "MESSAGE",
                    sanitizedSnippet,
                    response.getClassification(),
                    response.getRiskScore(),
                    response.getRiskLevel(),
                    response.getExplanation(),
                    LocalDateTime.now()
            );
            historyService.addRecord(record);
        } catch (Exception e) {
            log.warn("Failed to record Message scan: {}", e.getMessage());
        }
    }
}
