package com.gillnet.dto;

import java.util.ArrayList;
import java.util.List;

public class PhishingScanDto {

    public static class Request {
        private String type; // "TEXT" or "IMAGE"
        private String content; // Text content or Base64 data URL
        private String fileName;
        private String userId;

        public Request() {}

        public Request(String type, String content, String fileName, String userId) {
            this.type = type;
            this.content = content;
            this.fileName = fileName;
            this.userId = userId;
        }

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
        public String getFileName() { return fileName; }
        public void setFileName(String fileName) { this.fileName = fileName; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
    }

    public static class Response {
        private String threatLevel; // "SAFE", "SUSPICIOUS", "PHISHING"
        private Integer riskScore; // 0 - 100
        private Double confidence; // e.g. 98.5%
        private String summary;
        private String brandImpersonated;
        private boolean credentialHarvesting;
        private List<String> urgencyTactics = new ArrayList<>();
        private List<String> extractedUrls = new ArrayList<>();
        private List<String> indicators = new ArrayList<>();
        private List<String> recommendations = new ArrayList<>();
        private String extractedText;

        public Response() {}

        public Response(String threatLevel, Integer riskScore, Double confidence, String summary,
                        String brandImpersonated, boolean credentialHarvesting,
                        List<String> urgencyTactics, List<String> extractedUrls,
                        List<String> indicators, List<String> recommendations) {
            this(threatLevel, riskScore, confidence, summary, brandImpersonated, credentialHarvesting,
                    urgencyTactics, extractedUrls, indicators, recommendations, null);
        }

        public Response(String threatLevel, Integer riskScore, Double confidence, String summary,
                        String brandImpersonated, boolean credentialHarvesting,
                        List<String> urgencyTactics, List<String> extractedUrls,
                        List<String> indicators, List<String> recommendations, String extractedText) {
            this.threatLevel = threatLevel;
            this.riskScore = riskScore;
            this.confidence = confidence;
            this.summary = summary;
            this.brandImpersonated = brandImpersonated;
            this.credentialHarvesting = credentialHarvesting;
            this.urgencyTactics = urgencyTactics;
            this.extractedUrls = extractedUrls;
            this.indicators = indicators;
            this.recommendations = recommendations;
            this.extractedText = extractedText;
        }

        public String getThreatLevel() { return threatLevel; }
        public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }
        public Integer getRiskScore() { return riskScore; }
        public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }
        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
        public String getBrandImpersonated() { return brandImpersonated; }
        public void setBrandImpersonated(String brandImpersonated) { this.brandImpersonated = brandImpersonated; }
        public boolean isCredentialHarvesting() { return credentialHarvesting; }
        public void setCredentialHarvesting(boolean credentialHarvesting) { this.credentialHarvesting = credentialHarvesting; }
        public List<String> getUrgencyTactics() { return urgencyTactics; }
        public void setUrgencyTactics(List<String> urgencyTactics) { this.urgencyTactics = urgencyTactics; }
        public List<String> getExtractedUrls() { return extractedUrls; }
        public void setExtractedUrls(List<String> extractedUrls) { this.extractedUrls = extractedUrls; }
        public List<String> getIndicators() { return indicators; }
        public void setIndicators(List<String> indicators) { this.indicators = indicators; }
        public List<String> getRecommendations() { return recommendations; }
        public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
        public String getExtractedText() { return extractedText; }
        public void setExtractedText(String extractedText) { this.extractedText = extractedText; }
    }
}
