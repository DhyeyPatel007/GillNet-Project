package com.gillnet.dto;

import java.util.List;

public class MessageScanDto {

    public static class Request {
        private String message;
        private String userId;

        public Request() {}
        public Request(String message, String userId) {
            this.message = message;
            this.userId = userId;
        }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
    }

    public static class Response {
        private String classification; // SAFE, SUSPICIOUS, SCAM
        private Integer riskScore;     // 0 - 100
        private String riskLevel;      // LOW, MEDIUM, HIGH, CRITICAL
        private List<String> indicators;
        private String explanation;
        private String recommendation;

        public Response() {}

        public Response(String classification, Integer riskScore, String riskLevel,
                        List<String> indicators, String explanation, String recommendation) {
            this.classification = classification;
            this.riskScore = riskScore;
            this.riskLevel = riskLevel;
            this.indicators = indicators;
            this.explanation = explanation;
            this.recommendation = recommendation;
        }

        public String getClassification() { return classification; }
        public void setClassification(String classification) { this.classification = classification; }
        public Integer getRiskScore() { return riskScore; }
        public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        public List<String> getIndicators() { return indicators; }
        public void setIndicators(List<String> indicators) { this.indicators = indicators; }
        public String getExplanation() { return explanation; }
        public void setExplanation(String explanation) { this.explanation = explanation; }
        public String getRecommendation() { return recommendation; }
        public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    }
}
