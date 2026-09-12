package com.gillnet.dto;

import java.util.List;
import java.util.Map;

public class UrlScanDto {

    public static class Request {
        private String url;
        private String userId;

        public Request() {}
        public Request(String url, String userId) {
            this.url = url;
            this.userId = userId;
        }

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
    }

    public static class Response {
        private String url;
        private String prediction;   // SAFE or PHISHING
        private Double confidence;
        private Integer riskScore;   // 0 - 100
        private String model;
        private List<String> reasons;
        private String recommendation;
        private Map<String, Object> details;

        public Response() {}

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getPrediction() { return prediction; }
        public void setPrediction(String prediction) { this.prediction = prediction; }
        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
        public Integer getRiskScore() { return riskScore; }
        public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public List<String> getReasons() { return reasons; }
        public void setReasons(List<String> reasons) { this.reasons = reasons; }
        public String getRecommendation() { return recommendation; }
        public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
        public Map<String, Object> getDetails() { return details; }
        public void setDetails(Map<String, Object> details) { this.details = details; }
    }
}
