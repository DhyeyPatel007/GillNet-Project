package com.gillnet.dto;

import java.util.List;

public class PasswordScanDto {

    public static class Request {
        private String password;

        public Request() {}
        public Request(String password) {
            this.password = password;
        }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class Response {
        private String strength;       // WEAK, FAIR, GOOD, STRONG, VERY_STRONG
        private Integer score;          // 0 - 100
        private Double entropy;        // in bits
        private String estimatedCrackTime;
        private List<String> passedCriteria;
        private List<String> suggestions;
        private Boolean isCommon;

        public Response() {}

        public String getStrength() { return strength; }
        public void setStrength(String strength) { this.strength = strength; }
        public Integer getScore() { return score; }
        public void setScore(Integer score) { this.score = score; }
        public Double getEntropy() { return entropy; }
        public void setEntropy(Double entropy) { this.entropy = entropy; }
        public String getEstimatedCrackTime() { return estimatedCrackTime; }
        public void setEstimatedCrackTime(String estimatedCrackTime) { this.estimatedCrackTime = estimatedCrackTime; }
        public List<String> getPassedCriteria() { return passedCriteria; }
        public void setPassedCriteria(List<String> passedCriteria) { this.passedCriteria = passedCriteria; }
        public List<String> getSuggestions() { return suggestions; }
        public void setSuggestions(List<String> suggestions) { this.suggestions = suggestions; }
        public Boolean getIsCommon() { return isCommon; }
        public void setIsCommon(Boolean isCommon) { this.isCommon = isCommon; }
    }
}
