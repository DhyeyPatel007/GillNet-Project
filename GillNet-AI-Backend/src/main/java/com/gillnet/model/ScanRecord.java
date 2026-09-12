package com.gillnet.model;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "ScanRecords")
public class ScanRecord {

    @Id
    private String id;

    private String userId;
    private String scanType;        // URL, MESSAGE, PASSWORD, ASSISTANT
    private String sanitizedTarget; // sanitized input, NEVER sensitive passwords
    private String result;          // SAFE, SUSPICIOUS, PHISHING, SCAM, etc.
    private Integer riskScore;      // 0 - 100
    private String riskLevel;       // LOW, MEDIUM, HIGH, CRITICAL
    private String summary;
    private LocalDateTime timestamp;

    public ScanRecord() {
    }

    public ScanRecord(String userId, String scanType, String sanitizedTarget, String result,
                      Integer riskScore, String riskLevel, String summary, LocalDateTime timestamp) {
        this.userId = userId;
        this.scanType = scanType;
        this.sanitizedTarget = sanitizedTarget;
        this.result = result;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.summary = summary;
        this.timestamp = timestamp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    public String getSanitizedTarget() {
        return sanitizedTarget;
    }

    public void setSanitizedTarget(String sanitizedTarget) {
        this.sanitizedTarget = sanitizedTarget;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Integer riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
