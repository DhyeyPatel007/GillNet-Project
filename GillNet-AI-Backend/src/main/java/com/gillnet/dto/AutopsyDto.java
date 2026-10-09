package com.gillnet.dto;

import java.util.ArrayList;
import java.util.List;

/**
 * Forensic "autopsy" of an uploaded file: cryptographic hashes, metadata,
 * embedded URLs (each run through the URL engine) and extracted text
 * (run through the text engine).
 */
public class AutopsyDto {

    public static class UrlFinding {
        private String url;
        private String verdict;      // SAFE / SUSPICIOUS / PHISHING
        private Integer riskScore;   // 0 - 100
        private List<String> reasons = new ArrayList<>();

        public UrlFinding() {}

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getVerdict() { return verdict; }
        public void setVerdict(String verdict) { this.verdict = verdict; }
        public Integer getRiskScore() { return riskScore; }
        public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }
        public List<String> getReasons() { return reasons; }
        public void setReasons(List<String> reasons) { this.reasons = reasons; }
    }

    public static class Response {
        private String fileName;
        private long fileSizeBytes;
        private String fileSizeHuman;
        private String mimeType;
        private String md5;
        private String sha256;
        private String overallVerdict; // SAFE / SUSPICIOUS / PHISHING
        private Integer riskScore;     // 0 - 100 (max across findings)
        private List<UrlFinding> urlFindings = new ArrayList<>();
        private int urlsExtracted;
        private String textVerdict;    // null when text analysis skipped
        private Integer textRiskScore;
        private String textSummary;
        private List<String> textIndicators = new ArrayList<>();
        private List<String> notes = new ArrayList<>();
        private String analyzedAt;

        public Response() {}

        public String getFileName() { return fileName; }
        public void setFileName(String fileName) { this.fileName = fileName; }
        public long getFileSizeBytes() { return fileSizeBytes; }
        public void setFileSizeBytes(long fileSizeBytes) { this.fileSizeBytes = fileSizeBytes; }
        public String getFileSizeHuman() { return fileSizeHuman; }
        public void setFileSizeHuman(String fileSizeHuman) { this.fileSizeHuman = fileSizeHuman; }
        public String getMimeType() { return mimeType; }
        public void setMimeType(String mimeType) { this.mimeType = mimeType; }
        public String getMd5() { return md5; }
        public void setMd5(String md5) { this.md5 = md5; }
        public String getSha256() { return sha256; }
        public void setSha256(String sha256) { this.sha256 = sha256; }
        public String getOverallVerdict() { return overallVerdict; }
        public void setOverallVerdict(String overallVerdict) { this.overallVerdict = overallVerdict; }
        public Integer getRiskScore() { return riskScore; }
        public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }
        public List<UrlFinding> getUrlFindings() { return urlFindings; }
        public void setUrlFindings(List<UrlFinding> urlFindings) { this.urlFindings = urlFindings; }
        public int getUrlsExtracted() { return urlsExtracted; }
        public void setUrlsExtracted(int urlsExtracted) { this.urlsExtracted = urlsExtracted; }
        public String getTextVerdict() { return textVerdict; }
        public void setTextVerdict(String textVerdict) { this.textVerdict = textVerdict; }
        public Integer getTextRiskScore() { return textRiskScore; }
        public void setTextRiskScore(Integer textRiskScore) { this.textRiskScore = textRiskScore; }
        public String getTextSummary() { return textSummary; }
        public void setTextSummary(String textSummary) { this.textSummary = textSummary; }
        public List<String> getTextIndicators() { return textIndicators; }
        public void setTextIndicators(List<String> textIndicators) { this.textIndicators = textIndicators; }
        public List<String> getNotes() { return notes; }
        public void setNotes(List<String> notes) { this.notes = notes; }
        public String getAnalyzedAt() { return analyzedAt; }
        public void setAnalyzedAt(String analyzedAt) { this.analyzedAt = analyzedAt; }
    }
}
