package com.gillnet.dto;

import java.util.List;
import com.gillnet.model.ScanRecord;

public class HistoryDto {

    public static class Stats {
        private long totalScans;
        private long safeCount;
        private long suspiciousCount;
        private long highRiskCount;
        private double averageRiskScore;

        public Stats() {}

        public Stats(long totalScans, long safeCount, long suspiciousCount, long highRiskCount, double averageRiskScore) {
            this.totalScans = totalScans;
            this.safeCount = safeCount;
            this.suspiciousCount = suspiciousCount;
            this.highRiskCount = highRiskCount;
            this.averageRiskScore = averageRiskScore;
        }

        public long getTotalScans() { return totalScans; }
        public void setTotalScans(long totalScans) { this.totalScans = totalScans; }
        public long getSafeCount() { return safeCount; }
        public void setSafeCount(long safeCount) { this.safeCount = safeCount; }
        public long getSuspiciousCount() { return suspiciousCount; }
        public void setSuspiciousCount(long suspiciousCount) { this.suspiciousCount = suspiciousCount; }
        public long getHighRiskCount() { return highRiskCount; }
        public void setHighRiskCount(long highRiskCount) { this.highRiskCount = highRiskCount; }
        public double getAverageRiskScore() { return averageRiskScore; }
        public void setAverageRiskScore(double averageRiskScore) { this.averageRiskScore = averageRiskScore; }
    }

    public static class Response {
        private Stats stats;
        private List<ScanRecord> records;

        public Response() {}

        public Response(Stats stats, List<ScanRecord> records) {
            this.stats = stats;
            this.records = records;
        }

        public Stats getStats() { return stats; }
        public void setStats(Stats stats) { this.stats = stats; }
        public List<ScanRecord> getRecords() { return records; }
        public void setRecords(List<ScanRecord> records) { this.records = records; }
    }
}
