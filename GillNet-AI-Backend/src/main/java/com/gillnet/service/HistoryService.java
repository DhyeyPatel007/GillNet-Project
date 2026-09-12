package com.gillnet.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.gillnet.dto.HistoryDto;
import com.gillnet.model.ScanRecord;
import com.gillnet.repository.ScanRecordRepository;

import jakarta.annotation.PostConstruct;

@Service
public class HistoryService {

    private static final Logger log = LoggerFactory.getLogger(HistoryService.class);

    private final ScanRecordRepository scanRecordRepository;
    private final List<ScanRecord> inMemoryRecords = new CopyOnWriteArrayList<>();
    private volatile boolean mongoOnline = false;

    public HistoryService(ScanRecordRepository scanRecordRepository) {
        this.scanRecordRepository = scanRecordRepository;
    }

    @PostConstruct
    public void init() {
        seedInitialRecords();

        CompletableFuture.runAsync(() -> {
            try {
                scanRecordRepository.count();
                mongoOnline = true;
                log.info("MongoDB connection verified for HistoryService");
                List<ScanRecord> dbRecords = scanRecordRepository.findAllByOrderByTimestampDesc();
                if (dbRecords != null && !dbRecords.isEmpty()) {
                    inMemoryRecords.addAll(0, dbRecords);
                }
            } catch (Exception e) {
                mongoOnline = false;
                log.info("MongoDB not reachable for HistoryService — operating in instant in-memory mode");
            }
        });
    }

    private void seedInitialRecords() {
        inMemoryRecords.add(new ScanRecord("sample", "URL", "google.com", "SAFE", 5, "LOW", "Standard legitimate URL structure", LocalDateTime.now().minusMinutes(12)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "xyz-login.com", "PHISHING", 92, "HIGH", "Deceptive keyword in unverified domain", LocalDateTime.now().minusMinutes(30)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "youtube.com", "SAFE", 8, "LOW", "Valid domain and SSL certificate", LocalDateTime.now().minusHours(1)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "fake-bank.com", "SUSPICIOUS", 65, "MEDIUM", "Domain brand spoofing detected", LocalDateTime.now().minusHours(2)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "malware-download.xyz", "PHISHING", 98, "HIGH", "Suspicious TLD with obfuscated payload", LocalDateTime.now().minusHours(4)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "microsoft.com", "SAFE", 5, "LOW", "Legitimate corporate domain", LocalDateTime.now().minusHours(10)));
        inMemoryRecords.add(new ScanRecord("sample", "URL", "claude.ai", "SAFE", 10, "LOW", "Verified AI platform", LocalDateTime.now().minusDays(1)));
    }

    public void addRecord(ScanRecord record) {
        if (record != null) {
            inMemoryRecords.add(0, record);
            if (mongoOnline) {
                CompletableFuture.runAsync(() -> {
                    try {
                        scanRecordRepository.save(record);
                    } catch (Exception e) {
                        log.warn("Failed to persist ScanRecord to MongoDB: {}", e.getMessage());
                    }
                });
            }
        }
    }

    public List<ScanRecord> getHistory(String userId) {
        if (userId != null && !userId.trim().isEmpty()) {
            return inMemoryRecords.stream()
                    .filter(r -> userId.trim().equalsIgnoreCase(r.getUserId()) || "sample".equalsIgnoreCase(r.getUserId()))
                    .collect(Collectors.toList());
        }
        return new ArrayList<>(inMemoryRecords);
    }

    public HistoryDto.Stats getStats() {
        long total = inMemoryRecords.size();
        long safe = inMemoryRecords.stream().filter(r -> "SAFE".equalsIgnoreCase(r.getResult()) || (r.getRiskScore() != null && r.getRiskScore() < 40)).count();
        long suspicious = inMemoryRecords.stream().filter(r -> "SUSPICIOUS".equalsIgnoreCase(r.getResult()) || (r.getRiskScore() != null && r.getRiskScore() >= 40 && r.getRiskScore() < 70)).count();
        long highRisk = inMemoryRecords.stream().filter(r -> "PHISHING".equalsIgnoreCase(r.getResult()) || "SCAM".equalsIgnoreCase(r.getResult()) || (r.getRiskScore() != null && r.getRiskScore() >= 70)).count();

        double avgScore = total > 0
                ? inMemoryRecords.stream().mapToInt(r -> r.getRiskScore() != null ? r.getRiskScore() : 0).average().orElse(0.0)
                : 0.0;

        return new HistoryDto.Stats(total, safe, suspicious, highRisk, Math.round(avgScore * 10.0) / 10.0);
    }
}
