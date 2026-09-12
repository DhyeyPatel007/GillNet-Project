package com.gillnet.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.gillnet.dto.PasswordScanDto;
import com.gillnet.model.ScanRecord;
import com.gillnet.repository.ScanRecordRepository;

@Service
public class PasswordScanService {

    private static final Logger log = LoggerFactory.getLogger(PasswordScanService.class);

    private final HistoryService historyService;

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "123456", "password", "12345678", "qwerty", "123456789", "12345",
            "1234", "111111", "1234567", "dragon", "123123", "baseball",
            "football", "letmein", "monkey", "master", "sunshine", "shadow",
            "superman", "trustno1", "admin", "welcome", "pass123", "password123"
    );

    // Common keyboard walk and sequential sequences
    private static final String[] SEQUENCES = {
        "1234567890", "0987654321",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "abcdefghijklmnopqrstuvwxyz"
    };

    public PasswordScanService(HistoryService historyService) {
        this.historyService = historyService;
    }

    public PasswordScanDto.Response evaluatePassword(PasswordScanDto.Request request) {
        String password = request.getPassword();
        if (password == null) {
            password = "";
        }

        PasswordScanDto.Response response = new PasswordScanDto.Response();
        List<String> criteria = new ArrayList<>();
        List<String> suggestions = new ArrayList<>();

        int length = password.length();
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        String lowerPass = password.toLowerCase(Locale.ENGLISH).trim();

        // 1. Check common dictionary breaches
        boolean isCommon = COMMON_PASSWORDS.contains(lowerPass);
        response.setIsCommon(isCommon);

        if (isCommon) {
            suggestions.add("[Critical Vulnerability] Frequently Breached: This string appears in top global password leak databases. Automated bots test this instantly.");
        }

        // 2. Sequential / keyboard walk patterns
        boolean hasSequence = false;
        for (String seq : SEQUENCES) {
            for (int i = 0; i <= seq.length() - 4; i++) {
                String sub = seq.substring(i, i + 4);
                if (lowerPass.contains(sub)) {
                    hasSequence = true;
                    suggestions.add("[Pattern Risk] Sequential Pattern Detected: Contains predictable keyboard or alphabetical walk ('" + sub + "') easily guessed by specialized rule-based attacks.");
                    break;
                }
            }
            if (hasSequence) break;
        }

        // 3. Repeated consecutive characters
        Pattern repeatPattern = Pattern.compile("(.)\\1{2,}");
        if (repeatPattern.matcher(password).find()) {
            suggestions.add("[Pattern Risk] Character Repetition: Contains consecutive identical characters (e.g. 'aaa', '111') which drastically compresses the effective search space.");
        }

        // 4. Evaluate criteria
        if (length >= 16) {
            criteria.add("Superior Length (16+ characters, NIST SP 800-63B compliant)");
        } else if (length >= 12) {
            criteria.add("Strong Length (12-15 characters)");
        } else if (length >= 8) {
            criteria.add("Acceptable Length (8-11 characters)");
            suggestions.add("[Length Hardening] Increase length to 14+ characters: Exponentially increases keyspace against modern GPU offline cluster attacks.");
        } else {
            suggestions.add("[Critical Shortfall] Password is critically short (<8 characters). High vulnerability to instant offline brute force.");
        }

        if (hasUpper) criteria.add("Contains uppercase character set (A-Z)");
        else suggestions.add("[Character Diversity] Add uppercase letters (A-Z) to expand keyspace per character position.");

        if (hasLower) criteria.add("Contains lowercase character set (a-z)");
        else suggestions.add("[Character Diversity] Add lowercase letters (a-z).");

        if (hasDigit) criteria.add("Contains numeric digits (0-9)");
        else suggestions.add("[Character Diversity] Include numeric digits (0-9) to defend against dictionary word attacks.");

        if (hasSpecial) criteria.add("Contains special symbols and punctuation (!@#$%^&*)");
        else suggestions.add("[Character Diversity] Include non-alphanumeric special characters (!, @, #, $, %, ^, &).");

        if (!isCommon && !password.isEmpty()) {
            criteria.add("Absence of known top-breach password entries");
        }
        if (!hasSequence && length >= 8) {
            criteria.add("Zero predictable keyboard or sequential walk patterns");
        }

        // 5. Calculate Shannon Entropy
        double entropy = calculateEntropy(password);
        response.setEntropy(Math.round(entropy * 100.0) / 100.0);

        // 6. Calculate Overall Score
        int score = 0;
        if (length >= 16) score += 35;
        else if (length >= 12) score += 25;
        else if (length >= 8) score += 15;
        else score += 5;

        int poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 32;

        if (hasLower && hasUpper) score += 15;
        if (hasDigit) score += 15;
        if (hasSpecial) score += 20;
        if (poolSize >= 68 && length >= 12) score += 15;

        if (hasSequence) score = Math.max(0, score - 15);
        if (isCommon) score = Math.min(score, 10);

        score = Math.min(100, Math.max(0, score));
        response.setScore(score);

        // 7. Strength label & Realistic Crack Time Estimation
        String strength;
        String crackTime;

        if (score >= 85) {
            strength = "VERY_STRONG";
            crackTime = "Centuries / Decades (Resistant to GPU cluster brute force)";
            suggestions.add("[Best Practice] Excellent cryptographic complexity. Use a trusted password manager and enable Multi-Factor Authentication (MFA).");
        } else if (score >= 70) {
            strength = "STRONG";
            crackTime = "Several Years (Resistant to standard offline dictionary attacks)";
            suggestions.add("[Best Practice] Strong defense profile. Consider a multi-word passphrase for even greater memorability and resistance.");
        } else if (score >= 50) {
            strength = "GOOD";
            crackTime = "Several Months (Moderately vulnerable to dedicated hashcat rigs)";
            suggestions.add("[Passphrase Strategy] Use a 4-word passphrase (e.g. 'sunset-orchard-beacon-frost') to achieve >75 bits of entropy.");
        } else if (score >= 30) {
            strength = "FAIR";
            crackTime = "A Few Days to Weeks (Vulnerable to mask and dictionary attacks)";
            suggestions.add("[Passphrase Strategy] Avoid predictable word + digit substitutions; use random multi-word combinations.");
        } else {
            strength = "WEAK";
            crackTime = "Instantly / Seconds (Compromised by online or offline botnets)";
            suggestions.add("[Immediate Action] Change this password immediately. Never reuse this password across multiple services.");
        }

        response.setStrength(strength);
        response.setEstimatedCrackTime(crackTime);
        response.setPassedCriteria(criteria);
        response.setSuggestions(suggestions);

        // Audit Compliance Note: Persist ONLY the strength evaluation count without storing any password data
        try {
            ScanRecord record = new ScanRecord(
                    null,
                    "PASSWORD",
                    "[CONFIDENTIAL PASSWORD EVALUATION]",
                    strength,
                    score,
                    score < 40 ? "HIGH" : (score < 70 ? "MEDIUM" : "LOW"),
                    "Password Strength: " + strength + " (" + score + "/100)",
                    LocalDateTime.now()
            );
            historyService.addRecord(record);
        } catch (Exception e) {
            log.warn("Failed to record Password evaluation: {}", e.getMessage());
        }

        return response;
    }

    private double calculateEntropy(String password) {
        if (password.isEmpty()) return 0.0;
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : password.toCharArray()) {
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        int len = password.length();
        for (int count : counts.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy * len;
    }
}
