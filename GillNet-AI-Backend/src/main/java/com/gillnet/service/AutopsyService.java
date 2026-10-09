package com.gillnet.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.gillnet.dto.AutopsyDto;
import com.gillnet.dto.PhishingScanDto;
import com.gillnet.dto.UrlScanDto;

/**
 * Forensic post-mortem ("autopsy") of an uploaded file.
 *
 * <p>Techniques mirror classic digital-forensics workflow: cryptographic
 * hashing (MD5/SHA-256) for file identity, metadata capture, printable-string
 * extraction, then every embedded URL is run through the URL engine and the
 * extracted text through the text engine. The overall verdict is the worst
 * finding across all artifacts.</p>
 */
@Service
public class AutopsyService {

    public static final long MAX_FILE_SIZE = 10L * 1024 * 1024; // 10 MB
    private static final int MAX_URLS = 8;
    private static final int MAX_TEXT_CHARS = 2000;
    private static final Pattern URL_PATTERN =
            Pattern.compile("https?://[^\\s\"'<>\\\\]+", Pattern.CASE_INSENSITIVE);

    private final UrlScanService urlScanService;
    private final PhishingScanService phishingScanService;

    public AutopsyService(UrlScanService urlScanService, PhishingScanService phishingScanService) {
        this.urlScanService = urlScanService;
        this.phishingScanService = phishingScanService;
    }

    public AutopsyDto.Response analyze(MultipartFile file, String userId) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("No file uploaded.");
        }
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File too large (max 10 MB).");
        }

        byte[] bytes = file.getBytes();
        String fileName = file.getOriginalFilename() != null && !file.getOriginalFilename().isBlank()
                ? file.getOriginalFilename()
                : "unknown";

        AutopsyDto.Response res = new AutopsyDto.Response();
        res.setFileName(fileName);
        res.setFileSizeBytes(bytes.length);
        res.setFileSizeHuman(humanSize(bytes.length));
        res.setMimeType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        res.setMd5(hex(MessageDigest.getInstance("MD5").digest(bytes)));
        res.setSha256(hex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        res.setAnalyzedAt(Instant.now().toString());

        String text = extractStrings(bytes);

        // 1. Embedded URLs -> URL engine
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find() && urls.size() < MAX_URLS) {
            String u = trimTrailingPunct(m.group());
            if (u.length() > 10) urls.add(u);
        }
        res.setUrlsExtracted(urls.size());

        int maxRisk = 0;
        for (String url : urls) {
            try {
                UrlScanDto.Response r = urlScanService.analyzeUrl(new UrlScanDto.Request(url, userId));
                AutopsyDto.UrlFinding f = new AutopsyDto.UrlFinding();
                f.setUrl(url.length() > 90 ? url.substring(0, 90) + "..." : url);
                f.setVerdict(r.getPrediction() != null ? r.getPrediction() : "SAFE");
                f.setRiskScore(r.getRiskScore() != null ? r.getRiskScore() : 0);
                if (r.getReasons() != null) {
                    f.setReasons(r.getReasons().stream().limit(3).toList());
                }
                res.getUrlFindings().add(f);
                maxRisk = Math.max(maxRisk, f.getRiskScore());
            } catch (Exception e) {
                res.getNotes().add("Skipped embedded URL (engine error): " + url);
            }
        }
        if (urls.isEmpty()) {
            res.getNotes().add("No embedded URLs found in file.");
        }

        // 2. Extracted text -> text engine
        if (text.length() >= 60) {
            String sample = text.length() > MAX_TEXT_CHARS ? text.substring(0, MAX_TEXT_CHARS) : text;
            try {
                PhishingScanDto.Response t = phishingScanService.analyzeTextPhishing(sample, userId);
                int textRisk = t.getRiskScore() != null ? t.getRiskScore() : 0;
                res.setTextVerdict(t.getThreatLevel());
                res.setTextRiskScore(textRisk);
                res.setTextSummary(t.getSummary());
                if (t.getIndicators() != null) {
                    res.setTextIndicators(t.getIndicators().stream().limit(6).toList());
                }
                // Corroboration rule for the overall file verdict: the text engine's
                // word model is tuned for short SMS, so on a long document a purely
                // statistical vocabulary resemblance (no malicious URLs, no credential
                // harvesting, no pressure tactics, no brand impersonation) is a weak
                // signal. Note it honestly, but don't let it drive the verdict alone.
                boolean corroborated =
                        t.isCredentialHarvesting()
                        || (t.getUrgencyTactics() != null && !t.getUrgencyTactics().isEmpty())
                        || (t.getBrandImpersonated() != null && !t.getBrandImpersonated().isBlank()
                            && !"None Detected".equalsIgnoreCase(t.getBrandImpersonated().trim()))
                        || res.getUrlFindings().stream().anyMatch(f -> f.getRiskScore() >= 40);
                int textContribution = corroborated ? textRisk : Math.min(textRisk, 25);
                if (!corroborated && textRisk > 25) {
                    res.getNotes().add("Text shows only statistical spam-vocabulary resemblance "
                            + "(no malicious URLs, credential harvesting, or pressure tactics) — "
                            + "treated as a weak signal for the overall verdict.");
                }
                maxRisk = Math.max(maxRisk, textContribution);
            } catch (Exception e) {
                res.getNotes().add("Text analysis failed: " + e.getMessage());
            }
        } else {
            res.getNotes().add("Not enough readable text for message analysis.");
        }

        res.setRiskScore(maxRisk);
        res.setOverallVerdict(maxRisk >= 70 ? "PHISHING" : maxRisk >= 40 ? "SUSPICIOUS" : "SAFE");
        return res;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String humanSize(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format("%.1f KB", n / 1024.0);
        return String.format("%.2f MB", n / (1024.0 * 1024));
    }

    /** Classic forensics string extraction: runs of >= 4 printable ASCII chars. */
    private static String extractStrings(byte[] bytes) {
        String raw = new String(bytes, StandardCharsets.ISO_8859_1);
        StringBuilder out = new StringBuilder();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c >= 32 && c < 127) {
                cur.append(c);
            } else {
                if (cur.length() >= 4) out.append(cur).append(' ');
                cur.setLength(0);
            }
        }
        if (cur.length() >= 4) out.append(cur);
        return out.toString();
    }

    private static String trimTrailingPunct(String u) {
        int end = u.length();
        while (end > 0 && ".,;:!?)]}\"'".indexOf(u.charAt(end - 1)) >= 0) end--;
        return u.substring(0, end);
    }
}
