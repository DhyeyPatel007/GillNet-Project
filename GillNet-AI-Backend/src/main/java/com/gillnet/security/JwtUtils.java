package com.gillnet.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);
    /** Legacy hardcoded default that was committed to the repo — must never be used. */
    private static final String COMPROMISED_DEFAULT = "gillnet-ai-super-secret-security-key-2026-spring-boot-cybersecurity";

    private final String jwtSecret;
    private final long jwtExpirationMs;

    public JwtUtils(
            @Value("${app.jwt.secret:}") String configuredSecret,
            @Value("${app.jwt.expiration-ms:86400000}") long jwtExpirationMs) {
        String secret = configuredSecret == null ? "" : configuredSecret.trim();
        if (secret.isEmpty() || COMPROMISED_DEFAULT.equals(secret)) {
            // Fail closed: generate a strong random secret for this process.
            // Set the JWT_SECRET env var for stable sessions across restarts.
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            secret = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            log.warn("JWT_SECRET is not set (or uses the compromised default) — generated a random session secret. "
                    + "All users will be logged out on restart. Set the JWT_SECRET environment variable for persistence.");
        }
        this.jwtSecret = secret;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateToken(String email, String userId) {
        long now = System.currentTimeMillis();
        long exp = now + jwtExpirationMs;

        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)
        );

        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                String.format("{\"sub\":\"%s\",\"uid\":\"%s\",\"iat\":%d,\"exp\":%d}",
                        escape(email), escape(userId), now / 1000, exp / 1000)
                        .getBytes(StandardCharsets.UTF_8)
        );

        String signature = sign(header + "." + payload, jwtSecret);
        return header + "." + payload + "." + signature;
    }

    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        String content = parts[0] + "." + parts[1];
        String signature = parts[2];
        String expectedSig = sign(content, jwtSecret);

        if (!MessageDigest.isEqual(signature.getBytes(StandardCharsets.UTF_8), expectedSig.getBytes(StandardCharsets.UTF_8))) {
            return false;
        }

        // Check expiration
        try {
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            int expIdx = payloadJson.indexOf("\"exp\":");
            if (expIdx != -1) {
                int endIdx = payloadJson.indexOf("}", expIdx);
                int commaIdx = payloadJson.indexOf(",", expIdx);
                int limit = (commaIdx != -1 && commaIdx < endIdx) ? commaIdx : endIdx;
                long expSec = Long.parseLong(payloadJson.substring(expIdx + 6, limit).trim());
                if (System.currentTimeMillis() / 1000 > expSec) {
                    return false; // Token expired
                }
            }
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public String getEmailFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            int subIdx = payloadJson.indexOf("\"sub\":\"");
            if (subIdx != -1) {
                int start = subIdx + 7;
                int end = payloadJson.indexOf("\"", start);
                if (end != -1) {
                    return payloadJson.substring(start, end);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String sign(String data, String key) {
        try {
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256Hmac.init(secretKey);
            byte[] hash = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error signing JWT token", e);
        }
    }

    private String escape(String str) {
        return str == null ? "" : str.replace("\"", "\\\"");
    }
}
