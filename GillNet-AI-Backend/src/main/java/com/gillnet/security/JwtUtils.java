package com.gillnet.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {

    @Value("${app.jwt.secret:gillnet-ai-super-secret-security-key-2026-spring-boot-cybersecurity}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms:86400000}")
    private long jwtExpirationMs;

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
