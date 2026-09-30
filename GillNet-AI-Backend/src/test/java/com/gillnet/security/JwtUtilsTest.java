package com.gillnet.security;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

/**
 * Guards the fixes for the fake-auth vulnerabilities:
 *  - tokens must be HMAC-verified (not just decoded)
 *  - the compromised committed secret must never validate
 *  - tampered / wrong-secret tokens must be rejected
 */
class JwtUtilsTest {

    private static String hmac(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void roundTripTokenValidates() {
        JwtUtils jwt = new JwtUtils("test-secret-1234567890-test-secret", 86400000L);
        String token = jwt.generateToken("user@example.com", "user-id-1");
        assertTrue(jwt.validateToken(token));
        assertEquals("user@example.com", jwt.getEmailFromToken(token));
    }

    @Test
    void tamperedPayloadIsRejected() {
        JwtUtils jwt = new JwtUtils("test-secret-1234567890-test-secret", 86400000L);
        String token = jwt.generateToken("user@example.com", "user-id-1");
        String[] parts = token.split("\\.");
        // Flip the payload to a different email but keep the old signature
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"sub\":\"attacker@example.com\",\"uid\":\"user-id-1\",\"iat\":9999999999,\"exp\":9999999999}"
                        .getBytes(StandardCharsets.UTF_8));
        assertFalse(jwt.validateToken(parts[0] + "." + forgedPayload + "." + parts[2]),
                "A token with a forged payload must not validate");
    }

    @Test
    void wrongSecretIsRejected() {
        JwtUtils signer = new JwtUtils("correct-secret-1234567890-abcd", 86400000L);
        JwtUtils verifier = new JwtUtils("different-secret-1234567890-wxyz", 86400000L);
        String token = signer.generateToken("user@example.com", "user-id-1");
        assertFalse(verifier.validateToken(token), "Token signed with another secret must not validate");
    }

    @Test
    void compromisedCommittedSecretNeverValidates() throws Exception {
        // Tokens minted with the old hardcoded secret (that was committed to git)
        // must NOT validate against a fresh instance: the constructor must
        // refuse the compromised default and generate a random secret instead.
        String compromised = "gillnet-ai-super-secret-security-key-2026-spring-boot-cybersecurity";
        JwtUtils fresh = new JwtUtils("", 86400000L); // no secret configured -> random
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"sub\":\"user@example.com\",\"uid\":\"u1\",\"iat\":1999999999,\"exp\":1999999999}"
                        .getBytes(StandardCharsets.UTF_8));
        String forgedWithOldSecret = header + "." + payload + "." + hmac(header + "." + payload, compromised);
        assertFalse(fresh.validateToken(forgedWithOldSecret),
                "Token signed with the compromised committed secret must be rejected");
    }

    @Test
    void garbageTokensAreRejected() {
        JwtUtils jwt = new JwtUtils("test-secret-1234567890-test-secret", 86400000L);
        assertFalse(jwt.validateToken(null));
        assertFalse(jwt.validateToken(""));
        assertFalse(jwt.validateToken("not-a-jwt"));
        assertFalse(jwt.validateToken("a.b"));
    }
}
