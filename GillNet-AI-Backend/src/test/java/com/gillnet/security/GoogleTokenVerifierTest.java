package com.gillnet.security;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * The old backend "verified" Google logins by merely Base64-decoding the
 * JWT payload — any forged token was accepted. These tests lock in the fix:
 * tokens must be cryptographically verified against Google's keys.
 */
class GoogleTokenVerifierTest {

    private static String forgedIdToken() {
        // A well-formed but self-signed JWT: decodes cleanly, signature is bogus.
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"forged\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"iss\":\"https://accounts.google.com\",\"aud\":\"test-client-id\"," +
                 "\"sub\":\"123\",\"email\":\"attacker@example.com\",\"email_verified\":true," +
                 "\"exp\":1999999999,\"iat\":1000000000}")
                        .getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("forged-signature".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + sig;
    }

    @Test
    void unconfiguredVerifierRejectsEverything() {
        GoogleTokenVerifier verifier = new GoogleTokenVerifier("");
        assertFalse(verifier.isConfigured());
        assertNull(verifier.verify(forgedIdToken()),
                "Without GOOGLE_CLIENT_ID configured, Google login must fail closed");
    }

    @Test
    void nullAndBlankTokensAreRejected() {
        GoogleTokenVerifier verifier = new GoogleTokenVerifier("test-client-id");
        assertNull(verifier.verify(null));
        assertNull(verifier.verify(""));
        assertNull(verifier.verify("   "));
    }

    @Test
    void forgedTokenIsRejected() {
        GoogleTokenVerifier verifier = new GoogleTokenVerifier("test-client-id");
        // The forged token decodes to plausible claims, but its signature was
        // never made by Google — verification must return null, never claims.
        assertNull(verifier.verify(forgedIdToken()),
                "A forged Google ID token must be rejected, not decoded");
    }

    @Test
    void garbageTokenIsRejected() {
        GoogleTokenVerifier verifier = new GoogleTokenVerifier("test-client-id");
        assertNull(verifier.verify("not.a.valid.token.at.all"));
    }
}
