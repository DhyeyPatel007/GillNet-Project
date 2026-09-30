package com.gillnet.security;

import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;

/**
 * Verifies Google Sign-In ID tokens server-side using Google's public keys.
 * This is what makes Google login REAL: the token signature, expiry, issuer
 * and audience (our OAuth client ID) are all cryptographically checked.
 * Never trust claims that were merely decoded from an unverified token.
 */
@Service
public class GoogleTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(GoogleTokenVerifier.class);

    private final String clientId;
    private final GoogleIdTokenVerifier verifier;

    public GoogleTokenVerifier(@Value("${google.client.id:}") String clientId) {
        this.clientId = clientId == null ? "" : clientId.trim();
        this.verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(Collections.singletonList(this.clientId))
                .build();
    }

    public boolean isConfigured() {
        return !clientId.isEmpty();
    }

    /**
     * Verifies a Google ID token. Returns the verified payload, or null when
     * the token is invalid, expired, forged, or meant for another client.
     */
    public GoogleIdToken.Payload verify(String idTokenString) {
        if (!isConfigured()) {
            log.warn("Google OAuth is not configured (google.client.id / GOOGLE_CLIENT_ID missing) — rejecting Google login");
            return null;
        }
        if (idTokenString == null || idTokenString.isBlank()) {
            return null;
        }
        try {
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                log.warn("Google ID token failed verification (bad signature, expired, or wrong audience)");
                return null;
            }
            return idToken.getPayload();
        } catch (Exception e) {
            log.warn("Google ID token verification error: {}", e.getMessage());
            return null;
        }
    }
}
