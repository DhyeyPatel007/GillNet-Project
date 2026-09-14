package com.gillnet.controller;

import java.net.URI;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lightweight liveness endpoint for the hosting platform.
 *
 * <p>This deliberately has no dependency on MongoDB or the ML service: those
 * integrations have their own fallbacks and must not prevent the web process
 * from being declared ready.</p>
 */
@RestController
public class HealthController {

    /**
     * Provides a useful response when the deployed service URL is opened in a
     * browser. The frontend calls /api/* endpoints; this is a service landing
     * response, not a UI route.
     */
    @GetMapping("/")
    public ResponseEntity<Void> root() {
        // Render hosts the API, while Lovable hosts the UI. Redirecting the
        // public service URL makes the production entry point useful to people
        // instead of exposing a JSON-only backend landing page.
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("https://gillnet.lovable.app"))
                .build();
    }

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
