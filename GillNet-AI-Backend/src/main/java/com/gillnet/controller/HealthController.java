package com.gillnet.controller;

import java.util.Map;

import org.springframework.http.MediaType;
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
    @GetMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> root() {
        return Map.of(
                "service", "GillNet AI Backend",
                "status", "UP",
                "health", "/health"
        );
    }

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
