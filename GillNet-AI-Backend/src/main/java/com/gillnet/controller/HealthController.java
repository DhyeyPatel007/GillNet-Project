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

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
