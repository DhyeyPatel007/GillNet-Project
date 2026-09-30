package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.PhishingScanDto;
import com.gillnet.service.CreditGate;
import com.gillnet.service.PhishingScanService;

@RestController
@RequestMapping("/api/phishing")
public class PhishingScanController {

    private final PhishingScanService phishingScanService;
    private final CreditGate creditGate;

    public PhishingScanController(PhishingScanService phishingScanService, CreditGate creditGate) {
        this.phishingScanService = phishingScanService;
        this.creditGate = creditGate;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzePhishing(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody PhishingScanDto.Request request) {
        var blocked = creditGate.check(authHeader, 1);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        try {
            PhishingScanDto.Response response = phishingScanService.analyzePhishing(request);
            creditGate.consume(authHeader, 1);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Phishing analysis failed: " + e.getMessage());
        }
    }

    @PostMapping("/analyze-text")
    public ResponseEntity<?> analyzeText(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody PhishingScanDto.Request request) {
        request.setType("TEXT");
        return analyzePhishing(authHeader, request);
    }

    @PostMapping("/analyze-image")
    public ResponseEntity<?> analyzeImage(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody PhishingScanDto.Request request) {
        request.setType("IMAGE");
        return analyzePhishing(authHeader, request);
    }
}
