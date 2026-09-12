package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.PhishingScanDto;
import com.gillnet.service.PhishingScanService;

@RestController
@RequestMapping("/api/phishing")
public class PhishingScanController {

    private final PhishingScanService phishingScanService;

    public PhishingScanController(PhishingScanService phishingScanService) {
        this.phishingScanService = phishingScanService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzePhishing(@RequestBody PhishingScanDto.Request request) {
        try {
            PhishingScanDto.Response response = phishingScanService.analyzePhishing(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Phishing analysis failed: " + e.getMessage());
        }
    }

    @PostMapping("/analyze-text")
    public ResponseEntity<?> analyzeText(@RequestBody PhishingScanDto.Request request) {
        request.setType("TEXT");
        return analyzePhishing(request);
    }

    @PostMapping("/analyze-image")
    public ResponseEntity<?> analyzeImage(@RequestBody PhishingScanDto.Request request) {
        request.setType("IMAGE");
        return analyzePhishing(request);
    }
}
