package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.UrlScanDto;
import com.gillnet.service.UrlScanService;

@RestController
@RequestMapping("/api/url")
public class UrlScanController {

    private final UrlScanService urlScanService;

    public UrlScanController(UrlScanService urlScanService) {
        this.urlScanService = urlScanService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(@RequestBody UrlScanDto.Request request) {
        try {
            UrlScanDto.Response response = urlScanService.analyzeUrl(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("URL analysis error: " + e.getMessage());
        }
    }
}
