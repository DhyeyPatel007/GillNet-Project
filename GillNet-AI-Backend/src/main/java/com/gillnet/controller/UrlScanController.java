package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.UrlScanDto;
import com.gillnet.service.CreditGate;
import com.gillnet.service.UrlScanService;

@RestController
@RequestMapping("/api/url")
public class UrlScanController {

    private final UrlScanService urlScanService;
    private final CreditGate creditGate;

    public UrlScanController(UrlScanService urlScanService, CreditGate creditGate) {
        this.urlScanService = urlScanService;
        this.creditGate = creditGate;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeUrl(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody UrlScanDto.Request request) {
        var blocked = creditGate.check(authHeader, 1);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        try {
            UrlScanDto.Response response = urlScanService.analyzeUrl(request);
            creditGate.consume(authHeader, 1);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("URL analysis error: " + e.getMessage());
        }
    }
}
