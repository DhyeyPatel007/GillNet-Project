package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.PasswordScanDto;
import com.gillnet.service.PasswordScanService;

@RestController
@RequestMapping("/api/password")
public class PasswordScanController {

    private final PasswordScanService passwordScanService;

    public PasswordScanController(PasswordScanService passwordScanService) {
        this.passwordScanService = passwordScanService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> evaluatePassword(@RequestBody PasswordScanDto.Request request) {
        try {
            PasswordScanDto.Response response = passwordScanService.evaluatePassword(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Password evaluation error: " + e.getMessage());
        }
    }
}
