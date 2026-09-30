package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.MessageScanDto;
import com.gillnet.service.CreditGate;
import com.gillnet.service.MessageScanService;

@RestController
@RequestMapping("/api/message")
public class MessageScanController {

    private final MessageScanService messageScanService;
    private final CreditGate creditGate;

    public MessageScanController(MessageScanService messageScanService, CreditGate creditGate) {
        this.messageScanService = messageScanService;
        this.creditGate = creditGate;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeMessage(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody MessageScanDto.Request request) {
        var blocked = creditGate.check(authHeader, 1);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        try {
            MessageScanDto.Response response = messageScanService.analyzeMessage(request);
            creditGate.consume(authHeader, 1);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Message analysis error: " + e.getMessage());
        }
    }
}
