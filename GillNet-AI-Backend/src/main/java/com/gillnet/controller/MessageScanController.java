package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.MessageScanDto;
import com.gillnet.service.MessageScanService;

@RestController
@RequestMapping("/api/message")
public class MessageScanController {

    private final MessageScanService messageScanService;

    public MessageScanController(MessageScanService messageScanService) {
        this.messageScanService = messageScanService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeMessage(@RequestBody MessageScanDto.Request request) {
        try {
            MessageScanDto.Response response = messageScanService.analyzeMessage(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Message analysis error: " + e.getMessage());
        }
    }
}
