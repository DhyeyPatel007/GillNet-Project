package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.gillnet.dto.AutopsyDto;
import com.gillnet.service.AutopsyService;
import com.gillnet.service.CreditGate;

@RestController
@RequestMapping("/api/autopsy")
public class AutopsyController {

    private final AutopsyService autopsyService;
    private final CreditGate creditGate;

    public AutopsyController(AutopsyService autopsyService, CreditGate creditGate) {
        this.autopsyService = autopsyService;
        this.creditGate = creditGate;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyze(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "userId", required = false) String userId) {
        var blocked = creditGate.check(authHeader, 1);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        try {
            AutopsyDto.Response response = autopsyService.analyze(file, userId);
            creditGate.consume(authHeader, 1);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Autopsy analysis failed: " + e.getMessage());
        }
    }
}
