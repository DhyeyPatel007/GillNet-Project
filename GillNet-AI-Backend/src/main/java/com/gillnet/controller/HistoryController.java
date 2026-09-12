package com.gillnet.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.HistoryDto;
import com.gillnet.model.ScanRecord;
import com.gillnet.service.HistoryService;

@RestController
@RequestMapping("/api/history")
public class HistoryController {

    private final HistoryService historyService;

    public HistoryController(HistoryService historyService) {
        this.historyService = historyService;
    }

    @GetMapping
    public ResponseEntity<List<ScanRecord>> getHistory(@RequestParam(required = false) String userId) {
        return ResponseEntity.ok(historyService.getHistory(userId));
    }

    @GetMapping("/stats")
    public ResponseEntity<HistoryDto.Stats> getStats() {
        return ResponseEntity.ok(historyService.getStats());
    }
}
