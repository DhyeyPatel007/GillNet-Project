package com.gillnet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.ChatDto;
import com.gillnet.service.ChatService;
import com.gillnet.service.CreditGate;

@RestController
@RequestMapping("/api/chat")
public class ChatController {

    private final ChatService chatService;
    private final CreditGate creditGate;

    public ChatController(ChatService chatService, CreditGate creditGate) {
        this.chatService = chatService;
        this.creditGate = creditGate;
    }

    @PostMapping
    public ResponseEntity<?> askAssistant(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody ChatDto.Request request) {
        var blocked = creditGate.check(authHeader, 1);
        if (blocked.isPresent()) {
            return blocked.get();
        }
        try {
            ChatDto.Response response = chatService.answerQuestion(request);
            creditGate.consume(authHeader, 1);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Chat assistant error: " + e.getMessage());
        }
    }
}
