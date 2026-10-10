package com.gillnet.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.gillnet.dto.ChatDto;
import com.gillnet.dto.PhishingScanDto;

/**
 * Locks in the chat-assistant accuracy repairs:
 *  - whole-word keyword matching ("hr" must not fire on "three"/"through",
 *    "pin" must not fire on "shopping"/"spinning")
 *  - pasted message text is really analyzed via the text phishing engine
 *    (the welcome message promises this)
 *  - out-of-scope messages get an explicit scope notice, not generic tips
 */
@ExtendWith(MockitoExtension.class)
class ChatServiceTest {

    @Mock
    private PhishingScanService phishingScanService;

    private ChatService chatService;

    @BeforeEach
    void setUp() {
        chatService = new ChatService(phishingScanService);
    }

    private ChatDto.Response ask(String message) {
        return chatService.answerQuestion(new ChatDto.Request(message));
    }

    @Test
    void threeTipsDoesNotTriggerHrFalsePositive() {
        ChatDto.Response r = ask("What are three tips to stay safe?");
        assertNotEquals("ENTERPRISE_SPEAR_PHISHING", r.getCategory());
        assertEquals("GENERAL_SAFETY", r.getCategory());
    }

    @Test
    void chromeThroughShredDoNotTriggerHrFalsePositive() {
        assertNotEquals("ENTERPRISE_SPEAR_PHISHING", ask("How do I clear chrome cache?").getCategory());
        assertNotEquals("ENTERPRISE_SPEAR_PHISHING", ask("I clicked through a strange link").getCategory());
    }

    @Test
    void realHrMentionStillTriggersEnterpriseAlert() {
        ChatDto.Response r = ask("I got a suspicious HR email about disciplinary action");
        assertEquals("ENTERPRISE_SPEAR_PHISHING", r.getCategory());
    }

    @Test
    void shoppingDoesNotTriggerPinFalsePositive() {
        ChatDto.Response r = ask("I was shopping online yesterday");
        assertNotEquals("SCAM", r.getCategory());
    }

    @Test
    void atmPinAsWholeWordStillTriggersScamAdvice() {
        ChatDto.Response r = ask("What is my ATM pin?");
        assertEquals("SCAM", r.getCategory());
    }

    @Test
    void jokeGetsExplicitScopeNotice() {
        ChatDto.Response r = ask("Tell me a joke");
        assertEquals("OUT_OF_SCOPE", r.getCategory());
        assertTrue(r.getReply().contains("only help with cybersecurity"));
    }

    @Test
    void pastedPrizeSnippetIsAnalyzedByTextEngine() {
        PhishingScanDto.Response engine = new PhishingScanDto.Response();
        engine.setThreatLevel("PHISHING");
        engine.setRiskScore(85);
        engine.setSummary("Prize lure detected.");
        engine.setIndicators(List.of("[Psychological Lure Tactic] prize"));
        when(phishingScanService.analyzeTextPhishing(anyString(), isNull())).thenReturn(engine);

        ChatDto.Response r = ask("You won a prize, click here");
        assertEquals("PASTED_TEXT_ANALYSIS", r.getCategory());
        assertTrue(r.getReply().contains("looks like a scam"));
        verify(phishingScanService).analyzeTextPhishing(eq("You won a prize, click here"), isNull());
    }

    @Test
    void longPastedEmailIsAnalyzedByTextEngine() {
        PhishingScanDto.Response engine = new PhishingScanDto.Response();
        engine.setThreatLevel("SAFE");
        engine.setRiskScore(5);
        engine.setSummary("No threats found.");
        when(phishingScanService.analyzeTextPhishing(anyString(), isNull())).thenReturn(engine);

        StringBuilder longText = new StringBuilder("Dear customer, ");
        while (longText.length() < 200) {
            longText.append("this is a routine account notice with no urgency whatsoever. ");
        }
        ChatDto.Response r = ask(longText.toString());
        assertEquals("PASTED_TEXT_ANALYSIS", r.getCategory());
        assertTrue(r.getReply().contains("looks clean"));
    }
}
