package com.gillnet.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.gillnet.model.User;

/**
 * Locks in the credits contract the user asked for:
 *  - no sign-in  -> 401, call stopped
 *  - 0 credits   -> 402 with a clear "out of credits" message, call stopped
 *  - credits left -> proceeds; failed scans never consume credits
 */
@ExtendWith(MockitoExtension.class)
class CreditGateTest {

    @Mock
    private UserService userService;

    private CreditGate gate;
    private User user;

    @BeforeEach
    void setUp() {
        gate = new CreditGate(userService);
        user = new User();
        user.setEmail("user@example.com");
    }

    @Test
    void unauthenticatedCallIsStoppedWith401() {
        when(userService.userFromAuthHeader(null)).thenReturn(Optional.empty());

        Optional<ResponseEntity<?>> blocked = gate.check(null, 1);

        assertTrue(blocked.isPresent());
        assertEquals(HttpStatus.UNAUTHORIZED, blocked.get().getStatusCode());
        verify(userService, never()).tryConsumeCredits(any(), anyInt());
    }

    @Test
    void outOfCreditsStopsCallWith402AndClearMessage() {
        user.setCredits(0);
        when(userService.userFromAuthHeader("Bearer token")).thenReturn(Optional.of(user));
        when(userService.getCredits(user)).thenReturn(0);

        Optional<ResponseEntity<?>> blocked = gate.check("Bearer token", 1);

        assertTrue(blocked.isPresent());
        ResponseEntity<?> response = blocked.get();
        assertEquals(HttpStatus.PAYMENT_REQUIRED, response.getStatusCode());
        String body = response.getBody().toString();
        assertTrue(body.toLowerCase().contains("out of credits"),
                "402 response must clearly say credits ran out, got: " + body);
        verify(userService, never()).tryConsumeCredits(any(), anyInt());
    }

    @Test
    void checkDoesNotConsumeCreditsByItself() {
        user.setCredits(5);
        when(userService.userFromAuthHeader("Bearer token")).thenReturn(Optional.of(user));
        when(userService.getCredits(user)).thenReturn(5);

        Optional<ResponseEntity<?>> blocked = gate.check("Bearer token", 1);

        assertTrue(blocked.isEmpty(), "Call with credits should proceed");
        // Pre-check must not consume: only consume() after a SUCCESSFUL scan does.
        verify(userService, never()).tryConsumeCredits(any(), anyInt());
    }

    @Test
    void consumeDeductsAfterSuccessfulScan() {
        when(userService.userFromAuthHeader("Bearer token")).thenReturn(Optional.of(user));

        gate.consume("Bearer token", 1);

        verify(userService).tryConsumeCredits(user, 1);
    }
}
