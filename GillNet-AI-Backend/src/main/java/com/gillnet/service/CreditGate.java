package com.gillnet.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.gillnet.model.User;

/**
 * Gate for paid endpoints: requires a valid login and consumes credits.
 * When credits run out the request is STOPPED with HTTP 402 and a clear
 * message — there is no unlimited/permanent-credits fallback.
 */
@Component
public class CreditGate {

    private final UserService userService;

    public CreditGate(UserService userService) {
        this.userService = userService;
    }

    /**
     * Pre-check: verifies login and that enough credits exist.
     * Does NOT consume — call {@link #consume} only after a successful call
     * so failed validations never cost the user credits.
     *
     * @return empty when the call may proceed; otherwise a ResponseEntity
     *         (401/402) that the controller should return immediately.
     */
    public Optional<ResponseEntity<?>> check(String authHeader, int cost) {
        Optional<User> userOpt = userService.userFromAuthHeader(authHeader);
        if (userOpt.isEmpty()) {
            return Optional.of(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Please sign in to use this feature.")));
        }

        User user = userOpt.get();
        if (userService.getCredits(user) < cost) {
            return Optional.of(ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED)
                    .body(Map.of(
                            "message", "You're out of credits. Your credits have run out — please top up to continue using scans and the AI assistant.",
                            "credits", userService.getCredits(user))));
        }
        return Optional.empty();
    }

    /**
     * Consumes credits after a successful paid call. Safe to call after
     * {@link #check} passed; re-verifies balance atomically.
     */
    public void consume(String authHeader, int cost) {
        userService.userFromAuthHeader(authHeader)
                .ifPresent(user -> userService.tryConsumeCredits(user, cost));
    }
}
