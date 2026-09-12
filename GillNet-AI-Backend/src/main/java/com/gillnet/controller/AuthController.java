package com.gillnet.controller;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.AuthRequest;
import com.gillnet.dto.AuthResponse;
import com.gillnet.dto.ForgotPasswordRequest;
import com.gillnet.dto.GoogleAuthRequest;
import com.gillnet.dto.RegisterRequest;
import com.gillnet.dto.ResetPasswordRequest;
import com.gillnet.dto.UserResponseDTO;
import com.gillnet.model.User;
import com.gillnet.security.JwtUtils;
import com.gillnet.service.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtils jwtUtils;

    public AuthController(UserService userService, JwtUtils jwtUtils) {
        this.userService = userService;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            UserResponseDTO user = userService.register(request);
            String token = jwtUtils.generateToken(user.getEmail(), user.getId());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new AuthResponse(token, "User registered successfully", user));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, e.getMessage(), null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponse(null, "Registration failed: " + e.getMessage(), null));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request) {
        Optional<User> userOpt = userService.authenticate(request.getEmail(), request.getPassword());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse(null, "Invalid email or password", null));
        }

        User user = userOpt.get();
        UserResponseDTO userDto = UserResponseDTO.fromEntity(user);
        String token = jwtUtils.generateToken(user.getEmail(), user.getId());

        return ResponseEntity.ok(new AuthResponse(token, "Login successful", userDto));
    }

    @PostMapping("/google")
    public ResponseEntity<?> loginWithGoogle(@RequestBody GoogleAuthRequest request) {
        try {
            UserResponseDTO user = userService.loginWithGoogle(request);
            String token = jwtUtils.generateToken(user.getEmail(), user.getId());
            return ResponseEntity.ok(new AuthResponse(token, "Google authentication successful", user));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, e.getMessage(), null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponse(null, "Google authentication failed: " + e.getMessage(), null));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        Optional<User> userOpt = userService.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "No account registered with this email address."));
        }
        return ResponseEntity.ok(Map.of(
            "message", "Account found. Please enter your new password to complete the reset.",
            "email", request.getEmail()
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            userService.resetPassword(request.getEmail(), request.getNewPassword());
            return ResponseEntity.ok(Map.of(
                "message", "Password has been successfully updated! You can now sign in with your new password.",
                "success", true
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to reset password: " + e.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);
        if (!jwtUtils.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Expired or invalid authentication token");
        }

        String email = jwtUtils.getEmailFromToken(token);
        if (email == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid token payload");
        }

        return userService.findByEmail(email)
                .map(u -> ResponseEntity.ok(UserResponseDTO.fromEntity(u)))
                .orElse(ResponseEntity.notFound().build());
    }
}
