package com.gillnet.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gillnet.dto.UserResponseDTO;
import com.gillnet.model.User;
import com.gillnet.service.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        try {
            // Credits are always granted server-side — ignore any client-supplied value.
            user.setCredits(null);
            User savedUser = userService.registerUser(user);
            return ResponseEntity.ok(UserResponseDTO.fromEntity(savedUser));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Registration error: " + e.getMessage());
        }
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<?> getUserByEmail(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable String email) {
        // Authenticated users may only look up their own profile.
        var requester = userService.userFromAuthHeader(authHeader);
        if (requester.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(java.util.Map.of("message", "Please sign in."));
        }
        if (!requester.get().getEmail().equalsIgnoreCase(email)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(java.util.Map.of("message", "You can only view your own profile."));
        }
        return userService.findByEmail(email)
                .map(u -> ResponseEntity.ok(UserResponseDTO.fromEntity(userService.ensureCreditsInitialized(u))))
                .orElse(ResponseEntity.notFound().build());
    }
}
