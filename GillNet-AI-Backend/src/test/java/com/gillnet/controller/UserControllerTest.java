package com.gillnet.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import com.gillnet.dto.UserResponseDTO;
import com.gillnet.model.User;
import com.gillnet.service.UserService;

/**
 * A client must never be able to grant itself credits at registration —
 * the server always assigns the signup bonus itself.
 */
@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @Test
    void registerIgnoresClientSuppliedCredits() {
        User attacker = new User();
        attacker.setName("Attacker");
        attacker.setEmail("attacker@example.com");
        attacker.setPassword("hashed");
        attacker.setCredits(9_999_999); // attempt to mint credits

        User saved = new User();
        saved.setEmail("attacker@example.com");
        saved.setCredits(100);
        when(userService.registerUser(any(User.class))).thenReturn(saved);

        ResponseEntity<?> response = userController.registerUser(attacker);

        assertEquals(200, response.getStatusCode().value());
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userService).registerUser(captor.capture());
        assertNull(captor.getValue().getCredits(),
                "Client-supplied credits must be stripped before registration");
        UserResponseDTO dto = (UserResponseDTO) response.getBody();
        assertEquals(100, dto.getCredits());
    }
}
