package com.gillnet.dto;

public class AuthResponse {

    private String token;
    private String message;
    private UserResponseDTO user;

    public AuthResponse() {
    }

    public AuthResponse(String token, String message, UserResponseDTO user) {
        this.token = token;
        this.message = message;
        this.user = user;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public UserResponseDTO getUser() {
        return user;
    }

    public void setUser(UserResponseDTO user) {
        this.user = user;
    }
}
