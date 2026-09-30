package com.gillnet.dto;

import java.time.LocalDateTime;

import com.gillnet.model.User;

public class UserResponseDTO {
    private String id;
    private String name;
    private String email;
    private String picture;
    private String authProvider;
    private LocalDateTime createdAt;
    private Integer credits;

    public UserResponseDTO() {
    }

    public UserResponseDTO(String id, String name, String email, String picture, String authProvider, LocalDateTime createdAt, Integer credits) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.authProvider = authProvider;
        this.createdAt = createdAt;
        this.credits = credits;
    }

    public static UserResponseDTO fromEntity(User user) {
        if (user == null) return null;
        return new UserResponseDTO(
            user.getId(),
            user.getName(),
            user.getEmail(),
            user.getPicture(),
            user.getAuthProvider() != null ? user.getAuthProvider() : "LOCAL",
            user.getCreatedAt(),
            user.getCredits() != null ? user.getCredits() : 0
        );
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getAuthProvider() {
        return authProvider;
    }

    public void setAuthProvider(String authProvider) {
        this.authProvider = authProvider;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Integer getCredits() {
        return credits;
    }

    public void setCredits(Integer credits) {
        this.credits = credits;
    }
}
