package com.gillnet.dto;

public class GoogleAuthRequest {

    private String credential; // Google ID token (JWT)
    private String email;
    private String name;
    private String picture;
    private String googleId;

    public GoogleAuthRequest() {
    }

    public GoogleAuthRequest(String credential, String email, String name, String picture, String googleId) {
        this.credential = credential;
        this.email = email;
        this.name = name;
        this.picture = picture;
        this.googleId = googleId;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getGoogleId() {
        return googleId;
    }

    public void setGoogleId(String googleId) {
        this.googleId = googleId;
    }
}
