package com.sachm.oauth2.dto;

public record LoginResponse(User user, String accessToken, int expiresIn, String message) {

   public LoginResponse(User user, String accessToken, int expiresIn, String message) {
        this.user = user;
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.message = message;
   }

    public LoginResponse(String message) {
        this(null, null, 0, message);
    }
    
}
