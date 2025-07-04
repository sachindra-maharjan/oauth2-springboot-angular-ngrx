package com.sachm.oauth2.dto;

public record AuthRequest(String authCode, String codeVerifier) {
    
}
