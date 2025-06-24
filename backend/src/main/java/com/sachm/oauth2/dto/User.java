package com.sachm.oauth2.dto;

public record User(String id, String email, String firstName, String lastName, String picture) {
    public User(String id, String email, String firstName, String lastName) {
        this(id, email, firstName, lastName, null); // picture is optional
    }
}
