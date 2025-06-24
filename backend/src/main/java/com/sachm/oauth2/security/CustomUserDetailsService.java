package com.sachm.oauth2.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService{
    
    private final Map<String, UserDetails> users = new HashMap<>();

    // Implement the methods to load user details from the database or any other source
    // For example, you can use UserRepository to fetch user details by username or email

    public CustomUserDetailsService() {
        users.put("test@gmail.com", new User("test@gmail.com", "{noop}password", new ArrayList<>()));
    }


    // For JWT-based authentication, we primarily rely on the JWT for user details
    // This method might be called by Spring Security's DaoAuthenticationProvider if you were using
    // traditional username/password. For our Google OAuth flow, the JWT's subject (user ID)
    // and claims will be directly used to build an Authentication object in JwtAuthFilter.
    // This implementation is minimal because the user details come from Google, not a password store.
    public UserDetails loadUserByUsername(String email) {
        return new org.springframework.security.core.userdetails.User(email, "", new ArrayList<>());
    }

}
