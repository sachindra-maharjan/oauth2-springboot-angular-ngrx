package com.sachm.oauth2.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.sachm.oauth2.dto.AuthRequest;
import com.sachm.oauth2.dto.LoginResponse;
import com.sachm.oauth2.dto.User;
import com.sachm.oauth2.security.JwtService;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    
    private final WebClient webClient;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final JwtService jwtService;

    // Simulate refresh token storage (in production, use an encrypted database)
    private final Map<String, String> refreshTokens = new HashMap<>(); // userId -> refreshToken


    @Value("${FRONTEND_URL}")
    private String frontendUrl;

    public AuthController(WebClient webClient, 
                          ClientRegistrationRepository clientRegistrationRepository, 
                          JwtService jwtService) {
        this.webClient = webClient;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.jwtService = jwtService;
    }

    public String getFrontendUrl() {
        return frontendUrl;
    }

    public void setFrontendUrl(String frontendUrl) {
        this.frontendUrl = frontendUrl;
    }

    @GetMapping("/google/login")
    /**
     * Redirects the user to the Google OAuth2 login page.
     * 
     * @return ResponseEntity with a redirect to the Google login URL.
     */
    public ResponseEntity<?> redirectToGoogleLogin() {
        ClientRegistration googleClientRegistration = clientRegistrationRepository.findByRegistrationId("google");
        String authorizationUri = googleClientRegistration.getProviderDetails().getAuthorizationUri();

        String loginUrl = authorizationUri + "?response_type=code&client_id="
                + googleClientRegistration.getClientId()
                + "&redirect_uri=" + googleClientRegistration.getRedirectUri()
                + "&scope=" + String.join(" ", googleClientRegistration.getScopes())
                + "&access_type=offline" 
                + "&prompt=consent select_account"
                ;

        return ResponseEntity.status(302).header("Location", loginUrl).build();
    }

    @PostMapping("/google/callback")
    /**
     * Handles the callback from Google after the user has authenticated.
     * 
     * @param code The authorization code received from Google.
     * @return ResponseEntity with a JWT token or an error message.
     */
    public ResponseEntity<LoginResponse> handleGoogleCallback(@RequestBody AuthRequest authRequest) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("google");
        if (clientRegistration == null) {
            return ResponseEntity.badRequest().body(new LoginResponse("Client registration not found"));
        }

        Map<String, String> tokenData = fetchToken(authRequest, clientRegistration);

        if (tokenData == null || !tokenData.containsKey("access_token") || !tokenData.containsKey("refresh_token")) {
            return ResponseEntity.badRequest().body(new LoginResponse("Failed to fetch tokens from Google"));
        }

        String accessToken = tokenData.get("access_token");
        String refreshToken = tokenData.get("refresh_token");

        User user = fetchUserInfo(clientRegistration, accessToken);
        if (user == null) {
            return ResponseEntity.badRequest().body(new LoginResponse("Failed to fetch user info from Google"));
        }

        // --- Application's user management logic ---
        // 1. Check if user exists in your database based on googleId or email.
        // 2. If not, create a new user account.
        // 3. Store Google's refresh_token securely in your database, linked to your user.
        //    It MUST be encrypted at rest.
        if (refreshToken != null) {
            // In production: Encrypt and store in database
            refreshTokens.put(user.id(), refreshToken); // Simplified: In-memory map
        }

        String jwtToken = jwtService.generateToken(user);
        return ResponseEntity.ok(new LoginResponse(user, 
            jwtToken, 
            jwtService.extractExpiration(jwtToken), 
            "Login successful"));

    }

    /*
     * Fetches user information from Google using the access token.
     */
    private Map<String, String> fetchToken(AuthRequest authRequest, ClientRegistration clientRegistration) {
        
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientRegistration.getClientId());
        formData.add("client_secret", clientRegistration.getClientSecret());
        formData.add("grant_type", "authorization_code");
        formData.add("code", authRequest.authCode()); 
        formData.add("redirect_uri", clientRegistration.getRedirectUri());
        formData.add("code_verifier", authRequest.codeVerifier()); // PKCE

        try {
            ResponseEntity<Map<String, Object>> responseEntity = webClient.post()
                            .uri(clientRegistration.getProviderDetails().getTokenUri())
                            .headers(headers -> headers.addAll(httpHeaders))
                            .bodyValue(formData)
                            .retrieve()
                            .toEntity(new ParameterizedTypeReference<Map<String, Object>>() {})
                            .block();

            if (responseEntity.getStatusCode().isError()) {
                throw new RuntimeException("Failed to fetch token from Google: " + responseEntity.getStatusCode());
            }
    
            Map<String, Object> tokenData = responseEntity.getBody();
            if (tokenData == null || !tokenData.containsKey("access_token") || !tokenData.containsKey("refresh_token")) {
                throw new RuntimeException( "Invalid token response from Google");
            }
    
            String accessToken = (String) tokenData.get("access_token");
            String refreshToken = (String) tokenData.get("refresh_token");

            return Map.of(
                "access_token", accessToken,
                "refresh_token", refreshToken
            );

        } catch (WebClientResponseException e) {
            // Log the error and rethrow or handle it
            log.error("Error during token request: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve token", e);
        } catch (Exception e) {
            // Handle other exceptions
            log.error("Unexpected error: {}", e.getMessage(), e);
            throw new RuntimeException("Unexpected error occurred", e);
        }
    }

    private User fetchUserInfo(ClientRegistration clientRegistration, String accessToken) {
        try {
            ResponseEntity<Map<String, Object>> responseEntity = webClient.get()
                    .uri(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .toEntity(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();

            if (responseEntity.getStatusCode().isError()) {
                throw new RuntimeException("Failed to fetch user info from Google: " + responseEntity.getStatusCode());
            }

            Map<String, Object> userInfoResponse = responseEntity.getBody();
            if (userInfoResponse == null) {
                throw new RuntimeException("Invalid user info response from Provider: " + clientRegistration.getRegistrationId());
            }

            String id = (String) userInfoResponse.get("sub");
            String email = (String) userInfoResponse.get("email");
            String firstName = (String) userInfoResponse.get("given_name");
            String lastName = (String) userInfoResponse.get("family_name");

            return new User(id, email, firstName, lastName);

        } catch (WebClientResponseException e) {
            log.error("Error during user info request: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve user info", e);
        } catch (Exception e) {
            log.error("Unexpected error: {}", e.getMessage(), e);
            throw new RuntimeException("Unexpected error occurred", e);
        }
    }

    @GetMapping("/me")
    public ResponseEntity<User> getUserInfo(@RequestHeader("Authorization") String token) {
        String jwt = token.substring(7); // Remove "Bearer " prefix
        try {
            String userId = jwtService.extractUserId(jwt);
            String email = jwtService.extractEmail(jwt);
            String firstName = jwtService.extractFirstName(jwt);
            String lastName = jwtService.extractLastName(jwt);
            User user = new User(userId, email, firstName, lastName);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            log.error("Error extracting user from token: {}", e.getMessage(), e);
            return ResponseEntity.status(401).build(); // Unauthorized
        }
    }

}
