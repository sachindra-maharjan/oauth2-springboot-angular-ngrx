package com.sachm.oauth2.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.sachm.oauth2.dto.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Service
@Data
@Slf4j
public class JwtService {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpiration;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(User user) {
        Map<String, String> claims = new HashMap<>();
        claims.put("email", user.email());
        claims.put("firstName", user.firstName());
        claims.put("lastName", user.lastName());

        return Jwts.builder()
            .claims(claims)
            .subject(user.id())
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact();
    }

    public boolean validateToken(String token) {
        try{
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch(MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch(ExpiredJwtException ex) {
            log.error("Jwt token has expired: {}", ex.getMessage());
        } catch(UnsupportedJwtException ex) {
            log.error("Jwt token is unsupported: {}", ex.getMessage());
        } catch(IllegalArgumentException ex) {
            log.error("JWT claims is empty: {}", ex.getMessage());
        }
        
        return false;
    }

    private Claims extractALLClaims(String token) {
        return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractALLClaims(token);
        return claimsResolver.apply(claims);
    }


    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    public String extractFirstName(String token) {
        return extractClaim(token, claims -> claims.get("firstName", String.class));
    }

    public String extractLastName(String token) {
        return extractClaim(token, claims -> claims.get("lastName", String.class));
    }

    public int extractExpiration(String token) {
        return extractClaim(token, claims -> claims.get("exp", Integer.class));
    }

}
