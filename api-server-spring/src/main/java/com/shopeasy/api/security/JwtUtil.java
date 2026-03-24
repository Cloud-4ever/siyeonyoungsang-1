package com.shopeasy.api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000L; // 24 hours

    public JwtUtil(@Value("${app.jwt.secret}") String secret) {
        // Ensure the key is at least 256 bits (32 bytes)
        while (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            secret = secret + secret;
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(Long id, String email, String name) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", id);
        claims.put("email", email);
        claims.put("name", name);

        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
    }

    public Claims validateToken(String token) throws ExpiredJwtException {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public CurrentUser extractUser(String token) throws ExpiredJwtException {
        Claims claims = validateToken(token);
        Long id = claims.get("id", Long.class);
        if (id == null) {
            Integer idInt = claims.get("id", Integer.class);
            if (idInt != null) {
                id = idInt.longValue();
            }
        }
        String email = claims.get("email", String.class);
        String name = claims.get("name", String.class);
        return new CurrentUser(id, email, name);
    }
}
