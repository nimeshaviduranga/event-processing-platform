package com.eventprocessing.commonsecurity.security;

import com.eventprocessing.common.util.Constants;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${app.security.jwt.secret:your-256-bit-secret-key-change-this-in-production-environment}")
    private String jwtSecret;

    @Value("${app.security.jwt.expiration:86400000}") // 24 hours
    private long jwtExpiration;

    @Value("${app.security.jwt.refresh-expiration:604800000}") // 7 days
    private long refreshExpiration;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            throw new IllegalStateException("JWT secret must be at least 256 bits (32 characters)");
        }
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String userId, String email, List<String> roles, String workspaceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(Constants.JWT_CLAIM_USER_ID, userId);
        claims.put(Constants.JWT_CLAIM_EMAIL, email);
        claims.put(Constants.JWT_CLAIM_ROLES, roles);
        claims.put(Constants.JWT_CLAIM_WORKSPACE_ID, workspaceId);

        return createToken(claims, userId, jwtExpiration);
    }

    public String generateRefreshToken(String userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(Constants.JWT_CLAIM_USER_ID, userId);

        return createToken(claims, userId, refreshExpiration);
    }

    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        Instant now = Instant.now();
        Instant expiryDate = now.plusMillis(expiration);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiryDate))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getUserIdFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get(Constants.JWT_CLAIM_USER_ID, String.class);
    }

    public String getEmailFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get(Constants.JWT_CLAIM_EMAIL, String.class);
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get(Constants.JWT_CLAIM_ROLES, List.class);
    }

    public String getWorkspaceIdFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get(Constants.JWT_CLAIM_WORKSPACE_ID, String.class);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
}
