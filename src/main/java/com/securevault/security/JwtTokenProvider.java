package com.securevault.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * Provides JWT token generation and validation for authentication.
 *
 * Implements a dual-token system:
 * - Access Token: Short-lived (15 min default), used for API authentication
 * - Refresh Token: Long-lived (1 day default), used to obtain new access tokens
 *
 * TOKEN STRUCTURE:
 * Access tokens contain: userId (subject), email claim, issuedAt, expiration
 * Refresh tokens contain: userId (subject), issuedAt, expiration
 *
 * SECURITY:
 * - Tokens are signed with HMAC-SHA256
 * - Secret key is configured via app.jwt.secret
 * - Token validation checks signature and expiration
 * - Invalid tokens are rejected (prevents tampering)
 *
 * @see JwtAuthenticationFilter for token extraction and validation in requests
 */
@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final long jwtExpiration;
    private final long refreshExpiration;

    /**
     * Initializes the JWT provider with secret and expiration settings.
     *
     * @param secret HMAC-SHA256 secret (must be at least 256 bits / 32 bytes)
     * @param jwtExpiration Access token lifetime in milliseconds
     * @param refreshExpiration Refresh token lifetime in milliseconds
     */
    public JwtTokenProvider(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration}") long jwtExpiration,
            @Value("${app.jwt.refresh-expiration}") long refreshExpiration) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.jwtExpiration = jwtExpiration;
        this.refreshExpiration = refreshExpiration;
    }

    /**
     * Generates a short-lived access token for API authentication.
     *
     * Contains user ID as subject and email as a claim.
     * Used in the Authorization header: "Bearer <token>"
     *
     * @param userId UUID of the user
     * @param email Email of the user
     * @return Signed JWT access token
     */
    public String generateAccessToken(UUID userId, String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * Generates a long-lived refresh token for obtaining new access tokens.
     *
     * Contains only user ID as subject (email not needed for refresh).
     * Should be stored securely by the client and used to get new access tokens.
     *
     * @param userId UUID of the user
     * @return Signed JWT refresh token
     */
    public String generateRefreshToken(UUID userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshExpiration);

        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * Extracts the user ID from a JWT token.
     *
     * @param token Valid JWT token
     * @return UUID of the user
     * @throws JwtException if token is invalid
     */
    public UUID getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return UUID.fromString(claims.getSubject());
    }

    /**
     * Extracts the email from a JWT token.
     *
     * @param token Valid JWT token
     * @return Email address stored in the token
     * @throws JwtException if token is invalid
     */
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.get("email", String.class);
    }

    /**
     * Validates a JWT token's signature and checks expiration.
     *
     * @param token JWT token to validate
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}