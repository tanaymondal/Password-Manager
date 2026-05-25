package com.securevault.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing a JWT refresh token for session management.
 *
 * Refresh tokens provide long-lived authentication:
 * - Access tokens expire quickly (e.g., 15 minutes)
 * - Refresh tokens last longer (e.g., 1 day)
 * - Client uses refresh token to get new access token
 * - Tokens are invalidated on logout or password change
 *
 * SECURITY:
 * - Tokens are stored hashed in production (simplified here)
 * - Each token is unique per user session
 * - Token rotation: old token deleted when refreshed
 * - All tokens invalidated on password change
 *
 * @see com.securevault.service.AuthService for token management
 */
@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Owner user ID - tokens are isolated per user.
     */
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /**
     * SHA-256 hash of the refresh token JWT.
     * Only the hash is stored — the raw JWT is never persisted.
     * This prevents session hijacking if the database is compromised.
     */
    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    /**
     * Device ID this token was issued to, for device revocation.
     * Null for tokens issued before device tracking was added.
     */
    @Column(name = "device_id")
    private String deviceId;

    /**
     * Token expiration timestamp.
     * After this time, the token cannot be used for refresh.
     */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * Token creation timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    /**
     * Checks if the token has expired.
     *
     * @return true if current time is after expiration, false otherwise
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}