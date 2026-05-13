package com.securevault.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity for storing password history to prevent reuse.
 *
 * Maintains a history of recent password hashes to prevent users from
 * reusing passwords. When a user changes their password, the new hash
 * is checked against the history.
 *
 * SECURITY:
 * - Stores password hashes, not plaintext passwords
 * - Limited history (typically 5 entries) for privacy/performance
 * - Oldest entries are automatically removed when limit is exceeded
 *
 * CONFIGURATION:
 * - PASSWORD_HISTORY_LIMIT in AuthService controls how many hashes are stored
 * - Hash comparison uses constant-time comparison to prevent timing attacks
 *
 * @see com.securevault.service.AuthService for password history management
 */
@Entity
@Table(name = "password_history")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Owner user ID - history is isolated per user.
     */
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /**
     * Argon2id hash of a previous password.
     * Used to check if a new password was previously used.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /**
     * When this password was used (for ordering and cleanup).
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}