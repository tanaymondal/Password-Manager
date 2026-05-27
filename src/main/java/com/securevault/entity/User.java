package com.securevault.entity;

import com.securevault.config.TwoFactorSecretConverter;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing a user in the password manager.
 *
 * This entity stores authentication and cryptographic material for zero-knowledge
 * password management:
 *
 * PASSWORD SECURITY:
 * - passwordHash: Argon2id hash of the user's master password
 * - passwordSalt: Unique random salt for password hashing
 *
 * ENCRYPTION MATERIAL:
 * - encryptionSalt: Salt for deriving the Key Encryption Key (KEK)
 * - wrappedVaultKey: Vault key encrypted with KEK (client derives KEK from password)
 *
 * SECURITY FEATURES:
 * - twoFactorEnabled: Whether TOTP 2FA is active
 * - twoFactorSecret: TOTP secret (encrypted in transit, hashed at rest)
 * - failedLoginAttempts: Counter for brute-force protection
 * - lockedUntil: Account lockout timestamp
 *
 * ZERO-KNOWLEDGE ARCHITECTURE:
 * The server stores passwordHash (not password), wrappedVaultKey (not vaultKey),
 * and encryptedData (not plaintext). Only the client with the correct password
 * can access the actual vault data.
 *
 * @see com.securevault.service.AuthService for authentication logic
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * User's email address (unique, used for login).
     */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Argon2id hash of the user's master password.
     * The plaintext password is never stored.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /**
     * Random salt used for password hashing.
     * Unique per user, regenerated when password changes.
     */
    @Column(name = "password_salt", nullable = false)
    private String passwordSalt;

    /**
     * Salt for deriving the Key Encryption Key (KEK) from the user's password.
     * Sent to client after login for vault key unwrapping.
     * Unique per user, regenerated when password changes.
     */
    @Column(name = "encryption_salt")
    private String encryptionSalt;

    /**
     * TOTP secret for two-factor authentication.
     * Encrypted at rest using AES-256-GCM via TwoFactorSecretConverter.
     * Stored when 2FA is enabled, null otherwise.
     */
    @Convert(converter = TwoFactorSecretConverter.class)
    @Column(name = "two_factor_secret")
    private String twoFactorSecret;

    /**
     * Whether two-factor authentication is enabled.
     */
    @Column(name = "two_factor_enabled")
    private Boolean twoFactorEnabled = false;

    /**
     * Counter for failed login attempts (for brute-force protection).
     */
    @Column(name = "failed_login_attempts")
    private Integer failedLoginAttempts = 0;

    /**
     * Timestamp until which the account is locked.
     * Set after MAX_FAILED_ATTEMPTS consecutive failures.
     */
    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    /**
     * When the password was last updated.
     */
    @Column(name = "password_updated_at")
    private LocalDateTime passwordUpdatedAt;

    /**
     * The vault key encrypted (wrapped) with the user's KEK.
     * The server cannot decrypt this - only the client with the password can.
     * Format: [12-byte IV][AES-256-GCM ciphertext with auth tag]
     */
    @Column(name = "wrapped_vault_key", columnDefinition = "TEXT")
    private String wrappedVaultKey;

    /**
     * Encryption version for migration support.
     * Version 2 uses current encryption scheme.
     */
    @Column(name = "encryption_version")
    private Integer encryptionVersion = 1;

    /**
     * Account creation timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Last update timestamp.
     */
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Checks if the account is currently locked due to failed login attempts.
     *
     * @return true if locked, false otherwise
     */
    public boolean isLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Increments the failed login attempt counter.
     */
    public void incrementFailedAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null ? 0 : this.failedLoginAttempts) + 1;
    }

    /**
     * Resets failed login counter and clears lockout.
     * Called on successful login.
     */
    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }

    /**
     * Locks the account for the specified duration.
     *
     * @param lockoutMinutes Number of minutes to lock the account
     */
    public void lockAccount(int lockoutMinutes) {
        this.lockedUntil = LocalDateTime.now().plusMinutes(lockoutMinutes);
    }
}