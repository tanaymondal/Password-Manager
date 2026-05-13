package com.securevault.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing a password entry in the user's vault.
 *
 * This entity implements ZERO-KNOWLEDGE storage. The server stores only
 * encrypted blobs that it cannot decrypt:
 *
 * - encryptedData: AES-256-GCM ciphertext of the vault entry
 * - iv: Initialization vector used for encryption
 *
 * The plaintext format (decrypted by client) is:
 * "title|username|password|url|notes|folder"
 *
 * ENCRYPTION FLOW:
 * 1. Client derives vault key from master password
 * 2. Client encrypts entry data with vault key using AES-256-GCM
 * 3. Client sends encryptedData and iv to server
 * 4. Server stores these as opaque blobs
 * 5. On retrieval, client decrypts using vault key
 *
 * SECURITY:
 * - Each entry uses a unique IV (prevents pattern analysis)
 * - GCM mode provides authentication (tamper detection)
 * - Version field enables future encryption migrations
 *
 * @see com.securevault.service.VaultService for CRUD operations
 */
@Entity
@Table(name = "vault_entries")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class VaultEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Owner user ID - ensures entries are isolated per user.
     */
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /**
     * Optional device ID for multi-device scenarios.
     * Can track which device created/updated an entry.
     */
    @Column(name = "device_id")
    private UUID deviceId;

    /**
     * AES-256-GCM ciphertext of the vault entry.
     *
     * Format when decrypted: "title|username|password|url|notes|folder"
     *
     * The server never sees this in plaintext. Only the client with the
     * correct master password (to derive the vault key) can decrypt.
     */
    @Column(name = "encrypted_data", nullable = false, columnDefinition = "TEXT")
    private String encryptedData;

    /**
     * Initialization Vector (IV) used for AES-GCM encryption.
     *
     * 12 bytes (96 bits), randomly generated per encryption.
     * Stored alongside ciphertext; needed for decryption.
     */
    @Column(name = "iv", nullable = false, length = 64)
    private String iv;

    /**
     * Encryption version for schema migrations.
     * Incremented on update, enables future encryption upgrades.
     */
    @Column(nullable = false)
    private Integer version = 1;

    /**
     * Entry creation timestamp.
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
        version = version + 1;
    }
}