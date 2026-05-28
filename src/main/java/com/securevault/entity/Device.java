package com.securevault.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing a user device registered for vault access.
 *
 * Allows users to:
 * - Track which devices have been used to access the vault
 * - Manage device access (remove old/unused devices)
 * - See last access time for each device
 *
 * SECURITY:
 * - Device ID is unique system-wide (prevents ID collision attacks)
 *
 * @see com.securevault.service.DeviceService for business logic
 */
@Entity
@Table(name = "devices")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Owner user ID - devices are isolated per user.
     */
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    /**
     * Human-readable device name (e.g., "iPhone 15", "MacBook Pro").
     */
    @Column(name = "device_name", nullable = false)
    private String deviceName;

    /**
     * Unique device identifier (UUID from the client app).
     * Used to identify the device and prevent duplicate registrations.
     */
    @Column(name = "device_id", nullable = false, unique = true)
    private String deviceId;

    /**
     * Last time this device was used to access the vault.
     * Updates automatically on each successful authentication.
     */
    @Column(name = "last_accessed_at", nullable = false)
    private LocalDateTime lastAccessedAt;

    /**
     * Device registration timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        lastAccessedAt = LocalDateTime.now();
    }

    /**
     * Updates the last accessed timestamp to current time.
     */
    public void updateLastAccessed() {
        this.lastAccessedAt = LocalDateTime.now();
    }
}