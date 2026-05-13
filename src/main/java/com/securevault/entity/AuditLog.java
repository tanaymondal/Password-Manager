package com.securevault.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity for security audit logging.
 *
 * Records all important user actions and security events for:
 * - Security monitoring and incident detection
 * - Compliance requirements (GDPR, SOC2, etc.)
 * - User activity visibility
 * - Forensic investigation
 *
 * CAPTURED EVENTS:
 * - Authentication: LOGIN, LOGOUT, LOGIN_FAILED
 * - Account changes: REGISTER, PASSWORD_CHANGE
 * - 2FA: 2FA_ENABLED, 2FA_DISABLED
 * - Vault operations: VAULT_VIEW, VAULT_CREATE, VAULT_UPDATE, VAULT_DELETE
 *
 * SECURITY NOTES:
 * - Logs are append-only (no modification or deletion)
 * - Failed login attempts are logged even without user ID
 * - IP and User-Agent enable geographic/device tracking
 *
 * @see com.securevault.service.AuditService for logging operations
 */
@Entity
@Table(name = "audit_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * User ID (null for unauthenticated events like failed logins).
     */
    @Column(name = "user_id")
    private UUID userId;

    /**
     * Action type (e.g., "LOGIN", "PASSWORD_CHANGE", "2FA_ENABLED").
     */
    @Column(nullable = false)
    private String action;

    /**
     * Client IP address for geographic tracking.
     * Supports IPv6 (45 chars).
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /**
     * Client User-Agent string for device identification.
     */
    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    /**
     * Additional context as JSON.
     * Example: {"email": "user@example.com"} for failed logins.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String details;

    /**
     * Event timestamp (immutable - set on creation).
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}