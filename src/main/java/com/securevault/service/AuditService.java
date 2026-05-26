package com.securevault.service;

import com.securevault.entity.AuditLog;
import com.securevault.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Service for logging security-relevant events for auditing and compliance.
 *
 * This service records all important user actions and security events:
 * - Authentication events (login, logout, failed attempts)
 * - Account changes (password changes, 2FA enable/disable)
 * - Vault operations (view, create, update, delete entries)
 *
 * AUDIT LOGGING PURPOSES:
 * 1. Security monitoring: Detect suspicious patterns (e.g., many failed logins)
 * 2. Compliance: Meet regulatory requirements for access tracking
 * 3. Investigation: Reconstruct events if a security incident occurs
 * 4. User activity: Help users understand account usage
 *
 * DATA CAPTURED:
 * - User ID (when available)
 * - Action type (LOGIN, LOGOUT, PASSWORD_CHANGE, etc.)
 * - IP address (for geographic tracking of access)
 * - User agent (browser/app info for device identification)
 * - Additional details (JSON format for context-specific data)
 *
 * SECURITY NOTES:
 * - Failed login attempts are logged even without a user ID (for detecting attacks)
 * - IP and User-Agent help identify unauthorized access patterns
 * - Logs are append-only for integrity (modification not supported)
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    /**
     * Logs a generic action event.
     *
     * @param userId UUID of the user performing the action (can be null for failed auth)
     * @param action Type of action (e.g., LOGIN, LOGOUT, PASSWORD_CHANGE)
     * @param ipAddress IP address of the request
     * @param userAgent User-Agent header from the request
     * @param details Additional context as JSON string (can be null)
     */
    public void logAction(UUID userId, String action, String ipAddress, String userAgent, String details) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUserId(userId);
        auditLog.setAction(action);
        auditLog.setIpAddress(ipAddress);
        auditLog.setUserAgent(userAgent);
        auditLog.setDetails(details);

        auditLogRepository.save(auditLog);
    }

    /**
     * Logs a successful login event.
     *
     * @param userId UUID of the user who logged in
     * @param ipAddress IP address of the login request
     * @param userAgent User-Agent from the client
     */
    public void logLogin(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "LOGIN", ipAddress, userAgent, null);
    }

    /**
     * Logs a logout event.
     *
     * @param userId UUID of the user who logged out
     * @param ipAddress IP address of the logout request
     * @param userAgent User-Agent from the client
     */
    public void logLogout(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "LOGOUT", ipAddress, userAgent, null);
    }

    /**
     * Logs a vault access event (view, create, update, delete).
     *
     * @param userId UUID of the user accessing vault
     * @param action Specific action (VIEW, CREATE, UPDATE, DELETE)
     * @param ipAddress IP address of the request
     * @param userAgent User-Agent from the client
     */
    public void logVaultAccess(UUID userId, String action, String ipAddress, String userAgent) {
        logAction(userId, "VAULT_" + action, ipAddress, userAgent, null);
    }

    /**
     * Logs a failed login attempt.
     *
     * Records the attempt even though no user ID is available,
     * enabling detection of brute-force attacks.
     *
     * @param email Email that was used in the failed attempt
     * @param ipAddress IP address of the failed request
     * @param userAgent User-Agent from the client
     */
    public void logFailedLogin(String email, String ipAddress, String userAgent) {
        String escapedEmail = email
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
        logAction(null, "LOGIN_FAILED", ipAddress, userAgent, "{\"email\":\"" + escapedEmail + "\"}");
    }

    /**
     * Logs when a user enables two-factor authentication.
     *
     * @param userId UUID of the user
     * @param ipAddress IP address of the request
     * @param userAgent User-Agent from the client
     */
    public void log2FAEnabled(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "2FA_ENABLED", ipAddress, userAgent, null);
    }

    /**
     * Logs when a user disables two-factor authentication.
     *
     * @param userId UUID of the user
     * @param ipAddress IP address of the request
     * @param userAgent User-Agent from the client
     */
    public void log2FADisabled(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "2FA_DISABLED", ipAddress, userAgent, null);
    }
}