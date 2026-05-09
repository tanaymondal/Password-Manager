package com.securevault.service;

import com.securevault.entity.AuditLog;
import com.securevault.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void logAction(UUID userId, String action, String ipAddress, String userAgent, String details) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUserId(userId);
        auditLog.setAction(action);
        auditLog.setIpAddress(ipAddress);
        auditLog.setUserAgent(userAgent);
        auditLog.setDetails(details);

        auditLogRepository.save(auditLog);
    }

    public void logLogin(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "LOGIN", ipAddress, userAgent, null);
    }

    public void logLogout(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "LOGOUT", ipAddress, userAgent, null);
    }

    public void logVaultAccess(UUID userId, String action, String ipAddress, String userAgent) {
        logAction(userId, "VAULT_" + action, ipAddress, userAgent, null);
    }

    public void logFailedLogin(String email, String ipAddress, String userAgent) {
        logAction(null, "LOGIN_FAILED", ipAddress, userAgent, "{\"email\": \"" + email + "\"}");
    }

    public void log2FAEnabled(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "2FA_ENABLED", ipAddress, userAgent, null);
    }

    public void log2FADisabled(UUID userId, String ipAddress, String userAgent) {
        logAction(userId, "2FA_DISABLED", ipAddress, userAgent, null);
    }
}