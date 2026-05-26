package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.entity.AuditLog;
import com.securevault.repository.AuditLogRepository;
import com.securevault.util.UserUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.constraints.Max;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for viewing audit logs.
 *
 * Provides users access to their security audit trail:
 * - View login/logout history
 * - Track account changes
 * - Monitor vault access patterns
 *
 * SECURITY:
 * - All endpoints require JWT authentication
 * - Users can only view their own audit logs
 * - Logs are read-only (no modification or deletion)
 *
 * PAGINATION:
 * - Results are paginated for performance
 * - Default: page 0, size 20
 * - Supports custom page and size parameters
 *
 * @see AuditService for audit logging
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    /**
     * Retrieves paginated audit logs for the authenticated user.
     *
     * Returns a list of security events including:
     * - Login/logout attempts (successful and failed)
     * - Password changes
     * - 2FA enable/disable events
     * - Vault access (view, create, update, delete)
     *
     * @param userDetails Injected from JWT authentication
     * @param page Page number (0-indexed, default 0)
     * @param size Page size (default 20)
     * @return Map containing logs array, totalPages, and totalElements
     */
    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAuditLogs(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") @Max(100) int size) {
        UUID userId = getUserId(userDetails);
        log.debug("Fetching audit logs for user: {}, page: {}, size: {}", userId, page, size);

        Page<AuditLog> auditPage = auditLogRepository.findByUserId(userId, PageRequest.of(page, size));

        Map<String, Object> response = new HashMap<>();
        response.put("logs", auditPage.getContent().stream()
                .map(log -> Map.of(
                        "id", log.getId().toString(),
                        "action", log.getAction(),
                        "ipAddress", log.getIpAddress() != null ? log.getIpAddress() : "",
                        "createdAt", log.getCreatedAt().toString()
                ))
                .toList());
        response.put("totalPages", auditPage.getTotalPages());
        response.put("totalElements", auditPage.getTotalElements());

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UserUtils.getUserId(userDetails);
    }
}