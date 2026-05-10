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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAuditLogs(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
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