package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.dto.VaultEntriesResponse;
import com.securevault.dto.VaultEntryRequest;
import com.securevault.dto.VaultEntryResponse;
import com.securevault.service.AuditService;
import com.securevault.service.VaultService;
import com.securevault.util.UserUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/vault")
@RequiredArgsConstructor
public class VaultController {

    private final VaultService vaultService;
    private final AuditService auditService;

    @PostMapping
    public ResponseEntity<ApiResponse<VaultEntryResponse>> createEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody VaultEntryRequest request) {
        UUID userId = getUserId(userDetails);
        log.debug("Creating vault entry for user: {}", userId);
        VaultEntryResponse response = vaultService.createEntry(userId, request);
        auditService.logVaultAccess(userId, "CREATE", null, null);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Entry created successfully", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<VaultEntriesResponse>> getAllEntries(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        log.debug("Fetching all vault entries for user: {}", userId);
        VaultEntriesResponse response = vaultService.getAllEntries(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{entryId}")
    public ResponseEntity<ApiResponse<VaultEntryResponse>> getEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId) {
        UUID userId = getUserId(userDetails);
        log.debug("Fetching vault entry: {} for user: {}", entryId, userId);
        VaultEntryResponse response = vaultService.getEntry(userId, entryId);
        auditService.logVaultAccess(userId, "READ", null, null);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PutMapping("/{entryId}")
    public ResponseEntity<ApiResponse<VaultEntryResponse>> updateEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId,
            @Valid @RequestBody VaultEntryRequest request) {
        UUID userId = getUserId(userDetails);
        log.debug("Updating vault entry: {} for user: {}", entryId, userId);
        VaultEntryResponse response = vaultService.updateEntry(userId, entryId, request);
        auditService.logVaultAccess(userId, "UPDATE", null, null);
        return ResponseEntity.ok(ApiResponse.success("Entry updated successfully", response));
    }

    @DeleteMapping("/{entryId}")
    public ResponseEntity<ApiResponse<String>> deleteEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId) {
        UUID userId = getUserId(userDetails);
        log.debug("Deleting vault entry: {} for user: {}", entryId, userId);
        vaultService.deleteEntry(userId, entryId);
        auditService.logVaultAccess(userId, "DELETE", null, null);
        return ResponseEntity.ok(ApiResponse.success("Entry deleted successfully", ""));
    }

    @DeleteMapping
    public ResponseEntity<ApiResponse<String>> deleteAllEntries(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        log.warn("Deleting all vault entries for user: {}", userId);
        vaultService.deleteAllEntries(userId);
        auditService.logVaultAccess(userId, "DELETE_ALL", null, null);
        return ResponseEntity.ok(ApiResponse.success("All entries deleted successfully", ""));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UserUtils.getUserId(userDetails);
    }
}