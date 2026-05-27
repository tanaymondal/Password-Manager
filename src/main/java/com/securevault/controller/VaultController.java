package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.dto.VaultEntriesResponse;
import com.securevault.dto.VaultEntryRequest;
import com.securevault.dto.VaultEntryResponse;
import com.securevault.service.AuditService;
import com.securevault.service.VaultService;
import com.securevault.util.ClientIpResolver;
import com.securevault.util.UserUtils;
import jakarta.servlet.http.HttpServletRequest;
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
    private final ClientIpResolver clientIpResolver;

    /**
     * Creates a new vault entry.
     *
     * Stores encrypted data and IV sent by the client. The server
     * cannot decrypt or read the entry contents.
     *
     * @param userDetails Injected from JWT authentication
     * @param request Contains encryptedData and iv from client-side encryption
     * @return VaultEntryResponse with entry ID and metadata
     */
    @PostMapping
    public ResponseEntity<ApiResponse<VaultEntryResponse>> createEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody VaultEntryRequest request,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.debug("Creating vault entry for user: {}", userId);
        VaultEntryResponse response = vaultService.createEntry(userId, request);
        auditService.logVaultAccess(userId, "CREATE", clientIpResolver.getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Entry created successfully", response));
    }

    /**
     * Retrieves all vault entries for the authenticated user.
     *
     * Returns a list of encrypted blobs that the client must decrypt
     * using the vault key.
     *
     * @param userDetails Injected from JWT authentication
     * @return VaultEntriesResponse containing list of encrypted entries
     */
    @GetMapping
    public ResponseEntity<ApiResponse<VaultEntriesResponse>> getAllEntries(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        log.debug("Fetching all vault entries for user: {}", userId);
        VaultEntriesResponse response = vaultService.getAllEntries(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Retrieves a single vault entry by ID.
     *
     * Verifies ownership before returning the encrypted entry.
     *
     * @param userDetails Injected from JWT authentication
     * @param entryId UUID of the vault entry
     * @return VaultEntryResponse with encrypted entry data
     */
    @GetMapping("/{entryId}")
    public ResponseEntity<ApiResponse<VaultEntryResponse>> getEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.debug("Fetching vault entry: {} for user: {}", entryId, userId);
        VaultEntryResponse response = vaultService.getEntry(userId, entryId);
        auditService.logVaultAccess(userId, "READ", clientIpResolver.getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Updates an existing vault entry.
     *
     * Stores new encrypted data sent by the client. Typically used
     * when the user updates password or other details.
     *
     * @param userDetails Injected from JWT authentication
     * @param entryId UUID of the vault entry to update
     * @param request Contains new encryptedData and iv
     * @return VaultEntryResponse with updated entry metadata
     */
    @PutMapping("/{entryId}")
    public ResponseEntity<ApiResponse<VaultEntryResponse>> updateEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId,
            @Valid @RequestBody VaultEntryRequest request,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.debug("Updating vault entry: {} for user: {}", entryId, userId);
        VaultEntryResponse response = vaultService.updateEntry(userId, entryId, request);
        auditService.logVaultAccess(userId, "UPDATE", clientIpResolver.getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("Entry updated successfully", response));
    }

    /**
     * Deletes a single vault entry.
     *
     * Permanently removes the entry from storage.
     *
     * @param userDetails Injected from JWT authentication
     * @param entryId UUID of the vault entry to delete
     * @return Success response
     */
    @DeleteMapping("/{entryId}")
    public ResponseEntity<ApiResponse<String>> deleteEntry(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String entryId,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.debug("Deleting vault entry: {} for user: {}", entryId, userId);
        vaultService.deleteEntry(userId, entryId);
        auditService.logVaultAccess(userId, "DELETE", clientIpResolver.getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("Entry deleted successfully", ""));
    }

    @DeleteMapping
    public ResponseEntity<ApiResponse<String>> deleteAllEntries(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.warn("Deleting all vault entries for user: {}", userId);
        vaultService.deleteAllEntries(userId);
        auditService.logVaultAccess(userId, "DELETE_ALL", clientIpResolver.getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("All entries deleted successfully", ""));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UserUtils.getUserId(userDetails);
    }
}