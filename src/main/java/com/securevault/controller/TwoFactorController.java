package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.dto.Enable2FARequest;
import com.securevault.dto.TwoFactorSetupResponse;
import com.securevault.service.AuditService;
import com.securevault.service.TwoFactorAuthService;
import com.securevault.util.UserUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * REST controller for two-factor authentication (2FA) endpoints.
 *
 * Provides TOTP-based two-factor authentication:
 * - Generate setup QR code for authenticator apps
 * - Enable 2FA after verifying setup
 * - Disable 2FA
 * - Check 2FA status
 *
 * SECURITY:
 * - All endpoints require JWT authentication
 * - Enabling 2FA requires verification code
 * - All 2FA changes are logged for audit
 *
 * @see TwoFactorAuthService for business logic
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
public class TwoFactorController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final AuditService auditService;

    /**
     * Generates setup data for enabling two-factor authentication.
     *
     * Returns a TOTP secret and QR code URL that can be scanned
     * with authenticator apps like Google Authenticator or Authy.
     *
     * @param userDetails Injected from JWT authentication
     * @return TwoFactorSetupResponse with secret and QR code URL
     */
    @GetMapping("/setup")
    public ResponseEntity<ApiResponse<TwoFactorSetupResponse>> setup2FA(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        log.info("Generating 2FA setup for user: {}", userId);
        TwoFactorSetupResponse response = twoFactorAuthService.generateSetupSecret(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Enables two-factor authentication for the user.
     *
     * Verifies the TOTP code to ensure the authenticator app is
     * correctly set up before enabling 2FA.
     *
     * @param userDetails Injected from JWT authentication
     * @param request Contains the TOTP code for verification
     * @param httpRequest HTTP request for audit logging
     * @return Success response
     */
    @PostMapping("/enable")
    public ResponseEntity<ApiResponse<String>> enable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody Enable2FARequest request,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.info("Enabling 2FA for user: {}", userId);
        twoFactorAuthService.enable2FA(userId, request.getCode());
        auditService.log2FAEnabled(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("2FA enabled successfully", ""));
    }

    /**
     * Disables two-factor authentication for the user.
     *
     * Removes the TOTP secret and disables 2FA. The user will
     * then only need their password to log in.
     *
     * @param userDetails Injected from JWT authentication
     * @param httpRequest HTTP request for audit logging
     * @return Success response
     */
    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<String>> disable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody Enable2FARequest request,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.info("Disabling 2FA for user: {}", userId);
        twoFactorAuthService.disable2FA(userId, request.getCode());
        auditService.log2FADisabled(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("2FA disabled successfully", ""));
    }

    /**
     * Checks whether two-factor authentication is enabled for the user.
     *
     * @param userDetails Injected from JWT authentication
     * @return Map with "enabled" boolean
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> get2FAStatus(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        return ResponseEntity.ok(ApiResponse.success(Map.of("enabled", twoFactorAuthService.is2FAEnabled(userId))));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UserUtils.getUserId(userDetails);
    }
}