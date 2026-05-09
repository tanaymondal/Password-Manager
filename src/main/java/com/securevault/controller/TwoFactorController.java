package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.dto.Enable2FARequest;
import com.securevault.dto.TwoFactorSetupResponse;
import com.securevault.service.AuditService;
import com.securevault.service.TwoFactorAuthService;
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

@Slf4j
@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
public class TwoFactorController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final AuditService auditService;

    @GetMapping("/setup")
    public ResponseEntity<ApiResponse<TwoFactorSetupResponse>> setup2FA(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        log.info("Generating 2FA setup for user: {}", userId);
        TwoFactorSetupResponse response = twoFactorAuthService.generateSetupSecret(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/enable")
    public ResponseEntity<ApiResponse<String>> enable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody Enable2FARequest request,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.info("Enabling 2FA for user: {}", userId);
        twoFactorAuthService.enable2FA(userId, null, request.getCode());
        auditService.log2FAEnabled(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("2FA enabled successfully", ""));
    }

    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<String>> disable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        UUID userId = getUserId(userDetails);
        log.info("Disabling 2FA for user: {}", userId);
        twoFactorAuthService.disable2FA(userId);
        auditService.log2FADisabled(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(ApiResponse.success("2FA disabled successfully", ""));
    }

    @GetMapping("/status")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> get2FAStatus(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        return ResponseEntity.ok(ApiResponse.success(Map.of("enabled", twoFactorAuthService.is2FAEnabled(userId))));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UUID.fromString(userDetails.getUsername());
    }
}