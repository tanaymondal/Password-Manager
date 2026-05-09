package com.securevault.controller;

import com.securevault.dto.*;
import com.securevault.service.AuditService;
import com.securevault.service.AuthService;
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
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuditService auditService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        log.info("Registration attempt for email: {}", request.getEmail());
        AuthResponse response = authService.register(request);
        log.info("User registered successfully: {}", request.getEmail());
        auditService.logAction(
                UUID.fromString(response.getUserId()),
                "REGISTER",
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent"),
                null
        );
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registration successful", response));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        log.info("Login attempt for email: {}", request.getEmail());
        AuthResponse response = authService.login(request);
        log.info("User logged in successfully: {}", request.getEmail());
        auditService.logLogin(
                UUID.fromString(response.getUserId()),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent")
        );
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        if (userDetails != null) {
            UUID userId = UUID.fromString(userDetails.getUsername());
            log.info("User logged out: {}", userDetails.getUsername());
            auditService.logLogout(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
            authService.logout(userId);
        }
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully", ""));
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        UUID userId = UUID.fromString(userDetails.getUsername());
        log.info("Password change request for user: {}", userDetails.getUsername());
        authService.changePassword(userId, request.getCurrentPassword(), request.getNewPassword());
        auditService.logAction(
                userId,
                "PASSWORD_CHANGE",
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent"),
                null
        );
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully. Please login again.", ""));
    }
}