package com.securevault.controller;

import com.securevault.dto.*;
import com.securevault.service.AuditService;
import com.securevault.service.AuthService;
import com.securevault.service.BreachCheckService;
import com.securevault.util.UserUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuditService auditService;
    private final BreachCheckService breachCheckService;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    @PostMapping("/auth-salt")
    public ResponseEntity<ApiResponse<Map<String, String>>> getAuthSalt(
            @Valid @RequestBody AuthSaltRequest request) {
        String authSalt = authService.getAuthSalt(request.getEmail());
        return ResponseEntity.ok(ApiResponse.success(Map.of("authSalt", authSalt)));
    }

    @PostMapping("/check-breach")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> checkBreach(
            @Valid @RequestBody BreachCheckRequest request) {
        boolean breached = breachCheckService.isHashBreached(request.getSha1Hash());
        return ResponseEntity.ok(ApiResponse.success(Map.of("breached", breached)));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("Registration attempt for email: {}", request.getEmail());
        AuthResponse response = authService.register(request);
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
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
    public ResponseEntity<ApiResponse<TwoFactorLoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("Login attempt for email: {}", request.getEmail());
        String clientIp = getClientIp(httpRequest);
        TwoFactorLoginResponse response = authService.login(request, clientIp);
        if (response.isTwoFactorRequired()) {
            log.info("2FA required for user: {}", request.getEmail());
            return ResponseEntity.ok(ApiResponse.success("2FA verification required", response));
        }
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        log.info("User logged in successfully: {}", request.getEmail());
        auditService.logLogin(
                UUID.fromString(response.getUserId()),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent")
        );
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<ApiResponse<AuthResponse>> verifyTwoFactor(
            @Valid @RequestBody TwoFactorVerifyRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("2FA verification attempt for email: {}", request.getEmail());
        AuthResponse response = authService.verifyTwoFactorLogin(request.getEmail(), request.getChallengeId(), request.getCode());
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        log.info("User logged in with 2FA: {}", request.getEmail());
        auditService.logLogin(
                UUID.fromString(response.getUserId()),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent")
        );
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        String refreshToken = extractRefreshToken(httpRequest);
        if (refreshToken == null) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<AuthResponse>builder()
                            .success(false)
                            .message("No refresh token")
                            .timestamp(java.time.LocalDateTime.now())
                            .build());
        }
        AuthResponse response = authService.refreshToken(refreshToken);
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody(required = false) RefreshTokenRequest refreshRequest,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        if (userDetails != null) {
            UUID userId = UserUtils.getUserId(userDetails);
            log.info("User logged out: {}", userId);
            auditService.logLogout(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
            authService.logout(userId);
        } else {
            String refreshToken = extractRefreshToken(httpRequest);
            if (refreshToken != null) {
                authService.logoutByRefreshToken(refreshToken);
            } else if (refreshRequest != null && refreshRequest.getRefreshToken() != null && !refreshRequest.getRefreshToken().isEmpty()) {
                authService.logoutByRefreshToken(refreshRequest.getRefreshToken());
            }
        }
        clearRefreshTokenCookie(httpRequest, httpResponse);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully", ""));
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<ChangePasswordResponse>> changePassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        UUID userId = UserUtils.getUserId(userDetails);
        log.info("Password change request for user: {}", userId);
        ChangePasswordResponse response = authService.changePassword(
                userId,
                request.getCurrentAuthHash(),
                request.getNewAuthHash(),
                request.getNewAuthSalt(),
                request.getWrappedVaultKey(),
                request.getNewEncryptionSalt(),
                request.getEntries()
        );
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        auditService.logAction(
                userId,
                "PASSWORD_CHANGE",
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent"),
                null
        );
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully", response));
    }

    private void setRefreshTokenCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        if (refreshToken == null) return;
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath("/api/v1/auth");
        cookie.setMaxAge((int) (refreshTokenExpirationMs / 1000));
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }

    private void clearRefreshTokenCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath("/api/v1/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    @Data
    private static class AuthSaltRequest {
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        private String email;
    }
}