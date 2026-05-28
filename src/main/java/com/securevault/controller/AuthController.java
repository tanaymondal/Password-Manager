package com.securevault.controller;

import com.securevault.dto.*;
import com.securevault.service.AuditService;
import com.securevault.service.AuthService;
import com.securevault.util.ClientIpResolver;
import com.securevault.util.UserUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
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
public class AuthController {

    private final AuthService authService;
    private final AuditService auditService;
    private final ClientIpResolver clientIpResolver;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    public AuthController(AuthService authService, AuditService auditService,
                          ClientIpResolver clientIpResolver) {
        this.authService = authService;
        this.auditService = auditService;
        this.clientIpResolver = clientIpResolver;
    }

    @PostMapping("/prelogin")
    public ResponseEntity<ApiResponse<PreLoginResponse>> prelogin(
            @Valid @RequestBody PreLoginRequest request) {
        PreLoginResponse response = authService.prelogin(request.getEmail());
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("Registering user: {}", request.getEmail());
        String clientIp = clientIpResolver.getClientIp(httpRequest);
        AuthResponse response = authService.register(request, clientIp);
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        stripRefreshTokenForWeb(response, httpRequest);
        log.info("User registered successfully: {}", request.getEmail());
        auditService.logAction(
                UUID.fromString(response.getUserId()),
                "REGISTER",
                clientIp,
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
        String clientIp = clientIpResolver.getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        TwoFactorLoginResponse response = authService.login(request, clientIp, userAgent);
        log.info("Login challenge created for user: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.success("Login challenge created", response));
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<ApiResponse<AuthResponse>> verifyTwoFactor(
            @Valid @RequestBody TwoFactorVerifyRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("2FA verification attempt for email: {}", request.getEmail());
        String clientIp = clientIpResolver.getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        AuthResponse response = authService.verifyTwoFactorLogin(request.getEmail(), request.getChallengeId(), request.getCode(), clientIp, userAgent);
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        stripRefreshTokenForWeb(response, httpRequest);
        log.info("User logged in with 2FA: {}", request.getEmail());
        auditService.logLogin(
                UUID.fromString(response.getUserId()),
                clientIp,
                userAgent
        );
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse,
            @RequestBody(required = false) RefreshTokenRequest body) {
        String refreshToken = extractRefreshToken(httpRequest);
        if (refreshToken == null && body != null) {
            refreshToken = body.getRefreshToken();
        }
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.<AuthResponse>builder()
                            .success(false)
                            .message("No refresh token")
                            .timestamp(java.time.LocalDateTime.now())
                            .build());
        }
        AuthResponse response = authService.refreshToken(refreshToken);
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        stripRefreshTokenForWeb(response, httpRequest);
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
            auditService.logLogout(userId, clientIpResolver.getClientIp(httpRequest), httpRequest.getHeader("User-Agent"));
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
        String clientIp = clientIpResolver.getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        log.info("Password change request for user: {}", userId);
        ChangePasswordResponse response = authService.changePassword(
                userId,
                request.getCurrentAuthHash(),
                request.getNewAuthHash(),
                request.getWrappedVaultKey(),
                request.getNewEncryptionSalt(),
                clientIp,
                userAgent
        );
        setRefreshTokenCookie(httpRequest, httpResponse, response.getRefreshToken());
        stripRefreshTokenForWeb(response, httpRequest);
        auditService.logAction(
                userId,
                "PASSWORD_CHANGE",
                clientIp,
                userAgent,
                null
        );
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully", response));
    }

    @DeleteMapping("/account")
    public ResponseEntity<ApiResponse<String>> deleteAccount(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody DeleteAccountRequest request) {
        UUID userId = UserUtils.getUserId(userDetails);
        log.info("Account deletion request for user: {}", userId);
        authService.deleteAccount(userId, request.getCurrentAuthHash());
        log.info("Account deleted: {}", userId);
        return ResponseEntity.ok(ApiResponse.success("Account deleted successfully", ""));
    }

    private void setRefreshTokenCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        if (refreshToken == null) return;
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/v1/auth");
        cookie.setMaxAge((int) (refreshTokenExpirationMs / 1000));
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }

    private void clearRefreshTokenCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/v1/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private boolean isMobileClient(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return ua == null || !ua.contains("Mozilla");
    }

    private void stripRefreshTokenForWeb(Object response, HttpServletRequest request) {
        if (!isMobileClient(request) && response instanceof AuthResponse) {
            ((AuthResponse) response).setRefreshToken(null);
        } else if (!isMobileClient(request) && response instanceof ChangePasswordResponse) {
            ((ChangePasswordResponse) response).setRefreshToken(null);
        }
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

}