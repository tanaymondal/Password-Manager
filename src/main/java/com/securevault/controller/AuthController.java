package com.securevault.controller;

import com.securevault.dto.*;
import com.securevault.service.AuditService;
import com.securevault.service.AuthService;
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

/**
 * REST controller for authentication endpoints.
 *
 * This controller handles all authentication-related operations:
 * - User registration
 * - Login/logout
 * - Token refresh
 * - Password change
 *
 * All endpoints (except register/login) require JWT authentication.
 * The JWT is validated by JwtAuthenticationFilter before reaching these methods.
 *
 * @see AuthService for business logic
 * @see AuditService for audit logging
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuditService auditService;

    /**
     * Registers a new user account.
     *
     * Creates a new user with:
     * - Hashed password using Argon2id
     * - Unique authentication and encryption salts
     * - Wrapped vault key (encrypted with password-derived KEK)
     *
     * Returns JWT tokens and cryptographic material needed by the client
     * to encrypt/decrypt vault entries.
     *
     * @param request Contains email and password
     * @param httpRequest HTTP request for audit logging (IP, User-Agent)
     * @return AuthResponse with tokens and cryptographic material
     */
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

    /**
     * Authenticates a user and returns JWT tokens.
     *
     * Validates credentials and returns:
     * - Access token (JWT for API authentication)
     * - Refresh token (for obtaining new access tokens)
     * - Encryption salt and wrapped vault key (for client-side key unwrapping)
     *
     * @param request Contains email and password
     * @param httpRequest HTTP request for audit logging
     * @return AuthResponse with tokens and cryptographic material
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TwoFactorLoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        log.info("Login attempt for email: {}", request.getEmail());
        String clientIp = getClientIp(httpRequest);
        TwoFactorLoginResponse response = authService.login(request, clientIp);
        if (response.isTwoFactorRequired()) {
            log.info("2FA required for user: {}", request.getEmail());
            return ResponseEntity.ok(ApiResponse.success("2FA verification required", response));
        }
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
            HttpServletRequest httpRequest) {
        log.info("2FA verification attempt for email: {}", request.getEmail());
        AuthResponse response = authService.verifyTwoFactorLogin(request.getEmail(), request.getCode());
        log.info("User logged in with 2FA: {}", request.getEmail());
        auditService.logLogin(
                UUID.fromString(response.getUserId()),
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent")
        );
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    /**
     * Refreshes authentication tokens using a valid refresh token.
     *
     * Exchanges an expired access token + valid refresh token for new tokens.
     * Implements token rotation - the refresh token is invalidated after use.
     *
     * @param request Contains the refresh token
     * @return AuthResponse with new tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Logs out the current user by invalidating refresh tokens.
     *
     * Requires authentication. All refresh tokens for the user are invalidated.
     * The access token will still be valid until it expires (for graceful logout).
     *
     * @param userDetails Injected from JWT - contains authenticated user info
     * @param httpRequest HTTP request for audit logging
     * @return Success response
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {
        if (userDetails != null) {
            UUID userId = UserUtils.getUserId(userDetails);
            log.info("User logged out: {}", userId);
            auditService.logLogout(userId, httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
            authService.logout(userId);
        }
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully", ""));
    }

    /**
     * Changes the user's master password.
     *
     * This endpoint:
     * 1. Validates the current password
     * 2. Validates the new password strength
     * 3. Updates password hash with new salt
     * 4. Stores the new wrapped vault key (from client)
     * 5. Updates re-encrypted vault entries (from client)
     * 6. Invalidates all refresh tokens (forces re-login)
     *
     * The client is responsible for:
     * - Re-encrypting all vault entries with the new vault key
     * - Generating a new vault key and encryption salt
     * - Wrapping the new vault key with the new password-derived KEK
     *
     * @param userDetails Injected from JWT
     * @param request Contains current/new password and updated vault material
     * @param httpRequest HTTP request for audit logging
     * @return ChangePasswordResponse with new tokens
     */
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<ChangePasswordResponse>> changePassword(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        UUID userId = UserUtils.getUserId(userDetails);
        log.info("Password change request for user: {}", userId);
        ChangePasswordResponse response = authService.changePassword(
                userId,
                request.getCurrentPassword(),
                request.getNewPassword(),
                request.getWrappedVaultKey(),
                request.getEntries(),
                request.getNewEncryptionSalt()
        );
        auditService.logAction(
                userId,
                "PASSWORD_CHANGE",
                httpRequest.getRemoteAddr(),
                httpRequest.getHeader("User-Agent"),
                null
        );
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully", response));
    }

    private String getClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}