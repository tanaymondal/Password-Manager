package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.ChangePasswordResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.RegisterRequest;
import com.securevault.dto.TwoFactorLoginResponse;
import com.securevault.dto.VaultEntryRequest;
import com.securevault.entity.RefreshToken;
import com.securevault.entity.User;
import com.securevault.entity.VaultEntry;
import com.securevault.repository.RefreshTokenRepository;
import com.securevault.repository.UserRepository;
import com.securevault.repository.VaultEntryRepository;
import com.securevault.security.JwtTokenProvider;
import com.securevault.security.LoginRateLimiter;
import com.securevault.security.PendingLoginChallengeStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Authentication service that handles user registration, login, and security operations.
 *
 * This service implements zero-knowledge architecture where:
 * - The server never receives the plaintext master password
 * - Auth proof is computed client-side (Argon2id hash) and sent to the server
 * - Vault keys are generated, derived, and wrapped entirely client-side
 * - Vault entries are encrypted client-side using the vault key (server stores only opaque blobs)
 * - The server can never decrypt vault data - only the client with the correct password can
 *
 * Security features:
 * - Account lockout after failed login attempts
 * - JWT-based authentication with refresh tokens
 * - TOTP two-factor authentication
 * - Pending login challenges for 2FA (password-verified)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VaultEntryRepository vaultEntryRepository;
    private final PasswordService passwordService;
    private final JwtTokenProvider jwtTokenProvider;
    private final LoginRateLimiter loginRateLimiter;
    private final TwoFactorAuthService twoFactorAuthService;
    private final PendingLoginChallengeStore pendingLoginChallengeStore;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    @Value("${app.jwt.secret}")
    private String serverSecret;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already in use");
        }

        User user = new User();
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(serverSideHash(request.getAuthHash()));
        user.setPasswordSalt(request.getAuthSalt());
        user.setEncryptionSalt(request.getEncryptionSalt());
        user.setWrappedVaultKey(request.getWrappedVaultKey());
        user.setEncryptionVersion(request.getEncryptionVersion());
        user.setTwoFactorEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setPasswordUpdatedAt(LocalDateTime.now());

        user = userRepository.save(user);

        log.info("User registered successfully: {}", user.getEmail());
        return generateAuthResponse(user);
    }

    @Transactional
    public TwoFactorLoginResponse login(LoginRequest request, String clientIp) {
        if (loginRateLimiter.isBlocked(clientIp)) {
            log.warn("Login blocked due to rate limit for IP: {}", clientIp);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (user.isLocked()) {
            log.warn("Account locked for user: {}", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordService.constantTimeEquals(serverSideHash(request.getAuthHash()), user.getPasswordHash())) {
            loginRateLimiter.recordFailure(clientIp);
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        loginRateLimiter.recordSuccess(clientIp);

        if (user.getTwoFactorEnabled()) {
            log.info("2FA required for user: {}", user.getEmail());
            String challengeId = pendingLoginChallengeStore.createChallenge(user.getId(), user.getEmail());
            return TwoFactorLoginResponse.requireTwoFactor(
                    user.getId().toString(),
                    user.getEmail(),
                    challengeId,
                    user.getPasswordSalt(),
                    null,
                    null,
                    null
            );
        }

        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in successfully: {}", user.getEmail());
        AuthResponse authResponse = generateAuthResponse(user);
        return TwoFactorLoginResponse.loginSuccess(
                authResponse.getAccessToken(),
                authResponse.getRefreshToken(),
                authResponse.getUserId(),
                authResponse.getEmail(),
                authResponse.getAuthSalt(),
                authResponse.getEncryptionSalt(),
                authResponse.getWrappedVaultKey(),
                authResponse.getEncryptionVersion()
        );
    }

    @Transactional
    public AuthResponse verifyTwoFactorLogin(String email, String challengeId, String code) {
        UUID userId = pendingLoginChallengeStore.validateChallenge(challengeId, email);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!user.getTwoFactorEnabled()) {
            throw new BadCredentialsException("2FA is not enabled for this account");
        }

        if (!twoFactorAuthService.verifyCode(user.getId(), code)) {
            throw new BadCredentialsException("Invalid 2FA code");
        }

        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in with 2FA: {}", user.getEmail());
        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(hashToken(refreshToken))
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        if (storedToken.isExpired()) {
            refreshTokenRepository.delete(storedToken);
            throw new IllegalArgumentException("Refresh token expired");
        }

        UUID userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        refreshTokenRepository.delete(storedToken);

        return generateAuthResponse(user);
    }

    @Transactional
    public void logout(UUID userId) {
        if (userId != null) {
            refreshTokenRepository.deleteByUserId(userId);
        }
    }

    @Transactional
    public void logoutByRefreshToken(String refreshToken) {
        try {
            if (jwtTokenProvider.validateToken(refreshToken)) {
                UUID userId = jwtTokenProvider.getUserIdFromToken(refreshToken);
                refreshTokenRepository.deleteByUserId(userId);
            }
        } catch (Exception e) {
            log.warn("Logout by refresh token failed: {}", e.getMessage());
        }
    }

    @Transactional
    public ChangePasswordResponse changePassword(
            UUID userId,
            String currentAuthHash,
            String newAuthHash,
            String newAuthSalt,
            String newWrappedVaultKey,
            String newEncryptionSalt,
            List<VaultEntryRequest> newEntries) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordService.constantTimeEquals(serverSideHash(currentAuthHash), user.getPasswordHash())) {
            throw new BadCredentialsException("Current auth hash is incorrect");
        }

        String saltToUse = (newEncryptionSalt != null && !newEncryptionSalt.isEmpty())
                ? newEncryptionSalt : passwordService.generateSalt();

        if (newEntries != null && !newEntries.isEmpty()) {
            for (VaultEntryRequest entryReq : newEntries) {
                if (entryReq.getId() != null && !entryReq.getId().isEmpty()) {
                    VaultEntry existing = vaultEntryRepository.findById(UUID.fromString(entryReq.getId()))
                            .filter(e -> e.getUserId().equals(userId))
                            .orElse(null);
                    if (existing != null) {
                        existing.setEncryptedData(entryReq.getEncryptedData());
                        existing.setIv(entryReq.getIv());
                        vaultEntryRepository.save(existing);
                    }
                } else {
                    VaultEntry newEntry = new VaultEntry();
                    newEntry.setUserId(userId);
                    newEntry.setEncryptedData(entryReq.getEncryptedData());
                    newEntry.setIv(entryReq.getIv());
                    newEntry.setVersion(1);
                    vaultEntryRepository.save(newEntry);
                }
            }
        }

        user.setPasswordHash(serverSideHash(newAuthHash));
        user.setPasswordSalt(newAuthSalt);
        user.setEncryptionSalt(saltToUse);
        user.setWrappedVaultKey(newWrappedVaultKey);
        user.setEncryptionVersion(2);
        user.setPasswordUpdatedAt(LocalDateTime.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);

        userRepository.save(user);

        refreshTokenRepository.deleteByUserId(userId);

        log.info("Password changed for user: {}", user.getEmail());
        return generateChangePasswordResponse(user);
    }

    public String getAuthSalt(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        return userRepository.findByEmail(normalizedEmail)
                .map(User::getPasswordSalt)
                .orElseGet(() -> generateFakeSalt(normalizedEmail));
    }

    private String serverSideHash(String clientAuthHash) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                serverSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] hash = mac.doFinal(clientAuthHash.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute server-side auth hash", e);
        }
    }

    private String generateFakeSalt(String email) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                serverSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] hash = mac.doFinal(email.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // Truncate to 16 bytes (same length as real salts)
            byte[] truncated = java.util.Arrays.copyOf(hash, 16);
            return Base64.getEncoder().encodeToString(truncated);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate salt", e);
        }
    }

    private void handleFailedLogin(User user) {
        user.incrementFailedAttempts();
        log.warn("Failed login attempt {} for user: {}", user.getFailedLoginAttempts(), user.getEmail());

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.lockAccount(LOCKOUT_MINUTES);
            log.warn("Account locked for user: {} due to {} failed attempts", user.getEmail(), MAX_FAILED_ATTEMPTS);
        }

        userRepository.save(user);
    }

    private AuthResponse generateAuthResponse(User user) {
        refreshTokenRepository.deleteByUserId(user.getId());
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setTokenHash(hashToken(refreshToken));
        token.setExpiresAt(calculateRefreshTokenExpiry());
        refreshTokenRepository.save(token);

        return new AuthResponse(
                accessToken,
                refreshToken,
                user.getId().toString(),
                user.getEmail(),
                user.getPasswordSalt(),
                user.getEncryptionSalt(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : 2
        );
    }

    private ChangePasswordResponse generateChangePasswordResponse(User user) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setTokenHash(hashToken(refreshToken));
        token.setExpiresAt(calculateRefreshTokenExpiry());
        refreshTokenRepository.save(token);

        return new ChangePasswordResponse(
                accessToken,
                refreshToken,
                user.getEncryptionSalt(),
                user.getId().toString(),
                user.getEmail(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : 2
        );
    }

    private LocalDateTime calculateRefreshTokenExpiry() {
        return LocalDateTime.now().plus(refreshTokenExpirationMs, java.time.temporal.ChronoUnit.MILLIS);
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
