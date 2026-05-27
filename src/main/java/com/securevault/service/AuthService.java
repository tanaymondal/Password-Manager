package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.ChangePasswordResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.RegisterRequest;
import com.securevault.dto.TwoFactorLoginResponse;
import com.securevault.entity.PasswordHistory;
import com.securevault.entity.RefreshToken;
import com.securevault.entity.User;
import com.securevault.repository.AuditLogRepository;
import com.securevault.repository.PasswordHistoryRepository;
import com.securevault.repository.RefreshTokenRepository;
import com.securevault.repository.UserRepository;
import org.springframework.data.redis.core.StringRedisTemplate;
import com.securevault.security.JwtTokenProvider;
import com.securevault.security.LoginRateLimiter;
import com.securevault.security.PendingLoginChallengeStore;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;
    private static final int PASSWORD_HISTORY_LIMIT = 10;
    private static final int PBKDF2_ITERATIONS = 600_000;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordService passwordService;
    private final JwtTokenProvider jwtTokenProvider;
    private final LoginRateLimiter loginRateLimiter;
    private final TwoFactorAuthService twoFactorAuthService;
    private final PendingLoginChallengeStore pendingLoginChallengeStore;
    private final AuditService auditService;
    private final AuditLogRepository auditLogRepository;
    private final StringRedisTemplate redisTemplate;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;

    @Value("${app.server-hash-secret}")
    private String serverHashSecret;

    @PostConstruct
    public void init() {
        if (serverHashSecret == null || serverHashSecret.isBlank()) {
            throw new IllegalStateException("SERVER_HASH_SECRET environment variable is required");
        }
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Registration failed");
        }

        User user = new User();
        String userSalt = generateSalt();
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(serverSideHash(request.getAuthHash(), userSalt));
        user.setPasswordSalt(userSalt);
        user.setEncryptionSalt(request.getEncryptionSalt());
        user.setWrappedVaultKey(request.getWrappedVaultKey());
        user.setEncryptionVersion(request.getEncryptionVersion());
        user.setTwoFactorEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setPasswordUpdatedAt(LocalDateTime.now());

        user = userRepository.save(user);

        log.info("User registered successfully: {}", user.getEmail());
        return generateAuthResponse(user, request.getDeviceId());
    }

    @Transactional
    public TwoFactorLoginResponse login(LoginRequest request, String clientIp, String userAgent) {
        if (loginRateLimiter.isBlocked(clientIp)) {
            log.warn("Login blocked due to rate limit for IP: {}", clientIp);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        String email = request.getEmail().toLowerCase().trim();

        if (loginRateLimiter.isBlocked(email)) {
            log.warn("Login blocked due to rate limit for email: {}", email);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (user.isLocked()) {
            log.warn("Account locked for user: {}", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordService.constantTimeEquals(serverSideHash(request.getAuthHash(), user.getPasswordSalt()), user.getPasswordHash())) {
            loginRateLimiter.recordFailure(clientIp);
            loginRateLimiter.recordFailure(email);
            handleFailedLogin(user, clientIp, userAgent);
            throw new BadCredentialsException("Invalid email or password");
        }

        String deviceId = request.getDeviceId();

        if (user.getTwoFactorEnabled()) {
            log.info("2FA required for user: {}", user.getEmail());
            String challengeId = pendingLoginChallengeStore.createChallenge(user.getId(), user.getEmail(), deviceId);
            return TwoFactorLoginResponse.requireTwoFactor(
                    user.getId().toString(),
                    user.getEmail(),
                    challengeId,
                    user.getEmail(),
                    null,
                    null,
                    null
            );
        }

        loginRateLimiter.recordSuccess(clientIp);
        loginRateLimiter.recordSuccess(email);
        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in successfully: {}", user.getEmail());
        AuthResponse authResponse = generateAuthResponse(user, deviceId);
        auditService.logLogin(user.getId(), clientIp, userAgent);
        return TwoFactorLoginResponse.loginSuccess(
                authResponse.getAccessToken(),
                authResponse.getRefreshToken(),
                authResponse.getUserId(),
                authResponse.getEmail(),
                user.getEmail(),
                authResponse.getEncryptionSalt(),
                authResponse.getWrappedVaultKey(),
                authResponse.getEncryptionVersion()
        );
    }

    @Transactional
    public AuthResponse verifyTwoFactorLogin(String email, String challengeId, String code, String clientIp, String userAgent) {
        PendingLoginChallengeStore.ChallengeResult challengeResult = pendingLoginChallengeStore.validateChallenge(challengeId, email);
        UUID userId = challengeResult.userId();
        String deviceId = challengeResult.deviceId();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!user.getTwoFactorEnabled()) {
            throw new BadCredentialsException("2FA is not enabled for this account");
        }

        if (!twoFactorAuthService.verifyCode(user.getId(), code)) {
            loginRateLimiter.recordFailure(clientIp);
            loginRateLimiter.recordFailure(email);
            handleFailedLogin(user, clientIp, userAgent);
            throw new BadCredentialsException("Invalid 2FA code");
        }

        pendingLoginChallengeStore.consumeChallenge(challengeId);
        loginRateLimiter.recordSuccess(clientIp);
        loginRateLimiter.recordSuccess(email);
        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in with 2FA: {}", user.getEmail());
        auditService.logLogin(user.getId(), clientIp, userAgent);
        return generateAuthResponse(user, deviceId);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String tokenHash = hashToken(refreshToken);
        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Refresh token reuse detected - hash not found in DB");
                    return new IllegalArgumentException("Invalid refresh token");
                });

        if (storedToken.isExpired()) {
            refreshTokenRepository.delete(storedToken);
            throw new IllegalArgumentException("Refresh token expired");
        }

        UUID userId = jwtTokenProvider.getUserIdFromRefreshToken(refreshToken);

        String rateLimitKey = "refresh:user:" + userId;
        Long refreshCount = redisTemplate.opsForValue().increment(rateLimitKey);
        if (refreshCount != null && refreshCount == 1) {
            redisTemplate.expire(rateLimitKey, 60, java.util.concurrent.TimeUnit.SECONDS);
        }
        if (refreshCount != null && refreshCount > 5) {
            log.warn("Refresh rate limit exceeded for user: {}", userId);
            throw new IllegalArgumentException("Too many refresh attempts. Please log in again.");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        String deviceId = storedToken.getDeviceId();
        refreshTokenRepository.delete(storedToken);

        return generateAuthResponse(user, deviceId);
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
            if (jwtTokenProvider.validateRefreshToken(refreshToken)) {
                String tokenHash = hashToken(refreshToken);
                refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token ->
                    refreshTokenRepository.delete(token)
                );
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
            String newWrappedVaultKey,
            String newEncryptionSalt) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordService.constantTimeEquals(serverSideHash(currentAuthHash, user.getPasswordSalt()), user.getPasswordHash())) {
            throw new BadCredentialsException("Current auth hash is incorrect");
        }

        String newSalt = generateSalt();
        String newServerHash = serverSideHash(newAuthHash, newSalt);

        checkPasswordHistory(user, newAuthHash);

        savePasswordHistory(user, user.getPasswordHash(), user.getPasswordSalt());

        int historyCount = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId).size();
        if (historyCount > PASSWORD_HISTORY_LIMIT) {
            List<PasswordHistory> history = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId);
            for (int i = PASSWORD_HISTORY_LIMIT; i < history.size(); i++) {
                passwordHistoryRepository.delete(history.get(i));
            }
        }

        user.setPasswordHash(newServerHash);
        user.setPasswordSalt(newSalt);
        user.setEncryptionSalt(newEncryptionSalt);
        user.setWrappedVaultKey(newWrappedVaultKey);
        user.setEncryptionVersion(com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION);
        user.setPasswordUpdatedAt(LocalDateTime.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);

        userRepository.save(user);

        refreshTokenRepository.deleteByUserId(userId);

        log.info("Password changed for user: {}", user.getEmail());
        return generateChangePasswordResponse(user, null);
    }

    @Transactional
    public void deleteAccount(UUID userId, String currentAuthHash) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (!passwordService.constantTimeEquals(serverSideHash(currentAuthHash, user.getPasswordSalt()), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        auditService.logAction(userId, "ACCOUNT_DELETED", null, null, null);

        redisTemplate.delete("login:fail:" + user.getEmail());
        redisTemplate.opsForValue().set("deleted_user:" + userId, "1",
                java.time.Duration.ofHours(1));

        refreshTokenRepository.deleteByUserId(userId);
        userRepository.delete(user);

        log.info("Account deleted for user: {}", user.getEmail());
    }

    private void checkPasswordHistory(User user, String newAuthHash) {
        List<PasswordHistory> history = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(user.getId());
        for (PasswordHistory entry : history) {
            String candidateHash = serverSideHash(newAuthHash, entry.getPasswordSalt());
            if (passwordService.constantTimeEquals(candidateHash, entry.getPasswordHash())) {
                throw new IllegalArgumentException("Password has been used recently. Please choose a different password.");
            }
        }
    }

    private void savePasswordHistory(User user, String passwordHash, String passwordSalt) {
        PasswordHistory history = new PasswordHistory();
        history.setUserId(user.getId());
        history.setPasswordHash(passwordHash);
        history.setPasswordSalt(passwordSalt);
        passwordHistoryRepository.save(history);
    }

    private String generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String serverSideHash(String clientAuthHash, String userSalt) {
        try {
            String combinedSalt = serverHashSecret + ":" + userSalt;
            byte[] salt = combinedSalt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            KeySpec spec = new PBEKeySpec(clientAuthHash.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute server-side auth hash", e);
        }
    }

    private void handleFailedLogin(User user, String clientIp, String userAgent) {
        user.incrementFailedAttempts();
        log.warn("Failed login attempt {} for user: {}", user.getFailedLoginAttempts(), user.getEmail());

        auditService.logFailedLogin(user.getEmail(), clientIp, userAgent);

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.lockAccount(LOCKOUT_MINUTES);
            log.warn("Account locked for user: {} due to {} failed attempts", user.getEmail(), MAX_FAILED_ATTEMPTS);
        }

        userRepository.save(user);
    }

    private AuthResponse generateAuthResponse(User user, String deviceId) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setTokenHash(hashToken(refreshToken));
        token.setDeviceId(deviceId);
        token.setExpiresAt(calculateRefreshTokenExpiry());
        refreshTokenRepository.save(token);

        return new AuthResponse(
                accessToken,
                refreshToken,
                user.getId().toString(),
                user.getEmail(),
                user.getEmail(),
                user.getEncryptionSalt(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION
        );
    }

    private ChangePasswordResponse generateChangePasswordResponse(User user, String deviceId) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setTokenHash(hashToken(refreshToken));
        token.setDeviceId(deviceId);
        token.setExpiresAt(calculateRefreshTokenExpiry());
        refreshTokenRepository.save(token);

        return new ChangePasswordResponse(
                accessToken,
                refreshToken,
                user.getEncryptionSalt(),
                user.getId().toString(),
                user.getEmail(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION
        );
    }

    private LocalDateTime calculateRefreshTokenExpiry() {
        return LocalDateTime.now().plus(refreshTokenExpirationMs, java.time.temporal.ChronoUnit.MILLIS);
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}