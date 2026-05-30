package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.ChangePasswordResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.PreLoginResponse;
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
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
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

    // Dummy salt/hash for timing-constant login — same length as real base64(32 bytes)
    private static final String DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String DUMMY_HASH = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    @Value("${app.pbkdf2.iterations}")
    private int pbkdf2Iterations;

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

    @org.springframework.beans.factory.annotation.Autowired
    @org.springframework.context.annotation.Lazy
    private AuthService self;

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
    public AuthResponse register(RegisterRequest request, String clientIp) {
        String rateLimitKey = "register:ip:" + clientIp;
        Long count = redisTemplate.opsForValue().increment(rateLimitKey);
        if (count != null && count == 1) {
            redisTemplate.expire(rateLimitKey, 60, java.util.concurrent.TimeUnit.SECONDS);
        }
        if (count != null && count > 3) {
            log.warn("Register rate limit exceeded for IP: {}", clientIp);
            throw new RateLimitExceededException("Too many registration attempts. Please try again later.");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("An account with this email already exists. Please log in instead.");
        }

        User user = new User();
        String userSalt = generateSalt();
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(serverSideHash(request.getAuthHash(), userSalt));
        user.setPasswordSalt(userSalt);
        user.setAuthSalt(request.getAuthSalt());
        user.setEncryptionSalt(request.getEncryptionSalt());
        user.setWrappedVaultKey(request.getWrappedVaultKey());
        user.setEncryptionVersion(request.getEncryptionVersion());
        user.setTwoFactorEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setPasswordUpdatedAt(LocalDateTime.now());

        if (request.getKdfIterations() != null) {
            user.setKdfIterations(request.getKdfIterations());
        } else {
            user.setKdfIterations(com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS);
        }
        if (request.getKdfMemory() != null) {
            user.setKdfMemory(request.getKdfMemory());
        } else {
            user.setKdfMemory(com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY);
        }
        if (request.getKdfParallelism() != null) {
            user.setKdfParallelism(request.getKdfParallelism());
        } else {
            user.setKdfParallelism(com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM);
        }

        user = userRepository.save(user);

        log.info("User registered successfully: {}", user.getEmail());
        return generateAuthResponse(user, request.getDeviceId());
    }

    public PreLoginResponse prelogin(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        return userRepository.findByEmail(normalizedEmail)
                .map(user -> new PreLoginResponse(
                        user.getAuthSalt(),
                        user.getKdfIterations() != null ? user.getKdfIterations() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS,
                        user.getKdfMemory() != null ? user.getKdfMemory() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY,
                        user.getKdfParallelism() != null ? user.getKdfParallelism() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM
                ))
                .orElseGet(() -> {
                    byte[] randomSalt = new byte[16];
                    new java.security.SecureRandom().nextBytes(randomSalt);
                    return new PreLoginResponse(
                            java.util.Base64.getEncoder().encodeToString(randomSalt),
                            com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS,
                            com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY,
                            com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM
                    );
                });
    }

    @Transactional
    public TwoFactorLoginResponse login(LoginRequest request, String clientIp, String userAgent) {
        if (loginRateLimiter.isBlocked(clientIp)) {
            log.warn("Login blocked due to rate limit for IP: {}", clientIp);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        String email = request.getEmail().toLowerCase().trim();

        if (loginRateLimiter.isBlocked(email)) {
            log.warn("Login blocked due to rate limit for email: {}", maskEmail(email));
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        java.util.Optional<User> userOpt = userRepository.findByEmail(email);
        User user = userOpt.orElse(null);

        log.info("LOGIN_DEBUG: userExists={}, computing serverSideHash", user != null);

        if (user != null && user.isLocked()) {
            refreshTokenRepository.deleteByUserId(user.getId());
            log.warn("Account locked for user: {} — refresh tokens revoked", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        // Always compute PBKDF2 — timing-constant regardless of user existence
        String computedHash = serverSideHash(
                request.getAuthHash(),
                user != null ? user.getPasswordSalt() : DUMMY_SALT
        );

        String storedHash = user != null ? user.getPasswordHash() : DUMMY_HASH;

        if (!passwordService.constantTimeEquals(computedHash, storedHash)) {
            loginRateLimiter.recordFailure(clientIp);
            loginRateLimiter.recordFailure(email);
            if (user != null) {
                self.recordFailedChangePasswordAttempt(user.getId(), clientIp, userAgent);
            }
            throw new BadCredentialsException("Invalid email or password");
        }

        String deviceId = request.getDeviceId();

        log.info("Login challenge created for user: {}", user.getEmail());
        String challengeId = pendingLoginChallengeStore.createChallenge(user.getId(), user.getEmail(), deviceId);
        List<String> twoFactorMethods = user.getTwoFactorEnabled() ? List.of("totp") : List.of();
        return TwoFactorLoginResponse.requireTwoFactor(
                user.getId().toString(),
                null,
                challengeId,
                user.getAuthSalt(),
                twoFactorMethods,
                user.getKdfIterations() != null ? user.getKdfIterations() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS,
                user.getKdfMemory() != null ? user.getKdfMemory() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY,
                user.getKdfParallelism() != null ? user.getKdfParallelism() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM
        );
    }

    @Transactional
    public AuthResponse verifyTwoFactorLogin(String email, String challengeId, String code, String clientIp, String userAgent) {
        if (loginRateLimiter.isBlocked(clientIp)) {
            log.warn("2FA verify blocked due to rate limit for IP: {}", clientIp);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        if (loginRateLimiter.isBlocked(email)) {
            log.warn("2FA verify blocked due to rate limit for email: {}", email);
            throw new BadCredentialsException("Too many login attempts. Please try again later.");
        }

        PendingLoginChallengeStore.ChallengeResult challengeResult = pendingLoginChallengeStore.validateChallenge(challengeId, email);
        UUID userId = challengeResult.userId();
        String deviceId = challengeResult.deviceId();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (user.isLocked()) {
            refreshTokenRepository.deleteByUserId(user.getId());
            log.warn("Account locked for user: {} during 2FA verify", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (user.getTwoFactorEnabled()) {
            if (code == null || code.isBlank()) {
                log.warn("TOTP code required but not provided for user: {}", user.getEmail());
                throw new BadCredentialsException("TOTP code is required");
            }
            if (!twoFactorAuthService.verifyCode(user.getId(), code)) {
                loginRateLimiter.recordFailure(clientIp);
                loginRateLimiter.recordFailure(email);
                handleFailedLogin(user, clientIp, userAgent);
                throw new BadCredentialsException("Invalid 2FA code");
            }
        }

        pendingLoginChallengeStore.consumeChallenge(challengeId);
        loginRateLimiter.recordSuccess(clientIp);
        loginRateLimiter.recordSuccess(email);
        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in: {}", user.getEmail());
        auditService.logLogin(user.getId(), clientIp, userAgent);
        return generateAuthResponse(user, deviceId);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        UUID userId = jwtTokenProvider.getUserIdFromRefreshToken(refreshToken);

        String rateLimitKey = "refresh:user:" + userId;
        Long refreshCount = redisTemplate.opsForValue().increment(rateLimitKey);
        if (refreshCount != null && refreshCount == 1) {
            redisTemplate.expire(rateLimitKey, 60, java.util.concurrent.TimeUnit.SECONDS);
        }
        if (refreshCount != null && refreshCount > 5) {
            log.warn("Refresh rate limit exceeded for user: {}", userId);
            throw new RateLimitExceededException("Too many refresh attempts. Please log in again.");
        }

        String tokenHash = hashToken(refreshToken);
        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Refresh token reuse detected - revoking all tokens for user: {}", userId);
                    refreshTokenRepository.deleteByUserId(userId);
                    return new IllegalArgumentException("Invalid refresh token");
                });

        if (storedToken.isExpired()) {
            refreshTokenRepository.delete(storedToken);
            throw new IllegalArgumentException("Refresh token expired");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (user.isLocked()) {
            refreshTokenRepository.delete(storedToken);
            log.warn("Refresh token rejected for locked user: {}", userId);
            throw new IllegalArgumentException("Account is temporarily locked");
        }

        String tokenEmail = jwtTokenProvider.getEmailFromRefreshToken(refreshToken);
        long tokenPwdUpdatedAt = jwtTokenProvider.getPasswordUpdatedAtFromRefreshToken(refreshToken);
        long currentPwdUpdatedAt = user.getPasswordUpdatedAt().toEpochSecond(ZoneOffset.UTC);

        if (!tokenEmail.equals(user.getEmail()) || tokenPwdUpdatedAt != currentPwdUpdatedAt) {
            refreshTokenRepository.delete(storedToken);
            log.warn("Refresh token claim mismatch for user: {} (email changed or password reset)", userId);
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String deviceId = storedToken.getDeviceId();
        AuthResponse response = generateAuthResponse(user, deviceId);
        refreshTokenRepository.delete(storedToken);

        return response;
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
                String rateLimitKey = "logout:refresh:" + tokenHash;
                Long count = redisTemplate.opsForValue().increment(rateLimitKey);
                if (count != null && count == 1) {
                    redisTemplate.expire(rateLimitKey, 300, java.util.concurrent.TimeUnit.SECONDS);
                }
                if (count != null && count > 3) {
                    log.warn("Logout rate limit exceeded for refresh token");
                    throw new RateLimitExceededException("Too many logout attempts. Please try again later.");
                }
                refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token ->
                    refreshTokenRepository.delete(token)
                );
            }
        } catch (RateLimitExceededException e) {
            throw e;
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
            String newEncryptionSalt,
            String clientIp,
            String userAgent) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isLocked()) {
            log.warn("Account locked for user: {}", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordService.constantTimeEquals(serverSideHash(currentAuthHash, user.getPasswordSalt()), user.getPasswordHash())) {
            String failKey = "changepw:fail:" + userId;
            Long failCount = redisTemplate.opsForValue().increment(failKey);
            if (failCount != null && failCount == 1) {
                redisTemplate.expire(failKey, 60, java.util.concurrent.TimeUnit.SECONDS);
            }
            log.warn("Change-password failure {} for user: {}", failCount, userId);
            self.recordFailedChangePasswordAttempt(userId, clientIp, userAgent);
            if (failCount != null && failCount >= MAX_FAILED_ATTEMPTS) {
                log.warn("Account locked for user: {} due to {} failed change-password attempts", userId, MAX_FAILED_ATTEMPTS);
            }
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
        if (user.getKdfIterations() == null) {
            user.setKdfIterations(com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS);
            user.setKdfMemory(com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY);
            user.setKdfParallelism(com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM);
        }
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

    @Transactional
    public void upgradeKdf(UUID userId, com.securevault.dto.UpgradeKdfRequest request) {
        String rateLimitKey = "upgrade-kdf:user:" + userId;
        Long count = redisTemplate.opsForValue().increment(rateLimitKey);
        if (count != null && count == 1) {
            redisTemplate.expire(rateLimitKey, 300, java.util.concurrent.TimeUnit.SECONDS);
        }
        if (count != null && count > 1) {
            log.warn("KDF upgrade rate limit exceeded for user: {}", userId);
            throw new RateLimitExceededException("KDF upgrade can only be performed once every 5 minutes.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isLocked()) {
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        String newSalt = generateSalt();
        String newServerHash = serverSideHash(request.getAuthHash(), newSalt);

        user.setPasswordHash(newServerHash);
        user.setPasswordSalt(newSalt);
        user.setWrappedVaultKey(request.getWrappedVaultKey());
        user.setKdfIterations(request.getKdfIterations());
        user.setKdfMemory(request.getKdfMemory());
        user.setKdfParallelism(request.getKdfParallelism());
        user.setEncryptionVersion(com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION);
        user.setPasswordUpdatedAt(LocalDateTime.now());

        userRepository.save(user);
        log.info("KDF parameters upgraded in background for user: {}", user.getEmail());
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

    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        int at = email.indexOf('@');
        if (at <= 1) return email.charAt(0) + "***";
        return email.charAt(0) + "***" + email.substring(at);
    }

    @Transactional
    public void verifyPassword(UUID userId, String authHash) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isLocked()) {
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordService.constantTimeEquals(
                serverSideHash(authHash, user.getPasswordSalt()),
                user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid password");
        }
    }

    private String serverSideHash(String clientAuthHash, String userSalt) {
        try {
            String combinedSalt = serverHashSecret + ":" + userSalt;
            byte[] salt = combinedSalt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            KeySpec spec = new PBEKeySpec(clientAuthHash.toCharArray(), salt, pbkdf2Iterations, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute server-side auth hash", e);
        }
    }

    private void handleFailedLogin(User user, String clientIp, String userAgent) {
        if (user.getLockedUntil() != null && !user.isLocked()) {
            user.resetFailedAttempts();
        }
        user.incrementFailedAttempts();
        log.warn("Failed login attempt {} for user: {}", user.getFailedLoginAttempts(), user.getEmail());

        auditService.logFailedLogin(user.getEmail(), clientIp, userAgent);

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.lockAccount(LOCKOUT_MINUTES);
            refreshTokenRepository.deleteByUserId(user.getId());
            log.warn("Account locked for user: {} due to {} failed attempts. Refresh tokens revoked.", user.getEmail(), MAX_FAILED_ATTEMPTS);
        }

        userRepository.save(user);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailedChangePasswordAttempt(UUID userId, String clientIp, String userAgent) {
        User user = userRepository.findById(userId).orElse(null);
        if (user != null) {
            handleFailedLogin(user, clientIp, userAgent);
        }
    }

    private AuthResponse generateAuthResponse(User user, String deviceId) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());

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
                user.getAuthSalt(),
                user.getEncryptionSalt(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION,
                user.getKdfIterations() != null ? user.getKdfIterations() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS,
                user.getKdfMemory() != null ? user.getKdfMemory() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY,
                user.getKdfParallelism() != null ? user.getKdfParallelism() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM
        );
    }

    private ChangePasswordResponse generateChangePasswordResponse(User user, String deviceId) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId(), user.getEmail(), user.getPasswordUpdatedAt());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setTokenHash(hashToken(refreshToken));
        token.setDeviceId(deviceId);
        token.setExpiresAt(calculateRefreshTokenExpiry());
        refreshTokenRepository.save(token);

        return new ChangePasswordResponse(
                accessToken,
                refreshToken,
                user.getAuthSalt(),
                user.getEncryptionSalt(),
                user.getId().toString(),
                user.getEmail(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : com.securevault.config.EncryptionConstants.CURRENT_ENCRYPTION_VERSION,
                user.getKdfIterations() != null ? user.getKdfIterations() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS,
                user.getKdfMemory() != null ? user.getKdfMemory() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY,
                user.getKdfParallelism() != null ? user.getKdfParallelism() : com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM
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