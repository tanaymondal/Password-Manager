package com.securevault.service;

import com.securevault.dto.TwoFactorSetupResponse;
import com.securevault.entity.User;
import com.securevault.repository.UserRepository;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private static final long PENDING_SETUP_TTL_SECONDS = 600;
    private static final String KEY_PREFIX = "2fa_setup:";
    private static final int MAX_TOTP_ATTEMPTS = 5;
    private static final long TOTP_ATTEMPT_WINDOW_MINUTES = 5;

    private final UserRepository userRepository;
    private final StringRedisTemplate redisTemplate;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final SystemTimeProvider timeProvider = new SystemTimeProvider();
    private final DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA256, 6);
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public TwoFactorSetupResponse generateSetupSecret(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getTwoFactorEnabled()) {
            throw new IllegalArgumentException("2FA is already enabled. Disable it first to generate a new setup.");
        }

        String key = KEY_PREFIX + userId;
        redisTemplate.delete(key);

        String secret = secretGenerator.generate();
        redisTemplate.opsForHash().put(key, "secret", secret);
        redisTemplate.opsForHash().put(key, "createdAt", String.valueOf(Instant.now().toEpochMilli()));
        redisTemplate.expire(key, PENDING_SETUP_TTL_SECONDS, TimeUnit.SECONDS);

        String qrCodeUrl = "otpauth://totp/SecureVault:" + user.getEmail() +
                "?secret=" + secret +
                "&issuer=SecureVault" +
                "&algorithm=SHA256";

        return new TwoFactorSetupResponse(secret, qrCodeUrl);
    }

    public boolean verifyCode(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getTwoFactorSecret() == null) {
            return false;
        }

        return codeVerifier.isValidCode(user.getTwoFactorSecret(), code);
    }

    public void enable2FA(UUID userId, String code, String secondCode) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String key = KEY_PREFIX + userId;
        String pendingSecret = (String) redisTemplate.opsForHash().get(key, "secret");
        if (pendingSecret == null) {
            throw new IllegalArgumentException("2FA setup not started. Call generateSetupSecret first.");
        }

        checkTOTPActionRateLimit(userId, "enable");
        if (!codeVerifier.isValidCode(pendingSecret, code)) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        if (secondCode != null && !secondCode.isEmpty() && !secondCode.equals(code)) {
            if (!codeVerifier.isValidCode(pendingSecret, secondCode)) {
                throw new IllegalArgumentException("Invalid second verification code");
            }
        }

        user.setTwoFactorSecret(pendingSecret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        redisTemplate.delete(key);
    }

    public void disable2FA(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getTwoFactorEnabled()) {
            throw new IllegalArgumentException("2FA is not enabled");
        }

        checkTOTPActionRateLimit(userId, "disable");
        if (!codeVerifier.isValidCode(user.getTwoFactorSecret(), code)) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        user.setTwoFactorSecret(null);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

    public boolean is2FAEnabled(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return user.getTwoFactorEnabled();
    }

    private void checkTOTPActionRateLimit(UUID userId, String action) {
        String key = "totp_action:" + userId + ":" + action;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, TOTP_ATTEMPT_WINDOW_MINUTES, TimeUnit.MINUTES);
        }
        if (count != null && count > MAX_TOTP_ATTEMPTS) {
            log.warn("TOTP action '{}' rate limited for user: {}", action, userId);
            throw new IllegalArgumentException("Too many attempts. Please try again later.");
        }
    }
}