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
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private static final long PENDING_SETUP_TTL_SECONDS = 600;

    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final SystemTimeProvider timeProvider = new SystemTimeProvider();
    private final DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA256, 6);
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    private final Map<UUID, PendingSetup> pendingSetups = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupScheduler = Executors.newSingleThreadScheduledExecutor();

    @PostConstruct
    public void init() {
        cleanupScheduler.scheduleAtFixedRate(this::evictExpired, 60, 60, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void destroy() {
        cleanupScheduler.shutdownNow();
    }

    private void evictExpired() {
        Instant now = Instant.now();
        pendingSetups.entrySet().removeIf(entry ->
            now.isAfter(entry.getValue().createdAt().plusSeconds(PENDING_SETUP_TTL_SECONDS)));
    }

    public TwoFactorSetupResponse generateSetupSecret(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getTwoFactorEnabled()) {
            throw new IllegalArgumentException("2FA is already enabled. Disable it first to generate a new setup.");
        }

        String secret = secretGenerator.generate();
        pendingSetups.put(userId, new PendingSetup(secret, Instant.now()));

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

        PendingSetup pending = pendingSetups.get(userId);
        if (pending == null) {
            throw new IllegalArgumentException("2FA setup not started. Call generateSetupSecret first.");
        }

        if (!codeVerifier.isValidCode(pending.secret(), code)) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        if (secondCode != null && !secondCode.isEmpty() && !secondCode.equals(code)) {
            try {
                Thread.sleep(30000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (!codeVerifier.isValidCode(pending.secret(), secondCode)) {
                throw new IllegalArgumentException("Invalid second verification code");
            }
        }

        user.setTwoFactorSecret(pending.secret());
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        pendingSetups.remove(userId);
    }

    public void disable2FA(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getTwoFactorEnabled()) {
            throw new IllegalArgumentException("2FA is not enabled");
        }

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

    private record PendingSetup(String secret, Instant createdAt) {}
}