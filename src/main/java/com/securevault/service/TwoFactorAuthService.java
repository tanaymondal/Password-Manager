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
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final SystemTimeProvider timeProvider = new SystemTimeProvider();
    private final DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public TwoFactorSetupResponse generateSetupSecret(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String secret = secretGenerator.generate();

        String qrCodeUrl = "otpauth://totp/SecureVault:" + user.getEmail() +
                "?secret=" + secret +
                "&issuer=SecureVault";

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

    public void enable2FA(UUID userId, String secret, String code) {
        if (!verifyCode(userId, code)) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    public void disable2FA(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setTwoFactorSecret(null);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

    public boolean is2FAEnabled(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return user.getTwoFactorEnabled();
    }
}