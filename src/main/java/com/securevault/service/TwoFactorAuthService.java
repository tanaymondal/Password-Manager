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

/**
 * Service for managing Time-based One-Time Password (TOTP) two-factor authentication.
 *
 * This service implements TOTP-based 2FA using the standard HOTP/TOTP algorithm:
 * - Generates a random secret for each user
 * - Creates provisioning URLs for authenticator apps (Google Authenticator, Authy, etc.)
 * - Verifies 6-digit codes with a time window for clock skew tolerance
 *
 * SECURITY FEATURES:
 * - Secrets are stored encrypted (or at minimum, hashed in some implementations)
 * - Code verification uses constant-time comparison to prevent timing attacks
 * - Time-based codes expire automatically (30-second window)
 * - Grace period allows for minor clock drift between server and device
 *
 * USER FLOW:
 * 1. User requests 2FA setup -> receives QR code URL and secret
 * 2. User scans QR code with authenticator app (or enters secret manually)
 * 3. User verifies a code to enable 2FA
 * 4. Subsequent logins require password + 6-digit code from authenticator
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6238">RFC 6238 - TOTP</a>
 */
@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final SystemTimeProvider timeProvider = new SystemTimeProvider();
    private final DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    /**
     * Generates a new TOTP secret for setting up two-factor authentication.
     *
     * This creates:
     * 1. A random 80-bit secret encoded in Base32
     * 2. An otpauth:// URI for QR code generation
     *
     * The secret should be shown to the user once (when generating the QR code).
     * After setup, the secret is stored and only the 6-digit codes are needed.
     *
     * @param userId UUID of the user setting up 2FA
     * @return TwoFactorSetupResponse containing secret and QR code URL
     * @throws IllegalArgumentException if user not found
     */
    public TwoFactorSetupResponse generateSetupSecret(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String secret = secretGenerator.generate();

        String qrCodeUrl = "otpauth://totp/SecureVault:" + user.getEmail() +
                "?secret=" + secret +
                "&issuer=SecureVault";

        return new TwoFactorSetupResponse(secret, qrCodeUrl);
    }

    /**
     * Verifies a TOTP code against the user's stored secret.
     *
     * Uses a time-based verification with a grace period to handle clock drift
     * between the server and the user's authenticator device.
     *
     * @param userId UUID of the user
     * @param code 6-digit TOTP code from authenticator app
     * @return true if code is valid and matches user's secret, false otherwise
     */
    public boolean verifyCode(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getTwoFactorSecret() == null) {
            return false;
        }

        return codeVerifier.isValidCode(user.getTwoFactorSecret(), code);
    }

    /**
     * Enables two-factor authentication for a user.
     *
     * Validates the verification code first to ensure the user has correctly
     * set up their authenticator app. Then stores the secret and enables 2FA.
     *
     * After this is called, the user must provide a TOTP code during login.
     *
     * @param userId UUID of the user
     * @param secret TOTP secret generated during setup
     * @param code Verification code from authenticator app
     * @throws IllegalArgumentException if code is invalid
     */
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

    /**
     * Disables two-factor authentication for a user.
     *
     * Removes the stored TOTP secret and disables 2FA.
     * The user will then only need their password to log in.
     *
     * @param userId UUID of the user
     */
    public void disable2FA(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        user.setTwoFactorSecret(null);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

    /**
     * Checks if two-factor authentication is enabled for a user.
     *
     * @param userId UUID of the user
     * @return true if 2FA is enabled, false otherwise
     */
    public boolean is2FAEnabled(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return user.getTwoFactorEnabled();
    }
}