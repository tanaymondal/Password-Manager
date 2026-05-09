package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.RegisterRequest;
import com.securevault.entity.PasswordHistory;
import com.securevault.entity.RefreshToken;
import com.securevault.entity.User;
import com.securevault.repository.PasswordHistoryRepository;
import com.securevault.repository.RefreshTokenRepository;
import com.securevault.repository.UserRepository;
import com.securevault.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;
    private static final int PASSWORD_HISTORY_LIMIT = 5;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordService passwordService;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already in use");
        }

        int strength = passwordService.calculatePasswordStrength(request.getPassword());
        if (strength < 4) {
            throw new IllegalArgumentException("Password is too weak. Use at least 8 characters with mixed case, numbers, and symbols.");
        }

        String authSalt = passwordService.generateAuthSalt();
        String encryptionSalt = passwordService.generateEncryptionSalt();
        String passwordHash = passwordService.hashPasswordForAuthentication(request.getPassword(), authSalt);

        User user = new User();
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(passwordHash);
        user.setPasswordSalt(authSalt);
        user.setEncryptionSalt(encryptionSalt);
        user.setTwoFactorEnabled(false);
        user.setFailedLoginAttempts(0);

        user = userRepository.save(user);

        savePasswordHistory(user.getId(), passwordHash);

        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (user.isLocked()) {
            log.warn("Account locked for user: {}", user.getEmail());
            throw new BadCredentialsException("Account is temporarily locked. Please try again later.");
        }

        if (!passwordService.verifyPassword(request.getPassword(), user.getPasswordSalt(), user.getPasswordHash())) {
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        if (user.getTwoFactorEnabled()) {
            log.info("2FA required for user: {}", user.getEmail());
        }

        user.resetFailedAttempts();
        userRepository.save(user);

        log.info("User logged in successfully: {}", user.getEmail());
        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
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
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordService.verifyPassword(currentPassword, user.getPasswordSalt(), user.getPasswordHash())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        int strength = passwordService.calculatePasswordStrength(newPassword);
        if (strength < 4) {
            throw new IllegalArgumentException("New password is too weak");
        }

        List<PasswordHistory> recentPasswords = passwordHistoryRepository.findRecentPasswords(userId, PASSWORD_HISTORY_LIMIT);
        String newPasswordHash = passwordService.hashPasswordForAuthentication(newPassword, user.getPasswordSalt());
        for (PasswordHistory history : recentPasswords) {
            if (passwordService.verifyPassword(newPassword, user.getPasswordSalt(), history.getPasswordHash())) {
                throw new IllegalArgumentException("Password was used recently. Please choose a different password.");
            }
        }

        String newAuthSalt = passwordService.generateAuthSalt();
        String newEncryptionSalt = passwordService.generateEncryptionSalt();
        String hashedPassword = passwordService.hashPasswordForAuthentication(newPassword, newAuthSalt);

        user.setPasswordHash(hashedPassword);
        user.setPasswordSalt(newAuthSalt);
        user.setEncryptionSalt(newEncryptionSalt);
        user.setPasswordUpdatedAt(LocalDateTime.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);

        userRepository.save(user);
        savePasswordHistory(userId, hashedPassword);

        refreshTokenRepository.deleteByUserId(userId);

        log.info("Password changed for user: {}", user.getEmail());
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

    private void savePasswordHistory(UUID userId, String passwordHash) {
        List<PasswordHistory> history = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId);
        while (history.size() >= PASSWORD_HISTORY_LIMIT) {
            PasswordHistory oldest = history.get(history.size() - 1);
            passwordHistoryRepository.delete(oldest);
            history.remove(history.size() - 1);
        }

        PasswordHistory newEntry = new PasswordHistory();
        newEntry.setUserId(userId);
        newEntry.setPasswordHash(passwordHash);
        passwordHistoryRepository.save(newEntry);
    }

    private AuthResponse generateAuthResponse(User user) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(1));
        refreshTokenRepository.save(token);

        return new AuthResponse(
                accessToken,
                refreshToken,
                user.getId().toString(),
                user.getEmail(),
                user.getEncryptionSalt()
        );
    }
}