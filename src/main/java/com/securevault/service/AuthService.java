package com.securevault.service;

import com.securevault.dto.AuthResponse;
import com.securevault.dto.ChangePasswordResponse;
import com.securevault.dto.LoginRequest;
import com.securevault.dto.RegisterRequest;
import com.securevault.dto.VaultEntryRequest;
import com.securevault.entity.PasswordHistory;
import com.securevault.entity.RefreshToken;
import com.securevault.entity.User;
import com.securevault.entity.VaultEntry;
import com.securevault.repository.PasswordHistoryRepository;
import com.securevault.repository.RefreshTokenRepository;
import com.securevault.repository.UserRepository;
import com.securevault.repository.VaultEntryRepository;
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
    private final VaultEntryRepository vaultEntryRepository;
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

        String vaultKey = passwordService.generateVaultKey();
        String kek = passwordService.deriveKek(request.getPassword(), encryptionSalt);
        String wrappedVaultKey = passwordService.wrapVaultKey(vaultKey, kek);

        User user = new User();
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(passwordHash);
        user.setPasswordSalt(authSalt);
        user.setEncryptionSalt(encryptionSalt);
        user.setTwoFactorEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setWrappedVaultKey(wrappedVaultKey);
        user.setEncryptionVersion(2);

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
    public ChangePasswordResponse changePassword(UUID userId, String currentPassword, String newPassword, String newWrappedVaultKey, List<VaultEntryRequest> newEntries, String newEncryptionSalt) {
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
        String newAuthSalt = passwordService.generateAuthSalt();
        String newPasswordHash = passwordService.hashPasswordForAuthentication(newPassword, newAuthSalt);
        for (PasswordHistory history : recentPasswords) {
            if (passwordService.hashPasswordForAuthentication(newPassword, newAuthSalt).equals(history.getPasswordHash())) {
                throw new IllegalArgumentException("Password was used recently. Please choose a different password.");
            }
        }

        String oldEncryptionSalt = user.getEncryptionSalt();
        log.info("CHANGE PWD: oldSalt={}, newSaltFromClient={}", oldEncryptionSalt, newEncryptionSalt);
        String oldKek = passwordService.deriveMasterKey(currentPassword, oldEncryptionSalt);
        String saltToUse = (newEncryptionSalt != null && !newEncryptionSalt.isEmpty())
                ? newEncryptionSalt : passwordService.generateEncryptionSalt();
        log.info("CHANGE PWD: saltToUse={}", saltToUse);
        String newKek = passwordService.deriveMasterKey(newPassword, saltToUse);

        String vaultKey = passwordService.unwrapVaultKey(newWrappedVaultKey, oldKek);
        String rewrappedVaultKey = passwordService.wrapVaultKey(vaultKey, newKek);

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

        user.setPasswordHash(newPasswordHash);
        user.setPasswordSalt(newAuthSalt);
        user.setEncryptionSalt(saltToUse);
        user.setWrappedVaultKey(rewrappedVaultKey);
        user.setEncryptionVersion(2);
        user.setPasswordUpdatedAt(LocalDateTime.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);

        userRepository.save(user);
        savePasswordHistory(userId, newPasswordHash);

        refreshTokenRepository.deleteByUserId(userId);

        log.info("Password changed for user: {}", user.getEmail());
        return generateChangePasswordResponse(user);
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
                user.getEncryptionSalt(),
                user.getWrappedVaultKey(),
                user.getEncryptionVersion() != null ? user.getEncryptionVersion() : 2
        );
    }

    private ChangePasswordResponse generateChangePasswordResponse(User user) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        RefreshToken token = new RefreshToken();
        token.setUserId(user.getId());
        token.setToken(refreshToken);
        token.setExpiresAt(LocalDateTime.now().plusDays(1));
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
}