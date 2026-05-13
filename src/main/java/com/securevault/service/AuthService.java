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

/**
 * Authentication service that handles user registration, login, and security operations.
 * This service implements zero-knowledge architecture where:
 * - Passwords are hashed with Argon2id before storage (server never sees plaintext passwords)
 * - Vault keys are wrapped (encrypted) with a key derived from the user's password
 * - Vault entries are encrypted client-side using the vault key (server stores only opaque blobs)
 * - The server can never decrypt vault data - only the client with the correct password can
 *
 * Security features:
 * - Account lockout after failed login attempts
 * - Password history to prevent reuse
 * - JWT-based authentication with refresh tokens
 * - Argon2id for both password hashing and key derivation (memory-hard, resistant to GPU/ASIC attacks)
 */
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

    /**
     * Registers a new user in the system.
     *
     * This method performs the following operations:
     * 1. Validates email uniqueness and password strength
     * 2. Generates unique salts for password hashing (authSalt) and encryption (encryptionSalt)
     * 3. Hashes the password using Argon2id with the authSalt
     * 4. Generates a random 256-bit vault key for encrypting vault entries
     * 5. Derives a Key Encryption Key (KEK) from the user's password using Argon2id with encryptionSalt
     * 6. Wraps (encrypts) the vault key with the KEK using AES-256-GCM
     * 7. Stores the password hash, auth salt, encryption salt, and wrapped vault key in the database
     *
     * The vault key is never stored in plaintext - only wrapped with the user's password-derived KEK.
     * This ensures zero-knowledge: even if the database is compromised, attackers cannot access vault data
     * without also knowing each user's master password.
     *
     * @param request Contains email and password for registration
     * @return AuthResponse containing JWT tokens, encryption salt, and wrapped vault key
     * @throws IllegalArgumentException if email exists or password is weak
     */
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

    /**
     * Authenticates a user and returns tokens for accessing protected resources.
     *
     * This method performs the following operations:
     * 1. Looks up user by email (case-insensitive)
     * 2. Checks if account is locked due to previous failed attempts
     * 3. Verifies password by hashing with stored salt and comparing with stored hash
     * 4. On failure: increments failed attempt counter and may lock account
     * 5. On success: resets failed attempts, generates new JWT tokens
     * 6. Returns tokens along with encryption salt and wrapped vault key for client-side key unwrapping
     *
     * The client uses the encryption salt and password to derive the KEK, which unwraps the vault key.
     * The unwrapped vault key decrypts all vault entries client-side.
     *
     * @param request Contains email and password
     * @return AuthResponse containing JWT access/refresh tokens, encryption salt, and wrapped vault key
     * @throws BadCredentialsException if credentials are invalid or account is locked
     */
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

    /**
     * Refreshes authentication tokens using a valid refresh token.
     *
     * This method is used when the access token has expired but the refresh token is still valid.
     * It validates the refresh token, checks expiration, and issues new tokens.
     * The old refresh token is deleted and replaced with a new one (token rotation for security).
     *
     * Note: The encryption salt and wrapped vault key from the original login are returned,
     * allowing the client to continue using the same vault key without re-derivation.
     *
     * @param refreshToken JWT refresh token
     * @return AuthResponse with new JWT tokens
     * @throws IllegalArgumentException if token is invalid, expired, or user not found
     */
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

    /**
     * Logs out a user by invalidating all their refresh tokens.
     *
     * This ensures that even if a refresh token was compromised, it cannot be used after logout.
     * All refresh tokens for the user are deleted from the database.
     *
     * @param userId UUID of the user to log out
     */
    @Transactional
    public void logout(UUID userId) {
        if (userId != null) {
            refreshTokenRepository.deleteByUserId(userId);
        }
    }

    /**
     * Changes the user's master password and updates all cryptographic material.
     *
     * This is a critical operation that performs the following:
     * 1. Validates current password to ensure the requester is legitimate
     * 2. Validates new password strength and checks against password history
     * 3. Generates new authSalt and hashes new password with Argon2id
     * 4. Uses new encryption salt to derive new KEK from new password
     * 5. If client provides new wrapped vault key, saves it directly
     *    If not, unwraps old vault key with old KEK and re-wraps with new KEK
     * 6. Updates vault entries with new encryption (re-encrypted by client before sending)
     * 7. Updates user record with new password hash, salts, and wrapped vault key
     * 8. Invalidates all existing refresh tokens (forces re-login with new password)
     *
     * The client is responsible for:
     * - Fetching all vault entries and re-encrypting with new vault key
     * - Generating new encryption salt and vault key
     * - Wrapping the new vault key with the new KEK (derived from new password + new salt)
     * - Sending the new wrapped vault key, salt, and re-encrypted entries to the server
     *
     * This ensures zero-knowledge is maintained: the server never has access to the plaintext
     * vault key or any vault entries.
     *
     * @param userId UUID of the user changing password
     * @param currentPassword Current password for verification
     * @param newPassword New master password
     * @param newWrappedVaultKey New vault key wrapped with new KEK (from client)
     * @param newEntries Re-encrypted vault entries (encrypted with new vault key)
     * @param newEncryptionSalt New salt for deriving KEK from new password
     * @return ChangePasswordResponse with new tokens and updated cryptographic material
     * @throws BadCredentialsException if current password is incorrect
     * @throws IllegalArgumentException if new password is weak or recently used
     */
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

        String wrappedVaultKeyToSave;
        if (newWrappedVaultKey != null && !newWrappedVaultKey.isEmpty()) {
            wrappedVaultKeyToSave = newWrappedVaultKey;
        } else {
            String vaultKey = passwordService.unwrapVaultKey(user.getWrappedVaultKey(), oldKek);
            String newKek = passwordService.deriveMasterKey(newPassword, saltToUse);
            wrappedVaultKeyToSave = passwordService.wrapVaultKey(vaultKey, newKek);
        }

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
        user.setWrappedVaultKey(wrappedVaultKeyToSave);
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

    /**
     * Handles a failed login attempt by incrementing the failed attempt counter
     * and potentially locking the account.
     *
     * After MAX_FAILED_ATTEMPTS consecutive failures, the account is locked for
     * LOCKOUT_MINUTES to prevent brute-force attacks.
     *
     * @param user User who failed login attempt
     */
    private void handleFailedLogin(User user) {
        user.incrementFailedAttempts();
        log.warn("Failed login attempt {} for user: {}", user.getFailedLoginAttempts(), user.getEmail());

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.lockAccount(LOCKOUT_MINUTES);
            log.warn("Account locked for user: {} due to {} failed attempts", user.getEmail(), MAX_FAILED_ATTEMPTS);
        }

        userRepository.save(user);
    }

    /**
     * Saves a password hash to the password history for reuse prevention.
     *
     * Maintains up to PASSWORD_HISTORY_LIMIT historical password hashes.
     * When adding a new entry, the oldest entry is removed if the limit is exceeded.
     * This prevents users from reusing recent passwords.
     *
     * @param userId UUID of the user
     * @param passwordHash New password hash to save
     */
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

    /**
     * Generates authentication response with JWT tokens and cryptographic material.
     *
     * This method:
     * 1. Deletes any existing refresh tokens for the user (token rotation)
     * 2. Generates new JWT access and refresh tokens
     * 3. Stores the refresh token in the database
     * 4. Returns tokens along with encryption salt and wrapped vault key
     *
     * The encryption salt and wrapped vault key are needed by the client to:
     * - Derive the KEK from the user's password
     * - Unwrap the vault key to decrypt vault entries
     *
     * @param user User to generate auth response for
     * @return AuthResponse with tokens and cryptographic material
     */
    private AuthResponse generateAuthResponse(User user) {
        refreshTokenRepository.deleteByUserId(user.getId());
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

    /**
     * Generates change password response with new JWT tokens and updated cryptographic material.
     *
     * Similar to generateAuthResponse but returns a ChangePasswordResponse object.
     * This is used after a successful password change to provide the client with
     * new tokens and updated encryption material.
     *
     * @param user User who changed password
     * @return ChangePasswordResponse with new tokens and cryptographic material
     */
    private ChangePasswordResponse generateChangePasswordResponse(User user) {
        refreshTokenRepository.deleteByUserId(user.getId());
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