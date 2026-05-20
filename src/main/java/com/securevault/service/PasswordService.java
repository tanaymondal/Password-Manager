package com.securevault.service;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cryptographic service providing password hashing, key derivation, and vault key management.
 *
 * This service implements the cryptographic operations required for zero-knowledge password management:
 *
 * KEY DERIVATION (Argon2id):
 * - Uses Argon2id (memory-hard, GPU/ASIC resistant) to derive keys from passwords
 * - Two types of salts are used:
 *   1. authSalt: For password hashing (stored in DB, used for login verification)
 *   2. encryptionSalt: For deriving the Key Encryption Key (KEK) for vault key wrapping
 * - Parameters: 3 iterations, 64MB memory, 4 parallelism (balanced security/performance)
 *
 * VAULT KEY MANAGEMENT:
 * - Vault Key: Random 256-bit key used to encrypt all vault entries
 * - KEK (Key Encryption Key): Derived from user's password + encryptionSalt using Argon2id
 * - Wrapping: Vault key is encrypted (wrapped) with KEK using AES-256-GCM for storage
 * - This two-layer approach means the vault key is never stored in plaintext
 *
 * ENCRYPTION:
 * - All vault data is encrypted with AES-256-GCM (Authenticated Encryption)
 * - Each encryption uses a random 96-bit IV (Initialization Vector)
 * - GCM provides both confidentiality and integrity (tamper detection)
 *
 * ZERO-KNOWLEDGE ARCHITECTURE:
 * - Server stores: password hash, salts, wrapped vault key, encrypted vault entries
 * - Server CANNOT decrypt vault entries (no access to plaintext vault key)
 * - Client derives KEK from password -> unwraps vault key -> decrypts entries
 */
@Service
public class PasswordService {

    private static final int SALT_LENGTH = 32;
    private static final int AUTH_HASH_LENGTH = 32;
    private static final int KEY_LENGTH = 32;
    private static final int VAULT_KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private static final int ITERATIONS = 4;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 4;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a cryptographically secure random salt for general use.
     *
     * @return Base64-encoded random salt (32 bytes)
     */
    public String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Generates a random salt for password hashing (authentication).
     *
     * Uses a shorter salt (16 bytes) for password hashing since Argon2id
     * includes built-in protection against precomputation attacks.
     *
     * @return Base64-encoded 16-byte salt
     */
    public String generateAuthSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Generates a random salt for encryption key derivation.
     *
     * This salt is used to derive the Key Encryption Key (KEK) from the user's password.
     * A new salt is generated for each user and when passwords are changed.
     * The salt is stored alongside the wrapped vault key and sent to clients.
     *
     * @return Base64-encoded 16-byte encryption salt
     */
    public String generateEncryptionSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Generates a random 256-bit vault key for encrypting vault entries.
     *
     * This key is the core encryption key that protects all user data.
     * It's randomly generated and wrapped with the user's KEK before storage.
     * The plaintext key never leaves the client.
     *
     * @return Base64-encoded 32-byte random vault key
     */
    public String generateVaultKey() {
        byte[] key = new byte[VAULT_KEY_LENGTH];
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * Hashes a password using Argon2id for secure storage and verification.
     *
     * Argon2id is a memory-hard password hashing function resistant to:
     * - GPU acceleration (due to memory requirements)
     * - ASIC attacks (due to memory hardness and parallelism)
     * - Rainbow tables (due to unique salt per hash)
     *
     * The hash is deterministic for the same password + salt combination,
     * allowing verification by re-hashing and comparing.
     *
     * @param password Plaintext password to hash
     * @param salt Base64-encoded salt (should be unique per user)
     * @return Base64-encoded password hash (32 bytes)
     */
    public String hashPasswordForAuthentication(String password, String salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(Base64.getDecoder().decode(salt))
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] hash = new byte[AUTH_HASH_LENGTH];
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        generator.generateBytes(passwordBytes, hash);

        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Verifies a password against a stored hash using constant-time comparison.
     *
     * This prevents timing attacks where an attacker could determine which
     * password characters are correct by measuring response times.
     *
     * @param password Plaintext password to verify
     * @param salt Salt used when hash was created
     * @param hash Stored hash to compare against
     * @return true if password matches, false otherwise
     */
    public boolean verifyPassword(String password, String salt, String hash) {
        String computedHash = hashPasswordForAuthentication(password, salt);
        return constantTimeEquals(computedHash, hash);
    }

    /**
     * Derives a master key (KEK) from a password using Argon2id.
     *
     * This function is used to derive the Key Encryption Key (KEK) that wraps
     * the vault key. The same password + salt always produces the same KEK,
     * allowing the client to unwrap the vault key on subsequent logins.
     *
     * @param masterPassword User's master password
     * @param encryptionSalt Base64-encoded salt (stored in DB, sent to client)
     * @return Base64-encoded derived key (32 bytes)
     */
    public String deriveMasterKey(String masterPassword, String encryptionSalt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(Base64.getDecoder().decode(encryptionSalt))
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] key = new byte[KEY_LENGTH];
        byte[] passwordBytes = masterPassword.getBytes(StandardCharsets.UTF_8);
        generator.generateBytes(passwordBytes, key);

        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * Verifies a master key against a stored key hash.
     *
     * Used internally to validate that derived keys match expected values.
     * Not used in current implementation but available for future enhancements.
     *
     * @param masterPassword Password to verify
     * @param salt Encryption salt used in derivation
     * @param storedKeyHash Expected derived key hash
     * @return true if key matches, false otherwise
     */
    public boolean verifyMasterKey(String masterPassword, String salt, String storedKeyHash) {
        String derivedKey = deriveMasterKey(masterPassword, salt);
        return constantTimeEquals(derivedKey, storedKeyHash);
    }

    /**
     * Wraps (encrypts) a vault key with a Key Encryption Key using AES-256-GCM.
     *
     * The vault key is encrypted to protect it during storage. Only someone
     * with the KEK (derived from the master password) can unwrap and use it.
     *
     * Format: [12-byte IV][encrypted vault key with 16-byte auth tag]
     *
     * @param vaultKey Plaintext vault key to encrypt (Base64-encoded)
     * @param kek Key Encryption Key (Base64-encoded, derived from password)
     * @return Base64-encoded wrapped vault key (IV + ciphertext)
     * @throws RuntimeException if encryption fails
     */
    public String wrapVaultKey(String vaultKey, String kek) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(vaultKey);
            byte[] kekBytes = Base64.getDecoder().decode(kek);

            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            SecretKey secretKey = new SecretKeySpec(kekBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            byte[] encrypted = cipher.doFinal(keyBytes);

            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Failed to wrap vault key", e);
        }
    }

    /**
     * Unwraps (decrypts) a vault key using the Key Encryption Key.
     *
     * Reverses the wrapVaultKey operation to recover the plaintext vault key.
     * The KEK is derived from the user's password, so only the legitimate user
     * can unwrap their vault key.
     *
     * @param wrappedKey Base64-encoded wrapped vault key (IV + ciphertext)
     * @param kek Key Encryption Key (Base64-encoded, derived from password)
     * @return Base64-encoded plaintext vault key
     * @throws RuntimeException if decryption fails (wrong key or corrupted data)
     */
    public String unwrapVaultKey(String wrappedKey, String kek) {
        try {
            byte[] combined = Base64.getDecoder().decode(wrappedKey);
            byte[] kekBytes = Base64.getDecoder().decode(kek);

            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

            SecretKey secretKey = new SecretKeySpec(kekBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return Base64.getEncoder().encodeToString(decrypted);
        } catch (Exception e) {
            throw new RuntimeException("Failed to unwrap vault key", e);
        }
    }

    /**
     * Derives a Key Encryption Key (KEK) from password and encryption salt.
     *
     * This is an alias for deriveMasterKey for semantic clarity in the codebase.
     * The KEK is used to wrap/unwrap the vault key, not to encrypt vault data directly.
     *
     * @param password User's master password
     * @param encryptionSalt Base64-encoded salt
     * @return Base64-encoded KEK (32 bytes)
     */
    public String deriveKek(String password, String encryptionSalt) {
        return deriveMasterKey(password, encryptionSalt);
    }

    /**
     * Performs constant-time comparison of two strings to prevent timing attacks.
     *
     * Standard string comparison exits early on first mismatch, leaking information
     * about how many characters matched. This function takes the same time regardless
     * of where the mismatch occurs, preventing such attacks.
     *
     * @param a First string to compare
     * @param b Second string to compare
     * @return true if strings are equal, false otherwise
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);

        if (aBytes.length != bBytes.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

    /**
     * Calculates password strength on a scale of 0-10.
     *
     * Factors considered:
     * - Length: +1 for 8+, +1 for 12+, +1 for 16+ characters
     * - Character diversity: +1 each for lowercase, uppercase, digits, symbols
     * - Weak patterns: -2 for common words like "password", "123456"
     *
     * A score of 4+ is required for new passwords (8+ characters with good diversity).
     *
     * @param password Password to evaluate
     * @return Strength score from 0 (weakest) to 10 (strongest)
     */
    public int calculatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return 0;
        }

        int score = 0;

        if (password.length() >= 8) score += 1;
        if (password.length() >= 12) score += 1;
        if (password.length() >= 16) score += 1;

        if (password.chars().anyMatch(Character::isLowerCase)) score += 1;
        if (password.chars().anyMatch(Character::isUpperCase)) score += 1;
        if (password.chars().anyMatch(Character::isDigit)) score += 1;
        if (password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) score += 1;

        if (password.toLowerCase().contains("password")) score -= 2;
        if (password.toLowerCase().contains("123456")) score -= 2;

        return Math.max(0, Math.min(10, score));
    }
}