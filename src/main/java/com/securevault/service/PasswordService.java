package com.securevault.service;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class PasswordService {

    private static final int SALT_LENGTH = 32;
    private static final int AUTH_HASH_LENGTH = 32;
    private static final int KEY_LENGTH = 32;

    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 4;

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String generateAuthSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String generateEncryptionSalt() {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

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
        byte[] passwordBytes = password.getBytes();
        generator.generateBytes(passwordBytes, hash);

        return Base64.getEncoder().encodeToString(hash);
    }

    public boolean verifyPassword(String password, String salt, String hash) {
        String computedHash = hashPasswordForAuthentication(password, salt);
        return constantTimeEquals(computedHash, hash);
    }

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
        byte[] passwordBytes = masterPassword.getBytes();
        generator.generateBytes(passwordBytes, key);

        return Base64.getEncoder().encodeToString(key);
    }

    public boolean verifyMasterKey(String masterPassword, String salt, String storedKeyHash) {
        String derivedKey = deriveMasterKey(masterPassword, salt);
        return constantTimeEquals(derivedKey, storedKeyHash);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] aBytes = a.getBytes();
        byte[] bBytes = b.getBytes();

        if (aBytes.length != bBytes.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

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