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

@Service
public class PasswordService {

    private static final int SALT_LENGTH = 32;
    private static final int AUTH_HASH_LENGTH = 32;
    private static final int KEY_LENGTH = 32;
    private static final int VAULT_KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

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

    public String generateVaultKey() {
        byte[] key = new byte[VAULT_KEY_LENGTH];
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
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
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
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
        byte[] passwordBytes = masterPassword.getBytes(StandardCharsets.UTF_8);
        generator.generateBytes(passwordBytes, key);

        return Base64.getEncoder().encodeToString(key);
    }

    public boolean verifyMasterKey(String masterPassword, String salt, String storedKeyHash) {
        String derivedKey = deriveMasterKey(masterPassword, salt);
        return constantTimeEquals(derivedKey, storedKeyHash);
    }

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

    public String deriveKek(String password, String encryptionSalt) {
        return deriveMasterKey(password, encryptionSalt);
    }

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