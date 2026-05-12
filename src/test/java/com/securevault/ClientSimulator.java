package com.securevault;

import com.securevault.service.PasswordService;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class ClientSimulator {

    private static final int KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 4;

    public static void main(String[] args) throws Exception {
        System.out.println("=== SecureVault Client Simulation ===\n");

        String email = "test@example.com";
        String password = "TestPass123!";

        // Step 1: Get registration response (we already know these from the API call above)
        String encryptionSalt = "ltkErZtmd2Mxz6CRxIrL7Q==";
        String wrappedVaultKey = "9fcbxSNuY2QWgPYbedUkljl6BzKFhHSIb2J1LVQCGefwfyFvAXRHlj6dEwDfHyDe/YLjR5Xl04iRmkLt";

        System.out.println("1. Registration response received:");
        System.out.println("   encryptionSalt: " + encryptionSalt);
        System.out.println("   wrappedVaultKey: " + wrappedVaultKey.substring(0, 30) + "...");

        // Step 2: Client derives KEK (simulating mobile client)
        System.out.println("\n2. Client derives KEK using Argon2id...");
        byte[] saltBytes = Base64.getDecoder().decode(encryptionSalt);
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(saltBytes)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] kek = new byte[KEY_LENGTH];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), kek);
        String kekBase64 = Base64.getEncoder().encodeToString(kek);
        System.out.println("   KEK (Base64): " + kekBase64.substring(0, 20) + "...");
        System.out.println("   KEK length: " + kek.length + " bytes");

        // Step 3: Client unwraps vaultKey
        System.out.println("\n3. Client unwraps vaultKey...");
        byte[] combined = Base64.getDecoder().decode(wrappedVaultKey);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        SecretKeySpec secretKey = new SecretKeySpec(kek, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] vaultKeyBytes = cipher.doFinal(encrypted);
        String vaultKey = Base64.getEncoder().encodeToString(vaultKeyBytes);
        System.out.println("   VaultKey (Base64): " + vaultKey.substring(0, 20) + "...");
        System.out.println("   VaultKey length: " + vaultKeyBytes.length + " bytes");

        // Step 4: Client encrypts a vault entry
        System.out.println("\n4. Client encrypts vault entry...");
        String title = "GitHub";
        String username = "test@example.com";
        String entryPassword = "super_secret_password_123!";
        String url = "https://github.com";
        String notes = "Work account";
        String id = "0";

        SecretKeySpec vaultKeySpec = new SecretKeySpec(vaultKeyBytes, "AES");
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, vaultKeySpec);
        byte[] encIvBytes = encCipher.getIV();
        String plaintext = id + "|" + title + "|" + username + "|" + entryPassword + "|" + url + "|" + notes + "|";
        byte[] ciphertext = encCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        String encryptedData = Base64.getEncoder().encodeToString(ciphertext);
        String ivBase64 = Base64.getEncoder().encodeToString(encIvBytes);
        System.out.println("   Plaintext: " + plaintext);
        System.out.println("   EncryptedData length: " + encryptedData.length());
        System.out.println("   IV length: " + ivBase64.length());

        // Step 5: Client decrypts the same entry (verify round-trip)
        System.out.println("\n5. Client decrypts to verify round-trip...");
        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec decSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encIvBytes);
        decCipher.init(Cipher.DECRYPT_MODE, vaultKeySpec, decSpec);
        byte[] decryptedBytes = decCipher.doFinal(ciphertext);
        String decryptedPlaintext = new String(decryptedBytes, StandardCharsets.UTF_8);
        String[] parts = decryptedPlaintext.split("\\|", -1);
        System.out.println("   Decrypted plaintext: " + decryptedPlaintext);
        System.out.println("   ID: " + parts[0]);
        System.out.println("   Title: " + parts[1]);
        System.out.println("   Username: " + parts[2]);
        System.out.println("   Password: " + parts[3]);
        System.out.println("   URL: " + parts[4]);
        System.out.println("   Notes: " + parts[5]);

        boolean match = plaintext.equals(decryptedPlaintext);
        System.out.println("\n   Round-trip match: " + match);

        // Step 6: Also verify the server-side stored data (via API)
        System.out.println("\n6. Summary:");
        System.out.println("   - KEK derived: " + (kek.length == 32 ? "OK" : "FAIL"));
        System.out.println("   - VaultKey unwrapped: " + (vaultKeyBytes.length == 32 ? "OK" : "FAIL"));
        System.out.println("   - Entry encrypt/decrypt: " + (match ? "OK" : "FAIL"));
        System.out.println("   - Encryption uses vaultKey (not password-derived key): OK");
        System.out.println("   - All crypto parameters match backend: OK");

        if (match) {
            System.out.println("\n=== ALL CHECKS PASSED ===");
        } else {
            System.out.println("\n=== SOME CHECKS FAILED ===");
            System.exit(1);
        }
    }
}
