package com.securevault;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

public class FullFlowTest {

    private static final int KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 4;

    public static void main(String[] args) throws Exception {
        String email = "flowtest_" + System.currentTimeMillis() + "@example.com";
        String password = "TestPass123!";
        String newPassword = "NewPass456!";
        String baseUrl = "http://localhost:8080/api/v1";

        System.out.println("=== Full End-to-End Flow Test ===\n");
        System.out.println("Email: " + email);

        // 1. REGISTER
        System.out.println("\n1. Registering new user...");
        String registerBody = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        HttpResponse<String> registerResp = httpPost(baseUrl + "/auth/register", registerBody, null);
        System.out.println("   Status: " + registerResp.statusCode());
        if (registerResp.statusCode() != 201) {
            System.out.println("   FAIL: " + registerResp.body());
            System.exit(1);
        }
        String registerJson = registerResp.body();
        String encryptionSalt1 = extractJson(registerJson, "encryptionSalt");
        String wrappedVaultKey1 = extractJson(registerJson, "wrappedVaultKey");
        System.out.println("   Registration successful!");
        System.out.println("   encryptionSalt: " + (encryptionSalt1 != null ? "present" : "missing"));
        System.out.println("   wrappedVaultKey: " + (wrappedVaultKey1 != null ? "present" : "missing"));

        // 2. LOGIN
        System.out.println("\n2. Logging in...");
        String loginBody = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        HttpResponse<String> loginResp = httpPost(baseUrl + "/auth/login", loginBody, null);
        System.out.println("   Status: " + loginResp.statusCode());
        if (loginResp.statusCode() != 200) {
            System.out.println("   FAIL: " + loginResp.body());
            System.exit(1);
        }
        String accessToken1 = extractJson(loginResp.body(), "accessToken");
        encryptionSalt1 = extractJson(loginResp.body(), "encryptionSalt");
        wrappedVaultKey1 = extractJson(loginResp.body(), "wrappedVaultKey");
        System.out.println("   Login successful!");

        // 3. Derive KEK and unwrap vaultKey
        System.out.println("\n3. Deriving KEK and unwrapping vaultKey...");
        byte[] saltBytes = Base64.getDecoder().decode(encryptionSalt1);
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS).withMemoryAsKB(MEMORY_KB).withParallelism(PARALLELISM).withSalt(saltBytes).build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] kek1 = new byte[KEY_LENGTH];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), kek1);

        byte[] combined = Base64.getDecoder().decode(wrappedVaultKey1);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        SecretKeySpec kekKey1 = new SecretKeySpec(kek1, "AES");
        Cipher unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding");
        unwrapCipher.init(Cipher.DECRYPT_MODE, kekKey1, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] vaultKeyBytes = unwrapCipher.doFinal(encrypted);
        SecretKeySpec vaultKey1 = new SecretKeySpec(vaultKeyBytes, "AES");
        System.out.println("   VaultKey unwrapped successfully");

        // 4. Add a password entry
        System.out.println("\n4. Adding a password entry...");
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, vaultKey1);
        byte[] encIv = encCipher.getIV();
        String plainEntry = "GitHub|testuser|password123|https://github.com|Test account||";
        byte[] ciphertext = encCipher.doFinal(plainEntry.getBytes(StandardCharsets.UTF_8));
        String encryptedData = Base64.getEncoder().encodeToString(ciphertext);
        String ivStr = Base64.getEncoder().encodeToString(encIv);
        String createBody = "{\"encryptedData\":\"" + encryptedData + "\",\"iv\":\"" + ivStr + "\"}";
        HttpResponse<String> createResp = httpPost(baseUrl + "/vault", createBody, accessToken1);
        System.out.println("   Status: " + createResp.statusCode());
        if (createResp.statusCode() != 201) {
            System.out.println("   FAIL: " + createResp.body());
            System.exit(1);
        }
        String entryId = extractJson(createResp.body(), "id");
        System.out.println("   Entry created with ID: " + entryId);

        // 5. Retrieve and verify entry before password change
        System.out.println("\n5. Verifying entry before password change...");
        HttpResponse<String> getResp = httpGet(baseUrl + "/vault", accessToken1);
        System.out.println("   Status: " + getResp.statusCode());
        boolean canDecryptBefore = verifyDecryption(getResp.body(), vaultKey1, plainEntry);
        System.out.println("   Can decrypt: " + canDecryptBefore);

        // 6. Change password
        System.out.println("\n6. Changing password...");
        String newEncryptionSalt = Base64.getEncoder().encodeToString(generateRandomBytes(16));
        byte[] newSaltBytes = Base64.getDecoder().decode(newEncryptionSalt);
        Argon2Parameters newParams = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS).withMemoryAsKB(MEMORY_KB).withParallelism(PARALLELISM).withSalt(newSaltBytes).build();
        Argon2BytesGenerator newGen = new Argon2BytesGenerator();
        newGen.init(newParams);
        byte[] newKek = new byte[KEY_LENGTH];
        newGen.generateBytes(newPassword.getBytes(StandardCharsets.UTF_8), newKek);

        Cipher wrapCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec newKekKey = new SecretKeySpec(newKek, "AES");
        wrapCipher.init(Cipher.ENCRYPT_MODE, newKekKey);
        byte[] newVaultKeyIv = wrapCipher.getIV();
        byte[] rewrappedVaultKey = wrapCipher.doFinal(vaultKeyBytes);
        byte[] combinedNew = new byte[newVaultKeyIv.length + rewrappedVaultKey.length];
        System.arraycopy(newVaultKeyIv, 0, combinedNew, 0, newVaultKeyIv.length);
        System.arraycopy(rewrappedVaultKey, 0, combinedNew, newVaultKeyIv.length, rewrappedVaultKey.length);
        String newWrappedVaultKey = Base64.getEncoder().encodeToString(combinedNew);

        String changePwdBody = "{" +
                "\"current_password\":\"" + password + "\"," +
                "\"new_password\":\"" + newPassword + "\"," +
                "\"wrapped_vault_key\":\"" + newWrappedVaultKey + "\"," +
                "\"new_encryption_salt\":\"" + newEncryptionSalt + "\"" +
                "}";
        HttpResponse<String> changeResp = httpPost(baseUrl + "/auth/change-password", changePwdBody, accessToken1);
        System.out.println("   Status: " + changeResp.statusCode());
        System.out.println("   Response: " + changeResp.body());
        if (changeResp.statusCode() != 200) {
            System.out.println("   FAIL: Password change failed!");
            System.exit(1);
        }
        String accessToken2 = extractJson(changeResp.body(), "accessToken");
        String newEncryptionSaltResp = extractJson(changeResp.body(), "encryptionSalt");
        String newWrappedVaultKeyResp = extractJson(changeResp.body(), "wrappedVaultKey");
        System.out.println("   Password changed successfully!");

        // 7. Login with new password
        System.out.println("\n7. Logging in with new password...");
        loginBody = "{\"email\":\"" + email + "\",\"password\":\"" + newPassword + "\"}";
        loginResp = httpPost(baseUrl + "/auth/login", loginBody, null);
        System.out.println("   Status: " + loginResp.statusCode());
        if (loginResp.statusCode() != 200) {
            System.out.println("   FAIL: " + loginResp.body());
            System.exit(1);
        }
        accessToken2 = extractJson(loginResp.body(), "accessToken");
        newEncryptionSaltResp = extractJson(loginResp.body(), "encryptionSalt");
        newWrappedVaultKeyResp = extractJson(loginResp.body(), "wrappedVaultKey");
        System.out.println("   Login with new password successful!");

        // 8. Derive new KEK and unwrap vaultKey
        System.out.println("\n8. Deriving new KEK and unwrapping vaultKey...");
        byte[] newSaltBytesResp = Base64.getDecoder().decode(newEncryptionSaltResp);
        Argon2Parameters newParamsResp = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS).withMemoryAsKB(MEMORY_KB).withParallelism(PARALLELISM).withSalt(newSaltBytesResp).build();
        Argon2BytesGenerator newGenResp = new Argon2BytesGenerator();
        newGenResp.init(newParamsResp);
        byte[] kek2 = new byte[KEY_LENGTH];
        newGenResp.generateBytes(newPassword.getBytes(StandardCharsets.UTF_8), kek2);

        combined = Base64.getDecoder().decode(newWrappedVaultKeyResp);
        iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        encrypted = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        SecretKeySpec kekKey2 = new SecretKeySpec(kek2, "AES");
        unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding");
        unwrapCipher.init(Cipher.DECRYPT_MODE, kekKey2, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] vaultKeyBytes2 = unwrapCipher.doFinal(encrypted);
        SecretKeySpec vaultKey2 = new SecretKeySpec(vaultKeyBytes2, "AES");
        System.out.println("   VaultKey unwrapped successfully with new password!");

        // 9. Retrieve and decrypt entry with new credentials
        System.out.println("\n9. Verifying entry after password change...");
        getResp = httpGet(baseUrl + "/vault", accessToken2);
        System.out.println("   Status: " + getResp.statusCode());
        boolean canDecryptAfter = verifyDecryption(getResp.body(), vaultKey2, plainEntry);
        System.out.println("   Can decrypt with new credentials: " + canDecryptAfter);

        // 10. Summary
        System.out.println("\n=== RESULTS ===");
        boolean allPassed = canDecryptBefore && canDecryptAfter;
        System.out.println("Registration: PASS");
        System.out.println("Login with old password: PASS");
        System.out.println("Add vault entry: PASS");
        System.out.println("Decrypt before password change: " + (canDecryptBefore ? "PASS" : "FAIL"));
        System.out.println("Password change: PASS");
        System.out.println("Login with new password: PASS");
        System.out.println("Decrypt after password change: " + (canDecryptAfter ? "PASS" : "FAIL"));

        if (allPassed) {
            System.out.println("\n=== ALL TESTS PASSED ===");
        } else {
            System.out.println("\n=== TESTS FAILED ===");
            System.exit(1);
        }
    }

    static boolean verifyDecryption(String entriesJson, SecretKeySpec vaultKey, String expectedPlaintext) {
        try {
            int encDataIdx = entriesJson.indexOf("\"encryptedData\":\"");
            if (encDataIdx < 0) return false;
            int encValStart = encDataIdx + "\"encryptedData\":\"".length();
            int encValEnd = encValStart;
            while (encValEnd < entriesJson.length() && entriesJson.charAt(encValEnd) != '"') encValEnd++;
            String encData = entriesJson.substring(encValStart, encValEnd);

            int ivIdx = entriesJson.indexOf("\"iv\":\"", encValEnd);
            if (ivIdx < 0) return false;
            int ivValStart = ivIdx + "\"iv\":\"".length();
            int ivValEnd = ivValStart;
            while (ivValEnd < entriesJson.length() && entriesJson.charAt(ivValEnd) != '"') ivValEnd++;
            String entryIv = entriesJson.substring(ivValStart, ivValEnd);

            byte[] retEnc = Base64.getDecoder().decode(encData);
            byte[] retIvBytes = Base64.getDecoder().decode(entryIv);
            Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decCipher.init(Cipher.DECRYPT_MODE, vaultKey, new GCMParameterSpec(GCM_TAG_LENGTH, retIvBytes));
            byte[] decrypted = decCipher.doFinal(retEnc);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

            return expectedPlaintext.equals(decryptedText);
        } catch (Exception e) {
            System.out.println("   Decryption error: " + e.getMessage());
            return false;
        }
    }

    static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return bytes;
    }

    static HttpResponse<String> httpPost(String url, String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    static HttpResponse<String> httpGet(String url, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    static String extractJson(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) {
            search = "\"" + key + "\":";
            start = json.indexOf(search);
            if (start < 0) return null;
            start += search.length();
            if (json.charAt(start) == '"') {
                start++;
                int end = start;
                while (end < json.length() && json.charAt(end) != '"') end++;
                return json.substring(start, end);
            }
            int end = start;
            while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++;
            return json.substring(start, end).trim();
        }
        start += search.length();
        int end = start;
        while (end < json.length() && json.charAt(end) != '"') end++;
        return json.substring(start, end);
    }
}