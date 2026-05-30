package com.securevault;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Full end-to-end flow test against a running SecureVault backend.
 * Uses the same crypto chain as all clients:
 *   Argon2id(password, salt, params) → masterKey
 *   HKDF-Expand(masterKey, "auth") → authHash
 *   HKDF-Expand(masterKey, "kek")  → KEK
 */
public class FullFlowTest {

    private static final int KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 98304;
    private static final int PARALLELISM = 4;

    private static final String AUTH_TAG = "auth";
    private static final String KEK_TAG = "kek";

    public static void main(String[] args) throws Exception {
        String email = "e2e_" + System.currentTimeMillis() + "@test.com";
        String password = "TestPass123!";
        String newPassword = "NewPass456!";
        String baseUrl = "http://localhost:8080/api/v1";

        System.out.println("=== Full End-to-End Flow Test ===\n");
        System.out.println("Email: " + email);

        // Step 1: Generate master salt (single salt for both auth and KEK)
        byte[] masterSalt = generateRandomBytes(16);
        String masterSaltB64 = Base64.getEncoder().encodeToString(masterSalt);

        // Step 2: Derive master key (single Argon2id call)
        byte[] masterKey = argon2id(password, masterSalt);
        System.out.println("   Master key derived (1 Argon2id call)");

        // Step 3: HKDF-Expand split
        byte[] authHash = hkdfExpand(masterKey, AUTH_TAG);
        byte[] kek = hkdfExpand(masterKey, KEK_TAG);
        String authHashB64 = Base64.getEncoder().encodeToString(authHash);
        System.out.println("   Auth hash + KEK derived via HKDF-Expand");

        // Step 4: Generate vault key and wrap it
        byte[] vaultKey = generateRandomBytes(32);
        String vaultKeyB64 = Base64.getEncoder().encodeToString(vaultKey);
        String wrappedVaultKey = aesGcmEncrypt(kek, vaultKey);
        System.out.println("   Vault key encrypted with KEK");

        // ═══════════════════════════════════════════════════
        //  5. REGISTER
        // ═══════════════════════════════════════════════════

        System.out.println("\n1. Registering new user...");
        String registerBody = "{"
                + "\"email\":\"" + email + "\","
                + "\"authHash\":\"" + authHashB64 + "\","
                + "\"authSalt\":\"" + masterSaltB64 + "\","
                + "\"encryptionSalt\":\"" + masterSaltB64 + "\","
                + "\"wrappedVaultKey\":\"" + wrappedVaultKey + "\","
                + "\"encryptionVersion\":2,"
                + "\"kdfIterations\":" + ITERATIONS + ","
                + "\"kdfMemory\":" + MEMORY_KB + ","
                + "\"kdfParallelism\":" + PARALLELISM + ""
                + "}";
        HttpResponse<String> regResp = httpPost(baseUrl + "/auth/register", registerBody, null);
        checkStatus(regResp, 201, "Register");
        System.out.println("   Registration successful");

        // ═══════════════════════════════════════════════════
        //  6. LOGIN
        // ═══════════════════════════════════════════════════

        System.out.println("\n2. Logging in...");
        // Prelogin
        String preBody = "{\"email\":\"" + email + "\"}";
        HttpResponse<String> preResp = httpPost(baseUrl + "/auth/prelogin", preBody, null);
        checkStatus(preResp, 200, "Prelogin");
        String authSalt = extractJson(preResp.body(), "authSalt");
        System.out.println("   Prelogin returned authSalt: " + (authSalt != null ? "present" : "MISSING"));

        // Derive login auth hash from same master salt
        byte[] loginSalt = Base64.getDecoder().decode(authSalt);
        byte[] loginMasterKey = argon2id(password, loginSalt);
        byte[] loginAuthHash = hkdfExpand(loginMasterKey, AUTH_TAG);
        String loginAuthHashB64 = Base64.getEncoder().encodeToString(loginAuthHash);

        String loginBody = "{"
                + "\"email\":\"" + email + "\","
                + "\"authHash\":\"" + loginAuthHashB64 + "\""
                + "}";
        HttpResponse<String> loginResp = httpPost(baseUrl + "/auth/login", loginBody, null);
        checkStatus(loginResp, 200, "Login");

        // Extract challenge ID for 2FA verification (required even without 2FA)
        String challengeId = extractJson(loginResp.body(), "challengeId");
        System.out.println("   ChallengeId: " + (challengeId != null ? "present" : "MISSING"));

        // Verify 2FA with empty code (no 2FA set up)
        String verifyBody = "{"
                + "\"email\":\"" + email + "\","
                + "\"challengeId\":\"" + challengeId + "\","
                + "\"code\":\"\""
                + "}";
        HttpResponse<String> verifyResp = httpPost(baseUrl + "/auth/verify-2fa", verifyBody, null);
        checkStatus(verifyResp, 200, "Verify 2FA");

        String accessToken = extractJson(verifyResp.body(), "accessToken");
        String encSalt = extractJson(verifyResp.body(), "encryptionSalt");
        String wrappedVk = extractJson(verifyResp.body(), "wrappedVaultKey");
        System.out.println("   accessToken: " + (accessToken != null ? "present" : "MISSING"));
        System.out.println("   encSalt: " + (encSalt != null ? "present" : "MISSING"));
        System.out.println("   wrappedVk: " + (wrappedVk != null ? "present" : "MISSING"));
        System.out.println("   Login successful, access token obtained");

        // ═══════════════════════════════════════════════════
        //  7. UNLOCK VAULT
        // ═══════════════════════════════════════════════════

        System.out.println("\n3. Unlocking vault...");
        byte[] kekFromServer = hkdfExpand(loginMasterKey, KEK_TAG);
        byte[] unwrappedVk = aesGcmDecrypt(kekFromServer, wrappedVk);
        SecretKeySpec vaultKeySpec = new SecretKeySpec(unwrappedVk, "AES");
        System.out.println("   Vault key unwrapped successfully");

        // ═══════════════════════════════════════════════════
        //  8. ADD VAULT ENTRY
        // ═══════════════════════════════════════════════════

        System.out.println("\n4. Adding vault entry...");
        String plainEntry = "GitHub|testuser|password123|https://github.com|Test account||";
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, vaultKeySpec);
        byte[] entryIv = encCipher.getIV();
        byte[] entryCt = encCipher.doFinal(plainEntry.getBytes(StandardCharsets.UTF_8));
        String entryIvB64 = Base64.getEncoder().encodeToString(entryIv);
        String entryCtB64 = "v1:" + Base64.getEncoder().encodeToString(entryCt);

        String createBody = "{\"encryptedData\":\"" + entryCtB64 + "\",\"iv\":\"" + entryIvB64 + "\"}";
        HttpResponse<String> createResp = httpPost(baseUrl + "/vault", createBody, accessToken);
        checkStatus(createResp, 201, "Create entry");
        String entryId = extractJson(createResp.body(), "id");
        System.out.println("   Entry created: ID " + entryId);

        // ═══════════════════════════════════════════════════
        //  9. GET AND VERIFY ENTRY
        // ═══════════════════════════════════════════════════

        System.out.println("\n5. Verifying entry...");
        HttpResponse<String> getResp = httpGet(baseUrl + "/vault", accessToken);
        checkStatus(getResp, 200, "Get entries");
        boolean canDecrypt = verifyDecryption(getResp.body(), vaultKeySpec, plainEntry);
        if (!canDecrypt) {
            System.out.println("   FAIL: Cannot decrypt entry");
            System.exit(1);
        }
        System.out.println("   Entry created and decrypted correctly");

        // ═══════════════════════════════════════════════════
        //  10. DELETE ENTRY
        // ═══════════════════════════════════════════════════

        System.out.println("\n6. Deleting entry...");
        HttpResponse<String> delResp = httpDelete(baseUrl + "/vault/" + entryId, accessToken);
        checkStatus(delResp, 200, "Delete entry");
        System.out.println("   Entry deleted");

        // ═══════════════════════════════════════════════════
        //  ALL PASSED
        // ═══════════════════════════════════════════════════

        System.out.println("\n=== ALL E2E TESTS PASSED ===");
    }

    // ── Crypto helpers (matching Rust crypto-core) ──

    private static byte[] argon2id(String password, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] key = new byte[KEY_LENGTH];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), key);
        return key;
    }

    // HKDF-Expand single block: HMAC-SHA256(prk, info || 0x01)
    private static byte[] hkdfExpand(byte[] prk, String info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 0x01);
        return mac.doFinal();
    }

    private static String aesGcmEncrypt(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] iv = cipher.getIV();
        byte[] ct = cipher.doFinal(plaintext);
        byte[] combined = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ct, 0, combined, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static byte[] aesGcmDecrypt(byte[] key, String wrappedB64) throws Exception {
        byte[] combined = Base64.getDecoder().decode(wrappedB64);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ct = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(combined, GCM_IV_LENGTH, ct, 0, ct.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return cipher.doFinal(ct);
    }

    // ── Helpers ──

    private static void checkStatus(HttpResponse<String> resp, int expected, String step) {
        if (resp.statusCode() != expected) {
            System.out.println("   FAIL at " + step + ": HTTP " + resp.statusCode() + " — " + resp.body());
            System.exit(1);
        }
    }

    private static boolean verifyDecryption(String entriesJson, SecretKeySpec vaultKey, String expectedPlaintext) {
        try {
            int encIdx = entriesJson.indexOf("\"encryptedData\":\"");
            if (encIdx < 0) return false;
            int encStart = encIdx + "\"encryptedData\":\"".length();
            int encEnd = encStart;
            while (encEnd < entriesJson.length() && entriesJson.charAt(encEnd) != '"') encEnd++;
            String encData = entriesJson.substring(encStart, encEnd);
            if (encData.startsWith("v1:")) encData = encData.substring(3);

            int ivIdx = entriesJson.indexOf("\"iv\":\"", encEnd);
            if (ivIdx < 0) return false;
            int ivStart = ivIdx + "\"iv\":\"".length();
            int ivEnd = ivStart;
            while (ivEnd < entriesJson.length() && entriesJson.charAt(ivEnd) != '"') ivEnd++;
            String entryIv = entriesJson.substring(ivStart, ivEnd);

            byte[] retEnc = Base64.getDecoder().decode(encData);
            byte[] retIv = Base64.getDecoder().decode(entryIv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, vaultKey, new GCMParameterSpec(GCM_TAG_LENGTH, retIv));
            String decrypted = new String(cipher.doFinal(retEnc), StandardCharsets.UTF_8);
            return expectedPlaintext.equals(decrypted);
        } catch (Exception e) {
            System.out.println("   Decryption error: " + e.getMessage());
            return false;
        }
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static HttpResponse<String> httpPost(String url, String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> httpGet(String url, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> httpDelete(String url, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).DELETE();
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
