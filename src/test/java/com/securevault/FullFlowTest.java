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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FullFlowTest {

    private static final int KEY_LENGTH = 32;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 4;

    public static void main(String[] args) throws Exception {
        String email = "test@example.com";
        String password = "TestPass123!";
        String baseUrl = "http://localhost:8080/api/v1";

        System.out.println("=== Full End-to-End Flow Test ===\n");

        // 1. LOGIN
        System.out.println("1. Logging in...");
        String loginBody = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        HttpResponse<String> loginResp = httpPost(baseUrl + "/auth/login", loginBody, null);
        String response = loginResp.body();
        System.out.println("   Status: " + loginResp.statusCode());
        String accessToken = extractJson(response, "accessToken");
        String encryptionSalt = extractJson(response, "encryptionSalt");
        String wrappedVaultKey = extractJson(response, "wrappedVaultKey");
        System.out.println("   Got encryptionSalt: " + encryptionSalt);

        // 2. Derive KEK
        System.out.println("\n2. Client derives KEK via Argon2id...");
        byte[] saltBytes = Base64.getDecoder().decode(encryptionSalt);
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withIterations(ITERATIONS).withMemoryAsKB(MEMORY_KB).withParallelism(PARALLELISM).withSalt(saltBytes).build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] kek = new byte[KEY_LENGTH];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), kek);

        // 3. Unwrap vaultKey
        System.out.println("\n3. Client unwraps vaultKey...");
        byte[] combined = Base64.getDecoder().decode(wrappedVaultKey);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        SecretKeySpec kekKey = new SecretKeySpec(kek, "AES");
        Cipher unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding");
        unwrapCipher.init(Cipher.DECRYPT_MODE, kekKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] vaultKeyBytes = unwrapCipher.doFinal(encrypted);
        System.out.println("   VaultKey unwrapped: " + Base64.getEncoder().encodeToString(vaultKeyBytes).substring(0, 20) + "...");

        // 4. Encrypt entries
        SecretKeySpec vaultKey = new SecretKeySpec(vaultKeyBytes, "AES");
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");

        String[] plainTexts = {
            "Bank Account|john.doe@email.com|P@ssw0rd!2024|https://chase.com|Hidden savings account|HiddenAccounts",
            "Netflix|john.doe@gmail.com|V3ryS3cur3!Pass|https://netflix.com|Shared family account|Entertainment",
            "Router Admin|admin|routerP@ss!|http://192.168.1.1|Home network|gateway",
            "GitHub|dev@email.com|G1tHub!S3cur3|https://github.com|Personal repos|Development"
        };

        String[] encryptedDatas = new String[plainTexts.length];
        String[] ivStrs = new String[plainTexts.length];

        for (int i = 0; i < plainTexts.length; i++) {
            encCipher.init(Cipher.ENCRYPT_MODE, vaultKey);
            byte[] encIv = encCipher.getIV();
            byte[] ciphertext = encCipher.doFinal(plainTexts[i].getBytes(StandardCharsets.UTF_8));
            encryptedDatas[i] = Base64.getEncoder().encodeToString(ciphertext);
            ivStrs[i] = Base64.getEncoder().encodeToString(encIv);
        }

        System.out.println("\n4. Client encrypted " + plainTexts.length + " vault entries");
        for (int i = 0; i < plainTexts.length; i++) {
            System.out.println("   Entry " + (i+1) + ": " + plainTexts[i]);
        }

        // 5. Clear old entries first
        System.out.println("\n5. Clearing old vault entries...");
        HttpResponse<String> deleteResp = httpDelete(baseUrl + "/vault", accessToken);
        System.out.println("   Status: " + deleteResp.statusCode());

        // 6. Create entries via API
        String[] entryIds = new String[plainTexts.length];
        for (int i = 0; i < plainTexts.length; i++) {
            System.out.println("\n6." + (i+1) + ". Creating entry " + (i+1) + " via API...");
            String createBody = "{\"encryptedData\":\"" + encryptedDatas[i] + "\",\"iv\":\"" + ivStrs[i] + "\"}";
            HttpResponse<String> createResp = httpPost(baseUrl + "/vault", createBody, accessToken);
            System.out.println("   Status: " + createResp.statusCode());
            if (createResp.statusCode() == 201) {
                entryIds[i] = extractJson(createResp.body(), "id");
                System.out.println("   Entry ID: " + entryIds[i]);
            } else {
                System.out.println("   Failed: " + createResp.body());
                entryIds[i] = "FAILED";
            }
        }

        // 7. Retrieve vault entries
        System.out.println("\n7. Retrieving all vault entries...");
        HttpResponse<String> getResp = httpGet(baseUrl + "/vault", accessToken);
        System.out.println("   Status: " + getResp.statusCode());
        String entriesJson = getResp.body();
        String countStr = extractJson(entriesJson, "count");
        System.out.println("   Total entries: " + countStr);

        // 8. Decrypt all entries
        System.out.println("\n8. Client decrypts all retrieved entries...");
        int totalEntries = countStr != null ? Integer.parseInt(countStr) : 0;
        int matchCount = 0;
        int entryIdx = 0;

        int arrStart = entriesJson.indexOf("\"entries\":");
        if (arrStart >= 0) {
            int bracketStart = entriesJson.indexOf("[", arrStart);
            int bracketEnd = entriesJson.lastIndexOf("]");
            if (bracketStart >= 0 && bracketEnd > bracketStart) {
                String entriesArray = entriesJson.substring(bracketStart, bracketEnd + 1);
                int pos = 0;
                while (entryIdx < plainTexts.length && pos < entriesArray.length()) {
                    int encDataIdx = entriesArray.indexOf("\"encryptedData\":\"", pos);
                    if (encDataIdx < 0 || encDataIdx >= entriesArray.length()) break;
                    int encValStart = encDataIdx + "\"encryptedData\":\"".length();
                    int encValEnd = encValStart;
                    while (encValEnd < entriesArray.length() && entriesArray.charAt(encValEnd) != '"') encValEnd++;
                    String encData = entriesArray.substring(encValStart, encValEnd);

                    int ivIdx = entriesArray.indexOf("\"iv\":\"", encValEnd);
                    if (ivIdx < 0) break;
                    int ivValStart = ivIdx + "\"iv\":\"".length();
                    int ivValEnd = ivValStart;
                    while (ivValEnd < entriesArray.length() && entriesArray.charAt(ivValEnd) != '"') ivValEnd++;
                    String entryIv = entriesArray.substring(ivValStart, ivValEnd);

                    byte[] retEnc = Base64.getDecoder().decode(encData);
                    byte[] retIvBytes = Base64.getDecoder().decode(entryIv);
                    Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
                    decCipher.init(Cipher.DECRYPT_MODE, vaultKey, new GCMParameterSpec(GCM_TAG_LENGTH, retIvBytes));
                    byte[] decrypted = decCipher.doFinal(retEnc);
                    String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

                    boolean match = plainTexts[entryIdx].equals(decryptedText);
                    System.out.println("   Entry " + (entryIdx+1) + ": " + (match ? "PASS" : "FAIL"));
                    System.out.println("     Stored:   " + plainTexts[entryIdx]);
                    System.out.println("     Decrypted:" + decryptedText);
                    if (match) matchCount++;
                    entryIdx++;
                    pos = ivValEnd;
                }
            }
        }

        System.out.println("\n   Decryption match: " + matchCount + "/" + plainTexts.length);

        // 9. Verify all passed
        boolean allPassed = matchCount == plainTexts.length && totalEntries == plainTexts.length;
        System.out.println("\n=== " + (allPassed ? "ALL CHECKS PASSED ===" : "SOME CHECKS FAILED ==="));

        if (!allPassed) System.exit(1);
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

    static HttpResponse<String> httpDelete(String url, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                .DELETE();
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
            if (json.charAt(start) == '"') { start++; int end = start; while (end < json.length() && json.charAt(end) != '"') end++; return json.substring(start, end); }
            int end = start; while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++; return json.substring(start, end).trim();
        }
        start += search.length();
        int end = start;
        while (end < json.length() && json.charAt(end) != '"') end++;
        return json.substring(start, end);
    }
}
