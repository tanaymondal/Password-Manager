package com.securevault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that refresh tokens are stored as SHA-256 hashes, not raw JWTs.
 */
class RefreshTokenHashTest {

    private AuthService authService;
    private Method hashTokenMethod;

    @BeforeEach
    void setUp() throws Exception {
        authService = new AuthService(null, null, null, null, null, null, null, null);
        hashTokenMethod = AuthService.class.getDeclaredMethod("hashToken", String.class);
        hashTokenMethod.setAccessible(true);
    }

    @Test
    @DisplayName("hashToken produces deterministic output")
    void hashToken_deterministic() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.test_signature";

        String hash1 = (String) hashTokenMethod.invoke(authService, token);
        String hash2 = (String) hashTokenMethod.invoke(authService, token);

        assertEquals(hash1, hash2, "Same token must produce same hash");
    }

    @Test
    @DisplayName("hashToken produces 64-char hex string (SHA-256)")
    void hashToken_length() throws Exception {
        String token = "some-random-jwt-token";

        String hash = (String) hashTokenMethod.invoke(authService, token);

        assertEquals(64, hash.length(), "SHA-256 hex output must be 64 characters");
        assertTrue(hash.matches("[0-9a-f]+"), "SHA-256 output must be hexadecimal");
    }

    @Test
    @DisplayName("hashToken produces different output for different tokens")
    void hashToken_differentTokens() throws Exception {
        String token1 = "first-token";
        String token2 = "second-token";

        String hash1 = (String) hashTokenMethod.invoke(authService, token1);
        String hash2 = (String) hashTokenMethod.invoke(authService, token2);

        assertNotEquals(hash1, hash2, "Different tokens must produce different hashes");
    }

    @Test
    @DisplayName("hashToken output matches standard SHA-256 implementation")
    void hashToken_matchesStandardSha256() throws Exception {
        String token = "test-refresh-token-123";
        String hash = (String) hashTokenMethod.invoke(authService, token);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String expectedHash = HexFormat.of().formatHex(md.digest(token.getBytes()));

        assertEquals(expectedHash, hash, "hashToken must match standard SHA-256");
    }

    @Test
    @DisplayName("hashToken output is not the raw token (confirms hashing)")
    void hashToken_notRawToken() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.raw-jwt-token";

        String hash = (String) hashTokenMethod.invoke(authService, token);

        assertNotEquals(token, hash, "Hash must not equal the raw token");
        assertFalse(hash.contains("."), "Hash must not contain JWT dots");
        assertFalse(token.equalsIgnoreCase(hash), "Hash must be completely different from token");
    }

    @Test
    @DisplayName("hashToken does not contain any JWT payload fragments")
    void hashToken_noJwtContent() throws Exception {
        String token = "eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0";

        String hash = (String) hashTokenMethod.invoke(authService, token);

        assertFalse(hash.contains("user@example"),
                "Hash must not contain decoded JWT content");
    }
}
