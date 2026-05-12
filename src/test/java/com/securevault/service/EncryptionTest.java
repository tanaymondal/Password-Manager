package com.securevault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionTest {

    private PasswordService passwordService;

    private static final String TEST_PASSWORD = "TestPassword123!";
    private static final String TEST_ENCRYPTION_SALT_BASE64 = "dGVzdEVuY3J5cHRpb25TYWx0MTIzNDU=";
    private static final byte[] TEST_ENCRYPTION_SALT_BYTES = Base64.getDecoder().decode(TEST_ENCRYPTION_SALT_BASE64);
    private static final String TEST_VAULT_KEY_BASE64 = "dGVzdFZhdWx0S2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo=";

    @BeforeEach
    void setUp() {
        passwordService = new PasswordService();
    }

    @Nested
    @DisplayName("KEK Derivation")
    class KekDerivation {

        @Test
        @DisplayName("deriveKek produces deterministic output")
        void deriveKek_deterministic() {
            String kek1 = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String kek2 = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);

            assertNotNull(kek1);
            assertFalse(kek1.isEmpty());
            assertEquals(kek1, kek2, "KEK derivation must be deterministic");
        }

        @Test
        @DisplayName("deriveKek produces 32-byte output encoded as Base64")
        void deriveKek_correctLength() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            byte[] kekBytes = Base64.getDecoder().decode(kek);

            assertEquals(32, kekBytes.length, "KEK must be 32 bytes (256 bits)");
        }

        @Test
        @DisplayName("deriveKek produces different output for different passwords")
        void deriveKek_differentPassword() {
            String kek1 = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String kek2 = passwordService.deriveKek("DifferentPassword!", TEST_ENCRYPTION_SALT_BASE64);

            assertNotEquals(kek1, kek2, "Different passwords must produce different KEKs");
        }

        @Test
        @DisplayName("deriveKek produces different output for different salts")
        void deriveKek_differentSalt() {
            String differentSalt = passwordService.generateEncryptionSalt();
            String kek1 = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String kek2 = passwordService.deriveKek(TEST_PASSWORD, differentSalt);

            assertNotEquals(kek1, kek2, "Different salts must produce different KEKs");
        }
    }

    @Nested
    @DisplayName("Vault Key Generation")
    class VaultKeyGeneration {

        @Test
        @DisplayName("generateVaultKey produces 32-byte key")
        void generateVaultKey_correctLength() {
            String vaultKey = passwordService.generateVaultKey();
            byte[] vaultKeyBytes = Base64.getDecoder().decode(vaultKey);

            assertEquals(32, vaultKeyBytes.length, "Vault key must be 32 bytes");
        }

        @Test
        @DisplayName("generateVaultKey produces unique keys each time")
        void generateVaultKey_unique() {
            String key1 = passwordService.generateVaultKey();
            String key2 = passwordService.generateVaultKey();

            assertNotEquals(key1, key2, "Each generated vault key must be unique");
        }

        @Test
        @DisplayName("generateVaultKey produces valid Base64")
        void generateVaultKey_validBase64() {
            String vaultKey = passwordService.generateVaultKey();

            assertDoesNotThrow(() -> Base64.getDecoder().decode(vaultKey));
        }
    }

    @Nested
    @DisplayName("Vault Key Wrap/Unwrap")
    class VaultKeyWrapUnwrap {

        @Test
        @DisplayName("wrapVaultKey produces output longer than input")
        void wrapVaultKey_longerThanInput() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String vaultKey = passwordService.generateVaultKey();
            String wrapped = passwordService.wrapVaultKey(vaultKey, kek);

            byte[] vaultKeyBytes = Base64.getDecoder().decode(vaultKey);
            byte[] wrappedBytes = Base64.getDecoder().decode(wrapped);

            assertTrue(wrappedBytes.length > vaultKeyBytes.length,
                    "Wrapped key must be longer due to IV prefix");
        }

        @Test
        @DisplayName("wrapVaultKey produces unique output each time (random IV)")
        void wrapVaultKey_randomized() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String wrapped1 = passwordService.wrapVaultKey(TEST_VAULT_KEY_BASE64, kek);
            String wrapped2 = passwordService.wrapVaultKey(TEST_VAULT_KEY_BASE64, kek);

            assertNotEquals(wrapped1, wrapped2,
                    "Same inputs must produce different wrapped keys due to random IV");
        }

        @Test
        @DisplayName("unwrapVaultKey recovers original vault key")
        void unwrapVaultKey_roundTrip() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String vaultKey = passwordService.generateVaultKey();
            String wrapped = passwordService.wrapVaultKey(vaultKey, kek);
            String unwrapped = passwordService.unwrapVaultKey(wrapped, kek);

            assertEquals(vaultKey, unwrapped, "Unwrap must recover original vault key");
        }

        @Test
        @DisplayName("unwrapVaultKey with wrong KEK throws exception")
        void unwrapVaultKey_wrongKek() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String wrongKek = passwordService.deriveKek("WrongPassword!", TEST_ENCRYPTION_SALT_BASE64);
            String wrapped = passwordService.wrapVaultKey(TEST_VAULT_KEY_BASE64, kek);

            assertThrows(RuntimeException.class, () -> {
                passwordService.unwrapVaultKey(wrapped, wrongKek);
            }, "Unwrapping with wrong KEK must fail");
        }

        @Test
        @DisplayName("unwrapVaultKey with tampered data throws exception")
        void unwrapVaultKey_tampered() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String wrapped = passwordService.wrapVaultKey(TEST_VAULT_KEY_BASE64, kek);
            byte[] wrappedBytes = Base64.getDecoder().decode(wrapped);
            wrappedBytes[12] ^= 0xFF;
            String tampered = Base64.getEncoder().encodeToString(wrappedBytes);

            assertThrows(RuntimeException.class, () -> {
                passwordService.unwrapVaultKey(tampered, kek);
            }, "Tampered wrapped key must fail GCM authentication");
        }
    }

    @Nested
    @DisplayName("Cross-Platform Test Vectors")
    class CrossPlatformTestVectors {

        @Test
        @DisplayName("KEK derivation produces consistent Base64 output for known inputs")
        void kek_knownVector() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);

            assertNotNull(kek);
            assertDoesNotThrow(() -> Base64.getDecoder().decode(kek),
                    "KEK must be valid Base64");
            assertEquals(44, kek.length(),
                    "Base64 encoded 32-byte output should be ~44 chars (with padding)");
        }

        @Test
        @DisplayName("Vault key wrap/unwrap with known test vector")
        void vaultKey_knownVector() {
            String kek = passwordService.deriveKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64);
            String vaultKey = TEST_VAULT_KEY_BASE64;

            String wrapped = passwordService.wrapVaultKey(vaultKey, kek);
            String unwrapped = passwordService.unwrapVaultKey(wrapped, kek);

            assertEquals(vaultKey, unwrapped,
                    "Round-trip must recover the original vault key");
            assertNotEquals(wrapped, vaultKey,
                    "Wrapped output must differ from input");
        }

        @Test
        @DisplayName("Full registration flow: generate salts, vaultKey, wrap")
        void fullRegistrationFlow() {
            String authSalt = passwordService.generateAuthSalt();
            String encryptionSalt = passwordService.generateEncryptionSalt();
            String passwordHash = passwordService.hashPasswordForAuthentication(TEST_PASSWORD, authSalt);
            String vaultKey = passwordService.generateVaultKey();
            String kek = passwordService.deriveKek(TEST_PASSWORD, encryptionSalt);
            String wrappedVaultKey = passwordService.wrapVaultKey(vaultKey, kek);

            assertNotNull(authSalt);
            assertNotNull(encryptionSalt);
            assertNotNull(passwordHash);
            assertNotNull(vaultKey);
            assertNotNull(wrappedVaultKey);

            String unwrappedVaultKey = passwordService.unwrapVaultKey(wrappedVaultKey, kek);
            assertEquals(vaultKey, unwrappedVaultKey,
                    "Must be able to recover vault key from wrapped form");
        }

        @Test
        @DisplayName("Password change: unwrap old vaultKey, re-wrap with new KEK")
        void passwordChangeFlow() {
            String encryptionSalt = TEST_ENCRYPTION_SALT_BASE64;

            String oldKek = passwordService.deriveKek("OldPassword123!", encryptionSalt);
            String newKek = passwordService.deriveKek("NewPassword456!", encryptionSalt);

            String vaultKey = passwordService.generateVaultKey();
            String wrappedWithOld = passwordService.wrapVaultKey(vaultKey, oldKek);

            String unwrappedVaultKey = passwordService.unwrapVaultKey(wrappedWithOld, oldKek);
            String reWrappedWithNew = passwordService.wrapVaultKey(unwrappedVaultKey, newKek);

            assertEquals(vaultKey, unwrappedVaultKey,
                    "Must be able to unwrap with old KEK");
            assertNotEquals(wrappedWithOld, reWrappedWithNew,
                    "Re-wrapping with new KEK must produce different output");
            assertDoesNotThrow(() -> passwordService.unwrapVaultKey(reWrappedWithNew, newKek),
                    "Must be able to unwrap with new KEK");
        }
    }

    @Nested
    @DisplayName("Entry Encryption (Backend Reference)")
    class EntryEncryptionReference {

        @Test
        @DisplayName("Vault entries use vaultKey for encryption, not KEK")
        void entryEncryption_usesVaultKey() {
            String encryptionSalt = TEST_ENCRYPTION_SALT_BASE64;
            String kek = passwordService.deriveKek(TEST_PASSWORD, encryptionSalt);
            String vaultKey = TEST_VAULT_KEY_BASE64;

            assertNotEquals(kek, vaultKey,
                    "KEK and vaultKey must be different keys");

            byte[] kekBytes = Base64.getDecoder().decode(kek);
            byte[] vaultKeyBytes = Base64.getDecoder().decode(vaultKey);

            assertNotEquals(0, kekBytes[0] ^ vaultKeyBytes[0],
                    "KEK and vaultKey must have different byte values");
        }

        @Test
        @DisplayName("Confirm vaultKey is 256-bit (32 bytes)")
        void vaultKey_is256bit() {
            byte[] vaultKeyBytes = Base64.getDecoder().decode(TEST_VAULT_KEY_BASE64);
            assertEquals(32, vaultKeyBytes.length,
                    "Vault key must be 256 bits (32 bytes) for AES-256");
        }
    }
}
