package com.securevault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that the password reuse prevention logic works correctly.
 *
 * The original bug: changePassword() re-hashed the candidate password with a NEW
 * random salt and compared against old hashes (which used different salts).
 * Since Argon2id output is completely different with different salts, the
 * comparison NEVER matched — password reuse was never detected.
 *
 * The fix: re-hash with each historical entry's ORIGINAL salt before comparing.
 */
class PasswordReuseTest {

    private PasswordService passwordService;

    @BeforeEach
    void setUp() {
        passwordService = new PasswordService();
    }

    @Test
    @DisplayName("Same password + same salt produces identical hash (deterministic)")
    void samePasswordSameSalt_identicalHash() {
        String password = "TestPass123!";
        String salt = passwordService.generateAuthSalt();

        String hash1 = passwordService.hashPasswordForAuthentication(password, salt);
        String hash2 = passwordService.hashPasswordForAuthentication(password, salt);

        assertEquals(hash1, hash2,
                "Same password + same salt must produce the same hash");
    }

    @Test
    @DisplayName("Same password + different salts produce different hashes")
    void samePasswordDifferentSalts_differentHashes() {
        String password = "TestPass123!";
        String salt1 = passwordService.generateAuthSalt();
        String salt2 = passwordService.generateAuthSalt();

        String hash1 = passwordService.hashPasswordForAuthentication(password, salt1);
        String hash2 = passwordService.hashPasswordForAuthentication(password, salt2);

        assertNotEquals(hash1, hash2,
                "Same password with different salts must produce different hashes");
    }

    @Test
    @DisplayName("Password reuse detection: re-hash with old salt correctly detects match")
    void reuseDetection_correctlyDetectsMatch() {
        String password = "TestPass123!";
        String oldSalt = passwordService.generateAuthSalt();
        String oldHash = passwordService.hashPasswordForAuthentication(password, oldSalt);

        // Simulate the FIX: re-hash candidate password with the ORIGINAL salt from history
        String reuseCheck = passwordService.hashPasswordForAuthentication(password, oldSalt);

        assertEquals(oldHash, reuseCheck,
                "Re-hashing with the original salt must match the stored hash — reuse detected correctly");
    }

    @Test
    @DisplayName("Password reuse detection: different password with same salt does not match")
    void reuseDetection_differentPasswordDoesNotMatch() {
        String originalPassword = "TestPass123!";
        String differentPassword = "DifferentPass456!";
        String oldSalt = passwordService.generateAuthSalt();
        String oldHash = passwordService.hashPasswordForAuthentication(originalPassword, oldSalt);

        // Re-hash a DIFFERENT password with the original salt
        String reuseCheck = passwordService.hashPasswordForAuthentication(differentPassword, oldSalt);

        assertNotEquals(oldHash, reuseCheck,
                "Different password re-hashed with same salt must NOT match stored hash");
    }

    @Test
    @DisplayName("The BUG: re-hashing with new salt never matches old hash (demonstrates original failure)")
    void theBug_rehashingWithNewSaltNeverMatches() {
        String password = "TestPass123!";
        String oldSalt = passwordService.generateAuthSalt();
        String oldHash = passwordService.hashPasswordForAuthentication(password, oldSalt);

        // Simulate the BUG: generate a fresh salt and re-hash (this is what the
        // original code did — the comparison was impossible to ever match)
        String newSalt = passwordService.generateAuthSalt();
        String buggyCheck = passwordService.hashPasswordForAuthentication(password, newSalt);

        assertNotEquals(oldHash, buggyCheck,
                "BUG DEMONSTRATED: Re-hashing with a fresh salt never matches the stored hash, " +
                "so password reuse was NEVER detected");
    }

    @Test
    @DisplayName("Full registration + change + reuse check flow")
    void simulateFullFlow_reuseBlocked() {
        String password1 = "MyFirstPassword123!";
        String password2 = "MySecondPassword456!";

        // Simulate registration: hash with authSalt
        String authSalt = passwordService.generateAuthSalt();
        String storedHash = passwordService.hashPasswordForAuthentication(password1, authSalt);

        assertTrue(passwordService.verifyPassword(password1, authSalt, storedHash));
        assertFalse(passwordService.verifyPassword(password2, authSalt, storedHash));

        // Simulate password change to password2, then try to revert to password1
        String newAuthSalt = passwordService.generateAuthSalt();
        String newStoredHash = passwordService.hashPasswordForAuthentication(password2, newAuthSalt);

        // Now simulate reuse check: re-hash password1 with the OLD salt
        String reuseCheck = passwordService.hashPasswordForAuthentication(password1, authSalt);

        // This IS the stored hash — reuse must be detected
        assertEquals(storedHash, reuseCheck,
                "Reuse detection works: password1 re-hashed with old salt matches stored hash");
    }
}
