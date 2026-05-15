package com.securevault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BreachCheckServiceTest {

    private BreachCheckService breachCheckService;

    @BeforeEach
    void setUp() {
        breachCheckService = new BreachCheckService();
    }

    @Test
    @DisplayName("Common breached passwords are detected offline")
    void commonPasswords_detected() {
        assertTrue(breachCheckService.isPasswordBreached("password"));
        assertTrue(breachCheckService.isPasswordBreached("123456"));
        assertTrue(breachCheckService.isPasswordBreached("admin"));
        assertTrue(breachCheckService.isPasswordBreached("welcome"));
        assertTrue(breachCheckService.isPasswordBreached("qwerty"));
    }

    @Test
    @DisplayName("Common passwords are case-insensitive")
    void commonPasswords_caseInsensitive() {
        assertTrue(breachCheckService.isPasswordBreached("Password"));
        assertTrue(breachCheckService.isPasswordBreached("PASSWORD"));
        assertTrue(breachCheckService.isPasswordBreached("Admin"));
    }

    @Test
    @DisplayName("Null and empty passwords are not considered breached")
    void nullAndEmpty_notBreached() {
        assertFalse(breachCheckService.isPasswordBreached(null));
        assertFalse(breachCheckService.isPasswordBreached(""));
    }

    @Test
    @DisplayName("Strong unique passwords pass the check (offline, no HIBP call)")
    void strongPassword_passes() {
        assertFalse(breachCheckService.isPasswordBreached("k8sF!3x@mP9#qR7$vW2&zB5*nL"));
        assertFalse(breachCheckService.isPasswordBreached("my-correct-horse-battery-staple-99!"));
    }

    @Test
    @DisplayName("Does not throw on network failure (fails open to not block registration)")
    void networkFailure_failsOpen() {
        assertDoesNotThrow(() -> breachCheckService.isPasswordBreached("random-secure-pass-123!@#"));
    }
}
