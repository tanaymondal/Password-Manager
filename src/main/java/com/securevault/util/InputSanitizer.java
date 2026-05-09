package com.securevault.util;

import java.util.UUID;
import java.util.regex.Pattern;

public class InputSanitizer {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,100}$");

    public static String sanitizeEmail(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase();
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }

    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        return input.trim();
    }

    public static boolean isSafeInput(String input) {
        if (input == null || input.isBlank()) {
            return false;
        }
        return SAFE_PATTERN.matcher(input).matches();
    }

    public static boolean isValidUUID(String uuid) {
        if (uuid == null || uuid.isBlank()) {
            return false;
        }
        try {
            UUID.fromString(uuid);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private InputSanitizer() {
    }
}