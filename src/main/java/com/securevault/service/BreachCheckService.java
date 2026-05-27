package com.securevault.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;

@Slf4j
@Service
public class BreachCheckService {

    private static final String HIBP_URL = "https://api.pwnedpasswords.com/range/";
    private static final String USER_AGENT = "SecureVault-Password-Manager";
    private static final Set<String> COMMON_PASSWORDS = CommonPasswords.SET;

    private final RestClient restClient;

    public BreachCheckService() {
        this.restClient = RestClient.builder()
                .defaultHeader("User-Agent", USER_AGENT)
                .build();
    }

    public boolean isPasswordBreached(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }

        String lower = password.toLowerCase();
        if (COMMON_PASSWORDS.contains(lower)) {
            log.info("Password rejected: found in common breached passwords list");
            return true;
        }

        return isHashBreached(sha1Hex(password));
    }

    public boolean isHashBreached(String sha1Hex) {
        if (sha1Hex == null || sha1Hex.length() < 6) {
            return false;
        }

        try {
            String prefix = sha1Hex.substring(0, 5).toUpperCase();
            String suffix = sha1Hex.substring(5).toUpperCase();

            String response = restClient.get()
                    .uri(HIBP_URL + prefix)
                    .retrieve()
                    .body(String.class);

            if (response == null) {
                return false;
            }

            for (String line : response.split("\\r?\\n")) {
                String[] parts = line.split(":");
                if (parts.length == 2 && parts[0].equalsIgnoreCase(suffix)) {
                    int count = Integer.parseInt(parts[1]);
                    if (count > 0) {
                        log.info("Password breached: found in HIBP ({} occurrences)", count);
                        return true;
                    }
                }
            }

            return false;
        } catch (Exception e) {
            log.warn("HIBP check failed, allowing password: {}", e.getMessage());
            return false;
        }
    }

    private String sha1Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not available", e);
        }
    }
}
