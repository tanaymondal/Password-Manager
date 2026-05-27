package com.securevault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Auth hash is required")
    @Size(max = 1024, message = "Auth hash must not exceed 1024 characters")
    private String authHash;

    @NotBlank(message = "Auth salt is required")
    @Size(max = 1024, message = "Auth salt must not exceed 1024 characters")
    private String authSalt;

    @NotBlank(message = "Encryption salt is required")
    @Size(max = 1024, message = "Encryption salt must not exceed 1024 characters")
    private String encryptionSalt;

    @NotBlank(message = "Wrapped vault key is required")
    @Size(max = 100000, message = "Wrapped vault key must not exceed 100KB")
    private String wrappedVaultKey;

    @NotNull(message = "Encryption version is required")
    private Integer encryptionVersion;

    private String deviceId;
}