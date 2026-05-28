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

    @jakarta.validation.constraints.Min(value = 1, message = "KDF iterations must be at least 1")
    @jakarta.validation.constraints.Max(value = 100, message = "KDF iterations must not exceed 100")
    private Integer kdfIterations;

    @jakarta.validation.constraints.Min(value = 8192, message = "KDF memory must be at least 8MB")
    @jakarta.validation.constraints.Max(value = 1048576, message = "KDF memory must not exceed 1GB")
    private Integer kdfMemory;

    @jakarta.validation.constraints.Min(value = 1, message = "KDF parallelism must be at least 1")
    @jakarta.validation.constraints.Max(value = 16, message = "KDF parallelism must not exceed 16")
    private Integer kdfParallelism;

    @Size(max = 255, message = "Device ID must not exceed 255 characters")
    private String deviceId;
}