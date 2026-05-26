package com.securevault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Auth hash is required")
    private String authHash;

    @NotBlank(message = "Encryption salt is required")
    private String encryptionSalt;

    @NotBlank(message = "Wrapped vault key is required")
    private String wrappedVaultKey;

    @NotNull(message = "Encryption version is required")
    private Integer encryptionVersion;

    private String deviceId;
}