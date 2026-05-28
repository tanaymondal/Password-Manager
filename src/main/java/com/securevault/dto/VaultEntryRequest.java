package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class VaultEntryRequest {

    @Size(max = 36)
    private String id;

    @NotBlank(message = "Encrypted data is required")
    @Size(max = 100000, message = "Encrypted data must not exceed 100KB")
    @Pattern(regexp = "^(v[0-9]+:)?[A-Za-z0-9+/]*={0,2}$", message = "Encrypted data must be valid Base64")
    private String encryptedData;

    @NotBlank(message = "IV is required")
    @Size(min = 16, max = 24, message = "IV must be between 16 and 24 Base64 characters")
    @Pattern(regexp = "^[A-Za-z0-9+/]*={0,2}$", message = "IV must be valid Base64")
    private String iv;
}