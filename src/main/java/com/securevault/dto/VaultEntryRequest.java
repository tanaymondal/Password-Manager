package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class VaultEntryRequest {

    @Size(max = 36)
    private String id;

    @NotBlank(message = "Encrypted data is required")
    @Size(max = 100000, message = "Encrypted data must not exceed 100KB")
    private String encryptedData;

    @NotBlank(message = "IV is required")
    @Size(max = 64, message = "IV must not exceed 64 characters")
    private String iv;
}