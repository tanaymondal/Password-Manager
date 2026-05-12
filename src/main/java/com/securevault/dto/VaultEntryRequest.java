package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VaultEntryRequest {

    private String id;

    @NotBlank(message = "Encrypted data is required")
    private String encryptedData;

    @NotBlank(message = "IV is required")
    private String iv;
}