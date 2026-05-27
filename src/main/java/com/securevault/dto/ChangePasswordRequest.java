package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {

    @NotBlank(message = "Current auth hash is required")
    @Size(max = 1024, message = "Current auth hash must not exceed 1024 characters")
    @JsonProperty("current_auth_hash")
    private String currentAuthHash;

    @NotBlank(message = "New auth hash is required")
    @Size(max = 1024, message = "New auth hash must not exceed 1024 characters")
    @JsonProperty("new_auth_hash")
    private String newAuthHash;

    @NotBlank(message = "New encryption salt is required")
    @Size(max = 1024, message = "New encryption salt must not exceed 1024 characters")
    @JsonProperty("new_encryption_salt")
    private String newEncryptionSalt;

    @Size(max = 100000, message = "Wrapped vault key must not exceed 100KB")
    @JsonProperty("wrapped_vault_key")
    private String wrappedVaultKey;
}