package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ChangePasswordRequest {

    @NotBlank(message = "Current auth hash is required")
    @JsonProperty("current_auth_hash")
    private String currentAuthHash;

    @NotBlank(message = "New auth hash is required")
    @JsonProperty("new_auth_hash")
    private String newAuthHash;

    @NotBlank(message = "New encryption salt is required")
    @JsonProperty("new_encryption_salt")
    private String newEncryptionSalt;

    @JsonProperty("wrapped_vault_key")
    private String wrappedVaultKey;
}