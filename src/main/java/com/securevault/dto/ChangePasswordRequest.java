package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {

    @NotBlank(message = "Current password is required")
    @JsonProperty("current_password")
    private String currentPassword;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @JsonProperty("new_password")
    private String newPassword;

    @JsonProperty("wrapped_vault_key")
    private String wrappedVaultKey;

    @JsonProperty("new_encryption_salt")
    private String newEncryptionSalt;

    private java.util.List<VaultEntryRequest> entries;
}