package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpgradeKdfRequest {

    @NotBlank(message = "Auth hash is required")
    @Size(max = 1024, message = "Auth hash must not exceed 1024 characters")
    @JsonProperty("authHash")
    private String authHash;

    @NotBlank(message = "Wrapped vault key is required")
    @Size(max = 100000, message = "Wrapped vault key must not exceed 100KB")
    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @NotNull(message = "KDF iterations is required")
    @Min(value = 1, message = "KDF iterations must be at least 1")
    @Max(value = 100, message = "KDF iterations must not exceed 100")
    @JsonProperty("kdfIterations")
    private Integer kdfIterations;

    @NotNull(message = "KDF memory is required")
    @Min(value = 8192, message = "KDF memory must be at least 8MB")
    @Max(value = 1048576, message = "KDF memory must not exceed 1GB")
    @JsonProperty("kdfMemory")
    private Integer kdfMemory;

    @NotNull(message = "KDF parallelism is required")
    @Min(value = 1, message = "KDF parallelism must be at least 1")
    @Max(value = 16, message = "KDF parallelism must not exceed 16")
    @JsonProperty("kdfParallelism")
    private Integer kdfParallelism;
}
