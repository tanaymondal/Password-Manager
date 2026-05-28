package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpgradeKdfRequest {

    @NotBlank(message = "Auth hash is required")
    @JsonProperty("authHash")
    private String authHash;

    @NotBlank(message = "Wrapped vault key is required")
    @JsonProperty("wrappedVaultKey")
    private String wrappedVaultKey;

    @NotNull(message = "KDF iterations is required")
    @JsonProperty("kdfIterations")
    private Integer kdfIterations;

    @NotNull(message = "KDF memory is required")
    @JsonProperty("kdfMemory")
    private Integer kdfMemory;

    @NotNull(message = "KDF parallelism is required")
    @JsonProperty("kdfParallelism")
    private Integer kdfParallelism;
}
