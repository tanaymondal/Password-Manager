package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PreLoginResponse {
    @JsonProperty("authSalt")
    private String authSalt;

    @JsonProperty("kdfIterations")
    private Integer kdfIterations;

    @JsonProperty("kdfMemory")
    private Integer kdfMemory;

    @JsonProperty("kdfParallelism")
    private Integer kdfParallelism;

    public PreLoginResponse(String authSalt) {
        this.authSalt = authSalt;
        this.kdfIterations = com.securevault.config.EncryptionConstants.DEFAULT_KDF_ITERATIONS;
        this.kdfMemory = com.securevault.config.EncryptionConstants.DEFAULT_KDF_MEMORY;
        this.kdfParallelism = com.securevault.config.EncryptionConstants.DEFAULT_KDF_PARALLELISM;
    }
}
