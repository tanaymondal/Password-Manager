package com.securevault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.securevault.config.EncryptionConstants;

public class KdfConfigResponse {

    @JsonProperty("kdfIterations")
    private final int kdfIterations;

    @JsonProperty("kdfMemory")
    private final int kdfMemory;

    @JsonProperty("kdfParallelism")
    private final int kdfParallelism;

    @JsonProperty("encryptionVersion")
    private final int encryptionVersion;

    public KdfConfigResponse() {
        this.kdfIterations = EncryptionConstants.DEFAULT_KDF_ITERATIONS;
        this.kdfMemory = EncryptionConstants.DEFAULT_KDF_MEMORY;
        this.kdfParallelism = EncryptionConstants.DEFAULT_KDF_PARALLELISM;
        this.encryptionVersion = EncryptionConstants.CURRENT_ENCRYPTION_VERSION;
    }

    public int getKdfIterations() { return kdfIterations; }
    public int getKdfMemory() { return kdfMemory; }
    public int getKdfParallelism() { return kdfParallelism; }
    public int getEncryptionVersion() { return encryptionVersion; }
}
