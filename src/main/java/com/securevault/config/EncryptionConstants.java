package com.securevault.config;

public final class EncryptionConstants {

    public static final int CURRENT_ENCRYPTION_VERSION = 2;

    public static final int DEFAULT_KDF_ITERATIONS = 4;
    public static final int DEFAULT_KDF_MEMORY = 65536; // 64MB in KiB
    public static final int DEFAULT_KDF_PARALLELISM = 4;

    private EncryptionConstants() {}
}
