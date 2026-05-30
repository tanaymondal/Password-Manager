package com.securevault.config;

public final class EncryptionConstants {

    public static final int CURRENT_ENCRYPTION_VERSION = 2;

    public static final int DEFAULT_KDF_ITERATIONS = Integer.parseInt(
            System.getenv().getOrDefault("KDF_ITERATIONS", "3"));
    public static final int DEFAULT_KDF_MEMORY = Integer.parseInt(
            System.getenv().getOrDefault("KDF_MEMORY", "98304")); // 96MB in KiB
    public static final int DEFAULT_KDF_PARALLELISM = Integer.parseInt(
            System.getenv().getOrDefault("KDF_PARALLELISM", "4"));

    private EncryptionConstants() {}
}
