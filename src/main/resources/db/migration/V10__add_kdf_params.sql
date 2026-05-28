-- Add per-user KDF parameters for Argon2id auth hash and KEK derivation
ALTER TABLE users ADD COLUMN kdf_iterations INT NOT NULL DEFAULT 4;
ALTER TABLE users ADD COLUMN kdf_memory INT NOT NULL DEFAULT 98304;
ALTER TABLE users ADD COLUMN kdf_parallelism INT NOT NULL DEFAULT 4;
