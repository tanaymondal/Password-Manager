-- Add vault key management fields for DEK-wrapped model
ALTER TABLE users ADD COLUMN IF NOT EXISTS wrapped_vault_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_key_iv VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS encryption_version INTEGER DEFAULT 1;

-- Initially all existing users will have encryption_version = 1 (old format)
-- New registrations will have encryption_version = 2 (DEK-wrapped format)
UPDATE users SET encryption_version = 2 WHERE wrapped_vault_key IS NOT NULL;
UPDATE users SET encryption_version = 1 WHERE wrapped_vault_key IS NULL;

-- Force default for new column
ALTER TABLE users ALTER COLUMN encryption_version SET DEFAULT 1;

-- Add index for encryption version
CREATE INDEX IF NOT EXISTS idx_users_encryption_version ON users(encryption_version);