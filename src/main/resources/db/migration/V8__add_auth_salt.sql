-- Add per-user random auth salt for client-side Argon2id derivation
-- Previously the email was used as the Argon2id salt, which meant
-- the same email+password across deployments produced identical auth hashes.
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_salt VARCHAR(255) NOT NULL DEFAULT '';

-- Update existing users to use their email as auth salt for backward compatibility
UPDATE users SET auth_salt = email WHERE auth_salt = '';

-- After update, set the default to null (new registrations must provide auth_salt)
ALTER TABLE users ALTER COLUMN auth_salt DROP DEFAULT;
