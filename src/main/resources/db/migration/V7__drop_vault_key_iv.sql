-- vault_key_iv was part of the legacy DEK model and is no longer used
ALTER TABLE users DROP COLUMN IF EXISTS vault_key_iv;
