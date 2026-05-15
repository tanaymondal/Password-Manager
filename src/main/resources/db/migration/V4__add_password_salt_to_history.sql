ALTER TABLE password_history ADD COLUMN IF NOT EXISTS password_salt VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_password_history_salt ON password_history(password_salt);
