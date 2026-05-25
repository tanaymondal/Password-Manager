ALTER TABLE refresh_tokens ADD COLUMN device_id VARCHAR(255);
CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);
