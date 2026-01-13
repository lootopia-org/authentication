ALTER TABLE email_otps
  ALTER COLUMN code_hash NOT NULL,
  ALTER COLUMN expires_at NOT NULL;

