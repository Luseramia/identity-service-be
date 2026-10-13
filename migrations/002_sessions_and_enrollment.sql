CREATE TABLE IF NOT EXISTS identity_enrollment_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_enrollment_tokens_hash_uidx
  ON identity_enrollment_tokens (token_hash);
CREATE INDEX IF NOT EXISTS identity_enrollment_tokens_user_idx
  ON identity_enrollment_tokens (user_id);

CREATE TABLE IF NOT EXISTS identity_browser_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL,
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  authentication_method varchar(40) NOT NULL,
  authenticated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_browser_sessions_hash_uidx
  ON identity_browser_sessions (token_hash);
CREATE INDEX IF NOT EXISTS identity_browser_sessions_user_idx
  ON identity_browser_sessions (user_id);

