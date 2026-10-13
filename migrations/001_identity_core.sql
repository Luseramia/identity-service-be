CREATE TABLE IF NOT EXISTS identity_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name varchar(160) NOT NULL,
  status varchar(30) NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  type varchar(30) NOT NULL,
  credential_id text NOT NULL,
  public_key text NOT NULL,
  algorithm varchar(40) NOT NULL,
  sign_count text NOT NULL DEFAULT '0',
  status varchar(30) NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_credentials_credential_id_uidx
  ON identity_credentials (credential_id);
CREATE INDEX IF NOT EXISTS identity_credentials_user_idx
  ON identity_credentials (user_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
  id varchar(120) PRIMARY KEY,
  name varchar(160) NOT NULL,
  type varchar(30) NOT NULL,
  client_secret_hash text,
  allowed_scopes text[] NOT NULL DEFAULT '{}',
  allowed_resources text[] NOT NULL DEFAULT '{}',
  status varchar(30) NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_clients_type_check CHECK (type IN ('public', 'confidential'))
);

CREATE TABLE IF NOT EXISTS oauth_redirect_uris (
  client_id varchar(120) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid NOT NULL,
  token_hash text NOT NULL,
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  client_id varchar(120) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  scopes text[] NOT NULL DEFAULT '{}',
  resource text NOT NULL,
  expires_at timestamptz NOT NULL,
  rotated_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS oauth_refresh_sessions_token_hash_uidx
  ON oauth_refresh_sessions (token_hash);
CREATE INDEX IF NOT EXISTS oauth_refresh_sessions_family_idx
  ON oauth_refresh_sessions (family_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_sessions_user_idx
  ON oauth_refresh_sessions (user_id);

CREATE TABLE IF NOT EXISTS identity_audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid,
  client_id varchar(120),
  action varchar(100) NOT NULL,
  ip_address varchar(64),
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS identity_audit_events_actor_idx
  ON identity_audit_events (actor_id);
CREATE INDEX IF NOT EXISTS identity_audit_events_created_idx
  ON identity_audit_events (created_at);

