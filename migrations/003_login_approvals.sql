CREATE TABLE IF NOT EXISTS identity_user_roles (
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  role varchar(40) NOT NULL CHECK (role = 'approver'),
  PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS identity_access_grants (
  user_id uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
  client_id varchar(120) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  resource text NOT NULL,
  scopes text[] NOT NULL,
  updated_by uuid NOT NULL REFERENCES identity_users(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id, resource)
);

CREATE TABLE IF NOT EXISTS identity_login_approvals (
  id uuid PRIMARY KEY,
  display_name varchar(160) NOT NULL,
  credential_id text NOT NULL,
  public_key text NOT NULL,
  algorithm varchar(40) NOT NULL,
  message text NOT NULL,
  client_id varchar(120) NOT NULL REFERENCES oauth_clients(id),
  resource text NOT NULL,
  requested_scopes text[] NOT NULL,
  approved_scopes text[] NOT NULL DEFAULT '{}',
  user_id uuid REFERENCES identity_users(id),
  status varchar(30) NOT NULL DEFAULT 'proof_required'
    CHECK (status IN ('proof_required', 'pending', 'approved', 'rejected', 'consumed')),
  decided_by uuid REFERENCES identity_users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS identity_login_approvals_pending_idx
  ON identity_login_approvals (status, expires_at);

ALTER TABLE identity_browser_sessions ADD COLUMN IF NOT EXISTS
  approval_id uuid REFERENCES identity_login_approvals(id);
ALTER TABLE oauth_refresh_sessions ADD COLUMN IF NOT EXISTS
  approval_id uuid REFERENCES identity_login_approvals(id);
