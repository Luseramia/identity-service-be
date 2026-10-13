\set ON_ERROR_STOP on

-- Run through psql with identity_password supplied from deployment secrets.
SELECT 'CREATE ROLE bun_sso_identity LOGIN' WHERE NOT EXISTS
  (SELECT 1 FROM pg_roles WHERE rolname = 'bun_sso_identity') \gexec
ALTER ROLE bun_sso_identity PASSWORD :'identity_password';

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM bun_sso_identity;
GRANT CONNECT ON DATABASE :DBNAME TO bun_sso_identity;
GRANT USAGE ON SCHEMA public TO bun_sso_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  identity_users, identity_credentials, identity_enrollment_tokens,
  identity_browser_sessions, identity_audit_events, oauth_clients,
  oauth_redirect_uris, oauth_refresh_sessions
TO bun_sso_identity;
