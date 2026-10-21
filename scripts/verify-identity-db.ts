import pool from "../src/pg-connector";

try {
  const tables = await pool`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name IN (
      'identity_users', 'identity_credentials', 'identity_enrollment_tokens',
      'identity_browser_sessions', 'identity_audit_events', 'oauth_clients',
      'oauth_redirect_uris', 'oauth_refresh_sessions',
      'identity_user_roles', 'identity_access_grants', 'identity_login_approvals'
    )`;
  if (tables.length !== 11) throw new Error(`Expected 11 identity tables, found ${tables.length}`);

  const expectedClientIds = [...new Set([
    process.env.WEBAPP_OAUTH_CLIENT_ID ?? "x-webapp",
    process.env.FINANCE_OAUTH_CLIENT_ID ?? "finance-web",
    process.env.DOCUMENTS_OAUTH_CLIENT_ID ?? "documents-web",
    process.env.MARKET_OAUTH_CLIENT_ID ?? "market-client",
  ])];
  const clients = await pool`
    SELECT id, status FROM oauth_clients
    WHERE id = ANY(string_to_array(${expectedClientIds.join("\n")}, E'\n'))`;
  if (clients.length !== expectedClientIds.length || clients.some((row: { status: string }) => row.status !== "ACTIVE")) {
    throw new Error("Expected OAuth clients are missing or inactive");
  }
  const leftovers = await pool`
    SELECT
      (SELECT count(*)::int FROM identity_users WHERE display_name = 'Identity smoke test') AS users,
      (SELECT count(*)::int FROM identity_credentials WHERE credential_id LIKE 'smoke-%') AS credentials`;
  const row = leftovers[0] as { users: number; credentials: number };
  if (row.users || row.credentials) {
    throw new Error(`Smoke cleanup failed: ${JSON.stringify(row)}`);
  }
  console.log(JSON.stringify({
    status: "ok",
    tables: tables.length,
    oauthClients: clients.map((row: { id: string }) => row.id).sort(),
    smokeArtifacts: 0,
  }, null, 2));
} finally {
  await pool.close();
}
