import pool from "../src/pg-connector";

const [kind, id] = process.argv.slice(2);
if (!id || !["user", "client", "credential"].includes(kind ?? "")) {
  console.error("Usage: bun run identity:revoke <user|client|credential> <id>");
  process.exit(1);
}

try {
  const result = await pool.begin(async (transaction) => {
    if (kind === "user") {
      const rows = await transaction`
        UPDATE identity_users SET status = 'DISABLED', updated_at = now()
        WHERE id = ${id} AND status <> 'DISABLED' RETURNING id`;
      if (!rows.length) return false;
      await transaction`
        UPDATE identity_browser_sessions SET revoked_at = COALESCE(revoked_at, now())
        WHERE user_id = ${id}`;
      await transaction`
        UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
        WHERE user_id = ${id}`;
      await transaction`
        INSERT INTO identity_audit_events (actor_id, action, metadata)
        VALUES (${id}, 'user.disabled', jsonb_build_object('source', 'admin_cli'))`;
      return true;
    }
    if (kind === "client") {
      const rows = await transaction`
        UPDATE oauth_clients SET status = 'DISABLED', updated_at = now()
        WHERE id = ${id} AND status <> 'DISABLED' RETURNING id`;
      if (!rows.length) return false;
      await transaction`
        UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
        WHERE client_id = ${id}`;
      await transaction`
        INSERT INTO identity_audit_events (client_id, action, metadata)
        VALUES (${id}, 'client.disabled', jsonb_build_object('source', 'admin_cli'))`;
      return true;
    }

    const rows = await transaction`
      UPDATE identity_credentials SET status = 'REVOKED'
      WHERE credential_id = ${id} AND status <> 'REVOKED'
      RETURNING user_id`;
    const userId = (rows[0] as { user_id?: string } | undefined)?.user_id;
    if (!userId) return false;
    await transaction`
      UPDATE identity_browser_sessions SET revoked_at = COALESCE(revoked_at, now())
      WHERE user_id = ${userId}`;
    await transaction`
      UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
      WHERE user_id = ${userId}`;
    await transaction`
      INSERT INTO identity_audit_events (actor_id, action, metadata)
      VALUES (${userId}, 'credential.revoked',
              jsonb_build_object('source', 'admin_cli', 'credentialId', ${id}))`;
    return true;
  });
  if (!result) {
    console.error(`${kind} was not found or was already revoked`);
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify({ status: "revoked", kind, id }));
  }
} finally {
  await pool.close();
}
