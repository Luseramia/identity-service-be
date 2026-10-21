import pool from "../src/pg-connector";
import { validUuid } from "../src/services/approval-service";

const [action, userId] = process.argv.slice(2);
if (!["grant", "revoke"].includes(action ?? "") || !userId || !validUuid(userId)) {
  console.error("Usage: bun run user:approver <grant|revoke> <identity-uuid>");
  process.exit(1);
}
try {
  await pool.begin(async (tx) => {
    const users = await tx`SELECT id FROM identity_users WHERE id = ${userId} AND status = 'ACTIVE' FOR UPDATE`;
    if (!users.length) throw new Error("Active identity user not found");
    if (action === "grant") {
      await tx`INSERT INTO identity_user_roles (user_id, role) VALUES (${userId}, 'approver') ON CONFLICT DO NOTHING`;
    } else {
      await tx`DELETE FROM identity_user_roles WHERE user_id = ${userId} AND role = 'approver'`;
    }
    await tx`INSERT INTO identity_audit_events (actor_id, action, metadata)
      VALUES (${userId}, ${`approver.${action}`}, ${{ source: "admin_cli" }})`;
  });
  console.log(JSON.stringify({ userId, role: "approver", action }));
} finally { await pool.close(); }
