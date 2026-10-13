import pool from "../src/pg-connector";
import { hashToken, randomOpaqueToken } from "../src/security/crypto";

const displayName = process.argv.slice(2).join(" ").trim();
if (!displayName || displayName.length > 160) {
  console.error('Usage: bun run identity:create-user -- "Display name"');
  process.exit(1);
}
const ttlSeconds = Number(process.env.IDENTITY_ENROLLMENT_TOKEN_TTL_SECONDS ?? 86_400);
if (!Number.isInteger(ttlSeconds) || ttlSeconds < 300 || ttlSeconds > 604_800) {
  console.error("IDENTITY_ENROLLMENT_TOKEN_TTL_SECONDS must be between 300 and 604800");
  process.exit(1);
}

const token = randomOpaqueToken();
try {
  const result = await pool.begin(async (transaction) => {
    const users = await transaction`
      INSERT INTO identity_users (display_name) VALUES (${displayName})
      RETURNING id, display_name, status`;
    const user = users[0] as { id: string; display_name: string; status: string };
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    await transaction`
      INSERT INTO identity_enrollment_tokens (user_id, token_hash, expires_at)
      VALUES (${user.id}, ${hashToken(token)}, ${expiresAt})`;
    return { user, expiresAt };
  });
  console.log(JSON.stringify({
    userId: result.user.id,
    displayName: result.user.display_name,
    status: result.user.status,
    enrollmentToken: token,
    enrollmentTokenExpiresAt: result.expiresAt.toISOString(),
    note: "The enrollment token is shown once and only its SHA-256 hash is stored.",
  }, null, 2));
} finally {
  await pool.close();
}
