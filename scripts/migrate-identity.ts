import pool from "../src/pg-connector";
import { fileURLToPath } from "node:url";

const expectedTables = [
  "identity_audit_events",
  "identity_browser_sessions",
  "identity_credentials",
  "identity_enrollment_tokens",
  "identity_users",
  "oauth_clients",
  "oauth_redirect_uris",
  "oauth_refresh_sessions",
];

try {
  const migrationsDirectory = new URL("../migrations/identity/", import.meta.url);
  const migrationsPath = fileURLToPath(migrationsDirectory);
  const migrations: string[] = [];
  const glob = new Bun.Glob("*.sql");
  for await (const file of glob.scan({ cwd: migrationsPath })) {
    migrations.push(file);
  }
  migrations.sort();

  await pool.begin(async (transaction) => {
    await transaction`SET LOCAL search_path = public`;
    await transaction`SET LOCAL lock_timeout = '5s'`;
    await transaction`SET LOCAL statement_timeout = '20s'`;
    await transaction`SELECT pg_advisory_xact_lock(81427012)`;
    for (const file of migrations) {
      const migration = await Bun.file(new URL(file, migrationsDirectory)).text();
      for (const statement of migration
        .split(";")
        .map((part) => part.trim())
        .filter(Boolean)) {
        await transaction.unsafe(statement);
      }
    }
  });

  const tables = await pool`SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name IN (
      'identity_audit_events',
      'identity_browser_sessions',
      'identity_credentials',
      'identity_enrollment_tokens',
      'identity_users',
      'oauth_clients',
      'oauth_redirect_uris',
      'oauth_refresh_sessions'
    )
    ORDER BY table_name`;
  if (tables.length !== expectedTables.length) {
    throw new Error("Identity tables were not created in the expected schema");
  }

  console.log(
    "Identity migration complete: " +
      tables.map((row: { table_name: string }) => row.table_name).join(", "),
  );
} catch (error) {
  const rawMessage = error instanceof Error ? error.message : "unknown error";
  const password = process.env.DB_PASSWORD;
  const safeMessage = password ? rawMessage.replaceAll(password, "[redacted]") : rawMessage;
  console.error(
    `Identity migration failed: ${safeMessage}`,
  );
  process.exitCode = 1;
} finally {
  await pool.close();
}

