import { readFile } from "node:fs/promises";

const value = (name: string, fallback?: string) => {
  const configured = process.env[name]?.trim();
  if (configured) return configured;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable: ${name}`);
};

const integer = (name: string, fallback: number) => {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${name} must be an integer`);
  }
  return parsed;
};

export const redisConfig = () => ({
  host: value("REDIS_HOST"),
  port: integer("REDIS_PORT", 6379),
  db: integer("REDIS_DB", 0),
});

export const postgresConfig = () => ({
  hostname: value("DB_HOST"),
  port: integer("DB_PORT", 5432),
  database: value("DB_NAME"),
  username: value("DB_USER"),
  password: value("DB_PASSWORD"),
});

export const vaultConfig = () => ({
  address: value("VAULT_ADDR").replace(/\/$/, ""),
  tokenFile: value("VAULT_TOKEN_FILE", "/vault/secrets/token"),
});

export async function readVaultToken() {
  const fromEnvironment = process.env.VAULT_TOKEN?.trim();
  if (fromEnvironment) return fromEnvironment;

  const { tokenFile } = vaultConfig();
  const fromFile = (await readFile(tokenFile, "utf8")).trim();
  if (!fromFile) throw new Error(`Vault token file is empty: ${tokenFile}`);
  return fromFile;
}

export const httpConfig = () => ({
  corsAllowedOrigins: (
    process.env.CORS_ALLOWED_ORIGINS ??
    "http://localhost:3000,http://localhost:5173"
  )
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
});


