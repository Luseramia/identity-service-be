import { httpConfig, vaultConfig } from "./runtime-config";

export interface IdentityConfig {
  issuer: string;
  port: number;
  accessTokenTtlSeconds: number;
  idTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  deviceCodeTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  browserSessionTtlSeconds: number;
  authenticationChallengeTtlSeconds: number;
  loginApprovalTtlSeconds?: number;
  corsAllowedOrigins?: string[];
  vault: {
    address: string;
    transitMount: string;
    transitKey: string;
    keyMetadataCacheSeconds: number;
  };
}

const integer = (name: string, fallback: number) => {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
};

const segment = (name: string, fallback: string) => {
  const configured = process.env[name]?.trim() || fallback;
  if (!/^[a-zA-Z0-9_-]+$/.test(configured)) {
    throw new Error(`${name} must contain only letters, numbers, _ or -`);
  }
  return configured;
};

export function loadIdentityConfig(): IdentityConfig {
  const issuer = (process.env.SSO_ISSUER?.trim() || "http://localhost:3001").replace(
    /\/$/,
    "",
  );
  new URL(issuer);

  return {
    issuer,
    port: integer("IDENTITY_PORT", 3001),
    accessTokenTtlSeconds: integer("SSO_ACCESS_TOKEN_TTL_SECONDS", 600),
    idTokenTtlSeconds: integer("SSO_ID_TOKEN_TTL_SECONDS", 600),
    authorizationCodeTtlSeconds: integer("SSO_AUTHORIZATION_CODE_TTL_SECONDS", 90),
    deviceCodeTtlSeconds: integer("SSO_DEVICE_CODE_TTL_SECONDS", 600),
    refreshTokenTtlSeconds: integer("SSO_REFRESH_TOKEN_TTL_SECONDS", 2_592_000),
    browserSessionTtlSeconds: integer("SSO_BROWSER_SESSION_TTL_SECONDS", 28_800),
    loginApprovalTtlSeconds: integer("SSO_LOGIN_APPROVAL_TTL_SECONDS", 600),
    corsAllowedOrigins: httpConfig().corsAllowedOrigins,
    authenticationChallengeTtlSeconds: integer(
      "SSO_AUTH_CHALLENGE_TTL_SECONDS",
      300,
    ),
    vault: {
      address: vaultConfig().address,
      transitMount: segment("VAULT_TRANSIT_MOUNT", "sso-jwt"),
      transitKey: segment("VAULT_TRANSIT_ACCESS_KEY", "access-token"),
      keyMetadataCacheSeconds: integer("VAULT_KEY_CACHE_SECONDS", 30),
    },
  };
}

