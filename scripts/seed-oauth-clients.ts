import pool from "../src/pg-connector";

const list = (name: string, fallback: string) =>
  (process.env[name] ?? fallback).split(",").map((value) => value.trim()).filter(Boolean);

const clients = [
  {
    id: process.env.FINANCE_OAUTH_CLIENT_ID ?? "finance-web",
    name: "Finance Web",
    redirects: list("FINANCE_OAUTH_REDIRECT_URIS", "http://127.0.0.1:5173/oauth/callback"),
    scopes: ["openid", "profile", "finance:read", "finance:write"],
    resources: [process.env.BUSINESS_API_AUDIENCE ?? "urn:bun-sso:business-api"],
  },
  {
    id: process.env.DOCUMENTS_OAUTH_CLIENT_ID ?? "documents-web",
    name: "Documents Web",
    redirects: list("DOCUMENTS_OAUTH_REDIRECT_URIS", "http://127.0.0.1:5174/oauth/callback"),
    scopes: ["openid", "profile", "documents:read", "documents:write"],
    resources: [process.env.BUSINESS_API_AUDIENCE ?? "urn:bun-sso:business-api"],
  },
  {
    id: process.env.MARKET_OAUTH_CLIENT_ID ?? "market-client",
    name: "Market Client",
    redirects: list("MARKET_OAUTH_REDIRECT_URIS", "http://127.0.0.1:5175/oauth/callback"),
    scopes: ["openid", "profile", "market:read", "market:write"],
    resources: [process.env.BUSINESS_API_AUDIENCE ?? "urn:bun-sso:business-api"],
  },
];

try {
  await pool.begin(async (transaction) => {
    for (const client of clients) {
      await transaction`
        INSERT INTO oauth_clients
          (id, name, type, client_secret_hash, allowed_scopes, allowed_resources, status)
        VALUES
          (${client.id}, ${client.name}, 'public', NULL,
           string_to_array(${client.scopes.join("\n")}, E'\n'),
           string_to_array(${client.resources.join("\n")}, E'\n'), 'ACTIVE')
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          type = EXCLUDED.type,
          client_secret_hash = NULL,
          allowed_scopes = EXCLUDED.allowed_scopes,
          allowed_resources = EXCLUDED.allowed_resources,
          status = 'ACTIVE',
          updated_at = now()`;
      await transaction`DELETE FROM oauth_redirect_uris WHERE client_id = ${client.id}`;
      for (const redirect of client.redirects) {
        const url = new URL(redirect);
        if (!["https:", "http:"].includes(url.protocol) || url.hash) {
          throw new Error(`Unsupported redirect URI: ${redirect}`);
        }
        await transaction`
          INSERT INTO oauth_redirect_uris (client_id, redirect_uri)
          VALUES (${client.id}, ${url.toString()})`;
      }
    }
  });
  console.log(JSON.stringify(clients.map(({ id, redirects, scopes, resources }) => ({
    id, redirects, scopes, resources,
  })), null, 2));
} finally {
  await pool.close();
}
