# Identity Service

OAuth 2.1 and OpenID Connect service for the business platform. It owns identities, browser sessions, OAuth clients, refresh-token families, and Vault Transit signing.

## Run locally

```powershell
Copy-Item .env.example .env
bun install
bun run migrate
bun run seed:clients
bun run dev
```

The service exposes discovery at `/.well-known/openid-configuration` and public signing keys at `/.well-known/jwks.json`. Keep `SSO_ISSUER` stable: it is the token `iss` value consumed by Business API.

## Operations

```powershell
bun run user:create -- "Display name"
bun run access:revoke user <identity-uuid>
bun run configure:vault
bun run verify:vault
```

The runtime Vault policy is restricted to reading the signing key metadata and signing access tokens. This service is the only repository that receives a Vault token.
