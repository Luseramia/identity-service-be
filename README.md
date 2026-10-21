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

## Web console (React + Vite)

The frontend is a separate sibling project at [`../identity-service-fe`](../identity-service-fe/README.md). It creates an ECDSA P-256 key pair in the browser, registers only its public key, signs login challenges, and supports login approval and device-flow approval. See its README for frontend setup and the Bear Hugs theme.

```powershell
# terminal 1 — start the API, with CORS allowing the Vite origin
# In .env: SSO_ISSUER=http://localhost:3001
#          CORS_ALLOWED_ORIGINS=http://localhost:5173
bun run dev

# terminal 2 — from the identity-service directory
Set-Location ..\identity-service-fe
Copy-Item .env.example .env
npm.cmd ci
npm.cmd run dev
```

Use `http://localhost:5173`. The default `x-webapp` client supports Finance, Documents, and Market scopes. Set `WEBAPP_OAUTH_REDIRECT_URIS` to the console callback URL before seeding when using another origin.

The default login screen accepts a name, creates or reuses a browser key, proves key possession, and waits for an administrator to approve the requested permissions. The requester receives JWT access/refresh tokens and an HttpOnly session cookie after approval. Ordinary users do not need an enrollment token.

## Bootstrap an approver

After configuring PostgreSQL, Redis, and Vault:

```powershell
bun run migrate
bun run seed:clients
bun run user:create -- "Administrator"
# Use the userId printed by user:create:
bun run user:approver grant <identity-uuid>
```

In the web console, open **ลงทะเบียนอุปกรณ์** and register the administrator's device with the one-time enrollment token. Then open **เข้าสู่ระบบผู้ดูแล** and sign in with that device. **คิวอนุมัติและสิทธิ์** displays pending requests and permission controls. Use a separate browser profile or device to test the requester flow.

Only users with the `approver` role can manage requests and access grants. The API rejects self-approval. A second approver is needed when an administrator requests business access for their own identity. Role removal is available with `bun run user:approver revoke <identity-uuid>`.

Existing users and enrolled devices remain registered, but business token issuance now requires both a user access grant and an approved login. Signing in directly with an enrolled key creates an identity session for console administration; it does not bypass business login approval.

See [the approval integration guide](docs/login-approvals.md) for endpoint payloads, token lifecycle, and linking existing Business API data.

## Operations

```powershell
bun run user:create -- "Display name"
bun run access:revoke user <identity-uuid>
bun run configure:vault
bun run verify:vault
```

The runtime Vault policy is restricted to reading the signing key metadata and signing access tokens. This service is the only repository that receives a Vault token.
