# Login approvals and business permissions

## Behavior

1. The application supplies its configured OAuth client and API resource. The requester selects scopes and submits a display name and ECDSA P-256 public key. Private keys stay in IndexedDB in that browser origin.
2. The requester signs a one-time challenge. Only proven requests enter the administrator's queue.
3. An authenticated approver selects a subset of the requested scopes and approves or rejects the request. A known credential always identifies its existing user. A new credential creates a new user unless the approver explicitly selects an existing account. Names are display labels and never establish account ownership.
4. The requester signs a distinct polling message and waits for the decision. Successful redemption atomically consumes the approval and persists its browser session and refresh token. Concurrent redemptions return tokens to at most one caller. Rejection remains observable until request expiry.
5. The returned JWT subject is the requester. The approver's ID is recorded separately in `identity_login_approvals` and the audit log.

Each new approval login requires another administrator decision. The resulting browser session can use Authorization Code + PKCE and Device Grant only for that approved client, resource, and scope subset. Refresh tokens renew the approved session without prompting the approver on every API call. A direct credential session alone cannot authorize business tokens.

Requests expire after `SSO_LOGIN_APPROVAL_TTL_SECONDS` (default 600 seconds). Proof-required and expired requests do not appear in the pending queue. Historical requests remain in PostgreSQL for audit; apply a retention policy appropriate to your deployment. PostgreSQL stores the durable decision, while Redis still stores short-lived challenges and OAuth transactions.

## Setup and migration

Run `bun run migrate` using a migration-capable database account, then reapply `infra/postgres/identity-runtime-roles.sql` through the existing deployment process so the runtime role can access the three new tables. Run `bun run seed:clients` to add `x-webapp`; seeding also updates existing configured clients.

Create the first administrator with `bun run user:create -- "Administrator"`, assign the role using `bun run user:approver grant <uuid>`, enroll the administrator's browser with the printed enrollment token, and sign in. Enrollment tokens are still available for trusted administrator/device provisioning; public login requests do not require them.

Clients must allow the web origin in `CORS_ALLOWED_ORIGINS`. Cookie-backed mutations reject untrusted `Origin` values, and administrative mutations accept JSON only. Use HTTPS outside local development. Frontend configuration defaults to `x-webapp` and `urn:bun-sso:business-api`.

No grants are automatically assigned to existing users during migration. Existing browser/refresh sessions without an approval binding cannot issue business tokens. Existing JWTs remain usable until their normal expiry and the resource server's clock-skew allowance. Arrange administrator access and approval before cutting clients over to this flow.

## Requester API

`GET /auth/clients` lists public client IDs, display names, allowed scopes, and resources. It never returns client secrets.

Public clients can start a request without a secret. Confidential clients must authenticate the start request using HTTP Basic or `client_secret` in the JSON body; keep those credentials on the application's backend. The stored request and device proof bind subsequent approval redemption to that authenticated start. Standard OAuth token and refresh requests still require confidential-client authentication.

```http
POST /auth/approvals/start
Content-Type: application/json

{
  "display_name": "Alice",
  "credential_id": "browser-generated-uuid",
  "public_key": "base64-encoded-SPKI-public-key",
  "client_id": "x-webapp",
  "resource": "urn:bun-sso:business-api",
  "scope": "openid profile finance:read documents:read"
}
```

The response contains `requestId`, `message`, `pollMessage`, `expiresIn`, and `interval`. Sign the UTF-8 `message` using ECDSA P-256 / SHA-256 with a 64-byte IEEE P1363 signature, encoded as base64url, then send:

```http
POST /auth/approvals/<requestId>/prove
Content-Type: application/json

{"signature":"base64url-signature-of-message"}
```

Sign `pollMessage` separately, then poll at the returned interval (default five seconds):

```http
POST /auth/approvals/<requestId>/poll
Content-Type: application/json

{"signature":"base64url-signature-of-pollMessage"}
```

The response status is `pending`, `approved`, `rejected`, `expired`, or `consumed`. The successful `approved` response includes `access_token`, `refresh_token`, `token_type`, `expires_in`, `scope`, `user_id`, `expires_at`, and an `id_token` when `openid` was approved. It also sets the HttpOnly browser session cookie. Use `credentials: "include"` for browser requests; the raw cookie secret is never returned in JSON.

Store the device key before sending the request. The console stores pending request metadata in sessionStorage and resumes polling after a reload; it holds OAuth tokens in memory. If the successful response is lost after atomic consumption, use the established cookie session with Authorization Code + PKCE, or submit another approval request. Consumed approvals cannot be replayed. A Vault signing failure before consumption leaves the approval available for retry.

`GET /auth/session` returns the current identity, session expiry, approver flag, and approval ID. `DELETE /auth/session` logs out the browser session. Use `/oauth/revoke` to revoke a refresh-token family separately; logout does not invalidate already issued access tokens.

## Administrator API

All administrative endpoints require an authenticated cookie session whose user currently has the `approver` role. The role is checked on each request.

| Endpoint | Payload / result |
| --- | --- |
| `GET /admin/overview` | Pending requests, users, active client policy, and access grants |
| `POST /admin/approvals/<uuid>/approve` | `{"scopes":["openid","finance:read"],"target_user_id":"optional-existing-uuid"}` |
| `POST /admin/approvals/<uuid>/reject` | `{}` |
| `POST /admin/access-grants` | `{"user_id":"uuid","client_id":"x-webapp","resource":"urn:bun-sso:business-api","scopes":["finance:read"]}` |
| `POST /admin/access-grants/revoke` | `{"user_id":"uuid","client_id":"x-webapp","resource":"urn:bun-sso:business-api"}` |

Approval adds selected scopes to that user's durable grant. It does not silently remove previously granted scopes. The individual login receives only the selected subset. Updating an access grant explicitly replaces its scope list. Revoking deletes that grant. Both management actions revoke refresh sessions for that user/client/resource. All decisions and grant changes are audited.

Every token-issuing path checks the active user, active credential, current client policy, current user grant, and approval binding. Refresh rechecks these conditions and cannot expand its original scopes. Grant increases require a new approval login to receive broader permissions. Revoking access does not instantly invalidate a JWT already accepted offline by a resource server; use short token lifetimes or add resource-side online revocation if immediate invalidation becomes a requirement.

## Existing Business API data

Identity UUIDs and legacy business owner IDs are separate. After approving or explicitly linking a user, map the identity to the correct existing owner in the `business-api` repository:

```powershell
bun run subject:map <identity-uuid> <legacy-owner-id> all
```

Use `finance`, `documents`, or `market` instead of `all` when mapping only one module. The business API continues to check its module scope and data ownership. This service does not write directly to business tables or automatically choose a legacy owner from a supplied display name.

The old `x-webapp` login component must call the new start/prove/poll endpoints, retain its browser credential, and send the returned JWT to Business API. The new console includes this flow as a reference implementation. The legacy `/sso/*` endpoints and custom Vault `base64.signature` token format are not restored.
