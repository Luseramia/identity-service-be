# Identity service runbook

## Signals

- `/health/live` checks that the process can serve HTTP.
- `/health/ready` checks the active Vault signing key, PostgreSQL, and Redis.
- `/metrics` exposes login failures, token responses, refresh reuse, Vault signing
  failures and latency.
- `identity_audit_events` records enrollment, login, authorization, device
  approval/rejection, refresh rotation/reuse, and administrative revocation.

The Identity Deployment manifest is in `infra/k8s/identity.yaml`.

## Vault outage or sealed Vault

1. Confirm `/health/ready` is 503 and inspect `identity_vault_sign_failures_total`.
2. Check Vault health and seal state. Do not switch Identity to a local private key.
3. Existing access tokens remain verifiable from cached JWKS until they expire.
4. Restore Vault quorum/unseal it, then call `bun run verify:vault`.
5. Confirm Identity and Business API readiness endpoints return `ready`.

## Suspected signing-key compromise

1. Stop token issuance or remove Identity from service endpoints.
2. Rotate `sso-jwt/access-token` in Vault and restart Identity key metadata cache.
3. Keep the old public key in JWKS only when issued tokens may remain trusted.
   If the old private key is compromised, configure its Vault minimum verification
   version and force users to authenticate again.
4. Revoke browser and refresh sessions for affected users with
   `bun run access:revoke user <uuid>`.
5. Review `identity_audit_events`, restore service, and monitor forced JWKS refreshes.

## User, credential, or client revocation

```bash
bun run access:revoke user <identity-uuid>
bun run access:revoke credential <credential-id>
bun run access:revoke client <client-id>
```

User and credential revocation also revoke browser and refresh sessions. Access
tokens are intentionally short lived and expire within ten minutes.

## PostgreSQL backup and restore test

Back up Identity-owned tables with the platform secret manager supplying the
connection string:

```bash
pg_dump --format=custom --file identity.dump \
  --table='identity_*' --table='oauth_*' "$IDENTITY_DATABASE_URL"
```

Restore into an isolated database, run `bun run verify:db` against that
database, and delete the isolated database after the test. Keep backup files
encrypted and apply the same retention policy as authentication audit records.

## Redis loss

Redis contains only one-time challenges, authorization codes, and device
transactions. After a loss, clients restart the current authorization or
enrollment transaction. Browser and refresh sessions remain in PostgreSQL.

Administrator login approvals and access grants also remain in PostgreSQL. A
proven pending request can continue after Redis recovery. Review the approval
queue and `login.*` / `access.*` audit events when investigating access issues.

## Approval and permissions issues

- `approval_required`: use the request-login screen and obtain administrator
  approval for the requested client, API, and scopes. Direct device sign-in
  grants console administration only when the account has the approver role.
- `access_denied`: check user/credential status and the user's access grant.
- `subject_not_mapped` from Business API: map the identity UUID to the correct
  legacy owner with Business API's `subject:map` command.
- To recover administrator access, provision a trusted device with an enrollment
  token and use `bun run user:approver grant <uuid>` through the operator account.
- Changing grants revokes matching refresh sessions. Existing access tokens
  expire normally; browser logout alone does not revoke an OAuth refresh family.

See [login-approvals.md](login-approvals.md) for setup and API payloads.

## Clock and key rotation

- Synchronize Vault, Identity, resource APIs, PostgreSQL, and Kubernetes nodes.
- Keep every public key version in JWKS for at least the maximum access-token
  lifetime plus clock skew and JWKS cache time.
- Resource APIs force one JWKS refresh when they see an unknown `kid`.

## Legacy SSO

The `/sso/*` routes and `base64.signature` verifier are removed. The shared
Vault `sso/` mount remains because it contains unrelated keys. The `sso/login`
key is deleted, and the shared `sso` policy contains explicit deny rules for its
former sign, verify, and key paths.
