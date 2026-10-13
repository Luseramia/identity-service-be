import type { SQL } from "bun";
import type {
  AuditEventInput,
  BrowserSession,
  IdentityCredential,
  IdentityRepository,
  IdentityUser,
  OAuthClient,
  RefreshRotationResult,
  RefreshSessionInput,
} from "./identity-repository";

export class PostgresIdentityRepository implements IdentityRepository {
  constructor(private readonly sql: SQL) {}

  async ready() {
    await this.sql`SELECT 1`;
  }

  async findClient(clientId: string): Promise<OAuthClient | null> {
    const rows = await this.sql`
      SELECT c.id, c.name, c.type, c.client_secret_hash, c.allowed_scopes,
             c.allowed_resources, c.status,
             COALESCE(array_agg(r.redirect_uri) FILTER (WHERE r.redirect_uri IS NOT NULL), '{}') AS redirect_uris
      FROM oauth_clients c
      LEFT JOIN oauth_redirect_uris r ON r.client_id = c.id
      WHERE c.id = ${clientId}
      GROUP BY c.id`;
    const row = rows[0] as any;
    return row
      ? {
          id: row.id,
          name: row.name,
          type: row.type,
          clientSecretHash: row.client_secret_hash,
          redirectUris: row.redirect_uris ?? [],
          allowedScopes: row.allowed_scopes ?? [],
          allowedResources: row.allowed_resources ?? [],
          status: row.status,
        }
      : null;
  }

  async findUser(userId: string): Promise<IdentityUser | null> {
    const rows = await this.sql`
      SELECT id, display_name, status FROM identity_users WHERE id = ${userId}`;
    const row = rows[0] as any;
    return row
      ? { id: row.id, displayName: row.display_name, status: row.status }
      : null;
  }

  async findCredential(credentialId: string): Promise<IdentityCredential | null> {
    const rows = await this.sql`
      SELECT c.id, c.user_id, c.credential_id, c.public_key, c.algorithm,
             c.status, u.status AS user_status
      FROM identity_credentials c
      JOIN identity_users u ON u.id = c.user_id
      WHERE c.credential_id = ${credentialId}`;
    const row = rows[0] as any;
    return row
      ? {
          id: row.id,
          userId: row.user_id,
          credentialId: row.credential_id,
          publicKey: row.public_key,
          algorithm: row.algorithm,
          status: row.status,
          userStatus: row.user_status,
        }
      : null;
  }

  async findEnrollment(tokenHash: string) {
    const rows = await this.sql`
      SELECT id, user_id FROM identity_enrollment_tokens
      WHERE token_hash = ${tokenHash} AND consumed_at IS NULL AND expires_at > now()`;
    const row = rows[0] as any;
    return row ? { id: row.id, userId: row.user_id } : null;
  }

  async completeEnrollment(input: {
    enrollmentId: string;
    userId: string;
    credentialId: string;
    publicKey: string;
    algorithm: string;
  }) {
    await this.sql.begin(async (tx) => {
      const consumed = await tx`
        UPDATE identity_enrollment_tokens SET consumed_at = now()
        WHERE id = ${input.enrollmentId} AND user_id = ${input.userId}
          AND consumed_at IS NULL AND expires_at > now()
        RETURNING id`;
      if (consumed.length !== 1) throw new Error("Enrollment token is no longer valid");
      await tx`
        INSERT INTO identity_credentials
          (user_id, type, credential_id, public_key, algorithm)
        VALUES
          (${input.userId}, 'device_key', ${input.credentialId}, ${input.publicKey}, ${input.algorithm})`;
    });
  }

  async createBrowserSession(input: {
    tokenHash: string;
    userId: string;
    authenticationMethod: string;
    authenticatedAt: Date;
    expiresAt: Date;
  }) {
    await this.sql`
      INSERT INTO identity_browser_sessions
        (token_hash, user_id, authentication_method, authenticated_at, expires_at, last_seen_at)
      VALUES
        (${input.tokenHash}, ${input.userId}, ${input.authenticationMethod},
         ${input.authenticatedAt}, ${input.expiresAt}, ${input.authenticatedAt})`;
  }

  async findBrowserSession(tokenHash: string, now: Date): Promise<BrowserSession | null> {
    const rows = await this.sql`
      UPDATE identity_browser_sessions s
      SET last_seen_at = ${now}
      FROM identity_users u
      WHERE s.token_hash = ${tokenHash} AND s.user_id = u.id
        AND s.revoked_at IS NULL AND s.expires_at > ${now}
        AND u.status = 'ACTIVE'
      RETURNING s.id, s.authentication_method, s.authenticated_at, s.expires_at,
                u.id AS user_id, u.display_name, u.status AS user_status`;
    const row = rows[0] as any;
    return row
      ? {
          id: row.id,
          authenticationMethod: row.authentication_method,
          authenticatedAt: new Date(row.authenticated_at),
          expiresAt: new Date(row.expires_at),
          user: {
            id: row.user_id,
            displayName: row.display_name,
            status: row.user_status,
          },
        }
      : null;
  }

  async revokeBrowserSession(tokenHash: string) {
    await this.sql`
      UPDATE identity_browser_sessions SET revoked_at = now()
      WHERE token_hash = ${tokenHash} AND revoked_at IS NULL`;
  }

  async createRefreshSession(input: RefreshSessionInput) {
    const familyId = input.familyId ?? crypto.randomUUID();
    await this.sql`
      INSERT INTO oauth_refresh_sessions
        (family_id, token_hash, user_id, client_id, scopes, resource, expires_at)
      VALUES
        (${familyId}, ${input.tokenHash}, ${input.userId}, ${input.clientId},
         string_to_array(${input.scopes.join("\n")}, E'\n'),
         ${input.resource}, ${input.expiresAt})`;
    return familyId;
  }

  async rotateRefreshSession(input: {
    currentTokenHash: string;
    replacementTokenHash: string;
    replacementExpiresAt: Date;
    clientId: string;
    now: Date;
  }): Promise<RefreshRotationResult> {
    return this.sql.begin(async (tx) => {
      const rows = await tx`
        SELECT id, family_id, user_id, client_id, scopes, resource, expires_at,
               rotated_at, revoked_at
        FROM oauth_refresh_sessions
        WHERE token_hash = ${input.currentTokenHash}
        FOR UPDATE`;
      const row = rows[0] as any;
      if (!row || row.client_id !== input.clientId) return { status: "invalid" as const };
      if (row.rotated_at || row.revoked_at) {
        await tx`
          UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, ${input.now})
          WHERE family_id = ${row.family_id}`;
        return {
          status: "reused" as const,
          userId: row.user_id,
          clientId: row.client_id,
        };
      }
      if (new Date(row.expires_at) <= input.now) {
        await tx`
          UPDATE oauth_refresh_sessions SET revoked_at = ${input.now}
          WHERE id = ${row.id}`;
        return { status: "expired" as const };
      }

      await tx`
        UPDATE oauth_refresh_sessions SET rotated_at = ${input.now}
        WHERE id = ${row.id}`;
      await tx`
        INSERT INTO oauth_refresh_sessions
          (family_id, token_hash, user_id, client_id, scopes, resource, expires_at)
        VALUES
          (${row.family_id}, ${input.replacementTokenHash}, ${row.user_id},
           ${row.client_id},
           string_to_array(${(row.scopes ?? []).join("\n")}, E'\n'),
           ${row.resource}, ${input.replacementExpiresAt})`;
      return {
        status: "rotated" as const,
        userId: row.user_id,
        clientId: row.client_id,
        scopes: row.scopes ?? [],
        resource: row.resource,
        familyId: row.family_id,
      };
    });
  }

  async revokeRefreshSession(tokenHash: string, clientId: string) {
    await this.sql.begin(async (tx) => {
      const rows = await tx`
        SELECT family_id FROM oauth_refresh_sessions
        WHERE token_hash = ${tokenHash} AND client_id = ${clientId}`;
      const row = rows[0] as any;
      if (row) {
        await tx`
          UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
          WHERE family_id = ${row.family_id}`;
      }
    });
  }

  async audit(event: AuditEventInput) {
    await this.sql`
      INSERT INTO identity_audit_events
        (actor_id, client_id, action, ip_address, user_agent, metadata)
      VALUES
        (${event.actorId ?? null}, ${event.clientId ?? null}, ${event.action},
         ${event.ipAddress ?? null}, ${event.userAgent ?? null}, ${event.metadata ?? {}})`;
  }
}

