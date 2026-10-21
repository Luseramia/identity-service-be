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
  AccessGrant,
  LoginApproval,
} from "./identity-repository";
import { ApprovalConflictError } from "./identity-repository";

function approvalRow(row: any): LoginApproval {
  return {
    id: row.id, displayName: row.display_name, credentialId: row.credential_id,
    publicKey: row.public_key, algorithm: row.algorithm, message: row.message,
    clientId: row.client_id, resource: row.resource, requestedScopes: row.requested_scopes,
    approvedScopes: row.approved_scopes, userId: row.user_id, status: row.status,
    decidedBy: row.decided_by ?? undefined, createdAt: new Date(row.created_at), expiresAt: new Date(row.expires_at),
  };
}

export class PostgresIdentityRepository implements IdentityRepository {
  constructor(private readonly sql: SQL) {}

  async ready() {
    await this.sql`SELECT 1 FROM identity_login_approvals, identity_access_grants, identity_user_roles LIMIT 0`;
  }

  async isApprover(userId: string) {
    const rows = await this.sql`SELECT 1 FROM identity_user_roles r JOIN identity_users u ON u.id = r.user_id
      WHERE r.user_id = ${userId} AND r.role = 'approver' AND u.status = 'ACTIVE'`;
    return rows.length === 1;
  }
  async listUsers(): Promise<IdentityUser[]> {
    const rows = await this.sql`SELECT id, display_name, status FROM identity_users ORDER BY created_at DESC LIMIT 500`;
    return rows.map((r: any) => ({ id: r.id, displayName: r.display_name, status: r.status }));
  }
  async listClients() {
    const rows = await this.sql`SELECT id FROM oauth_clients WHERE status = 'ACTIVE' ORDER BY id`;
    const clients = await Promise.all(rows.map((r: any) => this.findClient(r.id)));
    return clients.filter((c): c is OAuthClient => c !== null);
  }
  async listAccessGrants(): Promise<AccessGrant[]> {
    const rows = await this.sql`SELECT user_id, client_id, resource, scopes FROM identity_access_grants ORDER BY updated_at DESC LIMIT 1000`;
    return rows.map((r: any) => ({ userId: r.user_id, clientId: r.client_id, resource: r.resource, scopes: r.scopes }));
  }
  async findAccessGrant(userId: string, clientId: string, resource: string): Promise<AccessGrant | null> {
    const rows = await this.sql`SELECT scopes FROM identity_access_grants
      WHERE user_id = ${userId} AND client_id = ${clientId} AND resource = ${resource}`;
    return rows[0] ? { userId, clientId, resource, scopes: rows[0].scopes } : null;
  }
  async setAccessGrant(grant: AccessGrant, actorId: string) {
    await this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${grant.userId}, 1))`;
      await tx`INSERT INTO identity_access_grants (user_id, client_id, resource, scopes, updated_by)
        VALUES (${grant.userId}, ${grant.clientId}, ${grant.resource}, string_to_array(${grant.scopes.join("\n")}, E'\n'), ${actorId})
        ON CONFLICT (user_id, client_id, resource) DO UPDATE SET scopes = EXCLUDED.scopes, updated_by = EXCLUDED.updated_by, updated_at = now()`;
      await tx`UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
        WHERE user_id = ${grant.userId} AND client_id = ${grant.clientId} AND resource = ${grant.resource}`;
      await tx`INSERT INTO identity_audit_events (actor_id, client_id, action, metadata)
        VALUES (${actorId}, ${grant.clientId}, 'access.granted', ${grant})`;
    });
  }
  async revokeAccessGrant(userId: string, clientId: string, resource: string, actorId: string) {
    await this.sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${userId}, 1))`;
      await tx`DELETE FROM identity_access_grants WHERE user_id = ${userId} AND client_id = ${clientId} AND resource = ${resource}`;
      await tx`UPDATE oauth_refresh_sessions SET revoked_at = COALESCE(revoked_at, now())
        WHERE user_id = ${userId} AND client_id = ${clientId} AND resource = ${resource}`;
      await tx`INSERT INTO identity_audit_events (actor_id, client_id, action, metadata)
        VALUES (${actorId}, ${clientId}, 'access.revoked', ${{ userId, resource }})`;
    });
  }
  async createLoginApproval(r: LoginApproval) {
    await this.sql`INSERT INTO identity_login_approvals
      (id, display_name, credential_id, public_key, algorithm, message, client_id, resource, requested_scopes, user_id, created_at, expires_at)
      VALUES (${r.id}, ${r.displayName}, ${r.credentialId}, ${r.publicKey}, ${r.algorithm}, ${r.message}, ${r.clientId}, ${r.resource},
        string_to_array(${r.requestedScopes.join("\n")}, E'\n'), ${r.userId}, ${r.createdAt}, ${r.expiresAt})`;
  }
  async findLoginApproval(id: string) {
    const rows = await this.sql`SELECT * FROM identity_login_approvals WHERE id = ${id}`;
    return rows[0] ? approvalRow(rows[0]) : null;
  }
  async proveLoginApproval(id: string, now: Date) {
    const rows = await this.sql`UPDATE identity_login_approvals SET status = 'pending'
      WHERE id = ${id} AND status = 'proof_required' AND expires_at > ${now} RETURNING id`;
    return rows.length === 1;
  }
  async listPendingApprovals(now: Date) {
    const rows = await this.sql`SELECT * FROM identity_login_approvals
      WHERE status = 'pending' AND expires_at > ${now} ORDER BY created_at LIMIT 200`;
    return rows.map(approvalRow);
  }
  async decideLoginApproval(input: {
    id: string; actorId: string; decision: "approved" | "rejected";
    scopes: string[]; targetUserId?: string; now: Date;
  }) {
    await this.sql.begin(async (tx) => {
      const rows = await tx`SELECT * FROM identity_login_approvals WHERE id = ${input.id} FOR UPDATE`;
      const r = rows[0] ? approvalRow(rows[0]) : null;
      if (!r || r.status !== 'pending' || r.expiresAt <= input.now) throw new ApprovalConflictError('Request is no longer pending');
      let userId = r.userId;
      if (input.decision === 'approved') {
        await tx`SELECT pg_advisory_xact_lock(hashtextextended(${r.credentialId}, 0))`;
        const credentials = await tx`SELECT * FROM identity_credentials WHERE credential_id = ${r.credentialId} FOR UPDATE`;
        const c = credentials[0];
        if (c && (c.public_key !== r.publicKey || c.status !== 'ACTIVE')) throw new ApprovalConflictError('Credential changed');
        if (c && input.targetUserId && c.user_id !== input.targetUserId) throw new ApprovalConflictError('Credential owner changed');
        userId = c?.user_id ?? userId ?? input.targetUserId ?? null;
        if (userId === input.actorId) throw new ApprovalConflictError('Self approval is not allowed');
        if (userId) {
          const users = await tx`SELECT id FROM identity_users WHERE id = ${userId} AND status = 'ACTIVE' FOR SHARE`;
          if (!users.length) throw new ApprovalConflictError('Target user is inactive');
        } else {
          const users = await tx`INSERT INTO identity_users (display_name) VALUES (${r.displayName}) RETURNING id`;
          userId = users[0].id;
        }
        if (!c) await tx`INSERT INTO identity_credentials (user_id, type, credential_id, public_key, algorithm)
          VALUES (${userId}, 'device_key', ${r.credentialId}, ${r.publicKey}, ${r.algorithm})`;
        await tx`SELECT pg_advisory_xact_lock(hashtextextended(${userId}, 1))`;
        await tx`INSERT INTO identity_access_grants (user_id, client_id, resource, scopes, updated_by)
          VALUES (${userId}, ${r.clientId}, ${r.resource}, string_to_array(${input.scopes.join("\n")}, E'\n'), ${input.actorId})
          ON CONFLICT (user_id, client_id, resource) DO UPDATE SET
            scopes = ARRAY(SELECT DISTINCT unnest(identity_access_grants.scopes || EXCLUDED.scopes)),
            updated_by = EXCLUDED.updated_by, updated_at = now()`;
      }
      await tx`UPDATE identity_login_approvals SET status = ${input.decision}, user_id = ${userId},
        approved_scopes = string_to_array(${input.scopes.join("\n")}, E'\n'), decided_by = ${input.actorId}, decided_at = ${input.now}
        WHERE id = ${r.id}`;
      await tx`INSERT INTO identity_audit_events (actor_id, client_id, action, metadata)
        VALUES (${input.actorId}, ${r.clientId}, ${`login.${input.decision}`}, ${{ requestId: r.id, userId, scopes: input.scopes }})`;
    });
  }
  async consumeLoginApproval(input: {
    id: string; now: Date;
    session: { tokenHash: string; authenticationMethod: string; expiresAt: Date };
    refresh: RefreshSessionInput;
  }) {
    return this.sql.begin(async (tx) => {
      const rows = await tx`SELECT * FROM identity_login_approvals WHERE id = ${input.id} FOR UPDATE`;
      const r = rows[0] ? approvalRow(rows[0]) : null;
      if (!r || r.status !== 'approved' || !r.userId || r.expiresAt <= input.now) return false;
      await tx`SELECT pg_advisory_xact_lock(hashtextextended(${r.userId}, 1))`;
      const valid = await tx`SELECT 1 FROM identity_access_grants g
        JOIN identity_users u ON u.id = g.user_id JOIN oauth_clients c ON c.id = g.client_id
        JOIN identity_credentials cr ON cr.user_id = u.id AND cr.credential_id = ${r.credentialId}
        WHERE g.user_id = ${r.userId} AND g.client_id = ${r.clientId} AND g.resource = ${r.resource}
          AND g.scopes @> string_to_array(${r.approvedScopes.join("\n")}, E'\n')
          AND c.allowed_scopes @> string_to_array(${r.approvedScopes.join("\n")}, E'\n')
          AND ${r.resource} = ANY(c.allowed_resources)
          AND u.status = 'ACTIVE' AND c.status = 'ACTIVE' AND cr.status = 'ACTIVE'
        FOR SHARE OF g, u, c, cr`;
      if (!valid.length) return false;
      await tx`INSERT INTO identity_browser_sessions
        (token_hash, user_id, authentication_method, authenticated_at, expires_at, last_seen_at, approval_id)
        VALUES (${input.session.tokenHash}, ${r.userId}, ${input.session.authenticationMethod}, ${input.now}, ${input.session.expiresAt}, ${input.now}, ${r.id})`;
      const f = input.refresh;
      await tx`INSERT INTO oauth_refresh_sessions (family_id, token_hash, user_id, client_id, scopes, resource, expires_at, approval_id)
        VALUES (${crypto.randomUUID()}, ${f.tokenHash}, ${r.userId}, ${r.clientId}, string_to_array(${f.scopes.join("\n")}, E'\n'), ${r.resource}, ${f.expiresAt}, ${r.id})`;
      await tx`UPDATE identity_login_approvals SET status = 'consumed', consumed_at = ${input.now} WHERE id = ${r.id}`;
      await tx`INSERT INTO identity_audit_events (actor_id, client_id, action, metadata)
        VALUES (${r.userId}, ${r.clientId}, 'login.consumed', ${{ requestId: r.id }})`;
      return true;
    });
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
      RETURNING s.id, s.authentication_method, s.authenticated_at, s.expires_at, s.approval_id,
                u.id AS user_id, u.display_name, u.status AS user_status`;
    const row = rows[0] as any;
    return row
      ? {
          id: row.id,
          authenticationMethod: row.authentication_method,
          authenticatedAt: new Date(row.authenticated_at),
          expiresAt: new Date(row.expires_at),
          approvalId: row.approval_id ?? undefined,
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
        (family_id, token_hash, user_id, client_id, scopes, resource, expires_at, approval_id)
      VALUES
        (${familyId}, ${input.tokenHash}, ${input.userId}, ${input.clientId},
         string_to_array(${input.scopes.join("\n")}, E'\n'),
         ${input.resource}, ${input.expiresAt}, ${input.approvalId ?? null})`;
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
               rotated_at, revoked_at, approval_id
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
          (family_id, token_hash, user_id, client_id, scopes, resource, expires_at, approval_id)
        VALUES
          (${row.family_id}, ${input.replacementTokenHash}, ${row.user_id},
           ${row.client_id},
           string_to_array(${(row.scopes ?? []).join("\n")}, E'\n'),
           ${row.resource}, ${input.replacementExpiresAt}, ${row.approval_id})`;
      return {
        status: "rotated" as const,
        userId: row.user_id,
        clientId: row.client_id,
        scopes: row.scopes ?? [],
        resource: row.resource,
        familyId: row.family_id,
        approvalId: row.approval_id ?? undefined,
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

