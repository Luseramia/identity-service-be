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

interface MemoryEnrollment {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt?: Date;
}

interface MemoryRefresh extends RefreshSessionInput {
  familyId: string;
  rotatedAt?: Date;
  revokedAt?: Date;
}

export class MemoryIdentityRepository implements IdentityRepository {
  readonly clients = new Map<string, OAuthClient>();
  readonly users = new Map<string, IdentityUser>();
  readonly credentials = new Map<string, IdentityCredential>();
  readonly enrollments = new Map<string, MemoryEnrollment>();
  readonly sessions = new Map<
    string,
    {
      id: string;
      userId: string;
      authenticationMethod: string;
      authenticatedAt: Date;
      expiresAt: Date;
      revokedAt?: Date;
      approvalId?: string;
    }
  >();
  readonly refresh = new Map<string, MemoryRefresh>();
  readonly auditEvents: AuditEventInput[] = [];
  readonly approvers = new Set<string>();
  readonly grants = new Map<string, AccessGrant>();
  readonly approvals = new Map<string, LoginApproval>();

  private grantKey(userId: string, clientId: string, resource: string) {
    return JSON.stringify([userId, clientId, resource]);
  }

  async isApprover(userId: string) {
    return this.approvers.has(userId) && this.users.get(userId)?.status === "ACTIVE";
  }
  async listUsers() { return [...this.users.values()]; }
  async listClients() { return [...this.clients.values()]; }
  async listAccessGrants() { return [...this.grants.values()]; }
  async findAccessGrant(userId: string, clientId: string, resource: string) {
    return this.grants.get(this.grantKey(userId, clientId, resource)) ?? null;
  }

  private replaceGrant(grant: AccessGrant, actorId: string) {
    this.grants.set(this.grantKey(grant.userId, grant.clientId, grant.resource), { ...grant });
    this.revokeGrantRefresh(grant.userId, grant.clientId, grant.resource);
    this.auditEvents.push({ actorId, clientId: grant.clientId, action: "access.granted", metadata: { ...grant } });
  }
  private revokeGrantRefresh(userId: string, clientId: string, resource: string) {
    for (const value of this.refresh.values()) {
      if (value.userId === userId && value.clientId === clientId && value.resource === resource) value.revokedAt ??= new Date();
    }
  }
  async setAccessGrant(grant: AccessGrant, actorId: string) { this.replaceGrant(grant, actorId); }
  async revokeAccessGrant(userId: string, clientId: string, resource: string, actorId: string) {
    this.revokeGrantRefresh(userId, clientId, resource);
    this.grants.delete(this.grantKey(userId, clientId, resource));
    this.auditEvents.push({ actorId, clientId, action: "access.revoked", metadata: { userId, resource } });
  }
  async createLoginApproval(approval: LoginApproval) { this.approvals.set(approval.id, structuredClone(approval)); }
  async findLoginApproval(id: string) { return this.approvals.get(id) ?? null; }
  async proveLoginApproval(id: string, now: Date) {
    const record = this.approvals.get(id);
    if (!record || record.status !== "proof_required" || record.expiresAt <= now) return false;
    record.status = "pending";
    return true;
  }
  async listPendingApprovals(now: Date) {
    return [...this.approvals.values()].filter((r) => r.status === "pending" && r.expiresAt > now);
  }
  async decideLoginApproval(input: {
    id: string; actorId: string; decision: "approved" | "rejected";
    scopes: string[]; targetUserId?: string; now: Date;
  }) {
    const r = this.approvals.get(input.id);
    if (!r || r.status !== "pending" || r.expiresAt <= input.now || !this.approvers.has(input.actorId)) throw new ApprovalConflictError("Request is no longer pending");
    if (input.decision === "approved") {
      const credential = this.credentials.get(r.credentialId);
      if (credential && (credential.publicKey !== r.publicKey || credential.status !== "ACTIVE")) throw new ApprovalConflictError("Credential changed");
      const target = credential?.userId ?? r.userId ?? input.targetUserId;
      if (credential && input.targetUserId && credential.userId !== input.targetUserId) throw new ApprovalConflictError("Credential owner changed");
      if (target === input.actorId || (target && this.users.get(target)?.status !== "ACTIVE")) throw new ApprovalConflictError("Select a different active user");
      r.userId = target ?? crypto.randomUUID();
      if (!target) this.users.set(r.userId, { id: r.userId, displayName: r.displayName, status: "ACTIVE" });
      this.credentials.set(r.credentialId, credential ?? {
        id: crypto.randomUUID(), userId: r.userId, credentialId: r.credentialId,
        publicKey: r.publicKey, algorithm: r.algorithm, status: "ACTIVE", userStatus: "ACTIVE",
      });
      r.approvedScopes = [...input.scopes];
      const key = this.grantKey(r.userId, r.clientId, r.resource);
      const scopes = [...new Set([...(this.grants.get(key)?.scopes ?? []), ...input.scopes])];
      this.grants.set(key, { userId: r.userId, clientId: r.clientId, resource: r.resource, scopes });
    }
    r.status = input.decision;
    r.decidedBy = input.actorId;
    this.auditEvents.push({ actorId: input.actorId, clientId: r.clientId, action: `login.${input.decision}`, metadata: { requestId: r.id, userId: r.userId, scopes: input.scopes } });
  }
  async consumeLoginApproval(input: {
    id: string; now: Date;
    session: { tokenHash: string; authenticationMethod: string; expiresAt: Date };
    refresh: RefreshSessionInput;
  }) {
    const r = this.approvals.get(input.id);
    const grant = r?.userId ? this.grants.get(this.grantKey(r.userId, r.clientId, r.resource)) : null;
    const client = r ? this.clients.get(r.clientId) : null;
    if (!r || r.status !== "approved" || r.expiresAt <= input.now || !r.userId ||
        this.users.get(r.userId)?.status !== "ACTIVE" || this.clients.get(r.clientId)?.status !== "ACTIVE" ||
        this.credentials.get(r.credentialId)?.status !== "ACTIVE" || !grant ||
        !client?.allowedResources.includes(r.resource) || r.approvedScopes.some((s) => !grant.scopes.includes(s) || !client.allowedScopes.includes(s))) return false;
    r.status = "consumed";
    this.sessions.set(input.session.tokenHash, { id: crypto.randomUUID(), ...input.session, userId: r.userId, approvalId: r.id, authenticatedAt: input.now });
    this.refresh.set(input.refresh.tokenHash, { ...input.refresh, familyId: crypto.randomUUID() });
    return true;
  }

  async ready() {}

  async findClient(clientId: string) {
    return this.clients.get(clientId) ?? null;
  }

  async findUser(userId: string) {
    return this.users.get(userId) ?? null;
  }

  async findCredential(credentialId: string) {
    const c = this.credentials.get(credentialId);
    return c ? { ...c, userStatus: this.users.get(c.userId)?.status ?? "DISABLED" } : null;
  }

  async findEnrollment(tokenHash: string) {
    const value = this.enrollments.get(tokenHash);
    return value && !value.consumedAt && value.expiresAt > new Date()
      ? { id: value.id, userId: value.userId }
      : null;
  }

  async completeEnrollment(input: {
    enrollmentId: string;
    userId: string;
    credentialId: string;
    publicKey: string;
    algorithm: string;
  }) {
    const enrollment = [...this.enrollments.values()].find(
      (value) => value.id === input.enrollmentId,
    );
    if (!enrollment || enrollment.consumedAt) throw new Error("Invalid enrollment");
    enrollment.consumedAt = new Date();
    this.credentials.set(input.credentialId, {
      id: crypto.randomUUID(),
      userId: input.userId,
      credentialId: input.credentialId,
      publicKey: input.publicKey,
      algorithm: input.algorithm,
      status: "ACTIVE",
      userStatus: "ACTIVE",
    });
  }

  async createBrowserSession(input: {
    tokenHash: string;
    userId: string;
    authenticationMethod: string;
    authenticatedAt: Date;
    expiresAt: Date;
  }) {
    this.sessions.set(input.tokenHash, { id: crypto.randomUUID(), ...input });
  }

  async findBrowserSession(tokenHash: string, now: Date): Promise<BrowserSession | null> {
    const session = this.sessions.get(tokenHash);
    const user = session ? this.users.get(session.userId) : undefined;
    if (
      !session ||
      !user ||
      session.revokedAt ||
      session.expiresAt <= now ||
      user.status !== "ACTIVE"
    ) {
      return null;
    }
    return {
      id: session.id,
      user,
      authenticationMethod: session.authenticationMethod,
      authenticatedAt: session.authenticatedAt,
      expiresAt: session.expiresAt,
      approvalId: session.approvalId,
    };
  }

  async revokeBrowserSession(tokenHash: string) {
    const session = this.sessions.get(tokenHash);
    if (session) session.revokedAt = new Date();
  }

  async createRefreshSession(input: RefreshSessionInput) {
    const familyId = input.familyId ?? crypto.randomUUID();
    this.refresh.set(input.tokenHash, { ...input, familyId });
    return familyId;
  }

  async rotateRefreshSession(input: {
    currentTokenHash: string;
    replacementTokenHash: string;
    replacementExpiresAt: Date;
    clientId: string;
    now: Date;
  }): Promise<RefreshRotationResult> {
    const current = this.refresh.get(input.currentTokenHash);
    if (!current || current.clientId !== input.clientId) return { status: "invalid" };
    if (current.rotatedAt || current.revokedAt) {
      for (const value of this.refresh.values()) {
        if (value.familyId === current.familyId) value.revokedAt ??= input.now;
      }
      return {
        status: "reused",
        userId: current.userId,
        clientId: current.clientId,
      };
    }
    if (current.expiresAt <= input.now) {
      current.revokedAt = input.now;
      return { status: "expired" };
    }
    current.rotatedAt = input.now;
    this.refresh.set(input.replacementTokenHash, {
      tokenHash: input.replacementTokenHash,
      userId: current.userId,
      clientId: current.clientId,
      scopes: current.scopes,
      resource: current.resource,
      expiresAt: input.replacementExpiresAt,
      familyId: current.familyId,
      approvalId: current.approvalId,
    });
    return {
      status: "rotated",
      userId: current.userId,
      clientId: current.clientId,
      scopes: current.scopes,
      resource: current.resource,
      familyId: current.familyId,
      approvalId: current.approvalId,
    };
  }

  async revokeRefreshSession(tokenHash: string, clientId: string) {
    const current = this.refresh.get(tokenHash);
    if (!current || current.clientId !== clientId) return;
    for (const value of this.refresh.values()) {
      if (value.familyId === current.familyId) value.revokedAt ??= new Date();
    }
  }

  async audit(event: AuditEventInput) {
    this.auditEvents.push(event);
  }
}

