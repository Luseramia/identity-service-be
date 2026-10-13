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
    }
  >();
  readonly refresh = new Map<string, MemoryRefresh>();
  readonly auditEvents: AuditEventInput[] = [];

  async ready() {}

  async findClient(clientId: string) {
    return this.clients.get(clientId) ?? null;
  }

  async findUser(userId: string) {
    return this.users.get(userId) ?? null;
  }

  async findCredential(credentialId: string) {
    return this.credentials.get(credentialId) ?? null;
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
    });
    return {
      status: "rotated",
      userId: current.userId,
      clientId: current.clientId,
      scopes: current.scopes,
      resource: current.resource,
      familyId: current.familyId,
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

