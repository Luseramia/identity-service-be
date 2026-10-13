export interface IdentityUser {
  id: string;
  displayName: string;
  status: string;
}

export interface IdentityCredential {
  id: string;
  userId: string;
  credentialId: string;
  publicKey: string;
  algorithm: string;
  status: string;
  userStatus: string;
}

export interface OAuthClient {
  id: string;
  name: string;
  type: "public" | "confidential";
  clientSecretHash: string | null;
  redirectUris: string[];
  allowedScopes: string[];
  allowedResources: string[];
  status: string;
}

export interface BrowserSession {
  id: string;
  user: IdentityUser;
  authenticationMethod: string;
  authenticatedAt: Date;
  expiresAt: Date;
}

export interface RefreshSessionInput {
  tokenHash: string;
  userId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  expiresAt: Date;
  familyId?: string;
}

export type RefreshRotationResult =
  | {
      status: "rotated";
      userId: string;
      clientId: string;
      scopes: string[];
      resource: string;
      familyId: string;
    }
  | { status: "reused"; userId: string; clientId: string }
  | { status: "invalid" | "expired" };

export interface AuditEventInput {
  actorId?: string;
  clientId?: string;
  action: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

export interface IdentityRepository {
  ready(): Promise<void>;
  findClient(clientId: string): Promise<OAuthClient | null>;
  findUser(userId: string): Promise<IdentityUser | null>;
  findCredential(credentialId: string): Promise<IdentityCredential | null>;
  findEnrollment(tokenHash: string): Promise<{ id: string; userId: string } | null>;
  completeEnrollment(input: {
    enrollmentId: string;
    userId: string;
    credentialId: string;
    publicKey: string;
    algorithm: string;
  }): Promise<void>;
  createBrowserSession(input: {
    tokenHash: string;
    userId: string;
    authenticationMethod: string;
    authenticatedAt: Date;
    expiresAt: Date;
  }): Promise<void>;
  findBrowserSession(tokenHash: string, now: Date): Promise<BrowserSession | null>;
  revokeBrowserSession(tokenHash: string): Promise<void>;
  createRefreshSession(input: RefreshSessionInput): Promise<string>;
  rotateRefreshSession(input: {
    currentTokenHash: string;
    replacementTokenHash: string;
    replacementExpiresAt: Date;
    clientId: string;
    now: Date;
  }): Promise<RefreshRotationResult>;
  revokeRefreshSession(tokenHash: string, clientId: string): Promise<void>;
  audit(event: AuditEventInput): Promise<void>;
}

