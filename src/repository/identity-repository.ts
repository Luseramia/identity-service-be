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
  approvalId?: string;
}

export interface LoginApproval {
  id: string;
  displayName: string;
  credentialId: string;
  publicKey: string;
  algorithm: string;
  message: string;
  clientId: string;
  resource: string;
  requestedScopes: string[];
  approvedScopes: string[];
  userId: string | null;
  status: "proof_required" | "pending" | "approved" | "rejected" | "consumed";
  decidedBy?: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface AccessGrant {
  userId: string;
  clientId: string;
  resource: string;
  scopes: string[];
}

export class ApprovalConflictError extends Error {}

export interface RefreshSessionInput {
  tokenHash: string;
  userId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  expiresAt: Date;
  familyId?: string;
  approvalId?: string;
}

export type RefreshRotationResult =
  | {
      status: "rotated";
      userId: string;
      clientId: string;
      scopes: string[];
      resource: string;
      familyId: string;
      approvalId?: string;
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
  isApprover(userId: string): Promise<boolean>;
  listUsers(): Promise<IdentityUser[]>;
  listClients(): Promise<OAuthClient[]>;
  listAccessGrants(): Promise<AccessGrant[]>;
  findAccessGrant(userId: string, clientId: string, resource: string): Promise<AccessGrant | null>;
  setAccessGrant(grant: AccessGrant, actorId: string): Promise<void>;
  revokeAccessGrant(userId: string, clientId: string, resource: string, actorId: string): Promise<void>;
  createLoginApproval(approval: LoginApproval): Promise<void>;
  findLoginApproval(id: string): Promise<LoginApproval | null>;
  proveLoginApproval(id: string, now: Date): Promise<boolean>;
  listPendingApprovals(now: Date): Promise<LoginApproval[]>;
  decideLoginApproval(input: {
    id: string; actorId: string; decision: "approved" | "rejected";
    scopes: string[]; targetUserId?: string; now: Date;
  }): Promise<void>;
  consumeLoginApproval(input: {
    id: string; now: Date; session: {
      tokenHash: string; authenticationMethod: string; expiresAt: Date;
    }; refresh: RefreshSessionInput;
  }): Promise<boolean>;
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

