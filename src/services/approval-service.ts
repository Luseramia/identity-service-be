import { createPublicKey } from "node:crypto";
import type { AccessGrant, BrowserSession, IdentityRepository, LoginApproval } from "../repository/identity-repository";
import { deviceApprovalMessage, hashToken, randomOpaqueToken, verifyDeviceSignature } from "../security/crypto";
import { OAuthError, OAuthService } from "./oauth-service";

export const validUuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

export class ApprovalService {
  private readonly now: () => number;
  constructor(
    private readonly repository: IdentityRepository,
    private readonly oauth: OAuthService,
    private readonly options: { ttlSeconds: number; sessionTtlSeconds: number; now?: () => number },
  ) { this.now = options.now ?? (() => Math.floor(Date.now() / 1000)); }

  async start(input: { displayName: string; credentialId: string; publicKey: string; clientId: string; clientSecret?: string; scopes: string; resource: string }) {
    const name = input.displayName.trim();
    if (!name || name.length > 160 || !/^[a-zA-Z0-9_-]{1,200}$/.test(input.credentialId) || input.publicKey.length > 2048) {
      throw new OAuthError("invalid_request", "A name and valid device credential are required");
    }
    try {
      const key = createPublicKey({ key: Buffer.from(input.publicKey, "base64"), format: "der", type: "spki" });
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error();
      input.publicKey = key.export({ format: "der", type: "spki" }).toString("base64");
    } catch { throw new OAuthError("invalid_request", "An ECDSA P-256 public key is required"); }
    const { client, scopes, resource } = await this.oauth.approvalClient(input.clientId, input.scopes, input.resource, { clientSecret: input.clientSecret });
    const credential = await this.repository.findCredential(input.credentialId);
    if (credential && (credential.publicKey !== input.publicKey || credential.status !== "ACTIVE" || credential.userStatus !== "ACTIVE")) {
      throw new OAuthError("access_denied", "This device credential cannot be used", 403);
    }
    const user = credential ? await this.repository.findUser(credential.userId) : null;
    const id = crypto.randomUUID();
    const message = deviceApprovalMessage({ purpose: "login_approval", transactionId: id, challenge: randomOpaqueToken() });
    const now = this.now();
    await this.repository.createLoginApproval({
      id, message, displayName: user?.displayName ?? name, credentialId: input.credentialId,
      publicKey: input.publicKey, algorithm: "ES256", clientId: client.id, resource,
      requestedScopes: scopes, approvedScopes: [], userId: user?.id ?? null, status: "proof_required",
      createdAt: new Date(now * 1000), expiresAt: new Date((now + this.options.ttlSeconds) * 1000),
    });
    return { requestId: id, message, pollMessage: `${message}\npoll`, expiresIn: this.options.ttlSeconds, interval: 5 };
  }

  private async signedRequest(id: string, signature: string, poll = false) {
    const r = validUuid(id) ? await this.repository.findLoginApproval(id) : null;
    if (!r || !verifyDeviceSignature({ publicKeyBase64: r.publicKey, algorithm: r.algorithm,
      message: poll ? `${r.message}\npoll` : r.message, signatureBase64Url: signature })) {
      throw new OAuthError("access_denied", "Device proof is invalid", 403);
    }
    return r;
  }

  async prove(id: string, signature: string) {
    await this.signedRequest(id, signature);
    if (!await this.repository.proveLoginApproval(id, new Date(this.now() * 1000))) {
      throw new OAuthError("invalid_request", "Request has expired or already been verified", 409);
    }
    return { status: "pending" };
  }

  async poll(id: string, signature: string) {
    const r = await this.signedRequest(id, signature, true);
    const now = this.now();
    if (r.status === "consumed") return { status: "consumed" as const };
    if (r.expiresAt.getTime() <= now * 1000) return { status: "expired" as const };
    if (r.status !== "approved") return { status: r.status };
    if (!r.userId) throw new OAuthError("invalid_request", "Approved user is missing", 409);
    const { client } = await this.oauth.approvalClient(r.clientId, r.approvedScopes.join(" "), r.resource);
    // Signing happens before consumption: a Vault outage leaves the approval redeemable.
    const prepared = await this.oauth.prepareTokens({ userId: r.userId, client, scopes: r.approvedScopes,
      resource: r.resource, approvalId: r.id, authenticationMethod: "admin_approved_device", authenticationTime: now }, true);
    const token = randomOpaqueToken();
    const completedAt = this.now();
    const expiresAt = new Date((completedAt + this.options.sessionTtlSeconds) * 1000);
    const consumed = await this.repository.consumeLoginApproval({ id, now: new Date(completedAt * 1000),
      session: { tokenHash: hashToken(token), authenticationMethod: "admin_approved_device", expiresAt }, refresh: prepared.refresh });
    if (!consumed) throw new OAuthError("invalid_grant", "Approval was consumed, expired, or its permissions changed", 409);
    return { status: "approved" as const, ...prepared.tokens, user_id: r.userId, session: { token, expiresAt } };
  }

  async requireApprover(session: BrowserSession | null) {
    if (!session) throw new OAuthError("login_required", "Sign in before managing approvals", 401);
    if (!await this.repository.isApprover(session.user.id)) throw new OAuthError("access_denied", "Approver role is required", 403);
    return session.user.id;
  }

  describe(r: LoginApproval) {
    return { id: r.id, displayName: r.displayName, userId: r.userId, credentialId: r.credentialId,
      keyFingerprint: hashToken(r.publicKey), clientId: r.clientId, resource: r.resource,
      requestedScopes: r.requestedScopes, createdAt: r.createdAt, expiresAt: r.expiresAt };
  }

  async decide(id: string, actorId: string, decision: "approved" | "rejected", scopes: unknown, targetUserId?: string) {
    const r = validUuid(id) ? await this.repository.findLoginApproval(id) : null;
    if (!r) throw new OAuthError("invalid_request", "Request not found", 404);
    const selected = decision === "approved" ? this.scopes(scopes) : [];
    if (targetUserId && (!validUuid(targetUserId) || (r.userId && r.userId !== targetUserId))) {
      throw new OAuthError("invalid_request", "The existing device owner cannot be changed");
    }
    if (decision === "approved") {
      if (selected.some((s) => !r.requestedScopes.includes(s))) throw new OAuthError("invalid_scope", "Only requested permissions can be approved");
      await this.oauth.approvalClient(r.clientId, selected.join(" "), r.resource);
    }
    await this.repository.decideLoginApproval({ id, actorId, decision, scopes: selected, targetUserId, now: new Date(this.now() * 1000) });
    return { success: true };
  }

  private scopes(value: unknown) {
    if (!Array.isArray(value) || !value.length || value.length > 100 || value.some((s) => typeof s !== "string" || !s || /\s/.test(s))) {
      throw new OAuthError("invalid_scope", "Select at least one valid permission");
    }
    return [...new Set(value as string[])];
  }

  async setGrant(grant: AccessGrant, actorId: string) {
    if (!validUuid(grant.userId) || (await this.repository.findUser(grant.userId))?.status !== "ACTIVE") {
      throw new OAuthError("invalid_request", "Select an active user");
    }
    grant.scopes = this.scopes(grant.scopes);
    const client = await this.repository.findClient(grant.clientId);
    if (!client || client.status !== "ACTIVE" || !client.allowedResources.includes(grant.resource) || grant.scopes.some((s) => !client.allowedScopes.includes(s))) {
      throw new OAuthError("invalid_scope", "Permissions must be allowed for this client and resource");
    }
    await this.repository.setAccessGrant(grant, actorId);
    return { success: true };
  }
}
