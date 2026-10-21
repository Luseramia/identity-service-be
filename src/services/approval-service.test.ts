import { describe, expect, it } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { ApprovalService } from "./approval-service";
import { OAuthService } from "./oauth-service";
import { MemoryIdentityRepository } from "../repository/memory-identity-repository";
import { MemoryIdentityTransientStore } from "../store/memory-transient-store";
import { AccessTokenIssuer } from "../jwt/access-token";
import { IdTokenIssuer } from "../jwt/id-token";
import { decodeJson } from "../jwt/base64url";
import type { JwtSigner } from "../jwt/signer";
import { createIdentityApp } from "../app";
import { hashToken, pkceChallenge } from "../security/crypto";

const audience = "urn:test:business";
const adminId = "11111111-1111-4111-8111-111111111111";
const issuer = "https://identity.test";
function fixture() {
  let now = Math.floor(Date.now() / 1000);
  let failSigning = false;
  let onSign = () => {};
  const repository = new MemoryIdentityRepository();
  const store = new MemoryIdentityTransientStore();
  const signingKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signer: JwtSigner = {
    activeKey: async () => ({ version: 1, kid: "key:v1" }),
    sign: async (input) => { if (failSigning) throw new Error("Vault unavailable"); onSign(); return sign("sha256", Buffer.from(input), { key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url"); },
    jwks: async () => ({ keys: [{ ...signingKey.publicKey.export({ format: "jwk" }), kid: "key:v1", alg: "ES256", use: "sig" }] }),
  };
  const client = { id: "x-webapp", name: "Webapp", type: "public" as const, clientSecretHash: null,
    redirectUris: ["https://web.test/callback"], allowedResources: [audience],
    allowedScopes: ["openid", "profile", "finance:read", "finance:write"], status: "ACTIVE" };
  repository.clients.set(client.id, client);
  repository.users.set(adminId, { id: adminId, displayName: "Admin", status: "ACTIVE" });
  repository.approvers.add(adminId);
  const oauth = new OAuthService(repository, store,
    new AccessTokenIssuer(signer, { issuer, defaultTtlSeconds: 600, now: () => now }),
    new IdTokenIssuer(signer, { issuer, ttlSeconds: 600, now: () => now }),
    { issuer, authorizationCodeTtlSeconds: 90, deviceCodeTtlSeconds: 600, refreshTokenTtlSeconds: 3600, now: () => now });
  const service = new ApprovalService(repository, oauth, { ttlSeconds: 600, sessionTtlSeconds: 3600, now: () => now });
  const device = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicKey = device.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const signature = (message: string) => sign("sha256", Buffer.from(message), { key: device.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  async function start(name = "Alice", credentialId = "alice-device") {
    return service.start({ displayName: name, credentialId, publicKey, clientId: client.id, resource: audience, scopes: "openid finance:read finance:write" });
  }
  async function approved() {
    const r = await start();
    await service.prove(r.requestId, signature(r.message));
    await service.decide(r.requestId, adminId, "approved", ["openid", "finance:read"]);
    const result = await service.poll(r.requestId, signature(r.pollMessage));
    if (!("access_token" in result)) throw new Error("Expected token response");
    return { request: r, result };
  }
  return { repository, store, signer, client, oauth, service, signature, publicKey, start, approved,
    setNow: (value: number) => { now = value; }, now: () => now, failSigning: (value: boolean) => { failSigning = value; },
    onSign: (fn: () => void) => { onSign = fn; } };
}

describe("Administrator login approvals", () => {
  it("requires device proof before queueing, issues only approved scopes to the requester, and consumes once", async () => {
    const f = fixture();
    const r = await f.start();
    expect(await f.repository.listPendingApprovals(new Date())).toHaveLength(0);
    await expect(f.service.prove(r.requestId, "invalid")).rejects.toMatchObject({ error: "access_denied" });
    await f.service.prove(r.requestId, f.signature(r.message));
    expect(await f.repository.listPendingApprovals(new Date())).toHaveLength(1);
    await expect(f.service.poll(r.requestId, f.signature(r.message))).rejects.toMatchObject({ error: "access_denied" });
    expect(await f.service.poll(r.requestId, f.signature(r.pollMessage))).toEqual({ status: "pending" });
    await expect(f.service.decide(r.requestId, adminId, "approved", ["documents:write"])).rejects.toMatchObject({ error: "invalid_scope" });
    await f.service.decide(r.requestId, adminId, "approved", ["openid", "finance:read"]);
    const results = await Promise.allSettled([f.service.poll(r.requestId, f.signature(r.pollMessage)), f.service.poll(r.requestId, f.signature(r.pollMessage))]);
    const tokens = results.flatMap((r) => r.status === "fulfilled" && "access_token" in r.value ? [r.value] : []);
    expect(tokens).toHaveLength(1);
    const claims = decodeJson<{ sub: string; scope: string; aud: string }>(tokens[0]!.access_token.split(".")[1]!);
    expect(claims.sub).not.toBe(adminId);
    expect(claims.scope).toBe("openid finance:read");
    expect(claims.aud).toBe(audience);
    expect(await f.service.poll(r.requestId, f.signature(r.pollMessage))).toEqual({ status: "consumed" });
    expect(f.repository.refresh.size).toBe(1);
    expect(f.repository.sessions.size).toBe(1);
  });

  it("preserves rejection and expiration without creating users or tokens", async () => {
    const f = fixture();
    const r = await f.start();
    await f.service.prove(r.requestId, f.signature(r.message));
    await f.service.decide(r.requestId, adminId, "rejected", []);
    expect(await f.service.poll(r.requestId, f.signature(r.pollMessage))).toEqual({ status: "rejected" });
    await expect(f.service.decide(r.requestId, adminId, "approved", ["openid"])).rejects.toThrow();
    const expired = await f.start();
    f.setNow(f.now() + 601);
    expect(await f.service.poll(expired.requestId, f.signature(expired.pollMessage))).toEqual({ status: "expired" });
    await expect(f.service.prove(expired.requestId, f.signature(expired.message))).rejects.toMatchObject({ status: 409 });
    expect(f.repository.users.size).toBe(1);
    expect(f.repository.refresh.size).toBe(0);
  });

  it("reuses known device owners but never finds identities by the supplied display name", async () => {
    const f = fixture();
    const { result } = await f.approved();
    const again = await f.start("Pretend to be Admin");
    expect((await f.repository.findLoginApproval(again.requestId))?.userId).toBe(result.user_id);
    expect((await f.repository.findLoginApproval(again.requestId))?.displayName).toBe("Alice");
    const clone = await f.start("Alice", "another-new-device");
    await f.service.prove(clone.requestId, f.signature(clone.message));
    await f.service.decide(clone.requestId, adminId, "approved", ["finance:read"]);
    expect((await f.repository.findLoginApproval(clone.requestId))?.userId).not.toBe(result.user_id);
  });

  it("checks user grants and approval binding for OAuth, Device Grant, and refresh", async () => {
    const f = fixture();
    const { result } = await f.approved();
    const session = await f.repository.findBrowserSession(hashToken(result.session.token), new Date(f.now() * 1000));
    const params = { responseType: "code", clientId: f.client.id, redirectUri: f.client.redirectUris[0], scopes: "finance:read", resource: audience, codeChallengeMethod: "S256", codeChallenge: pkceChallenge("a".repeat(43)) };
    await expect(f.oauth.authorize(params, { ...session!, approvalId: undefined })).rejects.toMatchObject({ error: "approval_required" });
    await expect(f.oauth.authorize({ ...params, scopes: "finance:write" }, session!)).rejects.toMatchObject({ error: "access_denied" });
    const device = await f.oauth.startDeviceAuthorization({ clientId: f.client.id }, { scopes: "finance:read", resource: audience });
    await expect(f.oauth.decideDeviceGrant(device.user_code, "approved", { ...session!, approvalId: undefined })).rejects.toMatchObject({ error: "approval_required" });
    const redirect = await f.oauth.authorize(params, session!);
    await f.repository.revokeAccessGrant(result.user_id, f.client.id, audience, adminId);
    await expect(f.oauth.exchangeAuthorizationCode({ clientId: f.client.id }, { code: new URL(redirect).searchParams.get("code")!, redirectUri: params.redirectUri, codeVerifier: "a".repeat(43) })).rejects.toMatchObject({ error: "access_denied" });
    await expect(f.oauth.refresh({ clientId: f.client.id }, { refreshToken: result.refresh_token })).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("rechecks current client policy on refresh and retries safely after Vault failure", async () => {
    const f = fixture();
    const r = await f.start();
    await f.service.prove(r.requestId, f.signature(r.message));
    await f.service.decide(r.requestId, adminId, "approved", ["finance:read"]);
    f.failSigning(true);
    await expect(f.service.poll(r.requestId, f.signature(r.pollMessage))).rejects.toThrow("Vault unavailable");
    expect((await f.repository.findLoginApproval(r.requestId))?.status).toBe("approved");
    expect(f.repository.refresh.size).toBe(0);
    f.failSigning(false);
    const tokens = await f.service.poll(r.requestId, f.signature(r.pollMessage));
    if (!("refresh_token" in tokens)) throw new Error("Expected refresh token");
    f.client.allowedScopes = ["openid"];
    await expect(f.oauth.refresh({ clientId: f.client.id }, { refreshToken: tokens.refresh_token })).rejects.toMatchObject({ error: "invalid_scope" });
    expect([...f.repository.refresh.values()].every((r) => r.revokedAt)).toBe(true);
  });

  it("requires an approver session and rejects cross-origin administrative changes over HTTP", async () => {
    const f = fixture();
    const app = createIdentityApp({ repository: f.repository, store: f.store, signer: f.signer,
      config: { issuer, port: 3001, accessTokenTtlSeconds: 600, idTokenTtlSeconds: 600, authorizationCodeTtlSeconds: 90,
        deviceCodeTtlSeconds: 600, refreshTokenTtlSeconds: 3600, browserSessionTtlSeconds: 3600, authenticationChallengeTtlSeconds: 300,
        vault: { address: "https://vault.test", transitMount: "test", transitKey: "test", keyMetadataCacheSeconds: 30 } } });
    const request = (path: string, init?: RequestInit) => app.handle(new Request(issuer + path, init));
    expect((await request("/admin/overview")).status).toBe(401);
    const { result } = await f.approved();
    const userCookie = `__Host-sso_session=${result.session.token}`;
    expect((await request("/admin/overview", { headers: { cookie: userCookie } })).status).toBe(403);
    await f.repository.createBrowserSession({ tokenHash: hashToken("admin-cookie"), userId: adminId,
      authenticationMethod: "device_signature", authenticatedAt: new Date(), expiresAt: new Date(Date.now() + 3600000) });
    const adminCookie = "__Host-sso_session=admin-cookie";
    const overview = await request("/admin/overview", { headers: { cookie: adminCookie } });
    expect(overview.status).toBe(200);
    expect(overview.headers.get("cache-control")).toBe("no-store");
    expect((await request("/admin/access-grants/revoke", { method: "POST", headers: { cookie: adminCookie, origin: "https://evil.test", "content-type": "application/json" }, body: JSON.stringify({ user_id: result.user_id, client_id: f.client.id, resource: audience }) })).status).toBe(403);
    const r = await f.start("Admin's key", "admin-new-key");
    await f.service.prove(r.requestId, f.signature(r.message));
    await expect(f.service.decide(r.requestId, adminId, "approved", ["finance:read"], adminId)).rejects.toThrow();
  });

  it("does not consume approvals that expire or lose client permissions during signing", async () => {
    for (const change of ["expire", "client-policy"]) {
      const f = fixture();
      const r = await f.start();
      await f.service.prove(r.requestId, f.signature(r.message));
      await f.service.decide(r.requestId, adminId, "approved", ["finance:read"]);
      f.onSign(() => {
        if (change === "expire") f.setNow(f.now() + 601);
        else f.client.allowedScopes = ["openid"];
      });
      await expect(f.service.poll(r.requestId, f.signature(r.pollMessage))).rejects.toMatchObject({ error: "invalid_grant" });
      expect(f.repository.sessions.size).toBe(0);
      expect(f.repository.refresh.size).toBe(0);
    }
  });

  it("requires confidential-client authentication before starting an approval login", async () => {
    const f = fixture();
    f.repository.clients.set(f.client.id, { ...f.client, type: "confidential", clientSecretHash: await Bun.password.hash("test-client-secret") });
    await expect(f.start()).rejects.toMatchObject({ error: "invalid_client" });
    const r = await f.service.start({ displayName: "Alice", credentialId: "backend-device", publicKey: f.publicKey,
      clientId: f.client.id, clientSecret: "test-client-secret", scopes: "finance:read", resource: audience });
    await f.service.prove(r.requestId, f.signature(r.message));
    await f.service.decide(r.requestId, adminId, "approved", ["finance:read"]);
    const result = await f.service.poll(r.requestId, f.signature(r.pollMessage));
    if (!("refresh_token" in result)) throw new Error("Expected tokens");
    await expect(f.oauth.refresh({ clientId: f.client.id }, { refreshToken: result.refresh_token })).rejects.toMatchObject({ error: "invalid_client" });
    expect(await f.oauth.refresh({ clientId: f.client.id, clientSecret: "test-client-secret" }, { refreshToken: result.refresh_token })).toHaveProperty("access_token");
  });
});
