import { describe, expect, it } from "bun:test";
import {
  generateKeyPairSync,
  sign as createSignature,
  type JsonWebKey,
} from "node:crypto";
import { AccessTokenIssuer } from "../jwt/access-token";
import { decodeJson } from "../jwt/base64url";
import { IdTokenIssuer } from "../jwt/id-token";
import type { ActiveSigningKey, JwtSigner } from "../jwt/signer";
import { MemoryIdentityRepository } from "../repository/memory-identity-repository";
import { hashToken, pkceChallenge } from "../security/crypto";
import { MemoryIdentityTransientStore } from "../store/memory-transient-store";
import { EnrollmentService } from "./enrollment-service";
import { OAuthService } from "./oauth-service";
import { AuthenticationError, SessionService } from "./session-service";

const NOW = 1_800_000_000;
const ISSUER = "https://auth.example.test";
const AUDIENCE = "https://finance-api.example.test";
const USER_ID = "019d2f29-b80a-7c21-b73a-415687c7d785";

class TestSigner implements JwtSigner {
  readonly pair = generateKeyPairSync("ec", { namedCurve: "P-256" });

  async activeKey(): Promise<ActiveSigningKey> {
    return { version: 1, kid: "access-token:v1" };
  }

  async sign(signingInput: string) {
    return createSignature(
      "sha256",
      Buffer.from(signingInput),
      { key: this.pair.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64url");
  }

  async jwks() {
    return {
      keys: [{
        ...(this.pair.publicKey.export({ format: "jwk" }) as JsonWebKey),
        kid: "access-token:v1",
        alg: "ES256",
        use: "sig" as const,
      }],
    };
  }
}

const client = {
  id: "finance-web",
  name: "Finance Web",
  type: "public" as const,
  clientSecretHash: null,
  redirectUris: ["https://finance.example.test/callback"],
  allowedScopes: ["openid", "profile", "finance:read", "finance:write"],
  allowedResources: [AUDIENCE],
  status: "ACTIVE",
};

function oauthFixture() {
  const repository = new MemoryIdentityRepository();
  const store = new MemoryIdentityTransientStore();
  const signer = new TestSigner();
  let now = NOW;
  repository.clients.set(client.id, client);
  repository.users.set(USER_ID, {
    id: USER_ID,
    displayName: "Test User",
    status: "ACTIVE",
  });
  const approvalId = "019d2f29-b80a-7c21-b73a-415687c7d786";
  repository.credentials.set("approved-device", { id: "credential-1", credentialId: "approved-device", userId: USER_ID,
    publicKey: "test-public-key", algorithm: "ES256", status: "ACTIVE", userStatus: "ACTIVE" });
  repository.approvals.set(approvalId, { id: approvalId, displayName: "Test User", credentialId: "approved-device",
    publicKey: "test-public-key", algorithm: "ES256", message: "proof", clientId: client.id, resource: AUDIENCE,
    requestedScopes: client.allowedScopes, approvedScopes: client.allowedScopes, userId: USER_ID, status: "consumed",
    createdAt: new Date(NOW * 1000), expiresAt: new Date((NOW + 600) * 1000) });
  repository.grants.set(JSON.stringify([USER_ID, client.id, AUDIENCE]), { userId: USER_ID, clientId: client.id,
    resource: AUDIENCE, scopes: client.allowedScopes });
  const access = new AccessTokenIssuer(signer, {
    issuer: ISSUER,
    defaultTtlSeconds: 600,
    now: () => now,
  });
  const id = new IdTokenIssuer(signer, {
    issuer: ISSUER,
    ttlSeconds: 600,
    now: () => now,
  });
  const service = new OAuthService(repository, store, access, id, {
    issuer: ISSUER,
    authorizationCodeTtlSeconds: 90,
    deviceCodeTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    now: () => now,
  });
  const session = {
    approvalId,
    id: "session-1",
    user: repository.users.get(USER_ID)!,
    authenticationMethod: "device_signature",
    authenticatedAt: new Date((NOW - 10) * 1000),
    expiresAt: new Date((NOW + 3600) * 1000),
  };
  return { repository, store, signer, service, session, setNow: (value: number) => { now = value; } };
}

async function authorizationCode(
  fixture: ReturnType<typeof oauthFixture>,
  verifier: string,
) {
  const redirect = await fixture.service.authorize({
    responseType: "code",
    clientId: client.id,
    redirectUri: client.redirectUris[0],
    scopes: "openid finance:read",
    resource: AUDIENCE,
    codeChallenge: pkceChallenge(verifier),
    codeChallengeMethod: "S256",
    state: "csrf-state",
    nonce: "oidc-nonce",
  }, fixture.session);
  const url = new URL(redirect);
  expect(url.searchParams.get("state")).toBe("csrf-state");
  return url.searchParams.get("code")!;
}

describe("Authorization Code and refresh-token flows", () => {
  it("enforces exact redirects and one-time PKCE codes, then binds the nonce", async () => {
    const fixture = oauthFixture();
    const verifier = "v".repeat(64);
    await expect(fixture.service.authorize({
      responseType: "code",
      clientId: client.id,
      redirectUri: `${client.redirectUris[0]}/attacker`,
      scopes: "openid",
      resource: AUDIENCE,
      codeChallenge: pkceChallenge(verifier),
      codeChallengeMethod: "S256",
    }, fixture.session)).rejects.toMatchObject({ error: "invalid_request" });

    const code = await authorizationCode(fixture, verifier);
    const tokens = await fixture.service.exchangeAuthorizationCode(
      { clientId: client.id },
      { code, redirectUri: client.redirectUris[0], codeVerifier: verifier },
    );
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.scope).toBe("openid finance:read");
    const idClaims = decodeJson<{ nonce?: string; aud: string }>(
      tokens.id_token!.split(".")[1]!,
    );
    expect(idClaims).toMatchObject({ nonce: "oidc-nonce", aud: client.id });

    await expect(fixture.service.exchangeAuthorizationCode(
      { clientId: client.id },
      { code, redirectUri: client.redirectUris[0], codeVerifier: verifier },
    )).rejects.toMatchObject({ error: "invalid_grant" });

    await fixture.service.revoke(
      { clientId: client.id },
      tokens.refresh_token,
    );
    await expect(fixture.service.refresh(
      { clientId: client.id },
      { refreshToken: tokens.refresh_token },
    )).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("rejects a PKCE mismatch and detects reuse across a refresh-token family", async () => {
    const fixture = oauthFixture();
    const verifier = "p".repeat(64);
    const badCode = await authorizationCode(fixture, verifier);
    await expect(fixture.service.exchangeAuthorizationCode(
      { clientId: client.id },
      { code: badCode, redirectUri: client.redirectUris[0], codeVerifier: "x".repeat(64) },
    )).rejects.toMatchObject({ error: "invalid_grant" });

    const expiredCode = await authorizationCode(fixture, verifier);
    fixture.setNow(NOW + 91);
    await expect(fixture.service.exchangeAuthorizationCode(
      { clientId: client.id },
      { code: expiredCode, redirectUri: client.redirectUris[0], codeVerifier: verifier },
    )).rejects.toMatchObject({ error: "invalid_grant" });
    fixture.setNow(NOW);

    const code = await authorizationCode(fixture, verifier);
    const issued = await fixture.service.exchangeAuthorizationCode(
      { clientId: client.id },
      { code, redirectUri: client.redirectUris[0], codeVerifier: verifier },
    );
    const rotated = await fixture.service.refresh(
      { clientId: client.id },
      { refreshToken: issued.refresh_token },
    );
    await expect(fixture.service.refresh(
      { clientId: client.id },
      { refreshToken: issued.refresh_token },
    )).rejects.toMatchObject({ error: "invalid_grant" });
    await expect(fixture.service.refresh(
      { clientId: client.id },
      { refreshToken: rotated.refresh_token },
    )).rejects.toMatchObject({ error: "invalid_grant" });
    expect(fixture.repository.auditEvents.map((event) => event.action)).toContain(
      "oauth.refresh.reuse_detected",
    );
  });
});

describe("Device Authorization Grant", () => {
  it("returns polling errors, records approval, and consumes an approved grant", async () => {
    const fixture = oauthFixture();
    const started = await fixture.service.startDeviceAuthorization(
      { clientId: client.id },
      { scopes: "openid finance:read", resource: AUDIENCE },
    );
    await expect(fixture.service.exchangeDeviceCode(
      { clientId: client.id },
      started.device_code,
    )).rejects.toMatchObject({ error: "slow_down" });

    fixture.setNow(NOW + 10);
    await expect(fixture.service.exchangeDeviceCode(
      { clientId: client.id },
      started.device_code,
    )).rejects.toMatchObject({ error: "authorization_pending" });

    await fixture.service.decideDeviceGrant(started.user_code, "approved", fixture.session);
    const issued = await fixture.service.exchangeDeviceCode(
      { clientId: client.id },
      started.device_code,
    );
    expect(issued).toHaveProperty("access_token");
    expect(fixture.repository.auditEvents.map((event) => event.action)).toContain(
      "oauth.device.approved",
    );
    await expect(fixture.service.exchangeDeviceCode(
      { clientId: client.id },
      started.device_code,
    )).rejects.toMatchObject({ error: "expired_token" });
  });

  it("returns access_denied after an authenticated user rejects the request", async () => {
    const fixture = oauthFixture();
    const started = await fixture.service.startDeviceAuthorization(
      { clientId: client.id },
      { scopes: "finance:read", resource: AUDIENCE },
    );
    await fixture.service.decideDeviceGrant(started.user_code, "denied", fixture.session);
    await expect(fixture.service.exchangeDeviceCode(
      { clientId: client.id },
      started.device_code,
    )).rejects.toMatchObject({ error: "access_denied" });
  });
});

describe("Device enrollment and SSO browser sessions", () => {
  it("requires signed one-time challenges and rejects disabled credentials", async () => {
    const repository = new MemoryIdentityRepository();
    const store = new MemoryIdentityTransientStore();
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
    const rawEnrollmentToken = "one-time-enrollment-token";
    repository.users.set(USER_ID, { id: USER_ID, displayName: "Test User", status: "ACTIVE" });
    repository.enrollments.set(hashToken(rawEnrollmentToken), {
      id: "enrollment-1",
      userId: USER_ID,
      tokenHash: hashToken(rawEnrollmentToken),
      expiresAt: new Date((NOW + 600) * 1000),
    });
    const enrollment = new EnrollmentService(repository, store, {
      challengeTtlSeconds: 300,
      now: () => NOW,
    });
    const sessions = new SessionService(repository, store, {
      challengeTtlSeconds: 300,
      sessionTtlSeconds: 3600,
      now: () => NOW,
    });
    const started = await enrollment.start({
      enrollmentToken: rawEnrollmentToken,
      credentialId: "device-1",
      publicKey,
      algorithm: "ES256",
    });
    const enrollmentSignature = createSignature(
      "sha256",
      Buffer.from(started.message),
      { key: pair.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64url");
    await expect(enrollment.complete(started.enrollmentId, enrollmentSignature)).resolves.toEqual({ success: true });
    await expect(enrollment.complete(started.enrollmentId, enrollmentSignature)).rejects.toBeInstanceOf(AuthenticationError);

    const challenge = await sessions.start("device-1");
    const loginSignature = createSignature(
      "sha256",
      Buffer.from(challenge.message),
      { key: pair.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64url");
    const session = await sessions.complete(challenge.challengeId, loginSignature);
    expect((await sessions.resolve(session.token))?.user.id).toBe(USER_ID);
    await sessions.logout(session.token);
    expect(await sessions.resolve(session.token)).toBeNull();

    repository.credentials.get("device-1")!.status = "REVOKED";
    await expect(sessions.start("device-1")).rejects.toBeInstanceOf(AuthenticationError);
  });
});
