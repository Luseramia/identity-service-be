import { describe, expect, it } from "bun:test";
import {
  generateKeyPairSync,
  sign as createSignature,
} from "node:crypto";
import type { JsonWebKey } from "node:crypto";
import { verifyIssuedAccessToken as verifyAccessToken } from "./access-token-verifier";
import { AccessTokenIssuer } from "./access-token";
import { encodeJson } from "./base64url";
import { IdTokenIssuer } from "./id-token";
import type {
  ActiveSigningKey,
  JsonWebKeySet,
  JwtSigner,
} from "./signer";

class RotatingTestSigner implements JwtSigner {
  private version = 0;
  private readonly keyring = new Map<
    number,
    ReturnType<typeof generateKeyPairSync>
  >();

  constructor() {
    this.rotate();
  }

  rotate() {
    this.version += 1;
    this.keyring.set(
      this.version,
      generateKeyPairSync("ec", { namedCurve: "P-256" }),
    );
  }

  async activeKey(): Promise<ActiveSigningKey> {
    return { version: this.version, kid: `access-token:v${this.version}` };
  }

  async sign(signingInput: string, key: ActiveSigningKey) {
    const pair = this.keyring.get(key.version);
    if (!pair) throw new Error("Unknown test signing key");
    return createSignature(
      "sha256",
      Buffer.from(signingInput),
      { key: pair.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64url");
  }

  async jwks(): Promise<JsonWebKeySet> {
    return {
      keys: [...this.keyring].map(([version, pair]) => ({
        ...(pair.publicKey.export({ format: "jwk" }) as JsonWebKey),
        kid: `access-token:v${version}`,
        alg: "ES256",
        use: "sig" as const,
      })),
    };
  }
}

const NOW = 1_800_000_000;
const ISSUER = "https://auth.example.test";
const AUDIENCE = "https://finance-api.example.test";

const issuer = (signer: JwtSigner) =>
  new AccessTokenIssuer(signer, {
    issuer: ISSUER,
    defaultTtlSeconds: 600,
    now: () => NOW,
    tokenId: () => "token-id",
  });

describe("Vault-backed JWT access tokens", () => {
  it("issues an RFC 9068-shaped ES256 token that the resource API accepts", async () => {
    const signer = new RotatingTestSigner();
    const issued = await issuer(signer).issue({
      subject: "019d2f29-b80a-7c21-b73a-415687c7d785",
      audience: AUDIENCE,
      clientId: "finance-web",
      scopes: ["finance:read", "finance:write", "finance:read"],
      authenticationMethods: ["device_signature"],
      authenticationTime: NOW - 5,
    });

    const context = verifyAccessToken(issued.accessToken, await signer.jwks(), {
      issuer: ISSUER,
      audience: AUDIENCE,
      requiredScopes: ["finance:write"],
      now: () => NOW,
    });

    expect(issued.tokenType).toBe("Bearer");
    expect(issued.expiresIn).toBe(600);
    expect(context.subject).toBe("019d2f29-b80a-7c21-b73a-415687c7d785");
    expect(context.clientId).toBe("finance-web");
    expect([...context.scopes]).toEqual(["finance:read", "finance:write"]);
    expect(context.claims.amr).toEqual(["device_signature"]);
  });

  it("rejects token substitution, wrong audiences and missing scopes", async () => {
    const signer = new RotatingTestSigner();
    const issued = await issuer(signer).issue({
      subject: "user-1",
      audience: AUDIENCE,
      clientId: "finance-web",
      scopes: ["finance:read"],
    });
    const jwks = await signer.jwks();

    expect(() =>
      verifyAccessToken(issued.accessToken, jwks, {
        issuer: ISSUER,
        audience: "https://documents-api.example.test",
        now: () => NOW,
      }),
    ).toThrow("Unexpected token audience");

    expect(() =>
      verifyAccessToken(issued.accessToken, jwks, {
        issuer: ISSUER,
        audience: AUDIENCE,
        requiredScopes: ["finance:write"],
        now: () => NOW,
      }),
    ).toThrow("Missing required scope");

    const parts = issued.accessToken.split(".");
    const signature = parts[2]!;
    const tamperedSignature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    const tampered = `${parts[0]}.${parts[1]}.${tamperedSignature}`;
    expect(() =>
      verifyAccessToken(tampered, jwks, {
        issuer: ISSUER,
        audience: AUDIENCE,
        now: () => NOW,
      }),
    ).toThrow("Invalid signature");
  });

  it("keeps old unexpired tokens valid after a signing-key rotation", async () => {
    const signer = new RotatingTestSigner();
    const service = issuer(signer);
    const beforeRotation = await service.issue({
      subject: "user-1",
      audience: AUDIENCE,
      clientId: "finance-web",
      scopes: ["finance:read"],
    });

    signer.rotate();
    const afterRotation = await service.issue({
      subject: "user-1",
      audience: AUDIENCE,
      clientId: "finance-web",
      scopes: ["finance:read"],
    });
    const jwks = await signer.jwks();

    expect(jwks.keys.map((key) => key.kid)).toEqual([
      "access-token:v1",
      "access-token:v2",
    ]);
    expect(
      verifyAccessToken(beforeRotation.accessToken, jwks, {
        issuer: ISSUER,
        audience: AUDIENCE,
        now: () => NOW,
      }).subject,
    ).toBe("user-1");
    expect(
      verifyAccessToken(afterRotation.accessToken, jwks, {
        issuer: ISSUER,
        audience: AUDIENCE,
        now: () => NOW,
      }).subject,
    ).toBe("user-1");
  });

  it("rejects unknown keys, expired/future tokens, and ID-token substitution", async () => {
    const signer = new RotatingTestSigner();
    const issued = await issuer(signer).issue({
      subject: "user-1",
      audience: AUDIENCE,
      clientId: "finance-web",
      scopes: ["finance:read"],
    });
    const jwks = await signer.jwks();
    const parts = issued.accessToken.split(".");
    const unknownKey = `${encodeJson({ alg: "ES256", typ: "at+jwt", kid: "missing:v1" })}.${parts[1]}.${parts[2]}`;
    expect(() => verifyAccessToken(unknownKey, jwks, {
      issuer: ISSUER, audience: AUDIENCE, now: () => NOW,
    })).toThrow("Unknown signing key");
    expect(() => verifyAccessToken(issued.accessToken, jwks, {
      issuer: ISSUER, audience: AUDIENCE, now: () => NOW + 700, clockSkewSeconds: 0,
    })).toThrow("Access token expired");
    expect(() => verifyAccessToken(issued.accessToken, jwks, {
      issuer: ISSUER, audience: AUDIENCE, now: () => NOW - 120, clockSkewSeconds: 0,
    })).toThrow("Access token is not active");

    const idToken = await new IdTokenIssuer(signer, {
      issuer: ISSUER,
      ttlSeconds: 600,
      now: () => NOW,
    }).issue({
      subject: "user-1",
      clientId: "finance-web",
      authenticationTime: NOW,
      authenticationMethods: ["device_signature"],
    });
    expect(() => verifyAccessToken(idToken, jwks, {
      issuer: ISSUER, audience: "finance-web", now: () => NOW,
    })).toThrow("Unsupported access token header");
  });
});

