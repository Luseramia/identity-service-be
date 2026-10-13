import { describe, expect, it } from "bun:test";
import { createIdentityApp } from "./app";
import type { JwtSigner } from "./jwt/signer";
import { MemoryIdentityRepository } from "./repository/memory-identity-repository";
import { MemoryIdentityTransientStore } from "./store/memory-transient-store";

const signer: JwtSigner = {
  activeKey: async () => ({ version: 1, kid: "access-token:v1" }),
  sign: async () => "signature",
  jwks: async () => ({
    keys: [
      {
        kty: "EC",
        crv: "P-256",
        x: "x",
        y: "y",
        kid: "access-token:v1",
        alg: "ES256",
        use: "sig",
      },
    ],
  }),
};

const app = createIdentityApp({
  signer,
  repository: new MemoryIdentityRepository(),
  store: new MemoryIdentityTransientStore(),
  config: {
    issuer: "https://auth.example.test",
    port: 3001,
    accessTokenTtlSeconds: 600,
    idTokenTtlSeconds: 600,
    authorizationCodeTtlSeconds: 90,
    deviceCodeTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    browserSessionTtlSeconds: 28_800,
    authenticationChallengeTtlSeconds: 300,
    vault: {
      address: "https://vault.example.test",
      transitMount: "sso-jwt",
      transitKey: "access-token",
      keyMetadataCacheSeconds: 30,
    },
  },
});

describe("Identity service discovery", () => {
  it("publishes OAuth metadata with PKCE and Device Grant", async () => {
    const response = await app.handle(
      new Request(
        "https://auth.example.test/.well-known/oauth-authorization-server",
      ),
    );
    const metadata = (await response.json()) as {
      issuer: string;
      code_challenge_methods_supported: string[];
      grant_types_supported: string[];
      jwks_uri: string;
    };

    expect(response.status).toBe(200);
    expect(metadata.issuer).toBe("https://auth.example.test");
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
    expect(metadata.grant_types_supported).toContain(
      "urn:ietf:params:oauth:grant-type:device_code",
    );
    expect(metadata.jwks_uri).toBe(
      "https://auth.example.test/.well-known/jwks.json",
    );
  });

  it("publishes JWKS with a bounded public cache", async () => {
    const response = await app.handle(
      new Request("https://auth.example.test/.well-known/jwks.json"),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=30");
    const body = (await response.json()) as { keys: Array<{ kid: string }> };
    expect(body.keys[0]?.kid).toBe("access-token:v1");
  });

  it("publishes OIDC signing metadata and Prometheus metrics", async () => {
    const discovery = await app.handle(
      new Request("https://auth.example.test/.well-known/openid-configuration"),
    );
    const metadata = await discovery.json() as {
      subject_types_supported: string[];
      id_token_signing_alg_values_supported: string[];
    };
    expect(metadata.subject_types_supported).toEqual(["public"]);
    expect(metadata.id_token_signing_alg_values_supported).toEqual(["ES256"]);

    const metrics = await app.handle(new Request("https://auth.example.test/metrics"));
    expect(metrics.status).toBe(200);
    expect(metrics.headers.get("content-type")).toContain("text/plain");
    expect(await metrics.text()).toContain("identity_vault_sign_failures_total");
  });
});

