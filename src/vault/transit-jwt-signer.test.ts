import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { VaultTransitJwtSigner } from "./transit-jwt-signer";

describe("VaultTransitJwtSigner", () => {
  it("pins a key version, requests JWS marshaling and publishes public JWKS", async () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicKey = pair.publicKey.export({ type: "spki", format: "pem" });
    const requests: Array<{ url: string; init: RequestInit }> = [];

    const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init: init ?? {} });
      if (url.endsWith("/keys/access-token")) {
        return Response.json({
          data: {
            type: "ecdsa-p256",
            latest_version: 2,
            keys: {
              "2": { public_key: publicKey },
            },
          },
        });
      }
      if (url.endsWith("/sign/access-token/sha2-256")) {
        return Response.json({ data: { signature: "vault:v2:signature_value" } });
      }
      return new Response(null, { status: 404 });
    }) as typeof fetch;

    const signer = new VaultTransitJwtSigner({
      address: "https://vault.example.test",
      mount: "sso-jwt",
      keyName: "access-token",
      token: async () => "vault-runtime-token",
      fetch: fakeFetch,
    });

    const active = await signer.activeKey();
    expect(active).toEqual({ version: 2, kid: "access-token:v2" });
    expect(await signer.sign("header.payload", active)).toBe("signature_value");
    expect((await signer.jwks()).keys[0]).toMatchObject({
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      use: "sig",
      kid: "access-token:v2",
    });

    const signRequest = requests.find(({ url }) => url.includes("/sign/"));
    expect(signRequest?.init.headers).toMatchObject({
      "X-Vault-Token": "vault-runtime-token",
    });
    expect(JSON.parse(String(signRequest?.init.body))).toMatchObject({
      key_version: 2,
      marshaling_algorithm: "jws",
    });
  });
});

