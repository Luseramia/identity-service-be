import { AccessTokenIssuer } from "../src/jwt/access-token";
import { verifyIssuedAccessToken as verifyAccessToken } from "../src/jwt/access-token-verifier";
import { loadIdentityConfig } from "../src/config";
import { VaultTransitJwtSigner } from "../src/vault/transit-jwt-signer";
import { readVaultToken } from "../src/runtime-config";

const config = loadIdentityConfig();
const signer = new VaultTransitJwtSigner({
  address: config.vault.address,
  mount: config.vault.transitMount,
  keyName: config.vault.transitKey,
  metadataCacheSeconds: config.vault.keyMetadataCacheSeconds,
  token: readVaultToken,
});
const audience = "urn:bun-sso:smoke-test";

try {
  const issuer = new AccessTokenIssuer(signer, {
    issuer: config.issuer,
    defaultTtlSeconds: 60,
  });
  const issued = await issuer.issue({
    subject: "smoke-test-subject",
    audience,
    clientId: "identity-smoke-test",
    scopes: ["identity:smoke-test"],
    authenticationMethods: ["test"],
  });
  const context = verifyAccessToken(issued.accessToken, await signer.jwks(), {
    issuer: config.issuer,
    audience,
    requiredScopes: ["identity:smoke-test"],
  });
  if (context.subject !== "smoke-test-subject") {
    throw new Error("Verified token subject did not match");
  }
  console.log(
    `Identity Vault verification complete: ${context.tokenId} (${issued.expiresIn}s)`,
  );
} catch (error) {
  console.error(
    `Identity Vault verification failed: ${error instanceof Error ? error.message : "unknown error"}`,
  );
  process.exitCode = 1;
}

