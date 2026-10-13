import { createPublicKey, verify as verifySignature } from "node:crypto";
import type { AccessTokenClaims } from "./access-token";
import { decodeJson } from "./base64url";
import type { JsonWebKeySet } from "./signer";

interface AccessTokenHeader {
  alg?: string;
  typ?: string;
  kid?: string;
}

export class AccessTokenVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccessTokenVerificationError";
  }
}

export function verifyIssuedAccessToken(
  token: string,
  jwks: JsonWebKeySet,
  options: { issuer: string; audience: string; requiredScopes?: string[]; now?: () => number },
) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new AccessTokenVerificationError("Malformed access token");
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts as [string, string, string];
  let header: AccessTokenHeader;
  let claims: AccessTokenClaims;
  try {
    header = decodeJson<AccessTokenHeader>(encodedHeader);
    claims = decodeJson<AccessTokenClaims>(encodedClaims);
  } catch {
    throw new AccessTokenVerificationError("Invalid access token JSON");
  }
  if (header.typ !== "at+jwt" || header.alg !== "ES256" || !header.kid) {
    throw new AccessTokenVerificationError("Unsupported access token header");
  }
  const jwk = jwks.keys.find((candidate) =>
    candidate.kid === header.kid && candidate.alg === "ES256" && candidate.use === "sig",
  );
  if (!jwk) throw new AccessTokenVerificationError("Unknown signing key");
  const signature = Buffer.from(encodedSignature, "base64url");
  if (signature.length !== 64) {
    throw new AccessTokenVerificationError("Invalid ES256 signature length");
  }
  const valid = verifySignature(
    "sha256",
    Buffer.from(`${encodedHeader}.${encodedClaims}`, "utf8"),
    { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
    signature,
  );
  if (!valid) throw new AccessTokenVerificationError("Invalid signature");
  if (claims.iss !== options.issuer) throw new AccessTokenVerificationError("Unexpected token issuer");
  if (claims.aud !== options.audience) throw new AccessTokenVerificationError("Unexpected token audience");
  const now = options.now?.() ?? Math.floor(Date.now() / 1000);
  if (![claims.iat, claims.nbf, claims.exp].every(Number.isFinite)) throw new AccessTokenVerificationError("Invalid token time claims");
  if (claims.exp <= now - 60) throw new AccessTokenVerificationError("Access token expired");
  if (claims.nbf > now + 60 || claims.iat > now + 60) throw new AccessTokenVerificationError("Access token is not active");
  const scopes = new Set(typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : []);
  for (const scope of options.requiredScopes ?? []) {
    if (!scopes.has(scope)) throw new AccessTokenVerificationError(`Missing required scope: ${scope}`);
  }
  return {
    subject: claims.sub,
    clientId: claims.client_id,
    tokenId: claims.jti,
    claims,
    scopes,
  };
}
