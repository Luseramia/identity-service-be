import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
} from "node:crypto";

export function randomOpaqueToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(token: string) {
  return createHash("sha256").update(token, "utf8").digest("base64url");
}

export function pkceChallenge(verifier: string) {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyPkce(verifier: string, expectedChallenge: string) {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  const actual = Buffer.from(pkceChallenge(verifier));
  const expected = Buffer.from(expectedChallenge);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function deviceApprovalMessage(input: {
  purpose: "login" | "enrollment" | "login_approval";
  transactionId: string;
  challenge: string;
}) {
  return [
    "bun-sso-device-proof:v1",
    input.purpose,
    input.transactionId,
    input.challenge,
  ].join("\n");
}

export function verifyDeviceSignature(input: {
  publicKeyBase64: string;
  algorithm: string;
  message: string;
  signatureBase64Url: string;
}) {
  if (!["ECDSA", "ECDSA_P256", "ES256"].includes(input.algorithm)) return false;
  try {
    const key = createPublicKey({
      key: Buffer.from(input.publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
    const signature = Buffer.from(input.signatureBase64Url, "base64url");
    if (signature.length !== 64) return false;
    return verify(
      "sha256",
      Buffer.from(input.message, "utf8"),
      { key, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch {
    return false;
  }
}

export function normalizeUserCode(value: string) {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

export function createUserCode() {
  const alphabet = "BCDFGHJKLMNPQRSTVWXYZ23456789";
  const bytes = randomBytes(8);
  const code = [...bytes]
    .map((byte) => alphabet[byte! % alphabet.length])
    .join("");
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

