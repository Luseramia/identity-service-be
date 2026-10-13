export function encodeBase64Url(input: string | Uint8Array) {
  return Buffer.from(input).toString("base64url");
}

export function encodeJson(value: unknown) {
  return encodeBase64Url(JSON.stringify(value));
}

export function decodeJson<T>(encoded: string): T {
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as T;
}

