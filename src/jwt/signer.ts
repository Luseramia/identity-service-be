export interface JsonWebKey {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [member: string]: string | undefined;
}

export interface ActiveSigningKey {
  version: number;
  kid: string;
}

export interface JsonWebKeySet {
  keys: Array<JsonWebKey & { kid: string; alg: string; use: "sig" }>;
}

export interface JwtSigner {
  activeKey(): Promise<ActiveSigningKey>;
  sign(signingInput: string, key: ActiveSigningKey): Promise<string>;
  jwks(): Promise<JsonWebKeySet>;
}

