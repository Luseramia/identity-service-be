import { createPublicKey } from "node:crypto";
import type {
  ActiveSigningKey,
  JsonWebKey,
  JsonWebKeySet,
  JwtSigner,
} from "../jwt/signer";

interface VaultTransitSignerOptions {
  address: string;
  mount: string;
  keyName: string;
  token: () => Promise<string>;
  metadataCacheSeconds?: number;
  fetch?: typeof fetch;
}

interface TransitKeyVersion {
  public_key?: string;
  creation_time?: string;
}

interface TransitKeyResponse {
  data?: {
    type?: string;
    latest_version?: number;
    keys?: Record<string, TransitKeyVersion | number>;
  };
}

interface TransitSignResponse {
  data?: {
    signature?: string;
  };
}

export class VaultTransitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultTransitError";
  }
}

export class VaultTransitJwtSigner implements JwtSigner {
  private readonly fetcher: typeof fetch;
  private cachedMetadata:
    | { value: Required<TransitKeyResponse>["data"]; expiresAt: number }
    | undefined;

  constructor(private readonly options: VaultTransitSignerOptions) {
    this.fetcher = options.fetch ?? fetch;
  }

  async activeKey(): Promise<ActiveSigningKey> {
    const metadata = await this.keyMetadata();
    const versions = Object.keys(metadata.keys ?? {})
      .map(Number)
      .filter(Number.isInteger);
    const version = metadata.latest_version ?? Math.max(...versions);
    if (!Number.isInteger(version) || version < 1) {
      throw new VaultTransitError("Vault Transit key has no active version");
    }
    return { version, kid: this.kid(version) };
  }

  async sign(signingInput: string, key: ActiveSigningKey): Promise<string> {
    const response = await this.request<TransitSignResponse>(
      `/v1/${this.options.mount}/sign/${this.options.keyName}/sha2-256`,
      {
        method: "POST",
        body: JSON.stringify({
          input: Buffer.from(signingInput, "utf8").toString("base64"),
          key_version: key.version,
          marshaling_algorithm: "jws",
        }),
      },
    );

    const encoded = response.data?.signature;
    const match = encoded?.match(/^vault:v(\d+):([A-Za-z0-9_-]+)$/);
    if (!match) {
      throw new VaultTransitError("Vault returned an invalid JWS signature");
    }
    if (Number(match[1]) !== key.version) {
      throw new VaultTransitError("Vault signed with an unexpected key version");
    }
    return match[2]!;
  }

  async jwks(): Promise<JsonWebKeySet> {
    const metadata = await this.keyMetadata();
    const keys: JsonWebKeySet["keys"] = [];

    for (const [rawVersion, value] of Object.entries(metadata.keys ?? {})) {
      if (typeof value === "number" || !value.public_key) continue;
      const version = Number(rawVersion);
      if (!Number.isInteger(version)) continue;

      const exported = createPublicKey(value.public_key).export({
        format: "jwk",
      }) as JsonWebKey;
      if (exported.kty !== "EC" || exported.crv !== "P-256") {
        throw new VaultTransitError(
          `Vault Transit key version ${version} is not ECDSA P-256`,
        );
      }
      keys.push({
        ...exported,
        kid: this.kid(version),
        alg: "ES256",
        use: "sig",
      });
    }

    keys.sort((a, b) => a.kid.localeCompare(b.kid));
    if (keys.length === 0) {
      throw new VaultTransitError("Vault Transit key has no public keys");
    }
    return { keys };
  }

  invalidateMetadata() {
    this.cachedMetadata = undefined;
  }

  private kid(version: number) {
    return `${this.options.keyName}:v${version}`;
  }

  private async keyMetadata() {
    const now = Date.now();
    if (this.cachedMetadata && this.cachedMetadata.expiresAt > now) {
      return this.cachedMetadata.value;
    }

    const response = await this.request<TransitKeyResponse>(
      `/v1/${this.options.mount}/keys/${this.options.keyName}`,
      { method: "GET" },
    );
    if (!response.data) {
      throw new VaultTransitError("Vault Transit key metadata is missing");
    }
    if (response.data.type !== "ecdsa-p256") {
      throw new VaultTransitError(
        `Expected ecdsa-p256 Transit key, received ${response.data.type ?? "unknown"}`,
      );
    }

    this.cachedMetadata = {
      value: response.data,
      expiresAt:
        now + (this.options.metadataCacheSeconds ?? 30) * 1000,
    };
    return response.data;
  }

  private async request<T>(path: string, init: RequestInit) {
    const token = await this.options.token();
    const response = await this.fetcher(`${this.options.address}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Vault-Token": token,
        ...init.headers,
      },
    });

    if (!response.ok) {
      throw new VaultTransitError(
        `Vault request ${path} failed with HTTP ${response.status}`,
      );
    }
    return (await response.json()) as T;
  }
}

