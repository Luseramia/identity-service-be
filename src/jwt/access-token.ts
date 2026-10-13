import { encodeJson } from "./base64url";
import type { JwtSigner } from "./signer";

export interface IssueAccessTokenInput {
  subject: string;
  audience: string;
  clientId: string;
  scopes: string[];
  authenticationMethods?: string[];
  authenticationTime?: number;
  ttlSeconds?: number;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  client_id: string;
  scope: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  amr?: string[];
  auth_time?: number;
}

interface AccessTokenIssuerOptions {
  issuer: string;
  defaultTtlSeconds: number;
  now?: () => number;
  tokenId?: () => string;
}

export class AccessTokenIssuer {
  private readonly now: () => number;
  private readonly tokenId: () => string;

  constructor(
    private readonly signer: JwtSigner,
    private readonly options: AccessTokenIssuerOptions,
  ) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.tokenId = options.tokenId ?? (() => crypto.randomUUID());
  }

  async issue(input: IssueAccessTokenInput) {
    const scopes = [...new Set(input.scopes.map((scope) => scope.trim()))].filter(
      Boolean,
    );
    if (!input.subject || !input.audience || !input.clientId) {
      throw new Error("subject, audience and clientId are required");
    }
    if (scopes.some((scope) => /\s/.test(scope))) {
      throw new Error("Each scope must be a single OAuth scope token");
    }

    const ttl = input.ttlSeconds ?? this.options.defaultTtlSeconds;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) {
      throw new Error("Access token TTL must be between 1 and 3600 seconds");
    }

    const issuedAt = this.now();
    const claims: AccessTokenClaims = {
      iss: this.options.issuer,
      sub: input.subject,
      aud: input.audience,
      client_id: input.clientId,
      scope: scopes.join(" "),
      iat: issuedAt,
      nbf: issuedAt,
      exp: issuedAt + ttl,
      jti: this.tokenId(),
      ...(input.authenticationMethods?.length
        ? { amr: input.authenticationMethods }
        : {}),
      ...(input.authenticationTime !== undefined
        ? { auth_time: input.authenticationTime }
        : {}),
    };

    const key = await this.signer.activeKey();
    const protectedHeader = {
      alg: "ES256",
      typ: "at+jwt",
      kid: key.kid,
    };
    const signingInput = `${encodeJson(protectedHeader)}.${encodeJson(claims)}`;
    const signature = await this.signer.sign(signingInput, key);

    return {
      accessToken: `${signingInput}.${signature}`,
      expiresIn: ttl,
      tokenType: "Bearer" as const,
      claims,
    };
  }
}

