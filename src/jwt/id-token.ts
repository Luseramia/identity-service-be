import { encodeJson } from "./base64url";
import type { JwtSigner } from "./signer";

export interface IssueIdTokenInput {
  subject: string;
  clientId: string;
  nonce?: string;
  authenticationTime: number;
  authenticationMethods: string[];
}

export class IdTokenIssuer {
  private readonly now: () => number;

  constructor(
    private readonly signer: JwtSigner,
    private readonly options: {
      issuer: string;
      ttlSeconds: number;
      now?: () => number;
    },
  ) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async issue(input: IssueIdTokenInput) {
    const now = this.now();
    const key = await this.signer.activeKey();
    const header = { alg: "ES256", typ: "JWT", kid: key.kid };
    const claims = {
      iss: this.options.issuer,
      sub: input.subject,
      aud: input.clientId,
      iat: now,
      exp: now + this.options.ttlSeconds,
      auth_time: input.authenticationTime,
      amr: input.authenticationMethods,
      ...(input.nonce ? { nonce: input.nonce } : {}),
    };
    const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
    return `${signingInput}.${await this.signer.sign(signingInput, key)}`;
  }
}

