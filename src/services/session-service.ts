import type { IdentityRepository } from "../repository/identity-repository";
import {
  deviceApprovalMessage,
  hashToken,
  randomOpaqueToken,
  verifyDeviceSignature,
} from "../security/crypto";
import type { IdentityTransientStore } from "../store/transient-store";

export class AuthenticationError extends Error {
  constructor(message = "Authentication failed") {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class SessionService {
  private readonly now: () => number;

  constructor(
    private readonly repository: IdentityRepository,
    private readonly store: IdentityTransientStore,
    private readonly options: {
      challengeTtlSeconds: number;
      sessionTtlSeconds: number;
      now?: () => number;
    },
  ) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async start(credentialId: string) {
    if (!credentialId) throw new AuthenticationError();
    const credential = await this.repository.findCredential(credentialId);
    if (
      !credential ||
      credential.status !== "ACTIVE" ||
      credential.userStatus !== "ACTIVE"
    ) {
      throw new AuthenticationError();
    }

    const id = crypto.randomUUID();
    const challenge = randomOpaqueToken();
    const message = deviceApprovalMessage({
      purpose: "login",
      transactionId: id,
      challenge,
    });
    const expiresAt = this.now() + this.options.challengeTtlSeconds;
    await this.store.putLoginChallenge(
      { id, credentialId, challenge, message, expiresAt },
      this.options.challengeTtlSeconds,
    );
    return { challengeId: id, challenge, message, expiresIn: this.options.challengeTtlSeconds };
  }

  async complete(challengeId: string, signature: string) {
    const challenge = await this.store.consumeLoginChallenge(challengeId);
    if (!challenge || challenge.expiresAt <= this.now()) throw new AuthenticationError();
    const credential = await this.repository.findCredential(challenge.credentialId);
    if (
      !credential ||
      credential.status !== "ACTIVE" ||
      credential.userStatus !== "ACTIVE" ||
      !verifyDeviceSignature({
        publicKeyBase64: credential.publicKey,
        algorithm: credential.algorithm,
        message: challenge.message,
        signatureBase64Url: signature,
      })
    ) {
      throw new AuthenticationError();
    }

    const now = this.now();
    const rawToken = randomOpaqueToken();
    const expiresAt = new Date((now + this.options.sessionTtlSeconds) * 1000);
    await this.repository.createBrowserSession({
      tokenHash: hashToken(rawToken),
      userId: credential.userId,
      authenticationMethod: "device_signature",
      authenticatedAt: new Date(now * 1000),
      expiresAt,
    });
    await this.repository.audit({
      actorId: credential.userId,
      action: "session.login",
      metadata: { credentialId: credential.id },
    });
    return { token: rawToken, expiresAt };
  }

  async resolve(rawToken?: string) {
    if (!rawToken) return null;
    return this.repository.findBrowserSession(
      hashToken(rawToken),
      new Date(this.now() * 1000),
    );
  }

  async logout(rawToken?: string) {
    if (rawToken) await this.repository.revokeBrowserSession(hashToken(rawToken));
  }
}

