import type { IdentityRepository } from "../repository/identity-repository";
import {
  deviceApprovalMessage,
  hashToken,
  randomOpaqueToken,
  verifyDeviceSignature,
} from "../security/crypto";
import type { IdentityTransientStore } from "../store/transient-store";
import { AuthenticationError } from "./session-service";

export class EnrollmentService {
  private readonly now: () => number;

  constructor(
    private readonly repository: IdentityRepository,
    private readonly store: IdentityTransientStore,
    private readonly options: { challengeTtlSeconds: number; now?: () => number },
  ) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async start(input: {
    enrollmentToken: string;
    credentialId: string;
    publicKey: string;
    algorithm: string;
  }) {
    if (
      !input.enrollmentToken ||
      !input.credentialId ||
      !input.publicKey ||
      !["ECDSA", "ECDSA_P256", "ES256"].includes(input.algorithm)
    ) {
      throw new AuthenticationError("Invalid enrollment request");
    }
    const enrollment = await this.repository.findEnrollment(
      hashToken(input.enrollmentToken),
    );
    if (!enrollment) throw new AuthenticationError("Invalid enrollment token");

    const id = crypto.randomUUID();
    const challenge = randomOpaqueToken();
    const message = deviceApprovalMessage({
      purpose: "enrollment",
      transactionId: id,
      challenge,
    });
    const expiresAt = this.now() + this.options.challengeTtlSeconds;
    await this.store.putEnrollmentChallenge(
      {
        id,
        enrollmentId: enrollment.id,
        userId: enrollment.userId,
        credentialId: input.credentialId,
        publicKey: input.publicKey,
        algorithm: input.algorithm,
        challenge,
        message,
        expiresAt,
      },
      this.options.challengeTtlSeconds,
    );
    return { enrollmentId: id, challenge, message, expiresIn: this.options.challengeTtlSeconds };
  }

  async complete(enrollmentId: string, signature: string) {
    const record = await this.store.consumeEnrollmentChallenge(enrollmentId);
    if (
      !record ||
      record.expiresAt <= this.now() ||
      !verifyDeviceSignature({
        publicKeyBase64: record.publicKey,
        algorithm: record.algorithm,
        message: record.message,
        signatureBase64Url: signature,
      })
    ) {
      throw new AuthenticationError("Enrollment proof failed");
    }
    await this.repository.completeEnrollment({
      enrollmentId: record.enrollmentId,
      userId: record.userId,
      credentialId: record.credentialId,
      publicKey: record.publicKey,
      algorithm: record.algorithm,
    });
    await this.repository.audit({
      actorId: record.userId,
      action: "credential.enrolled",
      metadata: { credentialId: record.credentialId },
    });
    return { success: true };
  }
}

