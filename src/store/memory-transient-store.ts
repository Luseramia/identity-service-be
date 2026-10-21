import { normalizeUserCode, randomOpaqueToken } from "../security/crypto";
import type {
  AuthorizationCodeRecord,
  DeviceGrantRecord,
  DevicePollResult,
  EnrollmentChallengeRecord,
  IdentityTransientStore,
  LoginChallengeRecord,
} from "./transient-store";

export class MemoryIdentityTransientStore implements IdentityTransientStore {
  private readonly login = new Map<string, LoginChallengeRecord>();
  private readonly enrollment = new Map<string, EnrollmentChallengeRecord>();
  private readonly codes = new Map<string, AuthorizationCodeRecord>();
  private readonly deviceById = new Map<string, DeviceGrantRecord>();
  private readonly deviceCodeToId = new Map<string, string>();
  private readonly userCodeToId = new Map<string, string>();
  private readonly claims = new Map<string, string>();

  async ready() {}

  async putLoginChallenge(record: LoginChallengeRecord) {
    this.login.set(record.id, record);
  }

  async consumeLoginChallenge(id: string) {
    return this.consume(this.login, id);
  }

  async putEnrollmentChallenge(record: EnrollmentChallengeRecord) {
    this.enrollment.set(record.id, record);
  }

  async consumeEnrollmentChallenge(id: string) {
    return this.consume(this.enrollment, id);
  }

  async putAuthorizationCode(codeHash: string, record: AuthorizationCodeRecord) {
    this.codes.set(codeHash, record);
  }

  async consumeAuthorizationCode(codeHash: string) {
    return this.consume(this.codes, codeHash);
  }

  async putDeviceGrant(record: DeviceGrantRecord) {
    this.deviceById.set(record.id, record);
    this.deviceCodeToId.set(record.deviceCodeHash, record.id);
    this.userCodeToId.set(normalizeUserCode(record.userCode), record.id);
  }

  async findDeviceGrantByUserCode(userCode: string) {
    const id = this.userCodeToId.get(normalizeUserCode(userCode));
    return id ? (this.deviceById.get(id) ?? null) : null;
  }

  async decideDeviceGrant(
    userCode: string,
    decision: "approved" | "denied",
    user: { id: string; authenticationMethod: string; authenticationTime: number; approvalId?: string },
  ) {
    const record = await this.findDeviceGrantByUserCode(userCode);
    if (!record || record.status !== "pending") return false;
    record.status = decision;
    record.userId = user.id;
    record.authenticationMethod = user.authenticationMethod;
    record.authenticationTime = user.authenticationTime;
    record.approvalId = user.approvalId;
    return true;
  }

  async pollDeviceGrant(
    deviceCodeHash: string,
    clientId: string,
    now: number,
  ): Promise<DevicePollResult> {
    const id = this.deviceCodeToId.get(deviceCodeHash);
    const record = id ? this.deviceById.get(id) : undefined;
    if (!record || record.clientId !== clientId || record.expiresAt <= now) {
      return { status: "invalid" };
    }
    if (record.status === "denied") return { status: "denied" };
    if (record.status === "pending") {
      if (now < record.nextPollAt) {
        record.interval += 5;
        record.nextPollAt = now + record.interval;
        return { status: "slow_down" };
      }
      record.nextPollAt = now + record.interval;
      return { status: "pending" };
    }
    const claimId = randomOpaqueToken(16);
    if (this.claims.has(record.id)) return { status: "pending" };
    this.claims.set(record.id, claimId);
    return { status: "claimed", record, claimId };
  }

  async completeDeviceGrant(record: DeviceGrantRecord, claimId: string) {
    if (this.claims.get(record.id) !== claimId) throw new Error("Invalid claim");
    this.claims.delete(record.id);
    this.deviceById.delete(record.id);
    this.deviceCodeToId.delete(record.deviceCodeHash);
    this.userCodeToId.delete(normalizeUserCode(record.userCode));
  }

  async releaseDeviceGrant(record: DeviceGrantRecord, claimId: string) {
    if (this.claims.get(record.id) === claimId) this.claims.delete(record.id);
  }

  private consume<T>(map: Map<string, T>, key: string) {
    const value = map.get(key) ?? null;
    map.delete(key);
    return value;
  }
}

