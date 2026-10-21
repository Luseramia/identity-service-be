import type Redis from "ioredis";
import { normalizeUserCode, randomOpaqueToken } from "../security/crypto";
import type {
  AuthorizationCodeRecord,
  DeviceGrantRecord,
  DevicePollResult,
  EnrollmentChallengeRecord,
  IdentityTransientStore,
  LoginChallengeRecord,
} from "./transient-store";

export class RedisIdentityTransientStore implements IdentityTransientStore {
  constructor(
    private readonly redis: Redis,
    private readonly prefix = "identity:v1",
  ) {}

  async ready() {
    const result = await this.redis.ping();
    if (result !== "PONG") throw new Error("Redis readiness check failed");
  }

  putLoginChallenge(record: LoginChallengeRecord, ttlSeconds: number) {
    return this.put(`login:${record.id}`, record, ttlSeconds);
  }

  consumeLoginChallenge(id: string) {
    return this.consume<LoginChallengeRecord>(`login:${id}`);
  }

  putEnrollmentChallenge(record: EnrollmentChallengeRecord, ttlSeconds: number) {
    return this.put(`enroll:${record.id}`, record, ttlSeconds);
  }

  consumeEnrollmentChallenge(id: string) {
    return this.consume<EnrollmentChallengeRecord>(`enroll:${id}`);
  }

  putAuthorizationCode(
    codeHash: string,
    record: AuthorizationCodeRecord,
    ttlSeconds: number,
  ) {
    return this.put(`code:${codeHash}`, record, ttlSeconds);
  }

  consumeAuthorizationCode(codeHash: string) {
    return this.consume<AuthorizationCodeRecord>(`code:${codeHash}`);
  }

  async putDeviceGrant(record: DeviceGrantRecord, ttlSeconds: number) {
    const transactionKey = this.key(`device-tx:${record.id}`);
    await this.redis
      .multi()
      .setex(transactionKey, ttlSeconds, JSON.stringify(record))
      .setex(this.key(`device-code:${record.deviceCodeHash}`), ttlSeconds, record.id)
      .setex(
        this.key(`user-code:${normalizeUserCode(record.userCode)}`),
        ttlSeconds,
        record.id,
      )
      .exec();
  }

  async findDeviceGrantByUserCode(userCode: string) {
    const id = await this.redis.get(
      this.key(`user-code:${normalizeUserCode(userCode)}`),
    );
    if (!id) return null;
    return this.read<DeviceGrantRecord>(`device-tx:${id}`);
  }

  async decideDeviceGrant(
    userCode: string,
    decision: "approved" | "denied",
    user: { id: string; authenticationMethod: string; authenticationTime: number; approvalId?: string },
  ) {
    const normalized = normalizeUserCode(userCode);
    const mappingKey = this.key(`user-code:${normalized}`);
    const id = await this.redis.get(mappingKey);
    if (!id) return false;
    const txKey = this.key(`device-tx:${id}`);
    const raw = await this.redis.get(txKey);
    if (!raw) return false;
    const record = JSON.parse(raw) as DeviceGrantRecord;
    if (record.status !== "pending" || record.expiresAt <= Date.now() / 1000) {
      return false;
    }
    record.status = decision;
    record.userId = user.id;
    record.authenticationMethod = user.authenticationMethod;
    record.authenticationTime = user.authenticationTime;
    record.approvalId = user.approvalId;
    await this.redis.set(txKey, JSON.stringify(record), "KEEPTTL");
    return true;
  }

  async pollDeviceGrant(
    deviceCodeHash: string,
    clientId: string,
    now: number,
  ): Promise<DevicePollResult> {
    const id = await this.redis.get(this.key(`device-code:${deviceCodeHash}`));
    if (!id) return { status: "invalid" };
    const record = await this.read<DeviceGrantRecord>(`device-tx:${id}`);
    if (!record || record.clientId !== clientId || record.expiresAt <= now) {
      return { status: "invalid" };
    }
    if (record.status === "denied") return { status: "denied" };
    if (record.status === "pending") {
      if (now < record.nextPollAt) {
        record.interval += 5;
        record.nextPollAt = now + record.interval;
        await this.redis.set(
          this.key(`device-tx:${record.id}`),
          JSON.stringify(record),
          "KEEPTTL",
        );
        return { status: "slow_down" };
      }
      record.nextPollAt = now + record.interval;
      await this.redis.set(
        this.key(`device-tx:${record.id}`),
        JSON.stringify(record),
        "KEEPTTL",
      );
      return { status: "pending" };
    }

    const claimId = randomOpaqueToken(16);
    const claimed = await this.redis.set(
      this.key(`device-claim:${record.id}`),
      claimId,
      "EX",
      30,
      "NX",
    );
    return claimed === "OK"
      ? { status: "claimed", record, claimId }
      : { status: "pending" };
  }

  async completeDeviceGrant(record: DeviceGrantRecord, claimId: string) {
    if ((await this.redis.get(this.key(`device-claim:${record.id}`))) !== claimId) {
      throw new Error("Device grant claim expired");
    }
    await this.redis
      .multi()
      .del(this.key(`device-tx:${record.id}`))
      .del(this.key(`device-code:${record.deviceCodeHash}`))
      .del(this.key(`user-code:${normalizeUserCode(record.userCode)}`))
      .del(this.key(`device-claim:${record.id}`))
      .exec();
  }

  async releaseDeviceGrant(record: DeviceGrantRecord, claimId: string) {
    if ((await this.redis.get(this.key(`device-claim:${record.id}`))) === claimId) {
      await this.redis.del(this.key(`device-claim:${record.id}`));
    }
  }

  private key(suffix: string) {
    return `${this.prefix}:${suffix}`;
  }

  private async put(key: string, value: unknown, ttlSeconds: number) {
    await this.redis.setex(this.key(key), ttlSeconds, JSON.stringify(value));
  }

  private async read<T>(key: string): Promise<T | null> {
    const raw = await this.redis.get(this.key(key));
    return raw ? (JSON.parse(raw) as T) : null;
  }

  private async consume<T>(key: string): Promise<T | null> {
    const raw = (await this.redis.call("GETDEL", this.key(key))) as string | null;
    return raw ? (JSON.parse(raw) as T) : null;
  }
}

