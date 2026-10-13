export interface LoginChallengeRecord {
  id: string;
  credentialId: string;
  challenge: string;
  message: string;
  expiresAt: number;
}

export interface EnrollmentChallengeRecord {
  id: string;
  enrollmentId: string;
  userId: string;
  credentialId: string;
  publicKey: string;
  algorithm: string;
  challenge: string;
  message: string;
  expiresAt: number;
}

export interface AuthorizationCodeRecord {
  clientId: string;
  redirectUri: string;
  userId: string;
  scopes: string[];
  resource: string;
  codeChallenge: string;
  nonce?: string;
  authenticationMethod: string;
  authenticationTime: number;
  expiresAt: number;
}

export interface DeviceGrantRecord {
  id: string;
  deviceCodeHash: string;
  userCode: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  resource: string;
  status: "pending" | "approved" | "denied";
  userId?: string;
  authenticationMethod?: string;
  authenticationTime?: number;
  interval: number;
  nextPollAt: number;
  expiresAt: number;
}

export type DevicePollResult =
  | { status: "invalid" | "pending" | "slow_down" | "denied" }
  | { status: "claimed"; record: DeviceGrantRecord; claimId: string };

export interface IdentityTransientStore {
  ready(): Promise<void>;
  putLoginChallenge(record: LoginChallengeRecord, ttlSeconds: number): Promise<void>;
  consumeLoginChallenge(id: string): Promise<LoginChallengeRecord | null>;
  putEnrollmentChallenge(
    record: EnrollmentChallengeRecord,
    ttlSeconds: number,
  ): Promise<void>;
  consumeEnrollmentChallenge(id: string): Promise<EnrollmentChallengeRecord | null>;
  putAuthorizationCode(
    codeHash: string,
    record: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void>;
  consumeAuthorizationCode(codeHash: string): Promise<AuthorizationCodeRecord | null>;
  putDeviceGrant(record: DeviceGrantRecord, ttlSeconds: number): Promise<void>;
  findDeviceGrantByUserCode(userCode: string): Promise<DeviceGrantRecord | null>;
  decideDeviceGrant(
    userCode: string,
    decision: "approved" | "denied",
    user: { id: string; authenticationMethod: string; authenticationTime: number },
  ): Promise<boolean>;
  pollDeviceGrant(
    deviceCodeHash: string,
    clientId: string,
    now: number,
  ): Promise<DevicePollResult>;
  completeDeviceGrant(record: DeviceGrantRecord, claimId: string): Promise<void>;
  releaseDeviceGrant(record: DeviceGrantRecord, claimId: string): Promise<void>;
}

