import type { AccessTokenIssuer } from "../jwt/access-token";
import type { IdTokenIssuer } from "../jwt/id-token";
import type {
  BrowserSession,
  IdentityRepository,
  OAuthClient,
} from "../repository/identity-repository";
import {
  createUserCode,
  hashToken,
  randomOpaqueToken,
  verifyPkce,
} from "../security/crypto";
import type { IdentityTransientStore } from "../store/transient-store";

export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status = 400,
  ) {
    super(description);
    this.name = "OAuthError";
  }
}

interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export class OAuthService {
  private readonly now: () => number;

  constructor(
    private readonly repository: IdentityRepository,
    private readonly store: IdentityTransientStore,
    private readonly accessTokens: AccessTokenIssuer,
    private readonly idTokens: IdTokenIssuer,
    private readonly options: {
      issuer: string;
      authorizationCodeTtlSeconds: number;
      deviceCodeTtlSeconds: number;
      refreshTokenTtlSeconds: number;
      now?: () => number;
      onRefreshReuse?: () => void;
    },
  ) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async authorize(
    input: {
      responseType?: string;
      clientId?: string;
      redirectUri?: string;
      scopes?: string;
      resource?: string;
      codeChallenge?: string;
      codeChallengeMethod?: string;
      state?: string;
      nonce?: string;
    },
    session: BrowserSession,
  ) {
    if (input.responseType !== "code") {
      throw new OAuthError("unsupported_response_type", "Only response_type=code is supported");
    }
    const client = await this.requireClient(input.clientId);
    if (!input.redirectUri || !client.redirectUris.includes(input.redirectUri)) {
      throw new OAuthError("invalid_request", "redirect_uri is not registered");
    }
    if (
      input.codeChallengeMethod !== "S256" ||
      !input.codeChallenge ||
      !/^[A-Za-z0-9_-]{43}$/.test(input.codeChallenge)
    ) {
      throw new OAuthError("invalid_request", "PKCE S256 code_challenge is required");
    }
    const { scopes, resource } = this.validateGrant(
      client,
      input.scopes,
      input.resource,
    );

    const code = randomOpaqueToken();
    await this.store.putAuthorizationCode(
      hashToken(code),
      {
        clientId: client.id,
        redirectUri: input.redirectUri,
        userId: session.user.id,
        scopes,
        resource,
        codeChallenge: input.codeChallenge,
        nonce: input.nonce,
        authenticationMethod: session.authenticationMethod,
        authenticationTime: Math.floor(session.authenticatedAt.getTime() / 1000),
        expiresAt: this.now() + this.options.authorizationCodeTtlSeconds,
      },
      this.options.authorizationCodeTtlSeconds,
    );
    await this.repository.audit({
      actorId: session.user.id,
      clientId: client.id,
      action: "oauth.authorization.approved",
      metadata: { scopes, resource },
    });

    const redirect = new URL(input.redirectUri);
    redirect.searchParams.set("code", code);
    if (input.state) redirect.searchParams.set("state", input.state);
    return redirect.toString();
  }

  async exchangeAuthorizationCode(
    credentials: ClientCredentials,
    input: { code?: string; redirectUri?: string; codeVerifier?: string },
  ) {
    const client = await this.authenticateClient(credentials);
    if (!input.code || !input.redirectUri || !input.codeVerifier) {
      throw new OAuthError("invalid_request", "code, redirect_uri and code_verifier are required");
    }
    const grant = await this.store.consumeAuthorizationCode(hashToken(input.code));
    if (
      !grant ||
      grant.expiresAt <= this.now() ||
      grant.clientId !== client.id ||
      grant.redirectUri !== input.redirectUri ||
      !verifyPkce(input.codeVerifier, grant.codeChallenge)
    ) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid or expired");
    }
    return this.issueTokens({
      userId: grant.userId,
      client,
      scopes: grant.scopes,
      resource: grant.resource,
      nonce: grant.nonce,
      authenticationMethod: grant.authenticationMethod,
      authenticationTime: grant.authenticationTime,
    });
  }

  async refresh(
    credentials: ClientCredentials,
    input: { refreshToken?: string },
  ) {
    const client = await this.authenticateClient(credentials);
    if (!input.refreshToken) {
      throw new OAuthError("invalid_request", "refresh_token is required");
    }
    const replacement = randomOpaqueToken();
    const now = this.now();
    const result = await this.repository.rotateRefreshSession({
      currentTokenHash: hashToken(input.refreshToken),
      replacementTokenHash: hashToken(replacement),
      replacementExpiresAt: new Date((now + this.options.refreshTokenTtlSeconds) * 1000),
      clientId: client.id,
      now: new Date(now * 1000),
    });
    if (result.status === "reused") {
      this.options.onRefreshReuse?.();
      await this.repository.audit({
        actorId: result.userId,
        clientId: result.clientId,
        action: "oauth.refresh.reuse_detected",
      });
      throw new OAuthError("invalid_grant", "Refresh token is invalid or expired");
    }
    if (result.status !== "rotated") {
      throw new OAuthError("invalid_grant", "Refresh token is invalid or expired");
    }
    const access = await this.accessTokens.issue({
      subject: result.userId,
      audience: result.resource,
      clientId: result.clientId,
      scopes: result.scopes,
    });
    await this.repository.audit({
      actorId: result.userId,
      clientId: result.clientId,
      action: "oauth.refresh.rotated",
    });
    return {
      access_token: access.accessToken,
      token_type: access.tokenType,
      expires_in: access.expiresIn,
      refresh_token: replacement,
      scope: result.scopes.join(" "),
    };
  }

  async revoke(credentials: ClientCredentials, token?: string) {
    const client = await this.authenticateClient(credentials);
    if (token) await this.repository.revokeRefreshSession(hashToken(token), client.id);
  }

  async startDeviceAuthorization(
    credentials: ClientCredentials,
    input: { scopes?: string; resource?: string },
  ) {
    const client = await this.authenticateClient(credentials);
    const { scopes, resource } = this.validateGrant(client, input.scopes, input.resource);
    const deviceCode = randomOpaqueToken();
    const userCode = createUserCode();
    const now = this.now();
    const id = crypto.randomUUID();
    await this.store.putDeviceGrant(
      {
        id,
        deviceCodeHash: hashToken(deviceCode),
        userCode,
        clientId: client.id,
        clientName: client.name,
        scopes,
        resource,
        status: "pending",
        interval: 5,
        nextPollAt: now + 5,
        expiresAt: now + this.options.deviceCodeTtlSeconds,
      },
      this.options.deviceCodeTtlSeconds,
    );
    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${this.options.issuer}/device`,
      verification_uri_complete: `${this.options.issuer}/device?user_code=${encodeURIComponent(userCode)}`,
      expires_in: this.options.deviceCodeTtlSeconds,
      interval: 5,
    };
  }

  async describeDeviceGrant(userCode: string) {
    const record = await this.store.findDeviceGrantByUserCode(userCode);
    if (!record || record.expiresAt <= this.now()) {
      throw new OAuthError("invalid_request", "Device request is invalid or expired", 404);
    }
    return {
      client: record.clientName,
      scopes: record.scopes,
      resource: record.resource,
      expires_in: Math.max(0, record.expiresAt - this.now()),
      status: record.status,
    };
  }

  async decideDeviceGrant(
    userCode: string,
    decision: "approved" | "denied",
    session: BrowserSession,
  ) {
    const updated = await this.store.decideDeviceGrant(userCode, decision, {
      id: session.user.id,
      authenticationMethod: session.authenticationMethod,
      authenticationTime: Math.floor(session.authenticatedAt.getTime() / 1000),
    });
    if (!updated) {
      throw new OAuthError("invalid_request", "Device request is invalid or expired", 404);
    }
    await this.repository.audit({
      actorId: session.user.id,
      action: `oauth.device.${decision}`,
      metadata: { userCode },
    });
  }

  async exchangeDeviceCode(credentials: ClientCredentials, deviceCode?: string) {
    const client = await this.authenticateClient(credentials);
    if (!deviceCode) throw new OAuthError("invalid_request", "device_code is required");
    const result = await this.store.pollDeviceGrant(
      hashToken(deviceCode),
      client.id,
      this.now(),
    );
    if (result.status === "invalid") {
      throw new OAuthError("expired_token", "Device code is invalid or expired");
    }
    if (result.status === "pending") {
      throw new OAuthError("authorization_pending", "Authorization is pending");
    }
    if (result.status === "slow_down") {
      throw new OAuthError("slow_down", "Polling is too frequent");
    }
    if (result.status === "denied") {
      throw new OAuthError("access_denied", "The user denied the request");
    }
    if (result.status !== "claimed") {
      throw new OAuthError("invalid_grant", "Device grant could not be claimed");
    }

    const record = result.record;
    if (!record.userId || !record.authenticationMethod || !record.authenticationTime) {
      await this.store.releaseDeviceGrant(record, result.claimId);
      throw new OAuthError("invalid_grant", "Approved device grant is incomplete");
    }
    try {
      const tokens = await this.issueTokens({
        userId: record.userId,
        client,
        scopes: record.scopes,
        resource: record.resource,
        authenticationMethod: record.authenticationMethod,
        authenticationTime: record.authenticationTime,
      });
      await this.store.completeDeviceGrant(record, result.claimId);
      return tokens;
    } catch (error) {
      await this.store.releaseDeviceGrant(record, result.claimId);
      throw error;
    }
  }

  private async issueTokens(input: {
    userId: string;
    client: OAuthClient;
    scopes: string[];
    resource: string;
    nonce?: string;
    authenticationMethod: string;
    authenticationTime: number;
  }) {
    const access = await this.accessTokens.issue({
      subject: input.userId,
      audience: input.resource,
      clientId: input.client.id,
      scopes: input.scopes,
      authenticationMethods: [input.authenticationMethod],
      authenticationTime: input.authenticationTime,
    });
    const refreshToken = randomOpaqueToken();
    await this.repository.createRefreshSession({
      tokenHash: hashToken(refreshToken),
      userId: input.userId,
      clientId: input.client.id,
      scopes: input.scopes,
      resource: input.resource,
      expiresAt: new Date(
        (this.now() + this.options.refreshTokenTtlSeconds) * 1000,
      ),
    });
    const idToken = input.scopes.includes("openid")
      ? await this.idTokens.issue({
          subject: input.userId,
          clientId: input.client.id,
          nonce: input.nonce,
          authenticationTime: input.authenticationTime,
          authenticationMethods: [input.authenticationMethod],
        })
      : undefined;
    return {
      access_token: access.accessToken,
      token_type: access.tokenType,
      expires_in: access.expiresIn,
      refresh_token: refreshToken,
      scope: input.scopes.join(" "),
      ...(idToken ? { id_token: idToken } : {}),
    };
  }

  private async requireClient(clientId?: string) {
    if (!clientId) throw new OAuthError("invalid_request", "client_id is required");
    const client = await this.repository.findClient(clientId);
    if (!client || client.status !== "ACTIVE") {
      throw new OAuthError("invalid_client", "Client authentication failed", 401);
    }
    return client;
  }

  private async authenticateClient(credentials: ClientCredentials) {
    const client = await this.requireClient(credentials.clientId);
    if (client.type === "confidential") {
      if (
        !credentials.clientSecret ||
        !client.clientSecretHash ||
        !(await Bun.password.verify(credentials.clientSecret, client.clientSecretHash))
      ) {
        throw new OAuthError("invalid_client", "Client authentication failed", 401);
      }
    }
    return client;
  }

  private validateGrant(
    client: OAuthClient,
    scopeValue?: string,
    resourceValue?: string,
  ) {
    const scopes = [...new Set((scopeValue ?? "openid").split(" ").filter(Boolean))];
    if (scopes.length === 0 || scopes.some((scope) => !client.allowedScopes.includes(scope))) {
      throw new OAuthError("invalid_scope", "Requested scope is not allowed");
    }
    const resource = resourceValue ||
      (client.allowedResources.length === 1 ? client.allowedResources[0] : undefined);
    if (!resource || !client.allowedResources.includes(resource)) {
      throw new OAuthError("invalid_target", "Requested resource is not allowed");
    }
    return { scopes, resource };
  }
}

