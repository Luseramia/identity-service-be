import type {
  ActiveSigningKey,
  JsonWebKeySet,
  JwtSigner,
} from "./jwt/signer";

export class IdentityMetrics {
  loginSuccesses = 0;
  loginFailures = 0;
  tokenResponses = 0;
  refreshReuse = 0;
  serverErrors = 0;
  signingRequests = 0;
  signingFailures = 0;
  signingDurationSeconds = 0;
  jwksRequests = 0;
  jwksFailures = 0;
  readonly oauthErrors = new Map<string, number>();

  oauthError(code: string) {
    const safe = /^[a-z_]+$/.test(code) ? code : "unknown";
    this.oauthErrors.set(safe, (this.oauthErrors.get(safe) ?? 0) + 1);
  }

  render() {
    const lines = [
      "# TYPE identity_login_success_total counter",
      `identity_login_success_total ${this.loginSuccesses}`,
      "# TYPE identity_login_failure_total counter",
      `identity_login_failure_total ${this.loginFailures}`,
      "# TYPE identity_token_response_total counter",
      `identity_token_response_total ${this.tokenResponses}`,
      "# TYPE identity_server_error_total counter",
      `identity_server_error_total ${this.serverErrors}`,
      "# TYPE identity_refresh_reuse_total counter",
      `identity_refresh_reuse_total ${this.refreshReuse}`,
      "# TYPE identity_vault_sign_requests_total counter",
      `identity_vault_sign_requests_total ${this.signingRequests}`,
      "# TYPE identity_vault_sign_failures_total counter",
      `identity_vault_sign_failures_total ${this.signingFailures}`,
      "# TYPE identity_vault_sign_duration_seconds_sum counter",
      `identity_vault_sign_duration_seconds_sum ${this.signingDurationSeconds}`,
      "# TYPE identity_jwks_requests_total counter",
      `identity_jwks_requests_total ${this.jwksRequests}`,
      "# TYPE identity_jwks_failures_total counter",
      `identity_jwks_failures_total ${this.jwksFailures}`,
      "# TYPE identity_oauth_errors_total counter",
      ...[...this.oauthErrors].sort(([a], [b]) => a.localeCompare(b)).map(
        ([code, value]) => `identity_oauth_errors_total{error="${code}"} ${value}`,
      ),
    ];
    return `${lines.join("\n")}\n`;
  }
}

export class InstrumentedJwtSigner implements JwtSigner {
  constructor(
    private readonly inner: JwtSigner,
    private readonly metrics: IdentityMetrics,
  ) {}

  activeKey(): Promise<ActiveSigningKey> {
    return this.inner.activeKey();
  }

  async sign(signingInput: string, key: ActiveSigningKey) {
    this.metrics.signingRequests += 1;
    const started = performance.now();
    try {
      return await this.inner.sign(signingInput, key);
    } catch (error) {
      this.metrics.signingFailures += 1;
      throw error;
    } finally {
      this.metrics.signingDurationSeconds += (performance.now() - started) / 1000;
    }
  }

  async jwks(): Promise<JsonWebKeySet> {
    this.metrics.jwksRequests += 1;
    try {
      return await this.inner.jwks();
    } catch (error) {
      this.metrics.jwksFailures += 1;
      throw error;
    }
  }
}
