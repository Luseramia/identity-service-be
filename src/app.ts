import { Elysia } from "elysia";
import { AccessTokenIssuer } from "./jwt/access-token";
import { decodeJson } from "./jwt/base64url";
import { IdTokenIssuer } from "./jwt/id-token";
import type { IdentityConfig } from "./config";
import type { JwtSigner } from "./jwt/signer";
import type { IdentityRepository } from "./repository/identity-repository";
import { EnrollmentService } from "./services/enrollment-service";
import { OAuthError, OAuthService } from "./services/oauth-service";
import {
  AuthenticationError,
  SessionService,
} from "./services/session-service";
import type { IdentityTransientStore } from "./store/transient-store";
import { verifyIssuedAccessToken } from "./jwt/access-token-verifier";
import { IdentityMetrics, InstrumentedJwtSigner } from "./metrics";
import { ApprovalService, validUuid } from "./services/approval-service";
import { ApprovalConflictError } from "./repository/identity-repository";

export interface IdentityAppDependencies {
  config: IdentityConfig;
  signer: JwtSigner;
  repository: IdentityRepository;
  store: IdentityTransientStore;
  metrics?: IdentityMetrics;
}

type Body = Record<string, unknown>;

const stringValue = (body: Body, key: string) =>
  typeof body?.[key] === "string" ? body[key] : undefined;

const bearer = (authorization?: string) =>
  authorization?.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : undefined;

const escapeHtml = (value: string) => value
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

const devicePage = (input: {
  userCode: string;
  client: string;
  resource: string;
  scopes: string[];
  signedInAs?: string;
}) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Authorize device</title><style>
body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#17202a}main{border:1px solid #d5d8dc;border-radius:12px;padding:2rem}code{font-size:1.3rem}button{padding:.65rem 1rem;margin:.5rem .5rem 0 0}ul{padding-left:1.25rem}.muted{color:#626567}
</style></head><body><main><h1>Authorize device</h1>
<p>Client: <strong>${escapeHtml(input.client)}</strong></p>
<p>Code: <code>${escapeHtml(input.userCode)}</code></p>
<p>Resource: ${escapeHtml(input.resource)}</p>
<ul>${input.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("")}</ul>
${input.signedInAs
  ? `<p class="muted">Signed in as ${escapeHtml(input.signedInAs)}</p>
<form method="post" action="/device/approve"><input type="hidden" name="user_code" value="${escapeHtml(input.userCode)}"><button type="submit">Approve</button></form>
<form method="post" action="/device/reject"><input type="hidden" name="user_code" value="${escapeHtml(input.userCode)}"><button type="submit">Reject</button></form>`
  : "<p><strong>Sign in with your enrolled device before approving this request.</strong></p>"}
</main></body></html>`;

const sessionCookie = (cookieHeader: string | null, name: string) => {
  for (const part of cookieHeader?.split(";") ?? []) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
};

const clientCredentials = (headers: Headers, body: Body) => {
  const authorization = headers.get("authorization");
  if (authorization?.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(
        authorization.slice("Basic ".length),
        "base64",
      ).toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator >= 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, separator)),
          clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
        };
      }
    } catch {
      // OAuthService returns the uniform invalid_client response.
    }
  }
  return {
    clientId: stringValue(body, "client_id") ?? "",
    clientSecret: stringValue(body, "client_secret"),
  };
};

export function createIdentityApp({
  config,
  signer,
  repository,
  store,
  metrics = new IdentityMetrics(),
}: IdentityAppDependencies) {
  const measuredSigner = new InstrumentedJwtSigner(signer, metrics);
  const accessTokens = new AccessTokenIssuer(measuredSigner, {
    issuer: config.issuer,
    defaultTtlSeconds: config.accessTokenTtlSeconds,
  });
  const idTokens = new IdTokenIssuer(measuredSigner, {
    issuer: config.issuer,
    ttlSeconds: config.idTokenTtlSeconds,
  });
  const sessions = new SessionService(repository, store, {
    challengeTtlSeconds: config.authenticationChallengeTtlSeconds,
    sessionTtlSeconds: config.browserSessionTtlSeconds,
  });
  const enrollments = new EnrollmentService(repository, store, {
    challengeTtlSeconds: config.authenticationChallengeTtlSeconds,
  });
  const oauth = new OAuthService(repository, store, accessTokens, idTokens, {
    issuer: config.issuer,
    authorizationCodeTtlSeconds: config.authorizationCodeTtlSeconds,
    deviceCodeTtlSeconds: config.deviceCodeTtlSeconds,
    refreshTokenTtlSeconds: config.refreshTokenTtlSeconds,
    onRefreshReuse: () => { metrics.refreshReuse += 1; },
  });
  const secureCookie = config.issuer.startsWith("https://");
  const cookieName = secureCookie ? "__Host-sso_session" : "sso_session";
  const approvals = new ApprovalService(repository, oauth, {
    ttlSeconds: config.loginApprovalTtlSeconds ?? 600, sessionTtlSeconds: config.browserSessionTtlSeconds,
  });
  const resolveSession = (request: Request) => sessions.resolve(sessionCookie(request.headers.get("cookie"), cookieName));
  const trustedOrigins = new Set([new URL(config.issuer).origin, ...(config.corsAllowedOrigins ?? [])]);

  const metadata = {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    revocation_endpoint: `${config.issuer}/oauth/revoke`,
    userinfo_endpoint: `${config.issuer}/oauth/userinfo`,
    device_authorization_endpoint: `${config.issuer}/oauth/device_authorization`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_basic",
      "client_secret_post",
    ],
    scopes_supported: [
      "openid", "profile",
      "finance:read", "finance:write",
      "documents:read", "documents:write",
      "market:read", "market:write",
    ],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    claims_supported: ["iss", "sub", "aud", "exp", "iat", "auth_time", "amr", "nonce", "name"],
  };

  return new Elysia({ name: "identity" })
    .onBeforeHandle(({ request }) => {
      if (!["POST", "DELETE"].includes(request.method)) return;
      const origin = request.headers.get("origin");
      if ((origin && !trustedOrigins.has(origin)) || (!origin && request.headers.get("sec-fetch-site") === "cross-site")) {
        throw new OAuthError("access_denied", "Request origin is not trusted", 403);
      }
      if (new URL(request.url).pathname.startsWith("/admin/") && !request.headers.get("content-type")?.startsWith("application/json")) {
        throw new OAuthError("invalid_request", "Administrative changes require JSON", 415);
      }
    })
    .onAfterHandle(({ set }) => {
      set.headers["x-content-type-options"] = "nosniff";
      set.headers["referrer-policy"] = "no-referrer";
      set.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()";
    })
    .onError(({ error, set }) => {
      set.headers["cache-control"] = "no-store";
      if (error instanceof ApprovalConflictError) {
        set.status = 409;
        return { error: "approval_conflict", error_description: error.message };
      }
      if (error instanceof OAuthError) {
        metrics.oauthError(error.error);
        set.status = error.status;
        if (error.error === "invalid_client") {
          set.headers["www-authenticate"] = 'Basic realm="oauth-token"';
        }
        return { error: error.error, error_description: error.description };
      }
      if (error instanceof AuthenticationError) {
        metrics.loginFailures += 1;
        set.status = 401;
        return { error: "authentication_failed", error_description: error.message };
      }
      console.error("Identity request failed", error);
      metrics.serverErrors += 1;
      set.status = 500;
      return { error: "server_error" };
    })
    .onAfterHandle(({ request, set, response }) => {
      const status = Number(set.status ?? 200);
      if (status >= 400) return;
      const path = new URL(request.url).pathname;
      if (request.method === "POST" && path === "/auth/sessions") {
        metrics.loginSuccesses += 1;
      }
      if (request.method === "POST" && path === "/oauth/token") {
        metrics.tokenResponses += 1;
      }
      if (path.startsWith("/auth/") || path.startsWith("/admin/")) set.headers["cache-control"] = "no-store";
      if (request.method === "POST" && /^\/auth\/approvals\/[^/]+\/poll$/.test(path) && response && typeof response === "object" && "access_token" in response) {
        metrics.loginSuccesses += 1;
        metrics.tokenResponses += 1;
      }
    })
    .get("/health/live", () => ({ status: "ok" }))
    .get("/health/ready", async ({ set }) => {
      try {
        const [key] = await Promise.all([
          signer.activeKey(),
          repository.ready(),
          store.ready(),
        ]);
        return { status: "ready", signingKey: key.kid };
      } catch {
        set.status = 503;
        return { status: "not_ready" };
      }
    })
    .get("/.well-known/oauth-authorization-server", () => metadata)
    .get("/.well-known/openid-configuration", () => metadata)
    .get("/.well-known/jwks.json", async ({ set }) => {
      set.headers["cache-control"] = `public, max-age=${config.vault.keyMetadataCacheSeconds}`;
      return measuredSigner.jwks();
    })
    .get("/metrics", ({ set }) => {
      set.headers["content-type"] = "text/plain; version=0.0.4; charset=utf-8";
      return metrics.render();
    })
    .get("/auth/clients", async () => (await repository.listClients())
      .filter((client) => client.type === "public")
      .map(({ id, name, allowedScopes, allowedResources }) => ({ id, name, allowedScopes, allowedResources })))
    .get("/auth/session", async ({ request, set }) => {
      set.headers["cache-control"] = "no-store";
      const session = await resolveSession(request);
      if (!session) return { authenticated: false };
      return { authenticated: true, user: session.user, expires_at: session.expiresAt,
        approver: await repository.isApprover(session.user.id), approval_id: session.approvalId };
    })
    .post("/auth/approvals/start", ({ body, request, set }) => {
      set.headers["cache-control"] = "no-store";
      const b = body as Body;
      const credentials = clientCredentials(request.headers, b);
      return approvals.start({ displayName: stringValue(b, "display_name") ?? "", credentialId: stringValue(b, "credential_id") ?? "",
        publicKey: stringValue(b, "public_key") ?? "", clientId: credentials.clientId, clientSecret: credentials.clientSecret,
        scopes: stringValue(b, "scope") ?? "openid", resource: stringValue(b, "resource") ?? "" });
    })
    .post("/auth/approvals/:id/prove", ({ params, body, set }) => {
      set.headers["cache-control"] = "no-store";
      return approvals.prove(params.id, stringValue(body as Body, "signature") ?? "");
    })
    .post("/auth/approvals/:id/poll", async ({ params, body, set }) => {
      set.headers["cache-control"] = "no-store";
      const result = await approvals.poll(params.id, stringValue(body as Body, "signature") ?? "");
      if (!("session" in result)) return result;
      const { session, ...tokens } = result;
      set.headers["set-cookie"] = [ `${cookieName}=${encodeURIComponent(session.token)}`, "Path=/", "HttpOnly", "SameSite=Lax",
        `Max-Age=${Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000))}`, ...(secureCookie ? ["Secure"] : []) ].join("; ");
      return { ...tokens, expires_at: session.expiresAt };
    })
    .get("/admin/overview", async ({ request, set }) => {
      await approvals.requireApprover(await resolveSession(request));
      set.headers["cache-control"] = "no-store";
      const [pending, users, clients, grants] = await Promise.all([
        repository.listPendingApprovals(new Date()), repository.listUsers(), repository.listClients(), repository.listAccessGrants(),
      ]);
      return { requests: pending.map((r) => approvals.describe(r)), users,
        clients: clients.map(({ id, name, type, allowedScopes, allowedResources }) => ({ id, name, type, allowedScopes, allowedResources })), grants };
    })
    .post("/admin/approvals/:id/approve", async ({ request, params, body }) => {
      const actor = await approvals.requireApprover(await resolveSession(request));
      const b = body as Body;
      return approvals.decide(params.id, actor, "approved", b?.scopes, stringValue(b, "target_user_id"));
    })
    .post("/admin/approvals/:id/reject", async ({ request, params }) => {
      const actor = await approvals.requireApprover(await resolveSession(request));
      return approvals.decide(params.id, actor, "rejected", []);
    })
    .post("/admin/access-grants", async ({ request, body }) => {
      const actor = await approvals.requireApprover(await resolveSession(request));
      const b = body as Body;
      return approvals.setGrant({ userId: stringValue(b, "user_id") ?? "", clientId: stringValue(b, "client_id") ?? "",
        resource: stringValue(b, "resource") ?? "", scopes: b?.scopes as string[] }, actor);
    })
    .post("/admin/access-grants/revoke", async ({ request, body }) => {
      const actor = await approvals.requireApprover(await resolveSession(request));
      const b = body as Body;
      const userId = stringValue(b, "user_id") ?? "";
      if (!validUuid(userId)) throw new OAuthError("invalid_request", "Invalid user ID");
      await repository.revokeAccessGrant(userId, stringValue(b, "client_id") ?? "", stringValue(b, "resource") ?? "", actor);
      return { success: true };
    })
    .post("/auth/enrollments/start", async ({ body }) =>
      enrollments.start({
        enrollmentToken: stringValue(body as Body, "enrollment_token") ?? "",
        credentialId: stringValue(body as Body, "credential_id") ?? "",
        publicKey: stringValue(body as Body, "public_key") ?? "",
        algorithm: stringValue(body as Body, "algorithm") ?? "",
      }),
    )
    .post("/auth/enrollments/complete", async ({ body }) =>
      enrollments.complete(
        stringValue(body as Body, "enrollment_id") ?? "",
        stringValue(body as Body, "signature") ?? "",
      ),
    )
    .post("/auth/challenges", async ({ body }) =>
      sessions.start(stringValue(body as Body, "credential_id") ?? ""),
    )
    .post("/auth/sessions", async ({ body, set }) => {
      const session = await sessions.complete(
        stringValue(body as Body, "challenge_id") ?? "",
        stringValue(body as Body, "signature") ?? "",
      );
      const maxAge = Math.max(
        0,
        Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
      );
      set.headers["set-cookie"] = [
        `${cookieName}=${encodeURIComponent(session.token)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        `Max-Age=${maxAge}`,
        ...(secureCookie ? ["Secure"] : []),
      ].join("; ");
      set.headers["cache-control"] = "no-store";
      return { authenticated: true, expires_at: session.expiresAt.toISOString() };
    })
    .delete("/auth/session", async ({ request, set }) => {
      await sessions.logout(
        sessionCookie(request.headers.get("cookie"), cookieName),
      );
      set.headers["set-cookie"] = [
        `${cookieName}=`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=0",
        ...(secureCookie ? ["Secure"] : []),
      ].join("; ");
      return { success: true };
    })
    .get("/oauth/authorize", async ({ query, request, set }) => {
      const session = await sessions.resolve(
        sessionCookie(request.headers.get("cookie"), cookieName),
      );
      if (!session) {
        set.status = 401;
        set.headers["cache-control"] = "no-store";
        return {
          error: "login_required",
          login_challenge_endpoint: `${config.issuer}/auth/challenges`,
          login_session_endpoint: `${config.issuer}/auth/sessions`,
        };
      }
      const redirect = await oauth.authorize(
        {
          responseType: query.response_type,
          clientId: query.client_id,
          redirectUri: query.redirect_uri,
          scopes: query.scope,
          resource: query.resource,
          codeChallenge: query.code_challenge,
          codeChallengeMethod: query.code_challenge_method,
          state: query.state,
          nonce: query.nonce,
        },
        session,
      );
      set.status = 302;
      set.headers.location = redirect;
      set.headers["cache-control"] = "no-store";
      return;
    })
    .post("/oauth/device_authorization", async ({ body, request, set }) => {
      set.headers["cache-control"] = "no-store";
      const values = body as Body;
      return oauth.startDeviceAuthorization(clientCredentials(request.headers, values), {
        scopes: stringValue(values, "scope"),
        resource: stringValue(values, "resource"),
      });
    })
    .get("/device", async ({ query, set, request }) => {
      set.headers["cache-control"] = "no-store";
      const description = await oauth.describeDeviceGrant(query.user_code ?? "");
      if (request.headers.get("accept")?.includes("application/json")) {
        return description;
      }
      const session = await sessions.resolve(
        sessionCookie(request.headers.get("cookie"), cookieName),
      );
      set.headers["content-type"] = "text/html; charset=utf-8";
      set.headers["content-security-policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
      return devicePage({
        userCode: query.user_code ?? "",
        ...description,
        signedInAs: session?.user.displayName,
      });
    })
    .post("/device/approve", async ({ body, request, set }) => {
      const session = await sessions.resolve(
        sessionCookie(request.headers.get("cookie"), cookieName),
      );
      if (!session) throw new AuthenticationError();
      const values = body as Body;
      await oauth.decideDeviceGrant(
        stringValue(values, "user_code") ?? "",
        "approved",
        session,
      );
      set.headers["cache-control"] = "no-store";
      if (request.headers.get("accept")?.includes("text/html")) {
        set.headers["content-type"] = "text/html; charset=utf-8";
        return "<!doctype html><title>Device approved</title><p>Device request approved. You may close this window.</p>";
      }
      return { success: true };
    })
    .post("/device/reject", async ({ body, request, set }) => {
      const session = await sessions.resolve(
        sessionCookie(request.headers.get("cookie"), cookieName),
      );
      if (!session) throw new AuthenticationError();
      await oauth.decideDeviceGrant(
        stringValue(body as Body, "user_code") ?? "",
        "denied",
        session,
      );
      set.headers["cache-control"] = "no-store";
      if (request.headers.get("accept")?.includes("text/html")) {
        set.headers["content-type"] = "text/html; charset=utf-8";
        return "<!doctype html><title>Device rejected</title><p>Device request rejected. You may close this window.</p>";
      }
      return { success: true };
    })
    .post("/oauth/token", async ({ body, request, set }) => {
      set.headers["cache-control"] = "no-store";
      set.headers.pragma = "no-cache";
      const values = body as Body;
      const credentials = clientCredentials(request.headers, values);
      const grantType = stringValue(values, "grant_type");
      if (grantType === "authorization_code") {
        return oauth.exchangeAuthorizationCode(credentials, {
          code: stringValue(values, "code"),
          redirectUri: stringValue(values, "redirect_uri"),
          codeVerifier: stringValue(values, "code_verifier"),
        });
      }
      if (grantType === "refresh_token") {
        return oauth.refresh(credentials, {
          refreshToken: stringValue(values, "refresh_token"),
        });
      }
      if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
        return oauth.exchangeDeviceCode(
          credentials,
          stringValue(values, "device_code"),
        );
      }
      throw new OAuthError("unsupported_grant_type", "Unsupported grant_type");
    })
    .post("/oauth/revoke", async ({ body, request, set }) => {
      const values = body as Body;
      await oauth.revoke(
        clientCredentials(request.headers, values),
        stringValue(values, "token"),
      );
      set.status = 200;
      set.headers["cache-control"] = "no-store";
      return "";
    })
    .get("/oauth/userinfo", async ({ headers, set }) => {
      const token = bearer(headers.authorization);
      if (!token) throw new OAuthError("invalid_token", "Bearer token is required", 401);
      const parts = token.split(".");
      let audience = "";
      try {
        audience = decodeJson<{ aud?: string }>(parts[1] ?? "").aud ?? "";
      } catch {
        throw new OAuthError("invalid_token", "Access token is invalid", 401);
      }
      let context;
      try {
        context = verifyIssuedAccessToken(token, await measuredSigner.jwks(), {
          issuer: config.issuer,
          audience,
          requiredScopes: ["openid"],
        });
      } catch {
        throw new OAuthError("invalid_token", "Access token is invalid", 401);
      }
      const user = await repository.findUser(context.subject);
      if (!user || user.status !== "ACTIVE") {
        throw new OAuthError("invalid_token", "Access token subject is inactive", 401);
      }
      set.headers["cache-control"] = "no-store";
      return { sub: user.id, name: user.displayName };
    });
}

