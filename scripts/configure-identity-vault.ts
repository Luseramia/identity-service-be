import { loadIdentityConfig } from "../src/config";
import { readVaultToken } from "../src/runtime-config";

interface VaultResponse<T = unknown> {
  data?: T;
}

const config = loadIdentityConfig();
const token = await readVaultToken();

async function vault<T>(path: string, init: RequestInit = {}) {
  const response = await fetch(`${config.vault.address}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Vault-Token": token,
      ...init.headers,
    },
  });
  const body = response.status === 204 ? undefined : await response.json();
  return { response, body: body as VaultResponse<T> | undefined };
}

try {
  const mounts = await vault<Record<string, { type?: string }>>("/v1/sys/mounts");
  if (!mounts.response.ok || !mounts.body?.data) {
    throw new Error(`Unable to list Vault mounts: HTTP ${mounts.response.status}`);
  }

  const mountPath = `${config.vault.transitMount}/`;
  const existingMount = mounts.body.data[mountPath];
  if (!existingMount) {
    const created = await vault(`/v1/sys/mounts/${config.vault.transitMount}`, {
      method: "POST",
      body: JSON.stringify({
        type: "transit",
        description: "SSO JWT signing keys",
      }),
    });
    if (!created.response.ok) {
      throw new Error(`Unable to enable Transit mount: HTTP ${created.response.status}`);
    }
  } else if (existingMount.type !== "transit") {
    throw new Error(
      `Vault mount ${mountPath} exists with type ${existingMount.type ?? "unknown"}`,
    );
  }

  const keyPath = `/v1/${config.vault.transitMount}/keys/${config.vault.transitKey}`;
  const existingKey = await vault<{ type?: string }>(keyPath);
  if (existingKey.response.status === 404) {
    const created = await vault(keyPath, {
      method: "POST",
      body: JSON.stringify({
        type: "ecdsa-p256",
        auto_rotate_period: "720h",
        exportable: false,
        allow_plaintext_backup: false,
      }),
    });
    if (!created.response.ok) {
      throw new Error(`Unable to create Transit key: HTTP ${created.response.status}`);
    }
  } else if (!existingKey.response.ok) {
    throw new Error(`Unable to read Transit key: HTTP ${existingKey.response.status}`);
  } else if (existingKey.body?.data?.type !== "ecdsa-p256") {
    throw new Error(
      `Transit key exists with type ${existingKey.body?.data?.type ?? "unknown"}`,
    );
  }

  const runtimePolicyName = process.env.VAULT_IDENTITY_POLICY ?? "bun-sso-identity-runtime";
  const runtimePolicy = [
    `path "${config.vault.transitMount}/sign/${config.vault.transitKey}/sha2-256" {`,
    '  capabilities = ["update"]',
    "}",
    "",
    `path "${config.vault.transitMount}/keys/${config.vault.transitKey}" {`,
    '  capabilities = ["read"]',
    "}",
  ].join("\n");
  const policy = await vault(`/v1/sys/policies/acl/${runtimePolicyName}`, {
    method: "PUT",
    body: JSON.stringify({ policy: runtimePolicy }),
  });
  if (!policy.response.ok) {
    throw new Error(`Unable to write Identity runtime policy: HTTP ${policy.response.status}`);
  }

  const serviceAccount = process.env.VAULT_KUBERNETES_SERVICE_ACCOUNT?.trim();
  const namespace = process.env.VAULT_KUBERNETES_NAMESPACE?.trim();
  if (serviceAccount && namespace) {
    const authMount = process.env.VAULT_KUBERNETES_AUTH_MOUNT?.trim() || "kubernetes";
    const roleName = process.env.VAULT_KUBERNETES_ROLE?.trim() || "bun-sso-identity";
    const role = await vault(`/v1/auth/${authMount}/role/${roleName}`, {
      method: "POST",
      body: JSON.stringify({
        bound_service_account_names: [serviceAccount],
        bound_service_account_namespaces: [namespace],
        policies: [runtimePolicyName],
        token_ttl: "1h",
        token_max_ttl: "4h",
      }),
    });
    if (!role.response.ok) {
      throw new Error(`Unable to configure Vault Kubernetes role: HTTP ${role.response.status}`);
    }
    console.log(`Vault Kubernetes role ready: ${authMount}/${roleName}`);
  }

  console.log(
    `Vault ready: ${config.vault.transitMount}/${config.vault.transitKey} (ecdsa-p256), policy ${runtimePolicyName}`,
  );
} catch (error) {
  console.error(
    `Vault identity provisioning failed: ${error instanceof Error ? error.message : "unknown error"}`,
  );
  process.exitCode = 1;
}

