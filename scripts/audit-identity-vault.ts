import { loadIdentityConfig } from "../src/config";
import { readVaultToken } from "../src/runtime-config";

const config = loadIdentityConfig();
const token = await readVaultToken();
const get = async (path: string) => {
  const response = await fetch(`${config.vault.address}${path}`, {
    headers: { "X-Vault-Token": token, accept: "application/json" },
  });
  const body = response.status === 204 ? {} : await response.json() as any;
  return { response, body };
};

const key = await get(`/v1/${config.vault.transitMount}/keys/${config.vault.transitKey}`);
if (!key.response.ok) throw new Error(`Identity signing key is unavailable: ${key.response.status}`);
const policyName = process.env.VAULT_IDENTITY_POLICY ?? "bun-sso-identity-runtime";
const policy = await get(`/v1/sys/policies/acl/${policyName}`);
if (!policy.response.ok) throw new Error(`Identity Vault policy is unavailable: ${policy.response.status}`);
const rules = policy.body.data?.policy ?? policy.body.data?.rules ?? "";
const requiredPaths = [
  `${config.vault.transitMount}/sign/${config.vault.transitKey}/sha2-256`,
  `${config.vault.transitMount}/keys/${config.vault.transitKey}`,
];
if (requiredPaths.some((path) => !rules.includes(`path "${path}"`))) {
  throw new Error("Identity Vault policy does not contain the required bounded paths");
}
const auth = await get("/v1/sys/auth");
if (!auth.response.ok) throw new Error(`Unable to list Vault auth methods: ${auth.response.status}`);
const authMethods = Object.entries(auth.body.data ?? {}).map(([path, value]) => ({
  path,
  type: (value as { type?: string }).type,
}));
const kubernetes = authMethods.filter((method) => method.type === "kubernetes");
const kubernetesRoles: Record<string, string[]> = {};
const expectedRoleName = process.env.VAULT_KUBERNETES_ROLE?.trim() || "bun-sso-identity";
let identityKubernetesRole: Record<string, unknown> | null = null;
for (const method of kubernetes) {
  const mount = method.path.replace(/\/$/, "");
  const roles = await get(`/v1/auth/${mount}/role?list=true`);
  kubernetesRoles[method.path] = roles.response.ok ? roles.body.data?.keys ?? [] : [];
  if (kubernetesRoles[method.path]?.includes(expectedRoleName)) {
    const role = await get(`/v1/auth/${mount}/role/${expectedRoleName}`);
    if (role.response.ok) {
      identityKubernetesRole = {
        mount,
        name: expectedRoleName,
        serviceAccounts: role.body.data?.bound_service_account_names,
        namespaces: role.body.data?.bound_service_account_namespaces,
        policies: role.body.data?.token_policies,
        tokenTtl: role.body.data?.token_ttl,
        tokenMaxTtl: role.body.data?.token_max_ttl,
      };
    }
  }
}
console.log(JSON.stringify({
  signingKey: {
    path: `${config.vault.transitMount}/${config.vault.transitKey}`,
    type: key.body.data?.type,
    latestVersion: key.body.data?.latest_version,
    exportable: key.body.data?.exportable,
  },
  runtimePolicy: policyName,
  policyPaths: requiredPaths,
  authMethods,
  kubernetesRoles,
  identityKubernetesRole,
}, null, 2));
