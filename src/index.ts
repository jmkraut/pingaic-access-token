import type { PluginDefinition } from "@yaakapp/api";
import { clearCachedToken, errorMessage, getAccessToken, type TokenConfig } from "./token";

function configFromValues(values: Record<string, unknown>): TokenConfig {
  return {
    tenantFqdn: String(values.tenantFqdn ?? ""),
    serviceAccountId: String(values.serviceAccountId ?? ""),
    privateKey: String(values.privateKey ?? ""),
    scope: String(values.scope ?? ""),
  };
}

export const plugin: PluginDefinition = {
  authentication: {
    name: "pingaic-service-account",
    label: "Ping AIC Service Account",
    shortLabel: "Ping AIC",
    args: [
      {
        type: "text",
        name: "tenantFqdn",
        label: "Tenant FQDN",
        placeholder: "openam-example.forgeblocks.com",
        description:
          "The tenant's own FQDN (not a custom domain). Used for the token endpoint and JWT audience.",
      },
      {
        type: "text",
        name: "serviceAccountId",
        label: "Service Account ID",
        placeholder: "449d7e27-7889-47af-a736-83b6bbf97ec5",
      },
      {
        type: "text",
        name: "privateKey",
        label: "Private Key (JWK or file path)",
        placeholder: '{"kty":"RSA",...} or C:\\path\\to\\key.jwk',
        password: true,
        multiLine: true,
        description:
          "Paste the JWK downloaded when creating the service account, or a path to that file. PEM is also accepted.",
      },
      {
        type: "text",
        name: "scope",
        label: "Scopes",
        defaultValue: "fr:am:* fr:idm:*",
        description:
          "Space-separated. Must match, or be a subset of, the scopes granted to the service account.",
      },
    ],
    async onApply(ctx, { values }) {
      const token = await getAccessToken(ctx, configFromValues(values));
      return { setHeaders: [{ name: "Authorization", value: `Bearer ${token}` }] };
    },
    actions: [
      {
        label: "Copy Access Token",
        icon: "copy",
        async onSelect(ctx, { values }) {
          try {
            const token = await getAccessToken(ctx, configFromValues(values));
            await ctx.clipboard.copyText(token);
            await ctx.toast.show({ message: "Access token copied", color: "success" });
          } catch (err) {
            await ctx.toast.show({ message: errorMessage(err), color: "danger" });
          }
        },
      },
      {
        label: "Clear Cached Token",
        icon: "trash",
        async onSelect(ctx, { values }) {
          const deleted = await clearCachedToken(ctx, configFromValues(values));
          await ctx.toast.show({
            message: deleted ? "Cached token cleared" : "No cached token to clear",
            color: deleted ? "success" : "info",
          });
        },
      },
    ],
  },
};
