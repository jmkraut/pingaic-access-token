import { createHash, createPrivateKey, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import type { Context, HttpRequest } from "@yaakapp/api";

// Service account access tokens have a fixed 899s lifetime. Refresh a little early so a
// token never expires between being applied and the request reaching the server.
const EXPIRY_BUFFER_MS = 60_000;
const ASSERTION_LIFETIME_S = 899;

export interface TokenConfig {
  tenantFqdn: string;
  serviceAccountId: string;
  privateKey: string;
  scope: string;
}

export interface CachedToken {
  accessToken: string;
  expiresAt: number;
  scope?: string;
}

/** The parts of the plugin context used to fetch and cache tokens. */
export type TokenContext = Pick<Context, "store"> & {
  httpRequest: Pick<Context["httpRequest"], "send">;
};

/** Accepts a bare FQDN or a pasted URL and returns just the host, e.g. `openam-x.forgeblocks.com`. */
export function normalizeTenantFqdn(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    return new URL(withScheme).hostname;
  } catch {
    throw new Error(`Invalid tenant FQDN: ${input}`);
  }
}

export function tokenEndpoint(tenantFqdn: string): string {
  // The audience must match exactly what AIC expects, including the explicit port.
  return `https://${tenantFqdn}:443/am/oauth2/access_token`;
}

/** Normalizes whitespace so "a  b" and "a b" share a cache entry. */
export function normalizeScope(scope: string): string {
  return scope.trim().split(/\s+/).filter(Boolean).join(" ");
}

/**
 * The private key box accepts either the contents of the JWK file downloaded from AIC
 * (or a PEM key), or a path to such a file.
 */
export async function loadPrivateKey(input: string): Promise<KeyObject> {
  const value = input.trim();
  if (!value) throw new Error("Private key is required");

  if (value.startsWith("{")) return parseKey(value, "pasted JWK");
  if (value.startsWith("-----BEGIN")) return parseKey(value, "pasted PEM");

  const path = expandHome(value);
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (err) {
    throw new Error(
      `Private key is not JWK/PEM text and could not be read as a file (${path}): ${errorMessage(err)}`,
    );
  }
  return parseKey(contents.trim(), path);
}

function parseKey(text: string, source: string): KeyObject {
  try {
    if (text.startsWith("{")) {
      return createPrivateKey({ key: JSON.parse(text), format: "jwk" });
    }
    return createPrivateKey(text);
  } catch (err) {
    throw new Error(`Failed to parse private key from ${source}: ${errorMessage(err)}`);
  }
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/") || path.startsWith("~\\")) return homedir() + path.slice(1);
  return path;
}

/** Builds the RS256-signed JWT bearer assertion described in the AIC docs. */
export function buildAssertion(
  key: KeyObject,
  serviceAccountId: string,
  audience: string,
  nowS = Math.floor(Date.now() / 1000),
): string {
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccountId,
    sub: serviceAccountId,
    aud: audience,
    exp: nowS + ASSERTION_LIFETIME_S,
    jti: randomUUID(),
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), key);
  return `${signingInput}.${base64url(signature)}`;
}

function base64url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

export async function requestAccessToken(ctx: TokenContext, config: TokenConfig): Promise<CachedToken> {
  const tenantFqdn = normalizeTenantFqdn(config.tenantFqdn);
  const serviceAccountId = config.serviceAccountId.trim();
  const scope = normalizeScope(config.scope);
  if (!tenantFqdn) throw new Error("Tenant FQDN is required");
  if (!serviceAccountId) throw new Error("Service account ID is required");
  if (!scope) throw new Error("At least one scope is required");

  const endpoint = tokenEndpoint(tenantFqdn);
  const key = await loadPrivateKey(config.privateKey);
  const assertion = buildAssertion(key, serviceAccountId, endpoint);

  // Sent through Yaak so its proxy, CA and client certificate settings apply. The request
  // has no id, so it is never saved to any request's history.
  const httpRequest: Partial<HttpRequest> = {
    method: "POST",
    url: endpoint,
    bodyType: "application/x-www-form-urlencoded",
    body: {
      form: [
        { name: "client_id", value: "service-account" },
        { name: "grant_type", value: "urn:ietf:params:oauth:grant-type:jwt-bearer" },
        { name: "assertion", value: assertion },
        { name: "scope", value: scope },
      ],
    },
    headers: [
      { name: "Content-Type", value: "application/x-www-form-urlencoded" },
      { name: "Accept", value: "application/json" },
    ],
    authenticationType: "none", // Don't inherit workspace auth
  };

  const requestedAt = Date.now();
  const { httpResponse, body: responseBody } = await ctx.httpRequest.send({ httpRequest });
  if (httpResponse.error) {
    throw new Error(`Ping AIC token request failed: ${httpResponse.error}`);
  }

  const text = await responseBody.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text);
  } catch {
    // Non-JSON error pages are reported as raw text below.
  }

  if (httpResponse.status < 200 || httpResponse.status >= 300) {
    const detail =
      [body.error, body.error_description].filter((v) => typeof v === "string").join(": ") ||
      text.slice(0, 500);
    throw new Error(`Ping AIC token request failed (${httpResponse.status}): ${detail}`);
  }

  if (typeof body.access_token !== "string") {
    throw new Error("Ping AIC token response did not include an access_token");
  }

  const expiresIn = typeof body.expires_in === "number" ? body.expires_in : ASSERTION_LIFETIME_S;
  return {
    accessToken: body.access_token,
    expiresAt: requestedAt + expiresIn * 1000,
    scope: typeof body.scope === "string" ? body.scope : undefined,
  };
}

/** Identifies a token by tenant, account and scope; the key itself never touches the store. */
export function cacheKey(config: TokenConfig): string {
  const parts = [
    normalizeTenantFqdn(config.tenantFqdn).toLowerCase(),
    config.serviceAccountId.trim(),
    normalizeScope(config.scope).split(" ").sort().join(" "),
  ];
  return `pingaic_token::${createHash("sha256").update(parts.join("\n")).digest("hex")}`;
}

// Requests applied in parallel share a single in-flight token fetch.
const inFlight = new Map<string, Promise<CachedToken>>();

export async function getAccessToken(ctx: TokenContext, config: TokenConfig): Promise<string> {
  const key = cacheKey(config);
  const cached = await ctx.store.get<CachedToken>(key);
  if (cached && cached.expiresAt - EXPIRY_BUFFER_MS > Date.now()) {
    return cached.accessToken;
  }

  let pending = inFlight.get(key);
  if (!pending) {
    pending = requestAccessToken(ctx, config)
      .then(async (token) => {
        await ctx.store.set(key, token);
        return token;
      })
      .finally(() => inFlight.delete(key));
    inFlight.set(key, pending);
  }
  return (await pending).accessToken;
}

export async function clearCachedToken(ctx: Pick<Context, "store">, config: TokenConfig): Promise<boolean> {
  return ctx.store.delete(cacheKey(config));
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
