import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { plugin } from "./index";
import {
  buildAssertion,
  cacheKey,
  clearCachedToken,
  getAccessToken,
  loadPrivateKey,
  normalizeTenantFqdn,
  type TokenConfig,
  type TokenStore,
} from "./token";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = JSON.stringify(privateKey.export({ format: "jwk" }));
const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();

const SA_ID = "449d7e27-7889-47af-a736-83b6bbf97ec5";
const ENDPOINT = "https://openam-x.forgeblocks.com:443/am/oauth2/access_token";

function config(overrides: Partial<TokenConfig> = {}): TokenConfig {
  return {
    tenantFqdn: "openam-x.forgeblocks.com",
    serviceAccountId: SA_ID,
    privateKey: jwk,
    scope: "fr:am:* fr:idm:*",
    ...overrides,
  };
}

function memoryStore(): TokenStore & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    async get<T>(key: string) {
      return data.get(key) as T | undefined;
    },
    async set<T>(key: string, value: T) {
      data.set(key, value);
    },
    async delete(key: string) {
      return data.delete(key);
    },
  };
}

function tokenResponse(token: string, status = 200) {
  return new Response(
    JSON.stringify({ access_token: token, scope: "fr:am:* fr:idm:*", token_type: "Bearer", expires_in: 899 }),
    { status, headers: { "Content-Type": "application/json" } },
  );
}

function decodePart(part: string) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

describe("plugin", () => {
  test("registers an authentication plugin", () => {
    expect(plugin.authentication?.name).toBe("pingaic-service-account");
  });
});

describe("normalizeTenantFqdn", () => {
  test.each([
    ["openam-x.forgeblocks.com", "openam-x.forgeblocks.com"],
    ["  https://openam-x.forgeblocks.com/am/ ", "openam-x.forgeblocks.com"],
    ["openam-x.forgeblocks.com:443", "openam-x.forgeblocks.com"],
  ])("%s", (input, expected) => {
    expect(normalizeTenantFqdn(input)).toBe(expected);
  });
});

describe("loadPrivateKey", () => {
  test("accepts pasted JWK", async () => {
    expect((await loadPrivateKey(jwk)).type).toBe("private");
  });

  test("accepts pasted PEM", async () => {
    expect((await loadPrivateKey(pem)).type).toBe("private");
  });

  test("accepts a path to a JWK file", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "pingaic-")), "key.jwk");
    writeFileSync(path, jwk);
    expect((await loadPrivateKey(`  ${path}\n`)).type).toBe("private");
  });

  test("reports a missing file clearly", async () => {
    await expect(loadPrivateKey("/does/not/exist.jwk")).rejects.toThrow(/could not be read as a file/);
  });
});

describe("buildAssertion", () => {
  test("produces an RS256 JWT with the claims AIC requires", () => {
    const jwt = buildAssertion(privateKey, SA_ID, ENDPOINT, 1_000_000);
    const [h, p, s] = jwt.split(".") as [string, string, string];

    expect(decodePart(h)).toEqual({ alg: "RS256", typ: "JWT" });
    const payload = decodePart(p);
    expect(payload).toMatchObject({ iss: SA_ID, sub: SA_ID, aud: ENDPOINT, exp: 1_000_899 });
    expect(payload.jti).toEqual(expect.any(String));
    expect(verify("RSA-SHA256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url"))).toBe(true);
  });
});

describe("getAccessToken", () => {
  let store: ReturnType<typeof memoryStore>;
  beforeEach(() => {
    store = memoryStore();
  });

  test("posts a JWT bearer grant to the tenant token endpoint", async () => {
    const fetchMock = vi.fn(async () => tokenResponse("tok-1"));
    const token = await getAccessToken(store, config(), fetchMock);

    expect(token).toBe("tok-1");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(ENDPOINT);
    const body = new URLSearchParams(init.body as string);
    expect(body.get("client_id")).toBe("service-account");
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(body.get("scope")).toBe("fr:am:* fr:idm:*");
    expect(decodePart(body.get("assertion")!.split(".")[1]!).aud).toBe(ENDPOINT);
  });

  test("reuses a cached token until it nears expiry", async () => {
    const fetchMock = vi.fn(async () => tokenResponse("tok-1"));
    await getAccessToken(store, config(), fetchMock);
    // Scope order/whitespace differences hit the same cache entry.
    await getAccessToken(store, config({ scope: "fr:idm:*   fr:am:*" }), fetchMock);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const key = cacheKey(config());
    store.data.set(key, { accessToken: "old", expiresAt: Date.now() + 30_000 });
    fetchMock.mockImplementationOnce(async () => tokenResponse("tok-2"));
    expect(await getAccessToken(store, config(), fetchMock)).toBe("tok-2");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test("never stores the private key", async () => {
    await getAccessToken(store, config(), async () => tokenResponse("tok-1"));
    expect(JSON.stringify([...store.data])).not.toContain(JSON.parse(jwk).d);
  });

  test("shares one in-flight request between concurrent callers", async () => {
    const fetchMock = vi.fn(async () => tokenResponse("tok-1"));
    const tokens = await Promise.all([1, 2, 3].map(() => getAccessToken(store, config(), fetchMock)));
    expect(tokens).toEqual(["tok-1", "tok-1", "tok-1"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test("surfaces the OAuth error description", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: "invalid_scope", error_description: "Unknown/invalid scope(s)" }), {
          status: 400,
        }),
    );
    await expect(getAccessToken(store, config(), fetchMock)).rejects.toThrow(
      "Ping AIC token request failed (400): invalid_scope: Unknown/invalid scope(s)",
    );
    expect(store.data.size).toBe(0);
  });

  test("clearCachedToken forces a new request", async () => {
    const fetchMock = vi.fn(async () => tokenResponse("tok-1"));
    await getAccessToken(store, config(), fetchMock);
    expect(await clearCachedToken(store, config())).toBe(true);
    await getAccessToken(store, config(), fetchMock);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
