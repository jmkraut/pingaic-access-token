import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { plugin } from "./index";
import {
  buildAssertion,
  cacheKey,
  clearCachedToken,
  getAccessToken,
  loadPrivateKey,
  normalizeTenantFqdn,
  type TokenConfig,
  type TokenContext,
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

type SendArgs = Parameters<TokenContext["httpRequest"]["send"]>[0];
type Sent = Awaited<ReturnType<TokenContext["httpRequest"]["send"]>>;

function sent(status: number, body: string, error: string | null = null): Sent {
  return {
    httpResponse: { status, error },
    body: { text: async () => body },
  } as unknown as Sent;
}

function tokenResponse(token: string) {
  return sent(
    200,
    JSON.stringify({ access_token: token, scope: "fr:am:* fr:idm:*", token_type: "Bearer", expires_in: 899 }),
  );
}

function mockContext(send: (args: SendArgs) => Promise<Sent>) {
  const data = new Map<string, unknown>();
  const sendMock = vi.fn(send);
  const ctx: TokenContext = {
    store: {
      async get<T>(key: string) {
        return data.get(key) as T | undefined;
      },
      async set<T>(key: string, value: T) {
        data.set(key, value);
      },
      async delete(key: string) {
        return data.delete(key);
      },
    },
    httpRequest: { send: sendMock },
  };
  return { ctx, data, sendMock };
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
  test("posts a JWT bearer grant to the tenant token endpoint through Yaak", async () => {
    const { ctx, sendMock } = mockContext(async () => tokenResponse("tok-1"));
    const token = await getAccessToken(ctx, config());

    expect(token).toBe("tok-1");
    const { httpRequest } = sendMock.mock.calls[0]![0];
    expect(httpRequest).toMatchObject({
      method: "POST",
      url: ENDPOINT,
      bodyType: "application/x-www-form-urlencoded",
      authenticationType: "none",
    });
    const form = Object.fromEntries(
      (httpRequest.body!.form as { name: string; value: string }[]).map((p) => [p.name, p.value]),
    );
    expect(form).toMatchObject({
      client_id: "service-account",
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      scope: "fr:am:* fr:idm:*",
    });
    expect(decodePart(form.assertion!.split(".")[1]!).aud).toBe(ENDPOINT);
  });

  test("reuses a cached token until it nears expiry", async () => {
    const { ctx, data, sendMock } = mockContext(async () => tokenResponse("tok-1"));
    await getAccessToken(ctx, config());
    // Scope order/whitespace differences hit the same cache entry.
    await getAccessToken(ctx, config({ scope: "fr:idm:*   fr:am:*" }));
    expect(sendMock).toHaveBeenCalledTimes(1);

    data.set(cacheKey(config()), { accessToken: "old", expiresAt: Date.now() + 30_000 });
    sendMock.mockImplementationOnce(async () => tokenResponse("tok-2"));
    expect(await getAccessToken(ctx, config())).toBe("tok-2");
    expect(sendMock).toHaveBeenCalledTimes(2);
  });

  test("never stores the private key", async () => {
    const { ctx, data } = mockContext(async () => tokenResponse("tok-1"));
    await getAccessToken(ctx, config());
    expect(JSON.stringify([...data])).not.toContain(JSON.parse(jwk).d);
  });

  test("shares one in-flight request between concurrent callers", async () => {
    const { ctx, sendMock } = mockContext(async () => tokenResponse("tok-1"));
    const tokens = await Promise.all([1, 2, 3].map(() => getAccessToken(ctx, config())));
    expect(tokens).toEqual(["tok-1", "tok-1", "tok-1"]);
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  test("surfaces the OAuth error description", async () => {
    const { ctx, data } = mockContext(async () =>
      sent(400, JSON.stringify({ error: "invalid_scope", error_description: "Unknown/invalid scope(s)" })),
    );
    await expect(getAccessToken(ctx, config())).rejects.toThrow(
      "Ping AIC token request failed (400): invalid_scope: Unknown/invalid scope(s)",
    );
    expect(data.size).toBe(0);
  });

  test("surfaces connection errors from Yaak", async () => {
    const { ctx } = mockContext(async () => sent(0, "", "dns error: no such host"));
    await expect(getAccessToken(ctx, config())).rejects.toThrow(
      "Ping AIC token request failed: dns error: no such host",
    );
  });

  test("clearCachedToken forces a new request", async () => {
    const { ctx, sendMock } = mockContext(async () => tokenResponse("tok-1"));
    await getAccessToken(ctx, config());
    expect(await clearCachedToken(ctx, config())).toBe(true);
    await getAccessToken(ctx, config());
    expect(sendMock).toHaveBeenCalledTimes(2);
  });
});
