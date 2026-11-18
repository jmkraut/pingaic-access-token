# Ping AIC Service Account Auth

A [Yaak](https://yaak.app) authentication plugin for **Ping Advanced Identity Cloud** (PingOne AIC).
It uses a service account ID and private key to get an access token, caches it, and sends it as
`Authorization: Bearer <token>`. It follows the
[JWT bearer flow described by Ping](https://docs.pingidentity.com/pingoneaic/developer-docs/authenticate-to-rest-api-with-access-token.html).

Use it to call AIC REST APIs such as `/am/*`, `/openidm/*` and `/environment/*`.

## Setup

1. In the AIC admin console, create a service account. Download its private key (`.jwk`) and note
   its ID.
2. In Yaak, open a request, folder or workspace and choose **Auth → Ping AIC Service Account**.
3. Fill in:

| Field | Value |
| --- | --- |
| Tenant FQDN | Your tenant's own FQDN, e.g. `openam-example.forgeblocks.com`. Don't use a custom domain. A full URL is also accepted. |
| Service Account ID | The service account's UUID. |
| Private Key | The contents of the `.jwk` file, **or** the path to it (`~` is supported). A PEM key is also accepted. |
| Scopes | Space-separated, e.g. `fr:am:* fr:idm:*` or `fr:idc:esv:*`. They must be a subset of the scopes granted to the service account. |

Any field can use Yaak environment variables, for example `${[ PING_TENANT ]}`.

> **Keep the key out of shared workspaces.** Auth settings are saved with the request, folder or
> workspace. If you sync the workspace to git, a pasted key would be committed too. Use a file path
> or a Yaak secret/environment variable instead.

## How it works

- A JWT with `iss`/`sub` set to the service account ID and `aud` set to the token endpoint is
  signed with RS256. It is exchanged at
  `https://<tenant>:443/am/oauth2/access_token` using `client_id=service-account`. The token
  request goes through Yaak, so your proxy and certificate settings apply.
- The token is cached in the plugin store. The cache key is the tenant, service account and scopes;
  scope order doesn't matter. Tokens last a fixed 899 seconds and are refreshed 60 seconds before
  they expire. The private key is never cached.
- Requests sent at the same moment share one token request.
- If AIC grants fewer scopes than you requested, a warning toast names the missing ones.
- The cached token is stored unencrypted in Yaak's plugin store, like the built-in OAuth 2.0
  plugin's tokens. It expires after 15 minutes.
- Lines starting with `[pingaic]` in Yaak's plugin log show whether each request used a cached
  token or fetched a new one.

## Limitations

- An auth plugin can't see the API's response. If AIC revokes a token early, requests fail with
  401 until it expires or you run **Clear Cached Token**.

## Actions

From the auth tab's menu:

- **Copy Access Token**: copies the current token to the clipboard, getting a new one if needed.
- **Clear Cached Token**: forces a new token on the next request. Use it after changing the
  service account's scopes or key in AIC.

## Development

The plugin is built and published with the [Yaak CLI](https://yaak.app/docs/plugin-development/plugins-quick-start)
(`npm install -g @yaakapp/cli`).

```sh
yaak plugin dev       # rebuild on every change
yaak plugin build     # one-off build into build/
```

To load your local copy, add this folder in Yaak under **Settings → Plugins**. Yaak reloads the
plugin after each rebuild.

Building doesn't need `npm install`. The tests and type-check do:

```sh
npm install
npm test              # vitest
npm run typecheck     # tsc; yaak plugin build doesn't check types
```

## Publishing

```sh
yaak auth login
yaak plugin publish
```

Increase `version` in `package.json` before each publish.
