# client-key-policy

A CLIProxyAPI (CPA) plugin that replaces CPA's static `access.api-keys` with
per-client keys stored in Vault or OpenBao. Each key belongs to a provider policy.
The policy limits which providers and models that client can use and defines
model aliases.

- **Keys live in Vault.**
  - The plugin generates each key and writes it to Vault. It never shows the key to an operator.
  - A downstream client reads its key from Vault using its own Vault policy.
- **The key identifies the policy.**
  - The plugin finds the client and its provider policy from the key value.
  - Optionally, the client also sends its client id, read from the same Vault secret, in a header.
- **Policies are also stored in Vault.** You edit them in the plugin's UI.
- **Aliases and duplicate model names.**
  - You can define custom aliases.
  - A model name that several allowed providers serve is exposed as `provider/model`.
  - Alternatively, you choose a winning provider for that name, and the other providers drop it.
- **The UI** manages policies and issues, rotates and revokes keys.

## How it works

The plugin registers these CPA plugin capabilities:

| Capability | Purpose |
| --- | --- |
| `frontend_auth_provider` (exclusive) | Authenticates every client request against the key index. Built-in `access.api-keys` stop working while the plugin is loaded. |
| `model_router` | Sends a policy-visible name (alias, `provider/model`, or a collision winner) to its provider and upstream model. |
| `request_interceptor` | Returns `403 model_not_allowed` for models outside the client's policy. |
| `scheduler` | The hard enforcement point: only credentials whose provider/model pair the policy grants can be picked, whatever routed the request. |
| `response_interceptor` | Replaces the model lists from `GET /v1/models` (OpenAI and Claude) and `GET /v1beta/models` with the client's own view. |
| `management_api` | Admin API under `/v0/management/client-key-policy/*` and the UI at `/v0/resource/plugins/client-key-policy/ui`. |

### Vault layout (KV v2)

```
<mount>/<prefix>/policies/<policy>         provider policy definition
<mount>/<prefix>/keys/<policy>/<client>    client key record
```

With the defaults (`mount: secret`, `prefix: cliproxyapi`), the client `billing-bot`
under policy `team-a` reads `secret/data/cliproxyapi/keys/team-a/billing-bot`:

```json
{
  "api_key": "cpa_…",
  "client_id": "team-a/billing-bot",
  "client_id_header": "X-CPA-Client-Id",
  "policy": "team-a",
  "name": "billing-bot",
  "created_at": "…",
  "rotated_at": "…"
}
```

The client sends `api_key` the way CPA normally accepts keys: `Authorization: Bearer`,
`x-api-key`, `x-goog-api-key` or `?key=`.

If it also sends `X-CPA-Client-Id: team-a/billing-bot`, the plugin looks the record up
by id and checks the key against it. Without the header, the plugin looks the key up
by its SHA-256 hash.

The plugin keeps only key hashes in memory. It reloads Vault every `refresh_interval`.
An unknown key also triggers a reload, at most once every 10 seconds, so keys issued by
another CPA instance are picked up quickly.

### Policies

```json
{
  "name": "team-a",
  "description": "Billing team",
  "providers": ["codex", "claude", "openai-compatible-openrouter"],
  "allow_models": ["gpt-5*", "claude-*"],
  "deny_models": ["*-preview"],
  "aliases": { "fast": { "provider": "codex", "model": "gpt-5-mini" } },
  "winners": { "claude-sonnet-4-6": "claude" }
}
```

- **`providers`**: CPA provider keys, such as `codex`, `claude` or `gemini`.
  - An `openai-compatibility` entry named `openrouter` has the key `openai-compatible-openrouter`.
  - `*` allows every provider.
- **`allow_models` / `deny_models`**: glob patterns matched against `model` or `provider/model`.
  - An empty allow list allows everything.
  - Deny always wins.
- **Duplicate names**: when two or more allowed providers serve the same model name, it is exposed as `provider/model` for each of them, unless `winners` names one provider.
  - With a winner, the model keeps its plain name on the winner, and the other providers do not offer it at all.
- **`aliases`**: explicit grants.
  - An alias may target any model of an allowed provider.
  - Allow/deny patterns do not apply to aliases.
  - An alias takes precedence over a catalog name it shadows.
- **Thinking suffixes** such as `fast(high)` are preserved through the mapping.

The UI shows the duplicate names for the selected providers so you can pick winners.
After you save a policy, the UI shows the resolved model list.

### Model catalog

CPA gives plugins no callback for its model registry, so the plugin reads the catalog
from CPA's Management API. That is why the plugin needs the management key. It combines
two sources:

- **OAuth and file credentials:** `/v8/management/credentials`, plus `/credentials/models` for each credential.
- **API-key providers from `config.yaml` (`api-keys.*`):**
  - each entry's `models` (the alias if set, otherwise the name);
  - for groups without `models`, CPA's static model definitions for that channel;
  - `excluded-models` and `prefix` are applied.

The catalog is re-read every `cpa.catalog_interval`.

## Installation

1. Build or download the shared library for your platform. You need Go 1.26 and a C toolchain, because the plugin uses cgo.

   ```bash
   cd plugins/client-key-policy
   make build            # dist/<goos>/<goarch>/client-key-policy.so
   make package checksums VERSION=0.1.0   # release zip + checksums.txt
   ```

2. Put `client-key-policy.so` (`.dylib` on macOS) in CPA's plugin directory, either `plugins/` or `plugins/<goos>/<goarch>/`. Alternatively, install it from this registry; see the repository README.

The file name is the plugin id, so it must stay `client-key-policy`.

## Vault / OpenBao setup

```bash
# KV v2 mount (skip if `secret/` already exists)
vault secrets enable -path=secret kv-v2

# Policy for the plugin itself
vault policy write cpa-client-key-policy - <<'EOF'
path "secret/data/cliproxyapi/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/cliproxyapi/*" { capabilities = ["list", "read", "delete"] }
EOF

# AppRole for the plugin (recommended over a static token)
vault auth enable approle
vault write auth/approle/role/cpa-client-key-policy token_policies=cpa-client-key-policy token_ttl=1h
vault read  -field=role_id   auth/approle/role/cpa-client-key-policy/role-id
vault write -f -field=secret_id auth/approle/role/cpa-client-key-policy/secret-id
```

Give each downstream client read access to its own record only:

```hcl
# policy: client-team-a-billing-bot
path "secret/data/cliproxyapi/keys/team-a/billing-bot" { capabilities = ["read"] }
```

or to every key of one provider policy:

```hcl
path "secret/data/cliproxyapi/keys/team-a/*" { capabilities = ["read"] }
```

For Vault Enterprise or OpenBao namespaces, set `vault.namespace`. The paths above
are then relative to that namespace, for example `cliproxyapi`.

Revoking a key destroys its Vault secret, including all versions and metadata.
Rotating a key writes a new KV version; the old value stays in KV history but no
longer authenticates.

## CPA configuration

```yaml
management:
  secret-key: "…"            # required: the plugin reads the model catalog via the Management API

access:
  api-keys:
    # Keep one unguessable placeholder here. The plugin is an exclusive auth provider,
    # so these keys are ignored while it is loaded. If the plugin ever fails to load,
    # CPA falls back to this list instead of allowing unauthenticated access, which is
    # what CPA does when no auth provider is registered at all.
    - "disabled-placeholder-<random>"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    client-key-policy:
      enabled: true
      priority: 100
      vault:
        address: "https://vault.example.com:8200"
        namespace: ""                  # Vault Enterprise / OpenBao namespace, optional
        mount: "secret"                # KV v2 mount
        prefix: "cliproxyapi"          # path inside the mount owned by the plugin
        auth_method: "approle"         # "token" or "approle"
        token_env: "VAULT_TOKEN"       # used when auth_method=token
        approle_mount: "approle"
        role_id_env: "VAULT_ROLE_ID"
        secret_id_env: "VAULT_SECRET_ID"
        ca_cert: ""                    # PEM file for a private CA, optional
        tls_skip_verify: false
      cpa:
        management_url: "http://127.0.0.1:8317"   # how the plugin reaches this CPA instance
        management_key_env: "CPA_MANAGEMENT_KEY"  # env var holding the plaintext management key
        catalog_interval: 1m
      client_id_header: "X-CPA-Client-Id"         # "" disables the header lookup
      refresh_interval: 1m
```

Secrets come only from environment variables. Set them in CPA's environment; CPA also
loads a `.env` from its working directory:

```bash
VAULT_ROLE_ID=…
VAULT_SECRET_ID=…
CPA_MANAGEMENT_KEY=…   # the same plaintext value as management.secret-key
```

If the configuration is invalid, the plugin still loads but rejects every client
request (it fails closed). The error is shown in CPA's log and in the UI status bar.

## Using the UI

Open `http://<cpa-host>:<port>/v0/resource/plugins/client-key-policy/ui` and enter
the CPA management key. The key is kept in the browser tab's session storage only.
The management API's `allow-remote` and localhost rules apply.

- **Policies**:
  - create or edit a policy;
  - tick the allowed providers (taken from the live catalog);
  - add allow/deny patterns and aliases (`alias = provider/model`, one per line);
  - choose winners for duplicate model names;
  - after saving, see the resolved model list.
- **Client keys**: issue a key for a policy, which writes it to Vault and shows the Vault path. Rotate or revoke existing keys.

The same operations are available as JSON endpoints under
`/v0/management/client-key-policy/` (management key required):

| Method | Path | Body / query |
| --- | --- | --- |
| GET | `state` | — |
| POST | `policies` | policy JSON |
| POST | `policies/delete` | `?name=` (fails while the policy has keys) |
| POST | `keys` | `{"policy","name","description"}` |
| POST | `keys/rotate` | `?id=<policy>/<client>` |
| POST | `keys/revoke` | `?id=<policy>/<client>` |
| POST | `refresh` | reload Vault and the catalog |

## Known limitations

- **Response model name.** Responses report the upstream model name, not the alias the client requested. CPA rewrites the response model only for its own config aliases.
- **Unfiltered lookup.** `GET /v1beta/models/<name>` (a single Gemini model lookup) bypasses CPA's response interceptors, so it is not filtered. Requests for that model are still enforced.
- **Error status from the scheduler.** If the router's target provider has no usable credential, CPA falls back to its normal routing. The scheduler check then rejects any credential outside the policy, and the client sees CPA's `auth_unavailable`-style error instead of a 403.
- **Multiple CPA instances.** A key revoked or rotated on one instance stops working on the others only after their next `refresh_interval`.
