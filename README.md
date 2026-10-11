# cap-plugin-registry

Wyrd Company's plugin registry for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA), together with the source of our plugins.

## Layout

| Path | Contents |
| --- | --- |
| `registry.json` | CPA plugin store registry (`schema_version` 2) |
| `plugins/client-key-policy/` | Vault-backed client keys with provider policies, model aliasing and a management UI ([README](plugins/client-key-policy/README.md)) |

## Using this registry in CPA

Add the registry as an extra plugin store source in CPA's `config.yaml`:

```yaml
plugins:
  enabled: true
  store-sources:
    - "https://raw.githubusercontent.com/wyrd-company/cap-plugin-registry/main/registry.json"
```

If the repository is private, add a store auth rule. The token is read from the environment:

```yaml
plugins:
  store-auth:
    - match: "https://raw.githubusercontent.com/wyrd-company/"
      apply-to: ["registry"]
      type: "github-token"
      token-env: "CLIPROXY_PLUGIN_GITHUB_TOKEN"
    - match: "https://api.github.com/repos/wyrd-company/"
      apply-to: ["metadata", "artifact"]
      type: "github-token"
      token-env: "CLIPROXY_PLUGIN_GITHUB_TOKEN"
```

Plugins then appear in the plugin store of CPA's management panel.

## Publishing a plugin release

Entries use the `github-release` install type. CPA reads the repository's **latest**
GitHub release and expects these release assets:

- `<plugin-id>_<version>_<goos>_<goarch>.zip`, with the shared library `<plugin-id>.so` / `.dylib` / `.dll` at the zip root;
- `checksums.txt`, in `sha256sum` format, covering those zips.

The version comes from the release tag (`v0.1.0` or `0.1.0`). Each plugin's Makefile produces these files:

```bash
cd plugins/client-key-policy
make package VERSION=0.1.0 GOOS=linux GOARCH=amd64
make checksums
```

Plugins use cgo, so build each platform natively or with a matching cross C toolchain.

> **More than one plugin:** `github-release` always installs from the repository's
> latest release. Once a second plugin is released here, switch the entries to the
> `direct` install type. A `direct` entry lists artifact URLs with their `sha256` per
> version, so each plugin can have its own release cadence.
