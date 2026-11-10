# Security Policy

## Supported Versions

Security fixes are prioritized for:

| Branch / release line | Status |
| --- | --- |
| `main` | actively supported |
| latest tagged release | actively supported |
| older releases | best effort only |

If you run an older release, upgrade first and re-test before reporting.

## Reporting a Vulnerability

Please do not open public issues for security problems.

Use GitHub private vulnerability reporting:
- https://github.com/alex98247/mtproto.zig/security/advisories/new

Include:
- affected version (`mtproto-proxy --version`)
- deployment model (bare metal / VM / container)
- minimal reproduction steps
- impact and attack preconditions
- logs/config snippets with secrets removed

## Response Targets

- initial acknowledgment: within 72 hours
- triage update: within 7 days
- fix timeline: depends on severity and reproducibility

## Disclosure

Please allow maintainers time to patch before public disclosure.
Coordinated disclosure is preferred for all critical and high-severity issues.

## Release signing for this fork

The local minisign pair is stored in `.release-keys/minisign.key` (private) and
`.release-keys/minisign.pub` (public). The directory is gitignored and has mode
700; the private file has mode 600. The private key is unencrypted so the release
job can sign noninteractively. Keep a backup outside this checkout before deleting
or replacing it.

The public key is pinned in `build.zig`, `deploy/bootstrap.sh`, and
`.github/workflows/release-please.yml`. Update all three together when rotating it.

To enable signed releases, create the GitHub Environment `release` in
`alex98247/mtproto.zig` and add its environment secret `MINISIGN_SECRET_KEY` with
the entire contents of the private file. With authenticated GitHub CLI:

```sh
gh secret set MINISIGN_SECRET_KEY --repo alex98247/mtproto.zig --env release < .release-keys/minisign.key
```

The file is passed directly to GitHub CLI without printing its contents.
