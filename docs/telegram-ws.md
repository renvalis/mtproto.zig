# Telegram WSS, Cloudflare and HTTP/2 upstream

Telegram WSS, Cloudflare fallback and HTTP/2 media routing are built into the
proxy. Select `type = "telegram_ws"` in `config.toml`; every binary and Docker
image includes the transport without an additional build flag. Incoming
FakeTLS, users and client secrets use the existing proxy implementation.

## Build and dependencies

Zig 0.16.0, Perl 5, Make and pkg-config are required. Builds compile OpenSSL
3.5.9 and nghttp2 1.71.0 into static archives and embed the Mozilla root store
from certifi 2026.10.23. Sources are pinned by hashes in `build.zig.zon`.
The first build needs network access; subsequent builds use Zig's cache.
No host OpenSSL installation or target SDK is needed.

```sh
zig build -Dtarget=x86_64-linux-musl -Dcpu=x86_64_v3+aes -Doptimize=ReleaseSafe -Dstrip=true
# ARM64 Linux:
zig build -Dtarget=aarch64-linux-musl -Dcpu=generic+aes -Doptimize=ReleaseSafe -Dstrip=true
# Standard Docker image:
docker build -t mtproto-zig .
```

The transport targets Linux x86_64 and ARM64; use an explicit Linux target when
cross-compiling on macOS. The musl binaries include libc, TLS and HTTP/2
statically. `-Dstrip=true` removes debug symbols; `-Dws_tls_jobs=N` controls
parallel native-library build jobs (default 4).

Trust defaults to embedded roots. If set, `SSL_CERT_FILE` replaces them with
that PEM file; an invalid or empty file fails startup. No implicit OpenSSL
configuration/provider modules or system trust directory are loaded.
Update pinned sources and rebuild to update bundled libraries or CA roots.
License and attribution notices remain in `src/extensions/ws_transport`.

## Configuration

Edit the existing sections; do not duplicate `[upstream]` or `[general]`.

```toml
[general]
use_middle_proxy = false
force_media_middle_proxy = false

[upstream]
type = "telegram_ws" # "zapret" is an alias, not nfqws integration
allow_direct_fallback = false

[upstream.telegram_ws]
fronting = true
fronting_sni = "sprinthost.ru"
fronting_verify_hostname = true
cf_fallback = true
cf_first = false # set true when Telegram IPs are blocked, to try CF immediately
cf_h2_media = true
# cf_domains = "sadnews.co.uk,pclead.co.uk" # overrides the pinned reference domain pool
pool_size = 1
handshake_timeout_sec = 8
# Same DC2/DC4 redirect defaults as the reference checkout:
dc2_ip = "149.154.167.220"
dc4_ip = "149.154.167.220"
# Also configurable: dc1_ip, dc3_ip, dc5_ip, dc203_ip (IPv4 literals).
```

Direct attempts connect to the DC's configured IP on port 443. HTTP Host is
`kwsN.web.telegram.org`, or first `kwsN-1.web.telegram.org` for a negative media
DC ID. DC203 uses the DC2 domain with its own destination IP. The request is
`GET /apiws`, WebSocket subprotocol `binary`. Test DCs are not supported.

Normal SNI equals HTTP Host. With `fronting=true`, the next attempt uses
`fronting_sni` while retaining the Telegram Host. CA-chain verification is always
required. By default, the certificate must also match the SNI. The Python
reference uses chain-only verification for alternate SNI; reproducing that policy
requires explicit `fronting_verify_hostname=false`. This setting affects only
alternate-SNI WSS sessions, never metadata fetches or ordinary TLS attempts.
There is no HTTP/plaintext or unverified-CA fallback.

`pool_size` is 0–4 **per DC/media bucket per worker**, default 1; 0 disables
prewarming. There are 12 buckets. Unused sessions expire after 120 seconds;
failed warmups use exponential backoff from 1 second to 1 hour and rotate route
variants. Sessions are consumed once, never reused for another MTProto stream.
A pool miss connects on demand instead of immediately selecting a different
transport. Workers own their pools; no thread is created per connection.

WS uses explicit nonblocking TCP/TLS/Upgrade phases, bounded queues and on-demand
buffers. The memory safety estimate reserves 48 MiB per active connection for
worst-case packet/queue capacity and allocator headroom; this is a conservative
capacity limit, not an idle-RSS measurement. Measure your workload before
increasing `max_connections` or enabling `unsafe_override_limits`.

MiddleProxy and ad-tags are incompatible and rejected. `fast_mode` is bypassed
because packet boundaries require decrypted MTProto transport headers.
`force_media_middle_proxy` is bypassed in WS mode. Media support, including
non-Premium accounts, must be checked against real Telegram from the target VPS.

Attempts rotate endpoints/SNI only before the outbound obfuscation init is sent.
If all WS attempts fail, plain TCP is used only when
`allow_direct_fallback=true`. An established stream is never replayed.
The overall client handshake deadline also limits connection setup: configure
`[server].handshake_timeout_sec` to cover the desired number of attempts rather
than increasing per-attempt timeouts alone.

**Current limitations:** Cloudflare Workers, CF domain
list refresh, shared HTTP/2 lanes across client connections, and automatic
migration/replay of established sessions. CF domains use the pinned reference's
pool (override with `cf_domains`); their DNS addresses refresh in the background.
HTTP/2 uses a statically bundled nghttp2 1.71.0 and one TLS connection per media
client, with up to eight concurrent POSTs and bounded request/reply buffers.
It removes MTProto transport padding for `/api` and reconstructs the native
transport framing on replies, as in the reference. HTTP/2 requires ALPN `h2`,
a valid CA chain and matching hostname; preflight failure rotates to another
CF route, then WSS. Established requests are never automatically replayed.
A passing local test does not establish bypass effectiveness.

CF WSS connects to `kwsN.<base-domain>:443` with matching SNI and HTTP Host,
using `GET /apiws`. This resolves and connects to the CF domain, not the DC IP.
`cf_fallback=false` restores direct-WSS-only routing. `cf_first=true` starts
with CF rather than spending the handshake budget on blocked Telegram IPs.
Media CF routes try HTTP/2 `/api` before CF WSS when `cf_h2_media=true`.

Settings require a proxy restart. `mtbuddy config print-effective` includes WS
settings; `doctor --network` reports that its ordinary TCP probes do not validate
TLS/WS. Release and Docker builds include the same transport.

## Verification

On Linux:

```sh
zig build test -Dtarget=x86_64-linux-musl
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe
# Uses only loopback, needs permission to bind TCP 443 and openssl executable:
sudo python3 test/ws_transport_e2e.py --proxy "$PWD/zig-out/bin/mtproto-proxy" --isolated-runtime
```

The test driver uses Python ssl/libcrypto and openssl to generate a private CA;
those are test tools, not dependencies of the deployed binary.
`--isolated-runtime` checks ELF headers for a dynamic interpreter/shared-library
dependencies and runs every proxy process in an empty chroot with only the binary,
config and, for positive fixtures, an explicitly supplied test CA. The negative
unknown-CA test uses embedded roots with no CA files at all.

The integration fixture checks real TLS and Upgrade, both client entry paths,
media Host selection, packet boundaries, fragmented WS replies with ping/pong,
SNI retry after redirects, prewarmed sessions, bad Upgrade rejection and unknown
CA rejection. It needs no Telegram credentials or public network access.

## Attribution

Protocol behavior follows Flowseal/tg-ws-proxy, reference commit
`6690b788432fd0f59b0f38e228494bcd6bede1ca` (MIT). Its license is preserved in
`src/extensions/ws_transport/LICENSE.Flowseal`; bundled-library notices are in
`src/extensions/ws_transport/licenses/`.
