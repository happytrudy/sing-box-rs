# sing-box-rs

`sing-box-rs` is a Tokio-based proxy runtime organized around the same major
boundaries as sing-box: typed protocol registries, small inbound/outbound
interfaces, staged lifecycle management, dependency-aware outbounds, and
protocol implementations that live outside the core runtime.

This repository is an initial working implementation, not yet a feature-for-
feature replacement for sing-box.

## What works

- extensible inbound and outbound factory registries
- two-pass JSON decoding based on each component's `type`
- four-stage service lifecycle and reverse-order shutdown
- outbound dependency validation and cycle detection
- TCP and UDP sessions, routing, and bidirectional relay
- ordered route, route-options, reject, rule-set, and final actions
- inline/local/remote source rule-sets and official sing-box SRS binary files
- transactional local rule-set hot reload and remote ETag-based periodic updates
- shared certificate-provider registry with tag-based protocol references
- ACME certificate provider with Cloudflare DNS-01, persistent cache, and renewal
- external UDP DNS resolver with IPv4/IPv6 strategies and TTL cache
- configurable logging, NTP offset measurement, direct and block outbounds
- executable client and server configurations

## Proxy transport combinations

The matrix lists implemented protocol, carrier, camouflage/TLS, and congestion
control combinations. `Inbound` and `Outbound` describe the current adapter,
not the upstream protocol's theoretical capabilities.

| Transport combination | Inbound | Outbound | Networks and capabilities | Examples |
| --- | --- | --- | --- | --- |
| Snell v4/v5 + legacy transport | Yes | Yes | TCP and UDP; authenticated sessions, reuse, replay protection, and obfs | `server.json`, `client.json` |
| Snell v6 + default/unshaped/unsafe-raw | Yes | Yes | TCP and UDP; v6 shaping modes and connection reuse | `server.json`, `client.json` |
| Hysteria2 + QUIC TLS + BBR | Yes | Yes | Inbound TCP/UDP; outbound TCP; selected when both bandwidth values are zero | `hysteria2-server.json`, `hysteria2-client.json` with `up_mbps` and `down_mbps` set to `0` |
| Hysteria2 + QUIC TLS + Brutal | Yes | Yes | Inbound TCP/UDP; outbound TCP; negotiated bandwidth and optional loss compensation | `hysteria2-server.json`, `hysteria2-client.json` |
| ShadowQUIC + JLS + BBR | Yes | Yes | Inbound TCP/UDP; outbound TCP; JLS authentication, 0-RTT, and optional upstream fallback | `shadowquic-server.json`, `shadowquic-client.json` with `congestion_control.type` set to `bbr` |
| ShadowQUIC + JLS + Brutal | Yes | Yes | Inbound TCP/UDP; outbound TCP; rate pacing and optional loss compensation | `shadowquic-server.json`, `shadowquic-client.json` |
| SunnyQUIC + native QUIC TLS + BBR | Yes | Yes | TCP and UDP; UDP datagrams or streams; static certificate or `certificate_provider` | `sunnyquic-server-bbr.json`, `sunnyquic-client-bbr.json` |
| SunnyQUIC + native QUIC TLS + Brutal | Yes | Yes | TCP and UDP; rate pacing and optional loss compensation | `sunnyquic-server-brutal.json`, `sunnyquic-client-brutal.json` |
| Cloudflared + HTTP/2 | Yes | No | Remote-managed tunnel; TCP, HTTP, WebSocket, and Cap'n Proto RPC | `cloudflared-inbound.json` with `protocol` set to `http2` |
| Cloudflared + QUIC | Yes | No | Remote-managed tunnel; TCP, HTTP, WebSocket, and datagram v2/v3 | `cloudflared-inbound.json` |
| VLESS + WebSocket | Yes | No | TCP; UUID authentication, path validation, masking, and early data | `vless-ws-server.json` |
| VLESS + WebSocket + Reality | Yes | No | TCP; Reality server authentication and invalid-client fallback | `vless-reality-ws-server.json` |
| AnyTLS + standard TLS | Yes | Yes | TCP and UDP-over-TCP; v2 multiplexing, padding, static certificate, or `certificate_provider` | `anytls-server.json`, `anytls-client.json` |
| AnyTLS + Reality | Yes | No | TCP and UDP-over-TCP; Reality replaces the inbound TLS acceptor | `anytls-reality-server.json` |
| AnyTLS + JLS | Yes | Yes | TCP and UDP-over-TCP; JLS handshake followed by normal AnyTLS authentication and multiplexing | `anytls-jls-server.json`, `anytls-jls-client.json` |

Core endpoints outside this transport matrix are the SOCKS5 TCP/UDP inbound and
the Direct and Block TCP/UDP outbounds.

## Project layout

```text
crates/
  sing-box-core/             protocol-neutral API and runtime
  sing-box-protocol-snell/   thin adapter around sing-snell-rs
  sing-box-protocol-hysteria2/ thin adapter around sing-quic-rs
  sing-box-protocol-vless/   VLESS WebSocket inbound adapter
  sing-box-protocol-anytls/  AnyTLS TLS multiplexing adapter
  sing-box-tls/              shared TLS and protocol-neutral Reality adapter
  sing-box-cli/              composition root and executable
```

The Snell wire implementation is a sibling project and is consumed through a
path dependency:

```text
../sing-snell-rs
../sing-quic-rs
../sing-dns-rs
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the extension contract.

## Run

Generate a REALITY X25519 keypair using the same output format as sing-box:

```bash
cargo run -p sing-box-rs -- generate reality-keypair
```

The command prints `PrivateKey: ...` for the server and `PublicKey: ...` for
clients. Both values use unpadded URL-safe Base64.

Start the server:

```bash
cargo run -p sing-box-rs -- run -c examples/server.json
```

After adjusting the server address and credentials, start the client in a
second terminal:

```bash
cargo run -p sing-box-rs -- run -c examples/client.json
```

The example client exposes a SOCKS5 proxy at `127.0.0.1:1080`.

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

For the Hysteria2 examples, first create a development certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/hysteria2-key.pem \
  -out examples/hysteria2-cert.pem \
  -days 3650 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost'
```

Then run `examples/hysteria2-server.json` and
`examples/hysteria2-client.json` in separate terminals.

SunnyQUIC has separate BBR, Brutal, and ACME `certificate_provider` examples:
`sunnyquic-server-bbr.json`, `sunnyquic-server-brutal.json`,
`sunnyquic-server-certificate-provider.json`, `sunnyquic-client-bbr.json`, and
`sunnyquic-client-brutal.json`. SunnyQUIC uses native QUIC TLS and the same
`listen: "::"` dual-stack behavior as the other inbound protocols.

The server can also be split into a base configuration and protocol-specific
inbound fragments:

```bash
cargo run -p sing-box-rs -- run \
  -c examples/modular/config.json \
  -C examples/modular/conf
```

`-c` and `-C` are repeatable. The loader collects direct `.json` files from
each directory, sorts all paths, recursively merges objects, and appends
arrays. This keeps inbounds in independent files while outbounds and routing
remain in the base configuration.

`examples/modular/config.json` is a fuller base configuration covering file
logging, UDP DNS, NTP, source/binary/inline rule-sets, ordered rules,
direct/block outbounds, plus commented remote rule-set and ACME provider
templates. Inbounds remain exclusively under `examples/modular/conf`.

An advanced base configuration with UDP DNS, local source rule-set client
authorization, ordered route/reject actions, NTP, file logging, direct, and
block outbounds is available at `examples/advanced/config.json`. It can be
combined with the modular Hysteria2 inbound:

```bash
cargo run -p sing-box-rs -- run \
  -c examples/advanced/config.json \
  -C examples/modular/conf
```

### Rule-sets

Local rule-sets support source JSON and official sing-box `.srs` binaries. The
format may be explicit or inferred from the `.json`/`.srs` suffix. Local files
are watched while the engine is running; a changed file is parsed and compiled
before its active snapshot is replaced. Invalid updates are logged and the
last valid snapshot remains active.

```json
{
  "type": "local",
  "tag": "local-example",
  "path": "examples/rule-set/compat.srs"
}
```

Remote rule-sets use HTTP or HTTPS. The first download must succeed before the
engine starts. Later downloads use `If-None-Match` when the server supplied an
ETag, and replace the active snapshot only after successful validation. The
default update interval is 24 hours.

```json
{
  "type": "remote",
  "tag": "remote-example",
  "format": "binary",
  "url": "https://example.com/path/to/rules.srs",
  "update_interval": "6h"
}
```

See `examples/rule-set/local-binary.json` and
`examples/rule-set/remote-binary.json`. The checked-in `compat.srs` fixture was
compiled by the official Go sing-box implementation from `compat.json`:

```bash
sing-box rule-set compile examples/rule-set/compat.json \
  -o examples/rule-set/compat.srs
```

### Certificate providers

Certificate providers are shared runtime services. Protocols reference them by
tag, so ACME account handling, DNS challenges, storage, and renewal remain
independent of Hysteria2 or any future TLS protocol. Providers start before
certificate consumers and stop after them. Updated certificates are published
to subscribers without interrupting existing connections.

The first provider implementation supports Let's Encrypt and custom HTTPS ACME
directories with Cloudflare DNS-01. It stores account credentials and an atomic
certificate/key bundle under `data_directory/sing-box-rs/<tag>`, uses cached
certificates across restarts, and starts renewal 30 days before expiration.

```json
{
  "certificate_providers": [
    {
      "type": "acme",
      "tag": "example-certificate",
      "domain": "h.example.com",
      "email": "admin@example.com",
      "data_directory": "acme",
      "dns01_challenge": {
        "provider": "cloudflare",
        "api_token": "${CLOUDFLARE_API_TOKEN}"
      }
    }
  ]
}
```

Set the token outside the configuration and reference it exactly as shown:

```bash
export CLOUDFLARE_API_TOKEN='replace-with-a-zone-scoped-token'
cargo run -p sing-box-rs -- run \
  -c examples/certificate-provider/acme-cloudflare.json
```

The token requires Cloudflare Zone DNS Edit and Zone Read access for the
certificate's zone. Hysteria2 is the first certificate consumer:

```json
{
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "server_name": "h.example.com",
    "certificate_provider": "example-certificate"
  }
}
```

Inbound `listen` semantics are shared by every protocol: `0.0.0.0` is
IPv4-only, `::` listens on all IPv6 and IPv4 interfaces, and `::1` binds both
the IPv6 and IPv4 loopback addresses. A full endpoint such as
`127.0.0.1:443` or `[::1]:443` may be used instead of a separate
`listen_port`.

VLESS currently supports TCP over a WebSocket inbound. The implementation
validates the configured UUID, WebSocket path, RFC 6455 client masking, and the
VLESS destination header before handing the stream to the common router. The
`early_data_header_name` option accepts URL-safe Base64 VLESS request bytes in
the named HTTP header, matching the V2Ray WebSocket transport. VLESS UDP and
outbound support are not implemented yet. VLESS and AnyTLS can both select the
shared `tls.reality` server mode; Reality authentication and fallback are
implemented in `sing-box-tls`, not in either protocol adapter.

### Reality TLS

The repository pins the official rustls `0.23.42` source through the local
`../rustls` fork. The fork retains a read-only `Accepted::reality_client_hello`
view and the JLS handshake hooks while tracking the latest official stable
rustls release. The shared TLS crate authenticates the legacy session ID and
X25519 key share before resuming the regular rustls TLS 1.3 state machine. A
valid client receives a per-connection temporary Ed25519 certificate signed
with the REALITY AuthKey; an invalid client is relayed to the configured
handshake server. The same adapter is reusable by VLESS, AnyTLS, and future
TLS-based protocols.

Cloudflared supports remote-managed tunnel tokens, SRV/DoT edge discovery,
HTTP/2 and QUIC transports, HA connection rotation, retry-after backoff,
graceful unregister, and the official Cap'n Proto registration/configuration
RPCs. TCP, HTTP, and WebSocket streams are routed through the common router;
HTTP origin requests use the remote ingress snapshot and support URL origins
and `http_status` services. QUIC Datagram v2 and v3 UDP sessions include
registration responses, payload limits, idle expiry, and the common packet
router. QUIC uses the AWS-LC rustls provider and enables the
X25519+ML-KEM hybrid key exchange when `post_quantum` is true. See
`examples/cloudflared-inbound.json` for the configuration shape.
ICMP datagrams are not enabled yet: the current core packet-router contract
is UDP-oriented and does not expose a raw ICMP socket/NAT mapping.

Hysteria2 `up_mbps` and `down_mbps` configure the local send and receive
limits. Positive negotiated rates use Brutal; leaving both at zero keeps BBR.
`ignore_client_bandwidth` ignores client bandwidth hints and keeps both sides
on their configured non-Brutal controller; it does not reject BBR clients.
For example, a server configured at 1000/1000 Mbps and a client configured at
30 Mbps upload and 100 Mbps download negotiate Brutal at 30 Mbps client-to-
server and 100 Mbps server-to-client.
`disable_loss_compensation` keeps the configured send rate instead of raising
it to compensate for packet loss, which is useful behind a hard bandwidth
policer. `brutal_debug` logs RTT, congestion window, MTU, packet loss, and
measured send/receive Mbps every two seconds for each active QUIC connection.
The inbound and outbound also accept the sing-box QUIC transport fields
`idle_timeout`, `keep_alive_period`, `stream_receive_window`,
`connection_receive_window`, `max_concurrent_streams`, `initial_packet_size`,
and `disable_path_mtu_discovery`. These map directly to Quinn's public
`TransportConfig` methods. The default incoming stream limit remains the
official Hysteria2 value; `max_concurrent_streams` only changes it when set.

AnyTLS uses the sing-box protocol shape: the inbound accepts `users` and TLS
certificate files or a shared `certificate_provider` tag; the outbound accepts
`server`, `server_port`, `password`, TLS options, and string durations such as
`"30s"` for idle-session cleanup. TCP streams use AnyTLS v2 settings,
SYN/PSH/FIN/SYNACK frames, SOCKS destination encoding, and the newest idle TLS
session for multiplexing. UDP uses `sp.v2.udp-over-tcp.arpa` with the sing-box
UDP-over-TCP v2 packet format. The default and configured padding schemes are
negotiated by MD5 and applied with `cmdWaste` frames. Padding ranges use the
existing AWS-LC secure random source without adding a separate random-number
dependency.

AnyTLS can also use the JLS TLS camouflage from the Rustls fork used by this
workspace. Set `enable_jls`, `jls_username`, and `jls_password` in the `tls`
object on both peers. A JLS inbound may omit certificate files and a provider;
it generates a temporary certificate for the TLS handshake. Clients using that
mode should set `insecure: true` unless the server supplies a trusted
certificate. See `examples/anytls-jls-server.json` and
`examples/anytls-jls-client.json`.

Hysteria2 masquerade handles ordinary HTTP/3 requests and failed
authentication attempts. Without it the server returns 404. The sing-box URL
short forms provide a file server or reverse proxy:

```json
"masquerade": "file:///var/www"
```

```json
"masquerade": "http://127.0.0.1:8080"
```

The equivalent object forms add host rewriting and fixed responses:

```json
"masquerade": {
  "type": "proxy",
  "url": "https://www.example.com/base",
  "rewrite_host": true
}
```

```json
"masquerade": {
  "type": "file",
  "directory": "/var/www"
}
```

```json
"masquerade": {
  "type": "string",
  "status_code": 200,
  "headers": {
    "content-type": "text/html; charset=utf-8"
  },
  "content": "<!doctype html><title>Welcome</title>"
}
```

The listener remains UDP/QUIC only. A TCP-only HTTPS client will not reach the
masquerade handler; use an HTTP/3-capable client when testing it directly.

Set `RUST_LOG=debug` to inspect routing, rule-set update, and handshake
failures.

## Configuration

Protocol options are flattened next to `type` and `tag`, matching sing-box's
configuration shape. The registry first reads the component header and then
deserializes the remaining JSON into the protocol crate's own option type.

```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "local",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

Snell v6 outbound options use `"version": 6` and optionally
`"mode": "default"`, `"unshaped"`, or `"unsafe-raw"`. Set `"reuse": true`
to pool CONNECT_V2 sessions. Both Snell inbound and outbound accept an `"obfs"`
value of `"http"` or `"tls"` plus an optional `"obfs_host"`.

## Current limitations

- route sniffing is not implemented
- binary rule items requiring unavailable process, package, interface, Wi-Fi,
  AdGuard, regular-expression, or DNS query metadata are rejected
- remote rule-set cache persistence, `download_detour`, and custom
  `http_client` options are not implemented
- ACME currently supports P-256 certificates and Cloudflare DNS-01; HTTP-01,
  TLS-ALPN-01, EAB, other DNS providers, and custom ACME HTTP clients are not implemented
- DNS currently supports UDP servers and address lookup; DNS rules, TCP/TLS/
  HTTPS/QUIC transports, fake IP, and hijack-dns are not implemented
- no TUN endpoint, endpoint registry, service registry, or connection tracking
- SOCKS authentication and BIND are not implemented
- Hysteria2 UDP forwarding, obfuscation, port hopping, TUIC, and legacy
  Hysteria are not implemented yet

## Verification

The integration tests start TCP/UDP echo servers and two proxy engines, then
exercise SOCKS5 TCP reuse and UDP ASSOCIATE through Snell and direct routing:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Manual release

Linux release binaries use the musl targets (`x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`) and are statically linked, so they do not require
the target system's glibc version.

The `Manual Release` workflow under GitHub Actions publishes Linux AMD64 and
ARM64 archives. It reads the release version from `[workspace.package]` in the
root `Cargo.toml`; for example, version `0.1.3` produces release tag `v0.1.3`.

Before running it, change that version to a new value and push the required
`sing-quic-rs`, `sing-snell-rs`, `sing-dns-rs`, `quinn`, and `rustls` revisions
to the `happytrudy` GitHub account. Open **Actions**, select **Manual Release**,
choose **Run workflow**, and optionally enable draft or prerelease mode. The
workflow pins each dependency's current `master` commit so verification and all
release builds use the same source. Re-running the workflow for the same commit
replaces the existing release assets; using the same version for a different
commit is rejected.
