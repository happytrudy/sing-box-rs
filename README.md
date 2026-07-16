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
- TCP/UDP `direct` outbound with IPv4 and IPv6 sockets
- SOCKS5 CONNECT and UDP ASSOCIATE inbound
- external Snell inbound/outbound adapter
- Snell v4/v5 legacy and v6 default/unshaped/unsafe-raw modes
- Snell authenticated TCP, UDP, connection reuse, replay protection, and obfs
- external Hysteria2 inbound/outbound adapter backed by `sing-quic-rs`
- Hysteria2 HTTP/3 authentication and multiplexed TCP streams over QUIC
- Hysteria2 BBR default and negotiated Brutal congestion control
- PEM and DER certificate loading for Hysteria2
- executable client and server configurations

## Project layout

```text
crates/
  sing-box-core/             protocol-neutral API and runtime
  sing-box-protocol-snell/   thin adapter around sing-snell-rs
  sing-box-protocol-hysteria2/ thin adapter around sing-quic-rs
  sing-box-cli/              composition root and executable
```

The Snell wire implementation is a sibling project and is consumed through a
path dependency:

```text
../sing-snell-rs
../sing-quic-rs
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the extension contract.

## Run

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

Inbound `listen` semantics are shared by every protocol: `0.0.0.0` is
IPv4-only, `::` listens on all IPv6 and IPv4 interfaces, and `::1` binds both
the IPv6 and IPv4 loopback addresses. A full endpoint such as
`127.0.0.1:443` or `[::1]:443` may be used instead of a separate
`listen_port`.

Hysteria2 `up_mbps` and `down_mbps` configure the local send and receive
limits. Positive negotiated rates use Brutal; leaving both at zero keeps BBR.
When server bandwidth is unset, `ignore_client_bandwidth` forces BBR. When it
is set, the option rejects clients that request BBR, matching sing-box.

Set `RUST_LOG=debug` to inspect routing and handshake failures.

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
    "final_outbound": "direct"
  }
}
```

Snell v6 outbound options use `"version": 6` and optionally
`"mode": "default"`, `"unshaped"`, or `"unsafe-raw"`. Set `"reuse": true`
to pool CONNECT_V2 sessions. Both Snell inbound and outbound accept an `"obfs"`
value of `"http"` or `"tls"` plus an optional `"obfs_host"`.

## Current limitations

- one final outbound route; rule matching and sniffing are not implemented
- no DNS subsystem, TUN endpoint, endpoint registry, or service registry
- no hot reload or connection tracking
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
