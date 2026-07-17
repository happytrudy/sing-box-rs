# Architecture

## Runtime flow

```text
JSON configuration
       |
       v
Registry -- type-erased factory -- protocol-specific typed options
       |
       v
Managers -- dependency validation -- staged lifecycle
       |
       v
Inbound -> Session + BoxStream/PacketConnection -> Router -> Outbound
                                                     |
                                                     v
                                            bidirectional relay
```

## Stable protocol API

`sing-box-core` owns only transport-neutral contracts:

- `Session`: source, destination, user, inbound and selected outbound metadata
- `ProxyStream` / `BoxStream`: object-safe asynchronous TCP stream
- `PacketConnection` / `BoxPacketConnection`: object-safe addressed UDP packets
- `Dialer`: creates a stream for a session
- `Outbound`: a tagged dialer with declared dependencies
- `Inbound`: a tagged lifecycle service with an optional bound address
- `Lifecycle`: initialize, start, post-start, started, and close

Protocol crates depend on this API. The core runtime never depends on a
protocol crate.

## Registry and configuration

The core deliberately does not define a closed Rust enum containing every
protocol configuration. Such an enum would require editing the core whenever a
protocol is added.

Instead, configuration is decoded in two passes:

1. Decode `type`, `tag`, and preserve the remaining JSON object.
2. Look up the factory registered for `type`.
3. Deserialize the remaining object into the factory's concrete option type.
4. Build an `Arc<dyn Inbound>` or `Arc<dyn Outbound>`.

The generic registration methods keep option decoding type-safe while storing
object-safe factories internally.

Configuration source composition happens in the CLI before this typed decode.
`-c` adds a JSON file and `-C` adds the direct `.json` children of a directory;
both flags are repeatable. All paths are sorted together. Objects merge
recursively, arrays append in path order, and an earlier scalar value takes
precedence. Each source may therefore be a partial document, but the final
merged document must satisfy the strict `Config` schema.

## Composition root

`sing-box-cli` creates a registry and explicitly installs modules:

```rust,ignore
let mut registry = Registry::new();
register_builtins(&mut registry)?;
sing_box_protocol_snell::register(&mut registry)?;
sing_box_protocol_hysteria2::register(&mut registry)?;
```

Registration is explicit on purpose. It works on desktop, mobile, and WASM
toolchains without relying on constructors or linker-section discovery.

## Adding a protocol

A new protocol crate normally contains:

1. Serde option types.
2. An outbound implementing `Lifecycle + Dialer + Outbound`, with
   `connect_packet` when it supports UDP.
3. An inbound implementing `Lifecycle + Inbound`, when server support exists.
4. A public `register(&mut Registry)` function.
5. Protocol conformance and end-to-end tests.

Wire logic should remain in a separate reusable library. The adapter should
only translate configuration and connect the library to listeners, dialers,
sessions, routing, logging, and lifecycle management.

## Inbound listen addresses

Every inbound protocol must accept both IPv4 and IPv6 address literals in its
`listen` field. The canonical form keeps the port in `listen_port`, but a full
endpoint such as `listen: "127.0.0.1:443"` or `listen: "[::1]:443"` is also
accepted. Build socket addresses structurally; never concatenate
`host + ":" + port`, since that produces invalid unbracketed IPv6 addresses.

The address meanings are consistent across protocols:

- `0.0.0.0` listens on all IPv4 interfaces only.
- A specific IPv4 address listens on that IPv4 interface only.
- `::` listens on all IPv6 and IPv4 interfaces. This uses one IPv4-mapped IPv6
  socket when supported, otherwise paired IPv6 and IPv4 wildcard sockets.
- `::1` creates both `[::1]:listen_port` and
  `127.0.0.1:listen_port`, covering both local loopback families.
- A specific non-loopback IPv6 address listens on that IPv6 interface only.

Protocol tests should cover the address expansion and, where the platform
supports dual stack, connections through both `127.0.0.1` and `::1`.

## Dependency and lifecycle rules

An outbound declares detours through `dependencies()`. The manager validates
that every dependency exists, rejects cycles, and returns a topological start
order. Shutdown uses the reverse order.

Factories are called before services start. No registry or manager lock is held
while a factory, lifecycle callback, network dial, or relay is awaited.

## Shared services

DNS wire logic, UDP transport, address-family strategy, and caching live in
the sibling `sing-dns-rs` project. `sing-box-core` defines only the
`DomainResolver` interface and injects it into outbound build contexts. Direct,
Snell, and Hysteria2 therefore share configured DNS without depending on its
implementation.

Route rules are compiled after outbounds and the initial rule-set snapshots are
loaded, but before inbounds are built. Non-final `route-options` actions mutate
the session and continue matching; `route` and `reject` actions terminate rule
evaluation.

### Inbound source policy contract

Source-address policy belongs to `sing-box-core`, not to protocol packages.
This is a mandatory contract for every current and future inbound:

1. The protocol creates every routable TCP stream and UDP session with
   `Session::inbound`. It passes the real transport peer socket address, its
   configured inbound tag, network type, destination, protocol type, and
   authenticated user when available. A multiplexed protocol propagates the
   outer transport peer to every accepted child stream or packet session.
2. The protocol must not substitute a forwarded header, requested destination,
   local listener address, or authenticated user address for the transport
   peer. Trusted-proxy address replacement requires a separate explicit core
   policy if it is added later.
3. The protocol must not normalize, match, cache, or enforce source IP rules.
   It only reports metadata. `Router::select` normalizes IPv4-mapped IPv6 and
   performs all `source_ip_cidr` and rule-set evaluation.
4. Route-rule conditions are conjunctive. A whitelist route containing both
   `inbound` and `rule_set` matches only when the session tag is listed and the
   source matches that rule-set. Tags not listed by the route rule are
   unaffected. This behavior is identical for TCP and UDP.
5. A protected tag uses an allow rule followed immediately by a reject rule.
   Both must precede broader terminal rules such as a global port 53 route.
   Rule evaluation is ordered and stops at the first `route` or `reject`.

An official source-format empty whitelist is represented by `"rules": []`.
It matches no client. Do not encode an empty whitelist as a condition with an
empty value such as `{"source_ip_cidr": []}`; condition-level empty-list
semantics are not a portable representation between sing-box versions.

The required fail-closed shape is:

```json
{
  "rules": [
    {
      "inbound": ["protected-in"],
      "rule_set": ["client-whitelist"],
      "action": "route",
      "outbound": "direct"
    },
    {
      "inbound": ["protected-in"],
      "action": "reject",
      "method": "drop"
    }
  ],
  "final": "direct"
}
```

Rule-set storage uses immutable compiled snapshots behind a short-lived read
lock. Local watchers and remote updaters fully decode and compile the next
source before swapping the snapshot, so routing never observes a partially
loaded rule-set and failed updates preserve the last valid version. Remote
transport is injected through the core `RuleSetFetcher` interface; HTTP, TLS,
redirect, and ETag handling stays in the CLI composition layer.

The binary decoder implements the official `SRS` header, zlib payload, domain
succinct-set, IP range-set, default-rule, and logical-rule layouts. It returns
an explicit error for item types that the current `Session` model cannot match
correctly instead of dropping those constraints.

## Certificate providers

Certificate providers are shared services owned by `sing-box-core`, never by a
specific protocol. The core defines `CertificateProvider`, its typed factory
registry, tag-indexed manager, lifecycle ordering, and certificate update
subscription. Provider implementations such as ACME live at the composition
layer and protocols only consume `Arc<Certificate>` snapshots.

Both `InboundBuildContext` and `OutboundBuildContext` expose the same
`CertificateProviderManager`. Any current or future component that needs a
server certificate must accept a `certificate_provider` tag, resolve it through
that manager, and subscribe to updates. It must not implement ACME, DNS API,
certificate persistence, or renewal inside the protocol crate.

Providers start at every lifecycle stage before outbounds and inbounds. During
shutdown, certificate consumers close first and providers close last. A
provider publishes a complete certificate chain and matching private key as one
snapshot; consumers apply the new snapshot to future handshakes while existing
connections continue normally.
