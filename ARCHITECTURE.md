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
Inbound -> Session + BoxStream -> Router -> Outbound/Dialer -> BoxStream
                                      |
                                      v
                              bidirectional relay
```

## Stable protocol API

`sing-box-core` owns only transport-neutral contracts:

- `Session`: source, destination, user, inbound and selected outbound metadata
- `ProxyStream` / `BoxStream`: object-safe asynchronous TCP stream
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
2. An outbound implementing `Lifecycle + Dialer + Outbound`.
3. An inbound implementing `Lifecycle + Inbound`, when server support exists.
4. A public `register(&mut Registry)` function.
5. Protocol conformance and end-to-end tests.

Wire logic should remain in a separate reusable library. The adapter should
only translate configuration and connect the library to listeners, dialers,
sessions, routing, logging, and lifecycle management.

## Dependency and lifecycle rules

An outbound declares detours through `dependencies()`. The manager validates
that every dependency exists, rejects cycles, and returns a topological start
order. Shutdown uses the reverse order.

Factories are called before services start. No registry or manager lock is held
while a factory, lifecycle callback, network dial, or relay is awaited.
