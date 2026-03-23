# zinoh

A [Zenoh](https://zenoh.io) client written in Zig 0.16, using async I/O backed by `io_uring`.

## Features

- **Full session lifecycle** — TCP connect, 4-message handshake (InitSyn → InitAck → OpenSyn → OpenAck), Interest/Declare exchange, and graceful close
- **Publish (`put`)** — Send key/value data to the Zenoh network
- **Query (`get`)** — Request data by key expression and collect replies
- **KeepAlive** — Background thread maintains session liveness
- **Codec** — VLE encoding, Zenoh protocol headers, and transport framing
- **Key expressions** — Zenoh key expression matching (wildcards, DSL chunks)

## Requirements

- Zig **0.16.0** (or compatible nightly)
- Linux (uses `io_uring` via `std.Io.Evented`)
- Docker (for integration tests — runs a `zenohd` router container)

## Build & Run

```bash
zig build              # Build the library and executable
zig build run          # Connect to a local Zenoh router at 127.0.0.1:7447
zig build run -- HOST:PORT   # Connect to a custom endpoint
```

The default executable opens a session, publishes `"Hello from zinoh!"` to `demo/example/zinoh-greeting`, queries it back, and closes.

## Tests

```bash
zig build test                # Unit tests (codec, framing, session wire format, key expressions)
zig build integration-test    # Integration tests (requires Docker; auto-starts zenohd)
```

Integration tests manage a `zenohd` Docker container automatically. If Docker is unavailable, they are skipped.

## Benchmarks

```bash
zig build bench               # Run all codec benchmarks
zig build bench -- vle        # Filter by name (e.g. "vle", "encode")
```

## Usage as a Library

Add zinoh as a Zig dependency, then import the module:

```zig
const zinoh = @import("zinoh");

// Open a session
const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x01, 0x02 });
var session = try zinoh.session.Session.open(allocator, io, address, zid);
defer session.deinit();

// Publish
try session.put("my/key", "hello", .{});

// Query
const result = try session.get("my/key", .{});
defer result.deinit(allocator);

for (result.replies) |reply| {
    // reply.key, reply.payload
}

// Close
try session.close(.generic);
```
