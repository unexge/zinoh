# Zenoh Protocol Basics: Client → Router over TCP

This document describes the minimal Zenoh protocol exchange for a **client** connecting
to a **router** at a fixed TCP address, publishing a value (`put`), and reading a value
(`get`). No scouting, discovery, or gossip is involved.

> **Source of truth**: This document is derived from the zenoh-pico codebase and the
> Zenoh protocol version **0x09**.

---

## Table of Contents

1. [TCP Framing](#1-tcp-framing)
2. [Encoding Primitives](#2-encoding-primitives)
3. [Message Header Format](#3-message-header-format)
4. [Session Establishment (4-Message Handshake)](#4-session-establishment-4-message-handshake)
5. [Interest and Declare Exchange](#5-interest-and-declare-exchange)
6. [Steady-State: KeepAlive](#6-steady-state-keepalive)
7. [Publishing a Value (Put)](#7-publishing-a-value-put)
8. [Reading a Value (Get / Query)](#8-reading-a-value-get--query)
9. [Closing the Session](#9-closing-the-session)
10. [Full Wire Sequence Example](#10-full-wire-sequence-example)

---

## 1. TCP Framing

TCP is stream-oriented — it delivers a continuous byte stream with no inherent message
boundaries. To recover individual messages the receiver needs to know where one ends
and the next begins. Zenoh solves this with a simple length-prefix scheme: every
message on the wire is preceded by a **2-byte little-endian length** indicating the
number of payload bytes that follow:

```
+-------+-------+=========================+
| len_L | len_H |     Zenoh Message       |
+-------+-------+=========================+
   2 bytes (LE)         len bytes
```

A 2-byte length field gives a maximum payload of **65,535 bytes**, which is sufficient
for a single Zenoh "batch" — the unit of data that fits in one TCP write. Messages
larger than this must be split across multiple batches using the FRAGMENT transport
message (§6 in the full spec). Using a fixed 2-byte prefix rather than a variable-
length one keeps the framing logic trivial: the receiver always reads exactly 2 bytes,
interprets them as a little-endian u16, then reads that many payload bytes. There is
no ambiguity or back-tracking.

This framing applies to **every** transport message described below — Init, Open,
KeepAlive, Close, Frame, and Fragment all appear on the wire wrapped in this
length-prefixed envelope.

> Defined in zenoh-pico as `_Z_MSG_LEN_ENC_SIZE = 2`.

> **zinoh**: [`src/transport/framing.zig`](../src/transport/framing.zig) —
> `writeFrame()`, `readFrame()`, `readFrameAlloc()`, `max_frame_size`.
> [`src/transport/tcp.zig`](../src/transport/tcp.zig) — `TcpTransport` wraps
> framing with a TCP stream. `Session` in `src/session.zig` uses framing
> directly on its own persistent `stream_reader`.

---

## 2. Encoding Primitives

Zenoh uses a small set of encoding primitives throughout the protocol. These building
blocks appear in every message — header fields, lengths, identifiers, key expressions,
cookies, and payloads are all encoded with the types described here.

> **zinoh**: [`src/codec/vle.zig`](../src/codec/vle.zig) (VLE integers),
> [`src/codec/primitives.zig`](../src/codec/primitives.zig) (uint16 LE, slices, strings).

### VLE Integers (Variable-Length Encoding)

Most integer fields use VLE, similar to protobuf varints. The motivation is
**compactness**: the majority of integer values in Zenoh are small (sequence numbers
starting at 0, key scope IDs in the low range, short payload lengths). VLE encodes
these in 1 byte while still supporting the full u64 range for the rare cases that
need it.
The encoding rules:

- Each byte contributes **7 data bits** (bits 0–6).
- **Bit 7** is the continuation flag: `1` = more bytes follow, `0` = last byte.
- The **9th byte** (if reached) uses all 8 data bits with no continuation flag. This
  special case allows a full 64-bit value (7×8 + 8 = 64 bits) to be encoded in at
  most 9 bytes.

> **zinoh**: [`src/codec/vle.zig`](../src/codec/vle.zig) — `encode()`, `decode()`,
> `encodedSize()`, `encodeToSlice()`.

Examples:
| Value   | Encoded (hex) |
|---------|---------------|
| 0       | `00`          |
| 10      | `0A`          |
| 127     | `7F`          |
| 128     | `80 01`       |
| 10000   | `90 4E`       |

### uint16 (Little-Endian)

A handful of fields use a **fixed 2-byte little-endian** encoding instead of VLE.
These are fields where the fixed size is either required by the framing layer (the
TCP length prefix) or where the value range is bounded and a constant-size encoding
simplifies parsing (e.g., `batch_size` in Init messages). The trade-off is
straightforward: 2 bytes always, regardless of value.

> **zinoh**: [`src/codec/primitives.zig`](../src/codec/primitives.zig) —
> `writeUint16LE()`, `readUint16LE()`.

### Slices / Byte Arrays

Byte slices are encoded as a **VLE length prefix** followed by the raw bytes. This
is used for opaque binary data: cookies, payloads, ZenohID bytes, etc.

```
%  length (VLE)  %
+----------------+
~   raw bytes    ~
+----------------+
```

The VLE prefix means a short payload like a 5-byte cookie costs only 1 + 5 = 6 bytes
on the wire, while a 64 KB payload costs 3 + 65535 bytes (VLE of 65535 is 3 bytes).

> **zinoh**: [`src/codec/primitives.zig`](../src/codec/primitives.zig) —
> `writeSlice()`, `readSlice()`.

### Strings

Strings are encoded the same as slices: VLE length + UTF-8 bytes. On the wire they
are indistinguishable from slices — the protocol does not validate UTF-8. The
distinction is purely semantic: fields documented as "string" carry human-readable
key expressions, selector parameters, or schema identifiers.

> **zinoh**: [`src/codec/primitives.zig`](../src/codec/primitives.zig) —
> `writeString()`, `readString()` (same wire format as slices).

---

## 3. Message Header Format

Every transport and network message starts with a **1-byte header**. This single byte
carries both the message type and up to 3 flag bits, keeping the overhead minimal (one
byte of framing per message, plus the 2-byte TCP length prefix).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|  Flags  | MID |
+-+-+-+-+-+-+-+-+
```

- **Bits 0–4** (`MID`): Message ID, masked with `0x1F`. Five bits allow up to 32
  distinct message types per protocol layer.
- **Bits 5–7** (`Flags`): Three flag bits whose meaning depends on the message type.
  Common conventions:
  - **Bit 5**: `A` (Ack) for Init/Open, `R` (Reliable) for Frame, `S` (Session) for Close,
    `N` (Name/suffix) for network messages, `T` (Timestamp) for Zenoh messages.
  - **Bit 6**: `S` (Size params) for Init, `T` (Time-in-seconds) for Open,
    `M` (Mapping) for network messages, `E` (Encoding) or `P` (Parameters) for Zenoh.
  - **Bit 7**: `Z` (Extensions present) — universally used across all message types.
    When set, one or more TLV-style extensions follow the message body.

**MID overlap**: The same numeric MID can appear at different protocol layers. For
example, transport Init and Zenoh Put are both `0x01`. This is safe because the
layers are nested: you always know which layer you are parsing based on context.
A transport Frame header is always first; inside it is a network header; inside that
is a Zenoh header. The layer context disambiguates the MID.

**Extension mechanism**: The Z flag enables forward-compatible evolution. A newer
protocol version can attach extensions to any message. Older implementations that
don't recognize an extension skip it (each extension header encodes its encoding
type and a "more" bit). This avoids hard version bumps for incremental features
like the `patch` extension on Init.

> **zinoh**: [`src/codec/header.zig`](../src/codec/header.zig) — `Header` struct,
> `TransportMid`, `NetworkMid`, `ZenohMid`, `DeclareMid`.

---

## 4. Session Establishment (4-Message Handshake)

Before any data can flow, the client and router establish a **session** through a
4-message handshake. This is deliberately modeled after the TCP SYN/ACK pattern, split
into two phases:

1. **Init** (messages 1–2): The two sides exchange identities, capabilities, and
   negotiate parameters. The router returns an opaque **cookie** that acts as a
   session token — it lets the router remain stateless during the Init phase
   (it doesn't have to allocate session state until the cookie comes back).

2. **Open** (messages 3–4): The client echoes the cookie to prove it received the
   InitAck, and both sides exchange their starting sequence numbers and lease
   durations. After the OpenAck, the session is established.

The split into Init + Open (rather than a single 2-message exchange) serves two
purposes: **parameter negotiation** (the client proposes, the router responds with
values ≤ the proposal) and **cookie-based anti-replay** (the router can validate
the cookie in the OpenSyn to confirm this is the same peer from the Init phase).

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) — `InitSyn`,
> `InitAck`, `OpenSyn`, `OpenAck`, `WhatAmI`, `Resolution`, `ZenohId`.
> [`src/session.zig`](../src/session.zig) — `Session.performHandshake()`.

```
  Client                                    Router
    |                                         |
    |  ─── TCP Connect ──────────────────→    |
    |                                         |
    |  ─── [1] InitSyn ─────────────────→    |
    |                                         |
    |  ←── [2] InitAck ──────────────────    |
    |                                         |
    |  ─── [3] OpenSyn ─────────────────→    |
    |                                         |
    |  ←── [4] OpenAck ──────────────────    |
    |                                         |
    |         === Session Established ===     |
```

### Message 1: InitSyn (Client → Router)

**MID** = `0x01` (INIT), **A flag** = 0 (Syn).

The client announces itself: protocol version, role (client/peer/router), unique
ZenohID, and optionally its preferred wire parameters. The MID is shared between Syn
and Ack — the **A flag** (bit 5) distinguishes them.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `InitSyn.encode()`, `InitSyn.decode()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|S|0|  0x01   |   S=1 if non-default size params; Z=1 if extensions present
+-+-+-+---------+
|  version=0x09 |
+---------------+
|zid_len|x|x|wai|   wai = WhatAmI: 0b10=Client; zid_len = (real_len - 1)
+-------+-+-+---+
~   ZenohID     ~   Client's unique ID (1–16 bytes)
+---------------+
                    ── if S=1 ──
|x|x|kid|rid|fsn|   Resolution byte:
+---------------+     fsn: frame SN resolution (0b00=8b, 0b01=16b, 0b10=32b, 0b11=64b)
|  batch_size   |     rid: request ID resolution
|  (uint16 LE)  |     kid: key expression ID resolution
+---------------+     batch_size: max batch size in bytes
                    ── if Z=1 ──
~  [Extensions] ~   e.g. Patch extension (ext ID=0x27, VLE value)
+---------------+
```

**Typical zenoh-pico values:**
- `version` = `0x09` — protocol version. Both sides must agree; a mismatch aborts
  the handshake.
- `whatami` = Client (`0b10`) — the role tells the router how to treat this peer.
  Clients receive a subset of the routing behavior (no peer-to-peer forwarding).
  Possible values: Router (`0b00`), Peer (`0b01`), Client (`0b10`).
- `seq_num_res` = `0x02` (32-bit) — how many VLE bytes to use for frame sequence
  numbers. 32-bit means 4 VLE bytes → 28 data bits → SN range [0, 2²⁸). This
  controls the wrap-around point for reliability tracking.
- `req_id_res` = `0x02` (32-bit) — same concept for request IDs in Get/Query.
- `batch_size` = `2048` (zenoh-pico default) — the maximum number of bytes the
  client can receive in a single TCP-framed batch. The router will not send batches
  larger than this. Constrained devices use a small value to limit buffer allocation.
- `patch` = `1` — a sub-version indicator carried as a Z-flag extension. Allows
  incremental protocol changes (like interest-based routing) without bumping the
  major version.

The **S flag** is set because `batch_size` (2048) differs from the protocol default (65535).
When S=0, both sides assume default resolution (all 32-bit) and batch_size (65535).

### Message 2: InitAck (Router → Client)

**MID** = `0x01` (INIT), **A flag** = 1 (Ack).

The router responds with its own identity and the **negotiated** parameters. The
key rule is that every negotiated value must be **≤** the client's proposal — the
router cannot demand more resources than the client offered. If the client proposed
`batch_size=2048`, the router may accept 2048 or lower it to 1024, but never raise it
to 4096.

The InitAck also carries an opaque **cookie**. The router generates this cookie (it
can encode whatever internal state it needs — session ID, timestamp, cryptographic
MAC) and the client must echo it back verbatim in the OpenSyn. This lets the router
defer session-state allocation until it verifies the cookie, preventing resource
exhaustion from half-open connections (analogous to TCP SYN cookies).

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `InitAck.encode()`, `InitAck.decodeAlloc()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|S|1|  0x01   |   A=1 → this is the Ack
+-+-+-+---------+
|  version=0x09 |
+---------------+
|zid_len|x|x|wai|   wai = 0b00=Router
+-------+-+-+---+
~   ZenohID     ~   Router's unique ID
+---------------+
                    ── if S=1 ──
|x|x|kid|rid|fsn|   Negotiated resolutions (must be ≤ InitSyn values)
+---------------+
|  batch_size   |   Negotiated batch size (must be ≤ InitSyn value)
|  (uint16 LE)  |
+---------------+
~    Cookie     ~   Opaque cookie (VLE-length-prefixed bytes)
+---------------+
~  [Extensions] ~   if Z=1
+---------------+
```

**Negotiation rules:** All parameters in the Ack must be **≤** the Syn's values.
The client must echo the **cookie** back in the OpenSyn. If any negotiated value
is unacceptable, the client may abort the connection rather than proceed with
degraded parameters.

### Message 3: OpenSyn (Client → Router)

**MID** = `0x02` (OPEN), **A flag** = 0 (Syn).

The client commits to the session: it echoes the cookie (proving it received the
InitAck), declares its **lease** duration, and announces its starting **sequence
number**. The lease is the maximum time the router should wait between messages
before declaring the session dead. The initial SN is randomized within the
negotiated resolution range to avoid predictable sequence numbers across sessions.

The **T flag** (bit 6) controls the lease unit: T=1 means the lease value is in
seconds, T=0 means milliseconds. Seconds are typical for production (lease=10 means
10s), while milliseconds offer finer granularity for testing or low-latency scenarios.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `OpenSyn.encode()`, `OpenSyn.decodeAlloc()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|T|0|  0x02   |   T=1 if lease is in seconds (vs milliseconds)
+-+-+-+---------+
%     lease     %   VLE: lease period (e.g. 10 with T=1 means 10 seconds)
+---------------+
%  initial_sn   %   VLE: client's starting TX sequence number (random)
+---------------+
~    Cookie     ~   VLE-length-prefixed: exact cookie from InitAck
+---------------+
```

### Message 4: OpenAck (Router → Client)

**MID** = `0x02` (OPEN), **A flag** = 1 (Ack).

The router confirms the session is open. It sends its own lease and starting SN.
After this message, both sides have everything they need for steady-state operation:

- **Lease**: Each side knows the other's heartbeat expectation. The effective lease
  is typically the minimum of the two values. If no message arrives within the lease
  period, the session is considered dead.
- **Starting SN**: Each side knows where the other's sequence numbering begins, which
  is needed to detect gaps and duplicates in the reliable channel.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `OpenAck.encode()`, `OpenAck.decode()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|T|1|  0x02   |   A=1 → Ack; T=1 if lease in seconds
+-+-+-+---------+
%     lease     %   VLE: router's lease period
+---------------+
%  initial_sn   %   VLE: router's starting TX sequence number
+---------------+
```

No cookie in the Ack. Session is now established:
- **Lease** = each side independently enforces the other's advertised lease.
- Each side knows the other's starting SN for reliability tracking.

After the OpenAck, the session transitions to the **open** state and proceeds to
the interest/declare exchange (§5).

---

## 5. Interest and Declare Exchange

After the 4-message handshake, the router and client exchange **Interest** and
**Declare** messages before data can flow. This is Zenoh 1.x's **interest-based
routing** (introduced at patch level ≥ 1): the router only forwards Push/Request
messages to a peer when it knows what that peer cares about.

**Why this exists**: Without interest-based routing, the router would have to flood
every published message to every connected client, regardless of whether the client
has a matching subscriber. The Interest/Declare exchange builds a routing table:
the router learns what each client publishes and subscribes to, and only forwards
matching traffic. This is especially important in large deployments with many
publishers and few subscribers per key expression.

**Ordering guarantee**: The router sends its Interest *before* the first KeepAlive.
If the first transport message after OpenAck is a KeepAlive rather than an Interest,
the router is at patch level 0 and does not use interest-based routing — the client
can skip this exchange entirely.

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) — `Interest`,
> `Declare`, `DeclareFinal`. [`src/session.zig`](../src/session.zig) —
> `Session.performInterestDeclare()`, `Session.encodeDeclareResponse()`.

```
  Client                                    Router
    |         === Session Established ===     |
    |                                         |
    |  ←── Frame[Interest(C+F)] ──────────   |  Router: "tell me your declarations"
    |                                         |
    |  ─── Frame[Declare(DeclareFinal)] ──→   |  Client: "I have nothing (for now)"
    |                                         |
    |  ←── Frame[Declare(DeclareSubscriber)]  |  Router: "I have a subscriber on demo/**"
    |  ←── Frame[Declare(DeclareFinal)] ────  |  Router: "end of my declarations"
    |                                         |
    |         === Data Can Flow ===           |
```

> **Minimal client implementation**: A client that only publishes and queries can
> respond to the router's Interest with a single `Declare(DeclareFinal)` message.
> This tells the router "I have no resources to declare right now" and unblocks
> the routing pipeline.

### Interest (MID = `0x19`)

The router sends an Interest message to ask the client about its declarations. The
**C flag** (current) means "tell me what you have right now" and the **F flag** (future)
means "also tell me whenever you declare something new later." A typical router
Interest has both C=1 and F=1, effectively subscribing to all declaration changes
for the lifetime of the session.

The **interest flags byte** (present when C or F is set) specifies *which kinds* of
declarations the router cares about: Key expressions (K), Subscribers (S),
Queryables (Q), and Tokens (T). The R (Restricted) flag optionally narrows the scope
to a specific key expression (e.g., "only tell me about subscribers on `demo/**`").

When C=0 and F=0, the Interest is a **final** (undeclare) — it cancels a previously
expressed interest. No flags byte follows in that case.

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `Interest.decode()`, `Interest.Flags`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|F|C|  0x19   |   C=1: current declarations; F=1: future declarations
+-+-+-+---------+
~    id:z32     ~   VLE: interest identifier
+---------------+
                    ── if C or F is set (not a final) ──
|A|M|N|R|T|Q|S|K|   Interest flags byte:
+---------------+     K=KeyExprs, S=Subscribers, Q=Queryables, T=Tokens
                      R=Restricted, N=has suffix, M=Mapping, A=Aggregate
~ key_scope:z16 ~     (only if R=1)
+---------------+
~  key_suffix   ~   if R=1 && N=1
+---------------+
```

**Typical router Interest**: The router sends Interest with C=1 (current) and F=1
(future), asking the client to declare all its resources. The interest flags byte
typically has K=1, S=1, Q=1, T=1 (interested in everything).

### Declare (MID = `0x1E`)

The client responds with Declare messages, each carrying a single declaration. The
**I flag** (bit 5) indicates this Declare is a response to a specific Interest — the
`interest_id` field echoes back the Interest's `id`, linking the response to the
request. This allows multiple concurrent interests to be in flight.

The inner `Declaration` sub-message varies by type: DeclareKeyExpr, DeclareSubscriber,
DeclareQueryable, DeclareToken, or DeclareFinal. Each has its own sub-MID within
the Declare body.

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `Declare.encodeHeader()`, `Declare.decodeHeader()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|I|  0x1E   |   I=1: this is a response to an interest (interest_id follows)
+-+-+-+---------+
~ interest_id   ~   if I=1: VLE (z32) — echoes back the Interest's id
+---------------+
~ Declaration   ~   Inner declaration sub-message (see below)
+---------------+
```

### DeclareFinal (Declaration sub-MID = `0x1A`)

Marks the end of a declaration batch. This is the minimum a client must send in
response to an Interest — even if the client has nothing to declare, it must send
a DeclareFinal to unblock the router's routing pipeline. Without it, the router
would wait indefinitely for the client to finish declaring.

Both sides send DeclareFinal: the client sends it after declaring its resources
(or immediately if it has none), and the router sends it after declaring its own
resources (like storage subscribers). The exchange is not complete until both
DeclareFinals have been seen.

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `DeclareFinal.encode()`, `DeclareFinal.decode()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x1A   |
+-+-+-+---------+
```

### Minimal Exchange for Put/Get

For a client that just wants to `put()` and `get()`:

1. **Receive** the router's `Interest(id=N, C=1, F=1, flags=0xFF)` — "tell me everything"
2. **Send** `Frame(sn) → Declare(I=1, interest_id=N) → DeclareFinal` — "I have nothing"
3. **Receive** the router's own `Declare` messages (its subscribers, queryables, etc.)
4. **Receive** the router's `Declare(DeclareFinal)` — "end of my declarations"
5. Now `put()` and `get()` will be routed correctly

---

## 6. Steady-State: KeepAlive

Once the session is open, both sides must prove they are still alive by sending
messages within the negotiated **lease** period. If a side has actual data to send
(Puts, Queries, etc.), those messages implicitly reset the lease timer. KeepAlive
is only needed during **idle** periods when no other traffic is flowing.

**MID** = `0x04` (KEEP_ALIVE)

The conventional sending interval is `lease / 3`, providing a safety margin: even
if one KeepAlive is lost or delayed, there is time for two more before the lease
expires. For a 10-second lease, KeepAlives are sent approximately every 3.3 seconds.

If a side does not receive *any* message (data or KeepAlive) from its peer within
the full lease duration, it should consider the session dead and close it.
KeepAlive is bidirectional — both client and router must send them.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `KeepAlive.encode()`, `KeepAlive.decode()`.
> [`src/session.zig`](../src/session.zig) — `Session.startKeepAlive()` spawns a
> background thread running `keepAliveLoop()`. `Session.isLeaseExpired()` checks
> the remote side's liveness.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|0|0|0|  0x04   |
+-+-+-+---------+
```

That's it — just a 1-byte message body (plus the 2-byte TCP length prefix, so 3 bytes
total on the wire). Sent roughly every `lease / 3` interval.

---

## 7. Publishing a Value (Put)

A `z_put(session, "demo/example/hello", "Hello World!")` results in a single
TCP-framed message that contains **three nested protocol layers**. This nesting
reflects Zenoh's layered architecture:

- **Transport layer** (Frame): handles reliability and ordering via sequence numbers.
  A Frame can carry one or more network messages in a single batch.
- **Network layer** (Push): handles routing — identifies the key expression and
  delivers data to matching subscribers. Push is pub/sub (fire-and-forget);
  Request/Response is query/reply.
- **Zenoh layer** (Put): carries the application data — payload bytes plus
  optional metadata (timestamp, encoding).

This separation means the transport layer doesn't need to know about key expressions,
the network layer doesn't need to know about encoding formats, and the Zenoh layer
doesn't need to know about sequence numbers or reliability.

> **zinoh**: [`src/session.zig`](../src/session.zig) — `Session.put()`,
> `Session.encodePutMessage()`. Composed from `Frame`
> ([`src/transport/messages.zig`](../src/transport/messages.zig)), `Push`
> ([`src/network/messages.zig`](../src/network/messages.zig)), and `Put`
> ([`src/zenoh/messages.zig`](../src/zenoh/messages.zig)). Key expressions are
> also modeled in [`src/network/key_expr.zig`](../src/network/key_expr.zig).

### Wire Structure: Frame → Push → Put

The **Put** is a Zenoh message (`Put`), wrapped in a **network Push** message, wrapped
in a **transport Frame** message:

```
[2-byte TCP length prefix]
[Frame header + SN]
  └─ [Push header + key expression]
       └─ [Put header + encoding + payload]
```

#### Transport Layer: Frame (MID = `0x05`)

Frame wraps one or more network-layer messages with a **sequence number** for
reliability tracking. The **R flag** (bit 5) marks the channel: R=1 for the reliable
channel (ordered, lossless), R=0 for best-effort. Put uses the reliable channel.

The sequence number increments with each Frame sent and wraps according to the
negotiated resolution (e.g., modulo 2²⁸ for 32-bit resolution). The receiver uses
it to detect gaps (lost messages) and duplicates.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `Frame.encodeHeader()`, `Frame.decodeHeader()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|0|0|R|  0x05   |   R=1 for reliable
+-+-+-+---------+
%    seq_num    %   VLE: incrementing sequence number
+---------------+
~ [NetworkMsg]+ ~   One or more network messages follow
+---------------+
```

#### Network Layer: Push (MID = `0x1D`)

Push delivers pub/sub data. It identifies the target **key expression** — the
hierarchical name that subscribers match against (e.g., `demo/example/hello`).

Key expressions have two parts: a numeric **scope** (a pre-declared short ID) and
an optional string **suffix**. For simple clients that don't pre-declare key
expressions, `scope=0` and the full key is sent as the suffix. Pre-declaration
(via DeclareKeyExpr) allows a client to assign a numeric ID to a frequently-used
key, reducing per-message overhead.

The **N flag** (bit 5) indicates a string suffix is present. The **M flag** (bit 6)
indicates whether the scope ID is from the sender's mapping table (M=1) or the
receiver's (M=0). For a client talking to a router, M=0 is typical.

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `Push.encodeHeader()`, `Push.decodeHeader()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1D   |   N=1 if key has string suffix; M=1 if sender's mapping
+-+-+-+---------+
~ key_scope:z16 ~   VLE: key expression numeric ID (0 if none declared)
+---------------+
~  key_suffix   ~   if N=1: string suffix (VLE-length + UTF-8)
+---------------+
~  [push_exts]  ~   if Z=1: QoS, Timestamp extensions
+---------------+
~ ZenohMessage  ~   The inner Put or Del message
+---------------+
```

For `z_put(session, "demo/example/hello", ...)`:
- `key_scope` = 0 (no pre-declared key expression)
- `key_suffix` = `"demo/example/hello"`

#### Zenoh Layer: Put (MID = `0x01`)

The Put message carries the actual data. Its fields are all optional (controlled
by flags), keeping the minimal case compact:

- **Timestamp** (T flag, bit 5): An NTP64 time + ZenohID identifying who and when
  the value was produced. Used by storages and merge logic to resolve conflicts.
  Absent for simple publishes without causality tracking.
- **Encoding** (E flag, bit 6): A numeric encoding ID (e.g., 0 = raw bytes,
  10 = application/json) plus an optional schema string. Tells the receiver how
  to interpret the payload. The encoding ID is packed as `(id << 1) | has_schema`
  in a single VLE value — if has_schema=1, a VLE-length-prefixed schema string follows.
- **Payload**: Always present. VLE-length-prefixed raw bytes.

A minimal Put with no timestamp and no encoding is just 2 bytes of overhead
(1 header + 1 VLE length) plus the payload itself.

> **zinoh**: [`src/zenoh/messages.zig`](../src/zenoh/messages.zig) — `Put.encode()`,
> `Put.decode()`, `Timestamp`, `Encoding`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|E|T|  0x01   |   T=1 if timestamp present; E=1 if encoding present
+-+-+-+---------+
~ timestamp     ~   if T=1: VLE time + ZenohID
+---------------+
~ encoding      ~   if E=1: VLE encoding ID (+ optional schema string)
+---------------+
~  [put_exts]   ~   if Z=1: source_info, attachment extensions
+---------------+
~ payload       ~   VLE-length-prefixed payload bytes ("Hello World!")
+---------------+
```

### Concrete Example

Publishing `"Hello World!"` to `"demo/example/hello"` with default options:

```
On the wire (inside TCP length frame):
  Frame:  header=0x25 (reliable), sn=<VLE>
    Push: header=0x3D (N=1, M=0), scope=0x00, suffix="demo/example/hello"
      Put: header=0x01, payload=<12 bytes: "Hello World!">
```

---

## 8. Reading a Value (Get / Query)

A `z_get(session, "demo/example/hello", ...)` sends a **Request(Query)** and receives
one or more **Response(Reply)** messages followed by a **ResponseFinal**. Unlike Put
(which is fire-and-forget pub/sub), Get is a **request-response** pattern — the client
expects replies and needs to correlate them with its original request.

**Why multiple replies?** A single Get can match multiple storages or queryables in
the Zenoh network. For example, if two storages both hold data for `demo/example/**`,
a query for `demo/example/hello` may receive a Reply from each. The ResponseFinal
message signals "no more replies are coming" so the client knows when to stop waiting.

**Request ID**: Each Request carries a unique `request_id` (VLE). Every Response and
ResponseFinal echoes this ID back, allowing the client to demux replies when multiple
Gets are in flight concurrently.

> **zinoh**: [`src/session.zig`](../src/session.zig) — `Session.get()`,
> `Session.encodeGetMessage()`. Message types: `Request`, `Response`, `ResponseFinal`
> ([`src/network/messages.zig`](../src/network/messages.zig)); `Query`, `Reply`,
> `ReplyBody`, `Err` ([`src/zenoh/messages.zig`](../src/zenoh/messages.zig)).

### Request Flow

```
  Client                                    Router
    |                                         |
    |  ─── Frame[Request(Query)] ────────→    |  (client asks)
    |                                         |
    |  ←── Frame[Response(Reply(Put))] ───    |  (router replies with data)
    |  ←── Frame[ResponseFinal] ──────────    |  (router says "no more replies")
    |                                         |
```

### Outgoing: Frame → Request → Query

#### Network Layer: Request (MID = `0x1C`)

Request is the network-layer envelope for query operations. It carries the
`request_id` for reply correlation, the key expression for routing, and wraps
an inner Zenoh message (Query, or in other use cases, RequestPut/RequestDel).

The key expression fields (scope, suffix, N/M flags) work identically to Push.

Extensions can carry QoS priority, a timestamp, a **target** selector (e.g.,
`BEST_MATCHING` vs `ALL` vs `ALL_COMPLETE`), a reply **budget** (max number of
replies), and a **timeout** (how long the router should wait for queryable replies).

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `Request.encodeHeader()`, `Request.decodeHeader()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1C   |   N=1 if key has suffix; M=1 if sender's mapping
+-+-+-+---------+
~ request_id:z32~   VLE: unique request ID
+---------------+
~ key_scope:z16 ~   VLE: key expression numeric ID
+---------------+
~  key_suffix   ~   if N=1: string suffix
+---------------+
~  [req_exts]   ~   if Z=1: QoS(0x01), Timestamp(0x02), Target(0x04),
+---------------+           Budget(0x05), Timeout(0x06) extensions
~ ZenohMessage  ~   The inner Query message
+---------------+
```

#### Zenoh Layer: Query (MID = `0x03`)

Query carries the selector details for a Get. It has two optional fields:

- **Consolidation** (C flag, bit 5): Controls how the router merges replies from
  multiple sources. Values: `AUTO` (router decides), `NONE` (send everything),
  `MONOTONIC` (deduplicate by key), `LATEST` (only newest per key).
- **Parameters** (P flag, bit 6): A UTF-8 string with additional selector parameters,
  similar to URL query parameters (e.g., `"time>now()-1h&limit=10"`). These are
  forwarded to queryables, which can use them to filter or paginate results.

A minimal query for a simple Get has neither consolidation nor parameters — just a
1-byte header (`0x03`).

> **zinoh**: [`src/zenoh/messages.zig`](../src/zenoh/messages.zig) — `Query.encode()`,
> `Query.decode()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|P|C|  0x03   |   C=1 if consolidation present; P=1 if parameters present
+-+-+-+---------+
~ consolidation ~   if C=1: 1 byte
+---------------+
~   parameters  ~   if P=1: VLE-length-prefixed UTF-8 (selector parameters)
+---------------+
~  [qry_exts]   ~   if Z=1: source_info(0x01), body/value(0x03), attachment(0x05)
+---------------+
```

### Incoming: Frame → Response → Reply → Put

#### Network Layer: Response (MID = `0x1B`)

Response is the network-layer envelope for replies. It echoes the `request_id` so
the client can correlate it with the original Request. Each Response carries its
own key expression — the reply's key may differ from the request's key (e.g., a
query for `demo/**` may produce replies for `demo/a`, `demo/b`, etc.).

The inner Zenoh message is either a **Reply** (success, containing a Put or Del)
or an **Err** (failure, containing an error payload with optional encoding).

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `Response.encodeHeader()`, `Response.decodeHeader()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1B   |
+-+-+-+---------+
~ request_id    ~   VLE: echoes back the request ID
+---------------+
~ key_scope:z16 ~   VLE: key expression ID
+---------------+
~  key_suffix   ~   if N=1
+---------------+
~  [resp_exts]  ~   if Z=1: QoS(0x01), Timestamp(0x02), Responder(0x03)
+---------------+
~ ZenohMessage  ~   Reply or Err message
+---------------+
```

#### Zenoh Layer: Reply (MID = `0x04`)

Reply wraps the actual data in a response. Its body is a **ReplyBody** — either a
`Put` (the key has a value) or a `Del` (the key was deleted). The Put inside a Reply
uses exactly the same format as a standalone Put (§7), making the encoding logic
reusable.

The optional **consolidation** byte mirrors the Query's consolidation field and
can indicate how this particular reply was consolidated.

> **zinoh**: [`src/zenoh/messages.zig`](../src/zenoh/messages.zig) — `Reply.encode()`,
> `Reply.decode()`, `ReplyBody`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|C|  0x04   |   C=1 if consolidation present
+-+-+-+---------+
~ consolidation ~   if C=1: 1 byte
+---------------+
~ ReplyBody     ~   A Put or Del message (same format as in Push)
+---------------+
```

The ReplyBody contains a **Put** message with the actual data.

#### Network Layer: ResponseFinal (MID = `0x1A`)

ResponseFinal signals "no more replies for this request." Without it, the client
would have no way to distinguish "the router is still collecting replies" from
"all replies have been sent." The `request_id` links it to the original Request.

After receiving a ResponseFinal, the client can free any state associated with the
request (pending callbacks, reply buffers, timeout timers).

Note: ResponseFinal has the same numeric MID as DeclareFinal (`0x1A`), but they
appear at different nesting levels — ResponseFinal is a network message (inside a
Frame), while DeclareFinal is a declaration sub-message (inside a Declare).

> **zinoh**: [`src/network/messages.zig`](../src/network/messages.zig) —
> `ResponseFinal.encode()`, `ResponseFinal.decode()`.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|0|0|  0x1A   |
+-+-+-+---------+
~ request_id    ~   VLE: same request ID
+---------------+
```

This signals "no more replies for this request."

---

## 9. Closing the Session

Either side can close the session by sending a Close message. This is a graceful
shutdown — it tells the peer "I'm done, please clean up your session state for me."

**MID** = `0x03` (CLOSE)

The **S flag** (bit 5) distinguishes a **session close** (S=1, tear down the entire
session and all its state) from a **link-only close** (S=0, close just this TCP
connection but keep the session alive — relevant for multi-link sessions in
peer-to-peer mode, not applicable for simple client-to-router setups).

The **reason** byte provides a hint about why the session is closing:
- `0x00` = generic (normal shutdown)
- `0x01` = unsupported (protocol version or feature not supported)
- `0x02` = invalid (malformed message or protocol violation)
- Other values are reserved for future use.

After sending Close, the sender should shut down the TCP send direction (TCP FIN)
and close the socket. The receiver, upon receiving a Close, should clean up session
state and close its end of the connection. There is no Close acknowledgment — it's
a one-way notification.

> **zinoh**: [`src/transport/messages.zig`](../src/transport/messages.zig) —
> `Close.encode()`, `Close.decode()`, `CloseReason`.
> [`src/session.zig`](../src/session.zig) — `Session.close()` sends Close +
> TCP shutdown; `Session.deinit()` cleans up without sending.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|0|0|S|  0x03   |   S=1 for session close (vs link-only close)
+-+-+-+---------+
|    reason     |   1 byte: 0x00=generic, 0x01=unsupported, 0x02=invalid, ...
+---------------+
```

---

## 10. Full Wire Sequence Example

Complete message sequence for: connect → interest/declare → put → get → close. This
shows the full lifecycle of a minimal Zenoh client session on a single TCP connection.

Note how the sequence numbers (`N`, `M`) track independently for each direction —
the client's SN starts at `N` (randomized during OpenSyn) and the router's starts
at `M` (from the OpenAck). Each Frame increments the sender's SN. Also note that
every message on the wire (including KeepAlive) resets the lease timer for the
receiving side.

> **zinoh**: [`src/session.zig`](../src/session.zig) — `Session.connect()` /
> `Session.open()`, `Session.put()`, `Session.get()`, `Session.close()`,
> `Session.deinit()`.

```
  Client                                        Router
    |                                             |
    |  ── TCP Connect to tcp/192.168.1.1:7447 ──→ |
    |                                             |
    |  ── [len] InitSyn ────────────────────────→ |  version=9, Client, ZID, batch=2048
    |  ←─ [len] InitAck ─────────────────────── | |  version=9, Router, ZID, cookie, batch=2048
    |  ── [len] OpenSyn ────────────────────────→ |  lease=10s, initial_sn=N, cookie
    |  ←─ [len] OpenAck ─────────────────────── | |  lease=10s, initial_sn=M
    |                                             |
    |         ═══ Session Established ═══         |
    |                                             |
    |  ←─ [len] Frame(sn=M) ────────────────── | |  Interest(id=1, C=1, F=1)
    |          Interest(id=1, C+F, flags=0xFF)    |    "tell me all your declarations"
    |                                             |
    |  ── [len] Frame(sn=N) ────────────────────→ |  Declare(I=1, interest_id=1)
    |          Declare(DeclareFinal)               |    "I have nothing to declare"
    |                                             |
    |  ←─ [len] Frame(sn=M+1) ──────────────── | |  Router's own declarations
    |          Declare(DeclareSubscriber)          |    (e.g. storage on demo/**)
    |  ←─ [len] Frame(sn=M+2) ──────────────── | |
    |          Declare(DeclareFinal)               |    "end of my declarations"
    |                                             |
    |         ═══ Data Can Flow ═══               |
    |                                             |
    |  ── [len] Frame(sn=N+1) ──────────────────→ |  Put "Hello" to "demo/hello"
    |          Push(key="demo/hello")             |
    |            Put(payload="Hello")             |
    |                                             |
    |  ── [len] Frame(sn=N+2) ──────────────────→ |  Query "demo/hello"
    |          Request(rid=1, key="demo/hello")   |
    |            Query()                          |
    |                                             |
    |  ←─ [len] Frame(sn=M+3) ──────────────── | |  Reply with data
    |          Response(rid=1, key="demo/hello")  |
    |            Reply(Put(payload="Hello"))       |
    |                                             |
    |  ←─ [len] Frame(sn=M+4) ──────────────── | |  No more replies
    |          ResponseFinal(rid=1)               |
    |                                             |
    |  ...KeepAlive exchanged periodically...     |
    |                                             |
    |  ── [len] Close(reason=0x00) ─────────────→ |  Client closes session
    |                                             |
    |  ── TCP FIN ─────────────────────────────→  |
```

---

## Message ID Quick Reference

The table below lists all message IDs used in the basic client-to-router flow.
Note the MID overlaps between layers: transport INIT (`0x01`) and Zenoh PUT (`0x01`)
share the same numeric value but are disambiguated by their nesting position.
Transport messages appear at the outermost level (directly inside the TCP frame),
network messages appear inside Frame, and Zenoh messages appear inside Push/Request/Response.

> **zinoh**: [`src/codec/header.zig`](../src/codec/header.zig) — `TransportMid`,
> `NetworkMid`, `ZenohMid`, `DeclareMid`.

| MID    | Name          | Layer     | Purpose                            |
|--------|---------------|-----------|------------------------------------|
| `0x01` | INIT          | Transport | Session initialization (Syn/Ack)   |
| `0x02` | OPEN          | Transport | Session open (Syn/Ack)             |
| `0x03` | CLOSE         | Transport | Session/link termination           |
| `0x04` | KEEP_ALIVE    | Transport | Lease keepalive                    |
| `0x05` | FRAME         | Transport | Carries network messages           |
| `0x06` | FRAGMENT      | Transport | Fragmented large messages          |
| `0x19` | INTEREST      | Network   | Declare interest in resources      |
| `0x1A` | RESPONSE_FINAL| Network   | End of replies for a request       |
| `0x1B` | RESPONSE      | Network   | Reply to a request                 |
| `0x1C` | REQUEST       | Network   | Query / request-put / request-del  |
| `0x1D` | PUSH          | Network   | Pub/sub data push                  |
| `0x1E` | DECLARE       | Network   | Resource/subscriber/queryable decl |
| `0x01` | PUT           | Zenoh     | Put data (inside Push/Reply)       |
| `0x02` | DEL           | Zenoh     | Delete (inside Push/Reply)         |
| `0x03` | QUERY         | Zenoh     | Query parameters (inside Request)  |
| `0x04` | REPLY         | Zenoh     | Reply wrapper (inside Response)    |
| `0x05` | ERR           | Zenoh     | Error reply (inside Response)      |
| `0x1A` | DECLARE_FINAL | Declare   | End of declaration batch           |
