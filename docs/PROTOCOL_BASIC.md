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

TCP is stream-oriented, so every Zenoh message on the wire is prefixed with a **2-byte
little-endian length** indicating the number of bytes that follow:

```
+-------+-------+=========================+
| len_L | len_H |     Zenoh Message       |
+-------+-------+=========================+
   2 bytes (LE)         len bytes
```

Maximum message size: **65,535 bytes**. This framing applies to **every** message
described below.

> Defined in `include/zenoh-pico/protocol/definitions/core.h` as `_Z_MSG_LEN_ENC_SIZE = 2`.

---

## 2. Encoding Primitives

### VLE Integers (Variable-Length Encoding)

Most integer fields use VLE, similar to protobuf varints:
- Each byte contributes **7 data bits** (bits 0–6).
- **Bit 7** is the continuation flag: `1` = more bytes follow, `0` = last byte.
- Up to 9 bytes for a full `uint64`.

Examples:
| Value   | Encoded (hex) |
|---------|---------------|
| 0       | `00`          |
| 10      | `0A`          |
| 127     | `7F`          |
| 128     | `80 01`       |
| 10000   | `90 4E`       |

### uint16 (Little-Endian)

Some fields (batch size, key expression IDs) use a fixed 2-byte little-endian encoding.

### Slices / Byte Arrays

Byte slices are encoded as a **VLE length prefix** followed by the raw bytes:
```
%  length (VLE)  %
+----------------+
~   raw bytes    ~
+----------------+
```

### Strings

Strings are encoded the same as slices: VLE length + UTF-8 bytes.

---

## 3. Message Header Format

Every transport and network message starts with a **1-byte header**:

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|  Flags  | MID |
+-+-+-+-+-+-+-+-+
```

- **Bits 0–4** (`MID`): Message ID, masked with `0x1F`
- **Bits 5–7** (`Flags`): Message-type-specific flags

---

## 4. Session Establishment (4-Message Handshake)

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
- `version` = `0x09`
- `whatami` = Client (`0b10`)
- `seq_num_res` = `0x02` (32-bit)
- `req_id_res` = `0x02` (32-bit)
- `batch_size` = `2048` (zenoh-pico default)
- `patch` = `1`

The **S flag** is set because `batch_size` (2048) differs from the protocol default (65535).

### Message 2: InitAck (Router → Client)

**MID** = `0x01` (INIT), **A flag** = 1 (Ack).

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
The client must echo the **cookie** back in the OpenSyn.

### Message 3: OpenSyn (Client → Router)

**MID** = `0x02` (OPEN), **A flag** = 0 (Syn).

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
- **Lease** = min(client's, router's) lease value.
- Each side knows the other's starting SN.

---

## 5. Interest and Declare Exchange

After the 4-message handshake, the router and client exchange **Interest** and
**Declare** messages before data can flow. This is Zenoh 1.x's **interest-based
routing**: the router only forwards Push/Request messages when it knows about the
client's publishers, subscribers, and queryables.

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

The router sends an Interest message to ask the client about its declarations.

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

The client responds with Declare messages, each carrying a single declaration.

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

Marks the end of a declaration batch. This is the minimum a client must send.

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

To prevent lease expiration during idle periods, both sides periodically send:

**MID** = `0x04` (KEEP_ALIVE)

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

A `z_put(session, "demo/example/hello", "Hello World!")` results in:

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
one or more **Response(Reply)** messages followed by a **ResponseFinal**.

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

Either side can close the session.

**MID** = `0x03` (CLOSE)

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

Complete message sequence for: connect → interest/declare → put → get → close.

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
