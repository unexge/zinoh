# Zenoh Protocol Reference

Complete protocol reference for the Zenoh transport protocol as implemented in
zenoh-pico. Protocol version **0x09**.

> Derived from the zenoh-pico source code. See `PROTOCOL_BASIC.md` for a simplified
> walkthrough focused on connect → put → get.

---

## Table of Contents

1. [Protocol Layers](#1-protocol-layers)
2. [Encoding Primitives](#2-encoding-primitives)
3. [TCP Framing](#3-tcp-framing)
4. [Message Header Format](#4-message-header-format)
5. [Extension System](#5-extension-system)
6. [Scouting Messages](#6-scouting-messages)
7. [Transport Messages](#7-transport-messages)
8. [Network Messages](#8-network-messages)
9. [Zenoh Messages](#9-zenoh-messages)
10. [Declaration Messages](#10-declaration-messages)
11. [Interest Messages](#11-interest-messages)
12. [Session Lifecycle](#12-session-lifecycle)
13. [Quick Reference Tables](#13-quick-reference-tables)

---

## 1. Protocol Layers

Zenoh protocol has a layered architecture. Messages nest inside each other:

```
┌──────────────────────────────────────────────┐
│                TCP Framing                    │  2-byte LE length prefix
│  ┌────────────────────────────────────────┐  │
│  │          Transport Message             │  │  Frame, Fragment, Init, Open, ...
│  │  ┌──────────────────────────────────┐  │  │
│  │  │        Network Message           │  │  │  Push, Request, Response, Declare, ...
│  │  │  ┌────────────────────────────┐  │  │  │
│  │  │  │      Zenoh Message         │  │  │  │  Put, Del, Query, Reply, Err
│  │  │  └────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────┘  │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

- **Transport layer**: Session management (Init, Open, Close, KeepAlive) and
  data framing (Frame, Fragment).
- **Network layer**: Data routing (Push, Request, Response, Declare, Interest, OAM).
- **Zenoh layer**: Data semantics (Put, Del, Query, Reply, Err).

Network messages are carried **inside** Frame (or Fragment) transport messages.
Zenoh messages are carried **inside** Network messages.

---

## 2. Encoding Primitives

### 2.1 VLE Integer (Variable-Length Encoding)

Used for most integer fields. Same concept as protobuf varints.

| Byte | Bits 6-0 | Bit 7 (MSB)     |
|------|----------|-----------------|
| Each | 7 data bits | 1=more bytes, 0=last |

Up to **9 bytes** for a full `uint64`.

```
Encoding algorithm:
  while (value has more than 7 significant bits):
    emit byte: (value & 0x7F) | 0x80
    value >>= 7
  emit byte: value & 0xFF    (last byte, no continuation)
```

| Value   | Encoded (hex)      | Bytes |
|---------|--------------------|-------|
| 0       | `00`               | 1     |
| 127     | `7F`               | 1     |
| 128     | `80 01`            | 2     |
| 10000   | `90 4E`            | 2     |
| 65535   | `FF FF 03`         | 3     |

### 2.2 uint8

Single byte, written directly.

### 2.3 uint16 (Little-Endian)

2 bytes, least significant byte first.

### 2.4 Slice (Byte Array)

VLE-length prefix followed by raw bytes:

```
% length (VLE) %
+──────────────+
~  raw bytes   ~
+──────────────+
```

### 2.5 String

Same as slice: VLE-length prefix + UTF-8 byte content.

### 2.6 WhatAmI

Encoded as a 2-bit value within a combined byte:

| Value | Meaning  | 2-bit encoding | Bitmask |
|-------|----------|----------------|---------|
| 0b00  | Router   | 0              | 0b001   |
| 0b01  | Peer     | 1              | 0b010   |
| 0b10  | Client   | 2              | 0b100   |

Conversion: `encoded = (whatami >> 1) & 0x03`; `whatami = 1 << (encoded & 0x03)`

### 2.7 ZenohID

A 1–16 byte unique identifier. Length is encoded as `(real_len - 1)` in the upper
4 bits of a combined byte.

### 2.8 WireExpr (Key Expression)

```
~ key_scope:z16 ~   VLE: numeric key expression ID (0 if unregistered)
+───────────────+
~  key_suffix   ~   if has_suffix: VLE-length-prefixed UTF-8 string
+───────────────+
```

### 2.9 Timestamp

```
~ time:z64      ~   VLE: HLC time value
+───────────────+
|  zid_len      |   1 byte: length of the following ZenohID
+───────────────+
~  ZenohID      ~   zid_len bytes
+───────────────+
```

### 2.10 Encoding (Data Encoding)

```
~ id:VLE        ~   Encoding ID << 1 (lowest bit indicates schema presence)
+───────────────+
~  schema       ~   if bit0==1: VLE-length + UTF-8 schema string
+───────────────+
```

---

## 3. TCP Framing

For stream-oriented transports (TCP, TLS, WebSocket), each message is prefixed with a
**2-byte little-endian length**:

```
+───────+───────+════════════════════════+
| len_L | len_H |     Zenoh Message      |
+───────+───────+════════════════════════+
   2 bytes (LE)        len bytes
```

- Maximum message size: **65,535 bytes**.
- For datagram transports (UDP), no length prefix is used.
- Defined as `_Z_MSG_LEN_ENC_SIZE = 2` in `protocol/definitions/core.h`.
- The finalize function encodes: `buf[0] = len & 0xFF; buf[1] = (len >> 8) & 0xFF`.

---

## 4. Message Header Format

Every message starts with a **1-byte header**:

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|  Flags  | MID |
+-+-+-+-+-+-+-+-+
```

- **Bits 0–4** (MID): Message ID, extracted with mask `0x1F`.
- **Bits 5–7** (Flags): Message-specific flags, extracted with mask `0xE0`.

Common flag patterns:
- **Bit 7 (`0x80`)**: Usually `Z` flag — extensions follow.
- **Bit 6 (`0x40`)**: Message-specific (e.g., `S` for size params, `T` for time unit).
- **Bit 5 (`0x20`)**: Message-specific (e.g., `A` for ack, `R` for reliable).

---

## 5. Extension System

Extensions provide optional, type-length-value fields after the core message body.

### Extension Header Byte

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z| ENC |M| ID  |
+-+-+-+-+-+-+-+-+
```

- **ID** (bits 0–3): Extension identifier (within message context).
- **M** (bit 4, `0x10`): Mandatory flag. If set, unknown extensions cause an error.
- **ENC** (bits 5–6): Encoding type:
  - `0b00` (`0x00`): Unit — no body.
  - `0b01` (`0x20`): ZInt — VLE integer body.
  - `0b10` (`0x40`): ZBuf — VLE-length-prefixed buffer body.
- **Z** (bit 7, `0x80`): More extensions follow.

### Extension Body

| ENC  | Body format                        |
|------|------------------------------------|
| Unit | (empty)                            |
| ZInt | VLE integer value                  |
| ZBuf | VLE length + raw bytes             |

### Known Extension IDs

| Context | Ext ID | Full Header | Meaning |
|---------|--------|-------------|---------|
| Join    | 0x01   | `0x61`      | QoS SN list (Mandatory+ZBuf) |
| Join    | 0x07   | `0x27`      | Patch version (ZInt) |
| Init    | 0x07   | `0x27`      | Patch version (ZInt) |
| Fragment| 0x02   | `0x02`      | First fragment marker (Unit) |
| Fragment| 0x03   | `0x03`      | Drop marker (Unit) |

---

## 6. Scouting Messages

Scouting messages are used for peer/router discovery. They are **not used** when
connecting to a fixed address, but are documented here for completeness.

### 6.1 Scout (MID = `0x01`)

Sent to discover peers/routers (typically over multicast or on a fresh TCP link).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x01   |
+-+-+-+---------+
|   version     |   Protocol version (0x09)
+───────────────+
|zid_len|I|what |   what: bitmask (0b001=Router, 0b010=Peer, 0b100=Client)
+───────+─+─────+   I=1: ZenohID is present; zid_len: ID length - 1
~   ZenohID     ~   if I=1: sender's ZenohID
+───────────────+
```

### 6.2 Hello (MID = `0x02`)

Sent in response to Scout, or as periodic advertisement.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|L|  0x02   |   L=1: locators are present
+-+-+-+---------+
|   version     |   Protocol version (0x09)
+───────────────+
|zid_len|X|X|wai|   wai: WhatAmI (0b00=Router, 0b01=Peer, 0b10=Client)
+───────+─+─+───+   zid_len: ZenohID length - 1
~   ZenohID     ~   Sender's ZenohID
+───────────────+
~ locators      ~   if L=1: VLE count + list of VLE-length-prefixed locator strings
+───────────────+     e.g. "tcp/192.168.0.1:7447", "udp/192.168.0.1:7447"
```

---

## 7. Transport Messages

### 7.1 Init (MID = `0x01`)

Initiates a unicast session. Two forms: **InitSyn** (A=0) and **InitAck** (A=1).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|S|A|  0x01   |
+-+-+-+---------+
```

**Flags:**
- **A** (bit 5, `0x20`): Ack — 0 for Syn, 1 for Ack.
- **S** (bit 6, `0x40`): Size parameters present.
- **Z** (bit 7, `0x80`): Extensions present.

**Body:**

```
|   version     |   uint8: protocol version (0x09)
+───────────────+
|zid_len|x|x|wai|   wai: WhatAmI; zid_len: (real_len - 1) in bits 7-4
+───────+─+─+───+
~   ZenohID     ~   1–16 bytes
+───────────────+
                    ── if S=1 ──
|x|x|kid|rid|fsn|   Resolution byte:
+───────────────+     fsn (bits 0-1): Frame SN resolution
|  batch_size   |     rid (bits 2-3): Request ID resolution
|  (uint16 LE)  |     kid (bits 4-5): Key expression ID resolution
+───────────────+     Resolution encoding: 0b00=8bit, 0b01=16bit, 0b10=32bit, 0b11=64bit
                    ── if A=1 ──
~    Cookie     ~   VLE-length-prefixed opaque bytes
+───────────────+
                    ── if Z=1 ──
~  [Extensions] ~   e.g. Patch (ID=0x07, ENC=ZInt): negotiated patch version
+───────────────+
```

**Defaults (when S=0):**
- `seq_num_res` = `0x02` (32-bit)
- `req_id_res` = `0x02` (32-bit)
- `batch_size` = 65535 (unicast)

**Patch negotiation:**
- `_Z_NO_PATCH` = 0x00: protocol as released with 1.0.0
- `_Z_CURRENT_PATCH` = 0x01: adds fragment start/stop markers
- Ack value must be ≤ Syn value.

### 7.2 Open (MID = `0x02`)

Opens an initialized session. Two forms: **OpenSyn** (A=0) and **OpenAck** (A=1).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|T|A|  0x02   |
+-+-+-+---------+
```

**Flags:**
- **A** (bit 5, `0x20`): Ack — 0 for Syn, 1 for Ack.
- **T** (bit 6, `0x40`): Lease in seconds (vs milliseconds).
- **Z** (bit 7, `0x80`): Extensions present.

**Body:**

```
%     lease     %   VLE: lease period (seconds if T=1, ms if T=0)
+───────────────+
%  initial_sn   %   VLE: sender's initial TX sequence number
+───────────────+
                    ── if A=0 (Syn only) ──
~    Cookie     ~   VLE-length-prefixed: must match InitAck cookie exactly
+───────────────+
                    ── if Z=1 ──
~  [Extensions] ~
+───────────────+
```

**Defaults:**
- zenoh-pico default lease: 10000 ms (`Z_TRANSPORT_LEASE`), sent as 10 with T=1.
- Initial SN: randomly generated, masked to the agreed SN resolution.

### 7.3 Close (MID = `0x03`)

Terminates a session or link.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|S|  0x03   |
+-+-+-+---------+
|    reason     |   uint8: close reason code
+───────────────+
```

**Flags:**
- **S** (bit 5, `0x20`): Session close (S=1) vs Link-only close (S=0).

**Close Reason Codes:**

| Code | Constant              | Meaning                     |
|------|-----------------------|-----------------------------|
| 0x00 | `_Z_CLOSE_GENERIC`    | Generic close               |
| 0x01 | `_Z_CLOSE_UNSUPPORTED`| Unsupported                 |
| 0x02 | `_Z_CLOSE_INVALID`    | Invalid message received    |
| 0x03 | `_Z_CLOSE_MAX_TRANSPORTS` | Max transports reached |
| 0x04 | `_Z_CLOSE_MAX_LINKS`  | Max links reached           |
| 0x05 | `_Z_CLOSE_EXPIRED`    | Lease expired               |

### 7.4 KeepAlive (MID = `0x04`)

Prevents lease expiration when no data is being exchanged.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x04   |
+-+-+-+---------+
~  [Extensions] ~   if Z=1 (typically none)
+───────────────+
```

- Sent every `lease / LEASE_EXPIRE_FACTOR` (default factor = 3, so every ~3.3s).
- Minimal wire cost: 1 byte body + 2 byte TCP prefix = **3 bytes on TCP**.

### 7.5 Frame (MID = `0x05`)

Carries one or more network messages.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|R|  0x05   |
+-+-+-+---------+
%    seq_num    %   VLE: monotonically incrementing sequence number
+───────────────+
~  [Extensions] ~   if Z=1
+───────────────+
~ [NetworkMsg]+ ~   One or more network messages (decoded until buffer exhausted)
+───────────────+
```

**Flags:**
- **R** (bit 5, `0x20`): Reliable channel (R=1) vs best-effort (R=0).

**Sequence numbers** increment independently for reliable and best-effort channels.
The SN wraps at `2^(8 * resolution)` where resolution was negotiated in Init.

### 7.6 Fragment (MID = `0x06`)

Used for messages exceeding the batch size (max 65,535 bytes or the negotiated
`batch_size`).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|R|  0x06   |
+-+-+-+---------+
%    seq_num    %   VLE: sequence number
+───────────────+
~  [Extensions] ~   if Z=1: First(0x02), Drop(0x03) markers
+───────────────+
~   payload     ~   Raw fragment bytes (to end of batch)
+───────────────+
```

**Flags:**
- **R** (bit 5, `0x20`): Reliable (R=1) or best-effort (R=0).
- **M** (bit 6, `0x40`): More fragments follow (M=1) or this is the last (M=0).

**Fragment Extensions (patch ≥ 1):**
- **First** (ext 0x02, Unit): Marks the first fragment of a sequence.
- **Drop** (ext 0x03, Unit): Tells receiver to drop the current fragment assembly.

Fragment reassembly: collect payload bytes from consecutive Fragment messages with
the same reliability until M=0 (last fragment), then decode the reassembled buffer
as the original network message.

### 7.7 Join (MID = `0x07`)

Used in **multicast** transports to advertise transport parameters. Not used in
unicast client-to-router connections.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|S|T|  0x07   |
+-+-+-+---------+
|   version     |   uint8: protocol version (0x09)
+───────────────+
|zid_len|x|x|wai|   WhatAmI + ZenohID length
+───────+─+─+───+
~   ZenohID     ~
+───────────────+
                    ── if S=1 ──
|x|x|kid|rid|fsn|   Resolution byte (same as Init)
+───────────────+
|  batch_size   |   uint16 LE
|               |
+───────────────+
%     lease     %   VLE: lease period (seconds if T=1, ms if T=0)
+───────────────+
%  reliable_sn  %   VLE: next reliable SN
+───────────────+
% best_eff_sn   %   VLE: next best-effort SN
+───────────────+
                    ── if Z=1 ──
~ [Extensions]  ~   QoS SN (ext 0x01): per-priority SN pairs
+───────────────+   Patch (ext 0x07): fragmentation patch version
```

**Flags:**
- **T** (bit 5, `0x20`): Lease in seconds (T=1) or milliseconds (T=0).
- **S** (bit 6, `0x40`): Size parameters present.
- **Z** (bit 7, `0x80`): Extensions present.

---

## 8. Network Messages

Network messages are carried inside Frame (or Fragment) transport messages. They
have their own 1-byte headers with MIDs in the range `0x19`–`0x1F`.

### 8.1 Push (MID = `0x1D`)

Delivers pub/sub data (publisher → subscriber).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1D   |
+-+-+-+---------+
~ key_scope:z16 ~   VLE: key expression numeric ID
+───────────────+
~  key_suffix   ~   if N=1: VLE-length + UTF-8 string
+───────────────+
~ [push_exts]   ~   if Z=1
+───────────────+
~ ZenohMessage  ~   Put or Del message
+───────────────+
```

**Flags:**
- **N** (bit 5, `0x20`): Key expression has a name/suffix.
- **M** (bit 6, `0x40`): Mapping — 1=sender's mapping, 0=receiver's mapping.
- **Z** (bit 7, `0x80`): Extensions present.

**Extensions:**
- QoS (ext 0x01, ZInt): QoS byte encoding priority, congestion control, express.
- Timestamp (ext 0x02, ZBuf): HLC timestamp.

### 8.2 Request (MID = `0x1C`)

Initiates a request (query, request-put, request-del).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1C   |
+-+-+-+---------+
~ request_id    ~   VLE (z32): unique request identifier
+───────────────+
~ key_scope:z16 ~   VLE: key expression numeric ID
+───────────────+
~  key_suffix   ~   if N=1: VLE-length + UTF-8 string
+───────────────+
~ [req_exts]    ~   if Z=1
+───────────────+
~ ZenohMessage  ~   Query, Put, or Del message
+───────────────+
```

**Flags:** Same as Push (N, M, Z).

**Extensions:**
| Ext | Enc  | ID   | Meaning                              |
|-----|------|------|--------------------------------------|
| QoS | ZInt | 0x01 | QoS byte                             |
| TS  | ZBuf | 0x02 | Timestamp                            |
| Tgt | ZInt | 0x04 | Query target (Mandatory)             |
| Bgt | ZInt | 0x05 | Reply budget                         |
| Tmo | ZInt | 0x06 | Timeout in milliseconds              |

**Inner message determines the request type:**
- `_Z_MID_Z_QUERY` (0x03) → Query
- `_Z_MID_Z_PUT` (0x01) → Request-Put
- `_Z_MID_Z_DEL` (0x02) → Request-Del

### 8.3 Response (MID = `0x1B`)

Reply to a Request.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x1B   |
+-+-+-+---------+
~ request_id    ~   VLE: echoes back the request ID
+───────────────+
~ key_scope:z16 ~   VLE: key expression ID
+───────────────+
~  key_suffix   ~   if N=1: VLE-length + UTF-8 string
+───────────────+
~ [resp_exts]   ~   if Z=1
+───────────────+
~ ZenohMessage  ~   Reply or Err message
+───────────────+
```

**Flags:** Same as Push (N, M, Z).

**Extensions:**
| Ext | Enc  | ID   | Meaning                              |
|-----|------|------|--------------------------------------|
| QoS | ZInt | 0x01 | QoS byte                             |
| TS  | ZBuf | 0x02 | Timestamp                            |
| Rsp | ZBuf | 0x03 | Responder info (ZenohID + entity ID) |

**Inner message:**
- `_Z_MID_Z_REPLY` (0x04) → Reply (contains Put or Del)
- `_Z_MID_Z_ERR` (0x05) → Error reply

### 8.4 ResponseFinal (MID = `0x1A`)

Signals that no more Response messages will follow for a given request.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x1A   |
+-+-+-+---------+
~ request_id    ~   VLE: the request ID being finalized
+───────────────+
~ [Extensions]  ~   if Z=1
+───────────────+
```

### 8.5 Declare (MID = `0x1E`)

Carries a single declaration (resource, subscriber, queryable, token, etc.).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|I|  0x1E   |   I=1: interest response (interest_id follows)
+-+-+-+---------+
~ interest_id   ~   if I=1: VLE (z32)
+───────────────+
~ [decl_exts]   ~   if Z=1: QoS(0x01), Timestamp(0x02) extensions
+───────────────+
~ Declaration   ~   Inner declaration message (see §10)
+───────────────+
```

### 8.6 Interest (MID = `0x19`)

Expresses interest in certain kinds of declarations (key exprs, subscribers,
queryables, tokens).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|F|C|  0x19   |
+-+-+-+---------+
~    id:z32     ~   VLE: interest identifier
+───────────────+
                    ── if not final (C or F is set) ──
|A|M|N|R|T|Q|S|K|   Interest flags byte:
+───────────────+     K=KeyExprs, S=Subscribers, Q=Queryables, T=Tokens
~ key_scope:z16 ~     R=Restricted, N=has suffix, M=Mapping, A=Aggregate
+───────────────+     (key_scope and suffix only if R=1)
~  key_suffix   ~   if R=1 && N=1
+───────────────+
~ [Extensions]  ~   if Z=1
+───────────────+
```

**Flags:**
- **C** (bit 5, `0x20`): Interest in current declarations.
- **F** (bit 6, `0x40`): Interest in future declarations.
- If C=0 and F=0: This is a **final** interest (undeclare).

### 8.7 OAM (MID = `0x1F`)

Operations, Administration, and Management message.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|ENC|  0x1F   |   ENC: 0b00=Unit, 0b01=ZInt, 0b10=ZBuf
+-+-+-+---------+
~    id:z16     ~   VLE: OAM message ID
+───────────────+
~ [oam_exts]    ~   if Z=1: QoS(0x01), Timestamp(0x02) extensions
+───────────────+
                    ── body depends on ENC ──
%    length     %   if ENC==ZInt or ENC==ZBuf: VLE length/value
+───────────────+
~    [u8]       ~   if ENC==ZBuf: raw bytes
+───────────────+
```

---

## 9. Zenoh Messages

Zenoh messages are the innermost layer, carried inside Network messages. They have
MIDs in the range `0x00`–`0x05`.

### 9.1 Put (MID = `0x01`)

Carries a key-value sample.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|E|T|  0x01   |   T=1: timestamp present; E=1: encoding present
+-+-+-+---------+
~ timestamp     ~   if T=1: VLE time + ZenohID (see §2.9)
+───────────────+
~ encoding      ~   if E=1: VLE encoding ID (see §2.10)
+───────────────+
~ [put_exts]    ~   if Z=1
+───────────────+
~ payload       ~   VLE-length-prefixed payload bytes
+───────────────+
```

**Extensions:**
- Source Info (ext 0x01, ZBuf): Source ZenohID + entity ID + SN.
- Attachment (ext 0x03, ZBuf): User attachment bytes.

### 9.2 Del (MID = `0x02`)

Signals deletion of a key.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|T|  0x02   |   T=1: timestamp present
+-+-+-+---------+
~ timestamp     ~   if T=1
+───────────────+
~ [del_exts]    ~   if Z=1: same extensions as Put
+───────────────+
```

No payload. Same extension set as Put (Source Info, Attachment).

### 9.3 Query (MID = `0x03`)

Query parameters for a request.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|P|C|  0x03   |   C=1: consolidation present; P=1: parameters present
+-+-+-+---------+
~ consolidation ~   if C=1: uint8 consolidation mode
+───────────────+
~  parameters   ~   if P=1: VLE-length-prefixed UTF-8 (selector parameters)
+───────────────+
~ [qry_exts]    ~   if Z=1
+───────────────+
```

**Consolidation modes:**
| Value | Mode    | Meaning |
|-------|---------|---------|
| 0     | Auto    | Automatic selection |
| 1     | None    | No consolidation |
| 2     | Mono    | Keep first |
| 3     | Latest  | Keep latest |

**Extensions:**
- Source Info (ext 0x01, ZBuf): Source information.
- Body/Value (ext 0x03, ZBuf): Query body (encoding + payload).
- Attachment (ext 0x05, ZBuf): User attachment.

### 9.4 Reply (MID = `0x04`)

Wraps a reply to a query.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|C|  0x04   |   C=1: consolidation present
+-+-+-+---------+
~ consolidation ~   if C=1: uint8
+───────────────+
~ [Extensions]  ~   if Z=1
+───────────────+
~ ReplyBody     ~   A Put or Del message (decoded by inner header)
+───────────────+
```

### 9.5 Err (MID = `0x05`)

Error reply to a query.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|E|X|  0x05   |   E=1: encoding present
+-+-+-+---------+
~ encoding      ~   if E=1: encoding of the error payload
+───────────────+
~ [err_exts]    ~   if Z=1: Source Info (ext 0x01, ZBuf)
+───────────────+
~ payload       ~   VLE-length-prefixed error payload bytes
+───────────────+
```

---

## 10. Declaration Messages

Declarations are carried inside the Declare network message (§8.5). Each declaration
has its own sub-header with a MID in the range `0x00`–`0x1A`.

### 10.1 DeclareKeyExpr (MID = `0x00`)

Registers a key expression mapping (numeric ID ↔ string).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|N|  0x00   |   N=1: key has string suffix
+-+-+-+---------+
~    id:z16     ~   VLE: numeric key expression ID to register
+───────────────+
~ key_scope:z16 ~   VLE: base key expression ID (for composition)
+───────────────+
~  key_suffix   ~   if N=1: VLE-length + UTF-8 string
+───────────────+
```

### 10.2 UndeclareKeyExpr (MID = `0x01`)

Unregisters a key expression.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x01   |
+-+-+-+---------+
~    id:z16     ~   VLE: key expression ID to unregister
+───────────────+
```

### 10.3 DeclareSubscriber (MID = `0x02`)

Declares a subscription interest.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x02   |   N=1: key has suffix; M=1: sender's mapping
+-+-+-+---------+
~    id:z32     ~   VLE: subscription ID
+───────────────+
~ key_scope:z16 ~   VLE: key expression ID
+───────────────+
~  key_suffix   ~   if N=1: VLE-length + UTF-8 string
+───────────────+
~ [Extensions]  ~   if Z=1
+───────────────+
```

### 10.4 UndeclareSubscriber (MID = `0x03`)

Removes a subscription.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x03   |
+-+-+-+---------+
~    id:z32     ~   VLE: subscription ID
+───────────────+
~ [Extensions]  ~   if Z=1: keyexpr extension (ext 0x0F, Mandatory+ZBuf)
+───────────────+
```

### 10.5 DeclareQueryable (MID = `0x04`)

Declares a queryable.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x04   |
+-+-+-+---------+
~    id:z32     ~   VLE: queryable ID
+───────────────+
~ key_scope:z16 ~   VLE: key expression ID
+───────────────+
~  key_suffix   ~   if N=1
+───────────────+
~ [Extensions]  ~   if Z=1: Queryable Info (ext 0x01, ZInt):
+───────────────+     bit 0: complete flag; bits 8+: distance
```

### 10.6 UndeclareQueryable (MID = `0x05`)

Removes a queryable.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x05   |
+-+-+-+---------+
~    id:z32     ~   VLE: queryable ID
+───────────────+
~ [Extensions]  ~   if Z=1: keyexpr extension
+───────────────+
```

### 10.7 DeclareToken (MID = `0x06`)

Declares a liveliness token.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|M|N|  0x06   |
+-+-+-+---------+
~    id:z32     ~   VLE: token ID
+───────────────+
~ key_scope:z16 ~
+───────────────+
~  key_suffix   ~   if N=1
+───────────────+
```

### 10.8 UndeclareToken (MID = `0x07`)

Removes a liveliness token.

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x07   |
+-+-+-+---------+
~    id:z32     ~   VLE: token ID
+───────────────+
~ [Extensions]  ~   if Z=1: keyexpr extension
+───────────────+
```

### 10.9 DeclareFinal (MID = `0x1A`)

Marks the end of a declaration batch (used in interest responses).

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|Z|X|X|  0x1A   |
+-+-+-+---------+
```

---

## 11. Interest Messages

See §8.6 for the Interest network message format. The interest flags byte
controls what kinds of declarations the sender is interested in:

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|A|M|N|R|T|Q|S|K|
+-+-+-+-+-+-+-+-+
```

| Bit | Flag | Meaning |
|-----|------|---------|
| 0   | K    | Key expressions |
| 1   | S    | Subscribers |
| 2   | Q    | Queryables |
| 3   | T    | Tokens |
| 4   | R    | Restricted to matching key expression |
| 5   | N    | Key expression has suffix (only if R=1) |
| 6   | M    | Sender's mapping (only if R=1) |
| 7   | A    | Replies should be aggregated |

---

## 12. Session Lifecycle

### 12.1 Client → Router (Unicast)

```
Phase 1: TCP Connect
  Client opens TCP connection to router's locator (e.g. tcp/192.168.1.1:7447)

Phase 2: Init Handshake
  Client → InitSyn(version, Client, ZID, batch_size, sn_res, patch)
  Router → InitAck(version, Router, ZID, batch_size, sn_res, cookie, patch)
  ● Size parameters in Ack must be ≤ Syn values
  ● Cookie is opaque, must be echoed back

Phase 3: Open Handshake
  Client → OpenSyn(lease, initial_sn, cookie)
  Router → OpenAck(lease, initial_sn)
  ● Session lease = min(client's, router's)
  ● Each side records the other's initial_sn

Phase 4: Interest/Declare Exchange
  Router → Interest(id, C=1, F=1, flags)    "tell me your declarations"
  Client → Declare(I=1, interest_id) → DeclareFinal    "nothing to declare"
  Router → Declare(DeclareSubscriber/...)    router's own declarations
  Router → Declare(DeclareFinal)             "end of my declarations"
  ● This exchange enables interest-based routing
  ● Without it, the router will not forward Push or Request messages
  ● A minimal client responds with just DeclareFinal

Phase 5: Established Session
  ● Frame messages carry network messages (Push, Request, Response, Declare, Interest)
  ● KeepAlive messages prevent lease expiration
  ● Fragment messages handle oversized data
  ● Either side may Close at any time

Phase 6: Teardown
  Sender → Close(reason, session_close=true)
  TCP connection is closed
```

### 12.2 QoS Byte Encoding

Used in Push, Request, and Response network extension 0x01:

```
 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+
|X|X|X|E|D|  P  |
+-+-+-+-+-+-+-+-+
```

| Bits  | Field | Meaning |
|-------|-------|---------|
| 0–2   | P     | Priority (0=highest to 7=lowest) |
| 3     | D     | NoDrop: 1=block (don't drop), 0=drop on congestion |
| 4     | E     | Express: 1=send immediately, 0=may batch |

### 12.3 Batching

Multiple network messages can be packed into a single Frame message, up to the
negotiated `batch_size`. This reduces TCP overhead. The batch is flushed when:
- An express message is encountered
- The batch buffer is full
- The batch is explicitly flushed (e.g. via timer)

---

## 13. Quick Reference Tables

### Transport Message IDs

| MID    | Hex    | Name       | Direction       | Purpose                       |
|--------|--------|------------|-----------------|-------------------------------|
| 0x00   | `0x00` | OAM        | Both            | Transport-level OAM           |
| 0x01   | `0x01` | INIT       | Both            | Session init (Syn/Ack)        |
| 0x02   | `0x02` | OPEN       | Both            | Session open (Syn/Ack)        |
| 0x03   | `0x03` | CLOSE      | Both            | Session/link termination      |
| 0x04   | `0x04` | KEEP_ALIVE | Both            | Lease keepalive               |
| 0x05   | `0x05` | FRAME      | Both            | Carries network messages      |
| 0x06   | `0x06` | FRAGMENT   | Both            | Fragmented large messages     |
| 0x07   | `0x07` | JOIN       | Multicast only  | Multicast parameter exchange  |

### Network Message IDs

| MID    | Hex    | Name           | Purpose                            |
|--------|--------|----------------|------------------------------------|
| 0x19   | `0x19` | INTEREST       | Declare interest in resources      |
| 0x1A   | `0x1A` | RESPONSE_FINAL | End of replies for a request       |
| 0x1B   | `0x1B` | RESPONSE       | Reply to a request                 |
| 0x1C   | `0x1C` | REQUEST        | Query / request-put / request-del  |
| 0x1D   | `0x1D` | PUSH           | Pub/sub data push                  |
| 0x1E   | `0x1E` | DECLARE        | Resource/subscriber/queryable decl |
| 0x1F   | `0x1F` | OAM            | Network-level OAM                  |

### Zenoh Message IDs

| MID    | Hex    | Name   | Purpose                                  |
|--------|--------|--------|------------------------------------------|
| 0x00   | `0x00` | OAM    | Zenoh-level OAM                          |
| 0x01   | `0x01` | PUT    | Put data (in Push, Request, Reply)       |
| 0x02   | `0x02` | DEL    | Delete (in Push, Request, Reply)         |
| 0x03   | `0x03` | QUERY  | Query parameters (in Request)            |
| 0x04   | `0x04` | REPLY  | Reply wrapper (in Response)              |
| 0x05   | `0x05` | ERR    | Error reply (in Response)                |

### Declaration Sub-Message IDs

| MID    | Hex    | Name                | Purpose                          |
|--------|--------|---------------------|----------------------------------|
| 0x00   | `0x00` | DeclareKeyExpr      | Register key expression mapping  |
| 0x01   | `0x01` | UndeclareKeyExpr    | Unregister key expression        |
| 0x02   | `0x02` | DeclareSubscriber   | Declare subscription             |
| 0x03   | `0x03` | UndeclareSubscriber | Remove subscription              |
| 0x04   | `0x04` | DeclareQueryable    | Declare queryable                |
| 0x05   | `0x05` | UndeclareQueryable  | Remove queryable                 |
| 0x06   | `0x06` | DeclareToken        | Declare liveliness token         |
| 0x07   | `0x07` | UndeclareToken      | Remove liveliness token          |
| 0x1A   | `0x1A` | DeclareFinal        | End of declaration batch         |

### Default Configuration (zenoh-pico)

| Parameter          | Value  | Constant                  |
|--------------------|--------|---------------------------|
| Protocol version   | 0x09   | `Z_PROTO_VERSION`         |
| Batch size (unicast)| 2048  | `Z_BATCH_UNICAST_SIZE`    |
| Batch size (multi) | 8192   | `Z_BATCH_MULTICAST_SIZE`  |
| Default batch (uni)| 65535  | `_Z_DEFAULT_UNICAST_BATCH_SIZE` |
| Default batch (mcast)| 8192| `_Z_DEFAULT_MULTICAST_BATCH_SIZE`|
| SN resolution      | 0x02 (32-bit) | `Z_SN_RESOLUTION`  |
| Request ID res     | 0x02 (32-bit) | `Z_REQ_RESOLUTION` |
| Default resolution | 0x02 (32-bit) | `_Z_DEFAULT_RESOLUTION_SIZE` |
| Transport lease    | 10000ms | `Z_TRANSPORT_LEASE`      |
| Lease expire factor| 3      | `Z_TRANSPORT_LEASE_EXPIRE_FACTOR` |
| Current patch      | 0x01   | `_Z_CURRENT_PATCH`        |
| Length prefix size  | 2      | `_Z_MSG_LEN_ENC_SIZE`     |
