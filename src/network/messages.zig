//! Network messages: Push, Request, Response, ResponseFinal.
//!
//! Implements encode/decode for network-layer messages per Zenoh protocol v0x09.
//! Network messages are carried inside Frame (or Fragment) transport messages.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const vle = @import("../codec/vle.zig");
const primitives = @import("../codec/primitives.zig");
const hdr = @import("../codec/header.zig");

/// Network-layer message IDs.
pub const MID = hdr.NetworkMid;

/// Flag masks for network messages.
pub const Flag = struct {
    /// Bit 5 (0x20): N=key has name/suffix (Push, Request, Response).
    pub const bit5: u8 = 0x20;
    /// Bit 6 (0x40): M=sender's mapping (Push, Request, Response).
    pub const bit6: u8 = 0x40;
    /// Bit 7 (0x80): Z=extensions present.
    pub const z_flag: u8 = 0x80;
};

// ═══════════════════════════════════════════════════════════════════════════
// Push (MID = 0x1D)
// ═══════════════════════════════════════════════════════════════════════════

/// Push message: delivers pub/sub data (publisher → subscriber).
///
/// Wire format (§8.1):
///   header: |Z|M|N| 0x1D |
///   key_scope: VLE (key expression numeric ID, 0 if none declared)
///   if N=1: key_suffix (VLE-length + UTF-8 string)
///   if Z=1: extensions (QoS, Timestamp)
///   ZenohMessage: inner Put or Del message
///
/// This struct encodes/decodes only the Push header + key expression.
/// The inner Zenoh message (Put/Del) must be encoded/decoded separately.
pub const Push = struct {
    /// Key expression numeric ID (0 if using string-only key).
    key_scope: u64 = 0,
    /// Key expression string suffix (sets N flag when non-null).
    key_suffix: ?[]const u8 = null,
    /// Sender's mapping (M flag). If true, key_scope is from sender's table.
    sender_mapping: bool = false,

    /// Free allocator-owned memory from a decoded Push.
    /// Must be called with the same allocator passed to `decodeHeader`.
    pub fn deinit(self: *const Push, allocator: Allocator) void {
        if (self.key_suffix) |s| allocator.free(@constCast(s));
    }

    /// Encode the Push header and key expression to the writer.
    /// The caller must encode the inner Zenoh message (Put/Del) immediately after.
    pub fn encodeHeader(self: *const Push, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|M|N| MID=0x1D |
        var header: u8 = @as(u8, MID.push);
        if (self.key_suffix != null) header |= Flag.bit5; // N flag
        if (self.sender_mapping) header |= Flag.bit6; // M flag
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Key scope (VLE)
        try vle.encode(self.key_scope, writer);

        // Key suffix (if N=1)
        if (self.key_suffix) |suffix| {
            try primitives.writeString(suffix, writer);
        }
    }

    /// Decode a Push header from the reader. The header byte has already been
    /// parsed to determine this is a Push (MID=0x1D).
    /// Returns the Push with fields populated. The remaining bytes are the
    /// inner Zenoh message (Put/Del), which the caller should decode separately.
    /// Caller owns key_suffix memory (if non-null) and must free with `allocator`.
    pub fn decodeHeader(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Push {
        const n_flag = (header & Flag.bit5) != 0;
        const m_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const key_scope = try vle.decode(reader);

        var key_suffix: ?[]u8 = null;
        if (n_flag) {
            key_suffix = try primitives.readString(reader, allocator);
        }
        errdefer if (key_suffix) |s| allocator.free(s);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Push{
            .key_scope = key_scope,
            .key_suffix = key_suffix,
            .sender_mapping = m_flag,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

pub const DecodeError = Io.Reader.Error;

pub const DecodeAllocError = Io.Reader.Error || Io.Reader.ReadAllocError;

// ═══════════════════════════════════════════════════════════════════════════
// Extension helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Skip the body of a single extension based on its encoding type.
fn skipExtensionBody(enc: u2, reader: *Io.Reader) DecodeError!void {
    switch (enc) {
        0b00 => {}, // Unit: no body
        0b01 => {
            // ZInt: skip VLE value
            _ = try vle.decode(reader);
        },
        0b10 => {
            // ZBuf: skip VLE-length-prefixed bytes
            const buf_len = try vle.decode(reader);
            try reader.discardAll(@intCast(buf_len));
        },
        0b11 => {}, // reserved — treat as Unit for forward compat
    }
}

/// Skip all extensions from reader. Each extension header byte has a "more"
/// bit (bit 7) indicating whether additional extensions follow.
/// Note: unknown mandatory extensions (M bit, 0x10) are not yet rejected —
/// full mandatory-extension enforcement is deferred to a future task.
fn skipExtensions(reader: *Io.Reader) DecodeError!void {
    while (true) {
        const ext_header = try reader.takeByte();
        const enc: u2 = @truncate((ext_header >> 5) & 0x03);
        const has_more = (ext_header & 0x80) != 0;

        try skipExtensionBody(enc, reader);

        if (!has_more) break;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Request (MID = 0x1C)
// ═══════════════════════════════════════════════════════════════════════════

/// Request message: carries query/request operations (e.g., Query).
///
/// Wire format (§7):
///   header: |Z|M|N| 0x1C |
///   request_id: VLE (unique request ID)
///   key_scope: VLE (key expression numeric ID, 0 if none declared)
///   if N=1: key_suffix (VLE-length + UTF-8 string)
///   if Z=1: extensions (QoS, Timestamp, Target, Budget, Timeout)
///   ZenohMessage: inner Query message
///
/// This struct encodes/decodes only the Request header + key expression.
/// The inner Zenoh message (Query) must be encoded/decoded separately.
pub const Request = struct {
    /// Unique request ID.
    request_id: u64,
    /// Key expression numeric ID (0 if using string-only key).
    key_scope: u64 = 0,
    /// Key expression string suffix (sets N flag when non-null).
    key_suffix: ?[]const u8 = null,
    /// Sender's mapping (M flag). If true, key_scope is from sender's table.
    sender_mapping: bool = false,

    /// Free allocator-owned memory from a decoded Request.
    /// Must be called with the same allocator passed to `decodeHeader`.
    pub fn deinit(self: *const Request, allocator: Allocator) void {
        if (self.key_suffix) |s| allocator.free(@constCast(s));
    }

    /// Encode the Request header and key expression to the writer.
    /// The caller must encode the inner Zenoh message (Query) immediately after.
    pub fn encodeHeader(self: *const Request, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|M|N| MID=0x1C |
        var header: u8 = @as(u8, MID.request);
        if (self.key_suffix != null) header |= Flag.bit5; // N flag
        if (self.sender_mapping) header |= Flag.bit6; // M flag
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Request ID (VLE)
        try vle.encode(self.request_id, writer);

        // Key scope (VLE)
        try vle.encode(self.key_scope, writer);

        // Key suffix (if N=1)
        if (self.key_suffix) |suffix| {
            try primitives.writeString(suffix, writer);
        }
    }

    /// Decode a Request header from the reader. The header byte has already been
    /// parsed to determine this is a Request (MID=0x1C).
    /// Returns the Request with fields populated. The remaining bytes are the
    /// inner Zenoh message (Query), which the caller should decode separately.
    /// Caller owns key_suffix memory (if non-null) and must free with `allocator`.
    pub fn decodeHeader(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Request {
        const n_flag = (header & Flag.bit5) != 0;
        const m_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const request_id = try vle.decode(reader);
        const key_scope = try vle.decode(reader);

        var key_suffix: ?[]u8 = null;
        if (n_flag) {
            key_suffix = try primitives.readString(reader, allocator);
        }
        errdefer if (key_suffix) |s| allocator.free(s);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Request{
            .request_id = request_id,
            .key_scope = key_scope,
            .key_suffix = key_suffix,
            .sender_mapping = m_flag,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Response (MID = 0x1B)
// ═══════════════════════════════════════════════════════════════════════════

/// Response message: carries a reply to a Request (e.g., Reply or Err).
///
/// Wire format (§7):
///   header: |Z|M|N| 0x1B |
///   request_id: VLE (echoes back the request ID)
///   key_scope: VLE (key expression numeric ID)
///   if N=1: key_suffix (VLE-length + UTF-8 string)
///   if Z=1: extensions (QoS, Timestamp, Responder)
///   ZenohMessage: inner Reply or Err message
///
/// This struct encodes/decodes only the Response header + key expression.
/// The inner Zenoh message (Reply/Err) must be encoded/decoded separately.
pub const Response = struct {
    /// Request ID this is responding to (echoes Request.request_id).
    request_id: u64,
    /// Key expression numeric ID (0 if using string-only key).
    key_scope: u64 = 0,
    /// Key expression string suffix (sets N flag when non-null).
    key_suffix: ?[]const u8 = null,
    /// Sender's mapping (M flag). If true, key_scope is from sender's table.
    sender_mapping: bool = false,

    /// Free allocator-owned memory from a decoded Response.
    /// Must be called with the same allocator passed to `decodeHeader`.
    pub fn deinit(self: *const Response, allocator: Allocator) void {
        if (self.key_suffix) |s| allocator.free(@constCast(s));
    }

    /// Encode the Response header and key expression to the writer.
    /// The caller must encode the inner Zenoh message (Reply/Err) immediately after.
    pub fn encodeHeader(self: *const Response, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|M|N| MID=0x1B |
        var header: u8 = @as(u8, MID.response);
        if (self.key_suffix != null) header |= Flag.bit5; // N flag
        if (self.sender_mapping) header |= Flag.bit6; // M flag
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Request ID (VLE)
        try vle.encode(self.request_id, writer);

        // Key scope (VLE)
        try vle.encode(self.key_scope, writer);

        // Key suffix (if N=1)
        if (self.key_suffix) |suffix| {
            try primitives.writeString(suffix, writer);
        }
    }

    /// Decode a Response header from the reader. The header byte has already been
    /// parsed to determine this is a Response (MID=0x1B).
    /// Returns the Response with fields populated. The remaining bytes are the
    /// inner Zenoh message (Reply/Err), which the caller should decode separately.
    /// Caller owns key_suffix memory (if non-null) and must free with `allocator`.
    pub fn decodeHeader(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Response {
        const n_flag = (header & Flag.bit5) != 0;
        const m_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const request_id = try vle.decode(reader);
        const key_scope = try vle.decode(reader);

        var key_suffix: ?[]u8 = null;
        if (n_flag) {
            key_suffix = try primitives.readString(reader, allocator);
        }
        errdefer if (key_suffix) |s| allocator.free(s);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Response{
            .request_id = request_id,
            .key_scope = key_scope,
            .key_suffix = key_suffix,
            .sender_mapping = m_flag,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ResponseFinal (MID = 0x1A)
// ═══════════════════════════════════════════════════════════════════════════

/// ResponseFinal message: signals end of replies for a request.
///
/// Wire format (§7):
///   header: |Z|0|0| 0x1A |
///   request_id: VLE (same request ID as the original Request)
///
/// This is a terminal message — no inner Zenoh message follows.
pub const ResponseFinal = struct {
    /// Request ID this is finalizing (same as Request.request_id).
    request_id: u64,

    /// Encode this ResponseFinal to the writer.
    pub fn encode(self: *const ResponseFinal, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|0|0| MID=0x1A |
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(@as(u8, MID.response_final));

        // Request ID (VLE)
        try vle.encode(self.request_id, writer);
    }

    /// Decode a ResponseFinal from the reader. The header byte has already been
    /// parsed to determine this is a ResponseFinal (MID=0x1A).
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!ResponseFinal {
        const z_flag = (header & Flag.z_flag) != 0;

        const request_id = try vle.decode(reader);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return ResponseFinal{
            .request_id = request_id,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Interest (MID = 0x19)
// ═══════════════════════════════════════════════════════════════════════════

/// Interest message: expresses interest in certain kinds of declarations.
///
/// Wire format (§8.6):
///   header: |Z|F|C| 0x19 |
///   id: VLE (z32) — interest identifier
///   -- if not final (C or F is set) --
///   flags: u8 — interest flags byte: |A|M|N|R|T|Q|S|K|
///   if R=1: key_scope (VLE z16)
///   if R=1 && N=1: key_suffix (VLE-length + UTF-8 string)
///   if Z=1: extensions
///
/// **Header Flags:**
/// - C (bit 5, 0x20): Interest in current declarations
/// - F (bit 6, 0x40): Interest in future declarations
/// - Z (bit 7, 0x80): Extensions present
/// - If C=0 and F=0: Final interest (undeclare); no flags byte follows
pub const Interest = struct {
    /// Interest identifier.
    id: u64,
    /// C flag: interest in current declarations.
    current: bool = false,
    /// F flag: interest in future declarations.
    future: bool = false,
    /// Interest flags byte (only present when C or F is set).
    /// Bits: |A|M|N|R|T|Q|S|K|
    interest_flags: ?u8 = null,
    /// Key expression numeric ID (only present when R=1 in interest_flags).
    key_scope: ?u64 = null,
    /// Key expression suffix (only present when R=1 && N=1 in interest_flags).
    key_suffix: ?[]const u8 = null,

    /// Free allocator-owned memory from a decoded Interest.
    pub fn deinit(self: *const Interest, allocator: Allocator) void {
        if (self.key_suffix) |s| allocator.free(@constCast(s));
    }

    /// Returns true if this is a final interest (C=0, F=0).
    pub fn isFinal(self: *const Interest) bool {
        return !self.current and !self.future;
    }

    /// Interest flags bit positions.
    pub const Flags = struct {
        pub const key_exprs: u8 = 0x01; // K: bit 0
        pub const subscribers: u8 = 0x02; // S: bit 1
        pub const queryables: u8 = 0x04; // Q: bit 2
        pub const tokens: u8 = 0x08; // T: bit 3
        pub const restricted: u8 = 0x10; // R: bit 4
        pub const has_suffix: u8 = 0x20; // N: bit 5
        pub const mapping: u8 = 0x40; // M: bit 6
        pub const aggregate: u8 = 0x80; // A: bit 7
    };

    /// Decode an Interest message from the reader. The header byte has already
    /// been read to determine this is an Interest (MID=0x19).
    pub fn decode(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Interest {
        const c_flag = (header & Flag.bit5) != 0; // C: bit 5
        const f_flag = (header & Flag.bit6) != 0; // F: bit 6
        const z_flag = (header & Flag.z_flag) != 0; // Z: bit 7

        const id = try vle.decode(reader);

        var interest_flags: ?u8 = null;
        var key_scope: ?u64 = null;
        var key_suffix: ?[]u8 = null;

        // If C or F is set, this is not a final interest — flags byte follows
        if (c_flag or f_flag) {
            interest_flags = try reader.takeByte();
            const flags = interest_flags.?;

            // If R=1 (restricted), decode key_scope
            if ((flags & Flags.restricted) != 0) {
                key_scope = try vle.decode(reader);

                // If R=1 && N=1, decode key_suffix
                if ((flags & Flags.has_suffix) != 0) {
                    key_suffix = try primitives.readString(reader, allocator);
                }
            }
        }

        errdefer if (key_suffix) |s| allocator.free(s);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Interest{
            .id = id,
            .current = c_flag,
            .future = f_flag,
            .interest_flags = interest_flags,
            .key_scope = key_scope,
            .key_suffix = key_suffix,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Declare (MID = 0x1E)
// ═══════════════════════════════════════════════════════════════════════════

/// Declare message: carries declaration sub-messages (e.g., DeclareFinal).
///
/// Wire format (§8.5):
///   header: |Z|X|I| 0x1E |
///   if I=1: interest_id (VLE z32) — responding to an Interest
///   Declaration: inner declaration sub-message (e.g., DeclareFinal)
///
/// **Header Flags:**
/// - I (bit 5, 0x20): Interest response — interest_id follows
/// - X (bit 6, 0x40): Reserved
/// - Z (bit 7, 0x80): Extensions present
///
/// This struct encodes/decodes only the Declare header (MID + interest_id).
/// The inner declaration sub-message must be encoded/decoded separately.
pub const Declare = struct {
    /// Interest ID this declare is responding to (set when I flag is true).
    interest_id: ?u64 = null,

    /// Encode the Declare header to the writer.
    /// The caller must encode the inner declaration sub-message immediately after.
    pub fn encodeHeader(self: *const Declare, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|X|I| MID=0x1E |
        var header: u8 = @as(u8, MID.declare);
        if (self.interest_id != null) header |= Flag.bit5; // I flag
        try writer.writeByte(header);

        // Interest ID (VLE) if I=1
        if (self.interest_id) |id| {
            try vle.encode(id, writer);
        }
    }

    /// Decode a Declare header from the reader. The header byte has already been
    /// parsed to determine this is a Declare (MID=0x1E).
    /// Returns the Declare with fields populated. The remaining bytes are the
    /// inner declaration sub-message, which the caller should decode separately.
    pub fn decodeHeader(header: u8, reader: *Io.Reader) DecodeError!Declare {
        const i_flag = (header & Flag.bit5) != 0; // I: bit 5
        const z_flag = (header & Flag.z_flag) != 0; // Z: bit 7

        var interest_id: ?u64 = null;
        if (i_flag) {
            interest_id = try vle.decode(reader);
        }

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Declare{
            .interest_id = interest_id,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// DeclareFinal (declaration sub-message, sub-MID = 0x1A)
// ═══════════════════════════════════════════════════════════════════════════

/// Declaration sub-message IDs.
pub const DeclareMID = hdr.DeclareMid;

/// DeclareFinal: a declaration sub-message signaling "I have no more declarations."
///
/// Wire format (§10):
///   header: |Z|X|X| 0x1A |
///
/// This is a single-byte sub-message with no additional fields.
/// When Z=1, extensions follow (skipped on decode).
pub const DeclareFinal = struct {
    /// Encode this DeclareFinal to the writer.
    /// Writes a single byte: 0x1A (sub-MID with no flags).
    pub fn encode(_: *const DeclareFinal, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeByte(@as(u8, DeclareMID.declare_final));
    }

    /// Decode a DeclareFinal from the reader. The header byte has already been
    /// read. Validates the sub-MID and skips extensions if Z=1.
    pub fn decode(header: u8, reader: *Io.Reader) (DecodeError || error{Unexpected})!DeclareFinal {
        const parsed = hdr.Header.decode(header);
        if (parsed.mid != DeclareMID.declare_final) {
            return error.Unexpected;
        }

        // Z flag: extensions present
        if (parsed.hasExtensions()) {
            try skipExtensions(reader);
        }

        return DeclareFinal{};
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("../testing.zig").assertEqualBytes;

// ---------------------------------------------------------------------------
// Push header tests
// ---------------------------------------------------------------------------

fn encodePushHeaderHelper(msg: *const Push, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encodeHeader(&writer) catch unreachable;
    return writer.buffered();
}

test "Push: header with key suffix — 'demo/example/hello'" {
    const msg = Push{
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // Header: 0x3D (MID=0x1D | N=0x20)
    // Scope: VLE(0) = 0x00
    // Suffix: VLE(18) = 0x12, then "demo/example/hello"
    try testing.expectEqual(@as(u8, 0x3D), encoded[0]); // header
    try testing.expectEqual(@as(u8, 0x00), encoded[1]); // scope
    try testing.expectEqual(@as(u8, 0x12), encoded[2]); // suffix length = 18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[3..21]);
    try testing.expectEqual(@as(usize, 21), encoded.len);
}

test "Push: header without suffix (N=0)" {
    const msg = Push{
        .key_scope = 42,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // Header: 0x1D (MID=0x1D, N=0)
    // Scope: VLE(42) = 0x2A
    try assertEqualBytes(&.{ 0x1D, 0x2A }, encoded);
}

test "Push: MID is push" {
    const msg = Push{ .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.push), hdr.Header.decode(encoded[0]).mid);
}

test "Push: N flag set when suffix present" {
    const msg = Push{ .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // N flag (bit 5)
}

test "Push: N flag clear when no suffix" {
    const msg = Push{ .key_scope = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // N flag not set
}

test "Push: M flag not set by default (receiver's mapping)" {
    const msg = Push{ .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // M flag not set
}

test "Push: M flag set when sender_mapping is true" {
    const msg = Push{ .key_scope = 1, .sender_mapping = true };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // M flag set
}

test "Push: wire compatibility — header 0x3D matches spec (N=1, M=0)" {
    const msg = Push{ .key_scope = 0, .key_suffix = "key" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    // 0x3D = MID(0x1D) | N(0x20)
    try testing.expectEqual(@as(u8, 0x3D), encoded[0]);
}

test "Push: wire compatibility — header 0x7D for N=1, M=1" {
    const msg = Push{ .key_scope = 0, .key_suffix = "key", .sender_mapping = true };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    // 0x7D = MID(0x1D) | N(0x20) | M(0x40)
    try testing.expectEqual(@as(u8, 0x7D), encoded[0]);
}

test "Push: scope > 127 uses multi-byte VLE" {
    const msg = Push{ .key_scope = 200 };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // Header: 0x1D (no suffix)
    // Scope: VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0x1D, 0xC8, 0x01 }, encoded);
}

// ---------------------------------------------------------------------------
// Push round-trip tests
// ---------------------------------------------------------------------------

test "Push: round-trip with key scope=0, suffix='demo/example/hello'" {
    const original = Push{
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePushHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.push), hdr.Header.decode(header).mid);
    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqualStrings("demo/example/hello", decoded.key_suffix.?);
    try testing.expectEqual(false, decoded.sender_mapping);
}

test "Push: round-trip with key scope=5, no suffix" {
    const original = Push{
        .key_scope = 5,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
    try testing.expectEqual(false, decoded.sender_mapping);
}

test "Push: round-trip with sender_mapping" {
    const original = Push{
        .key_scope = 3,
        .key_suffix = "test/key",
        .sender_mapping = true,
    };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqualStrings("test/key", decoded.key_suffix.?);
    try testing.expectEqual(true, decoded.sender_mapping);
}

test "Push: round-trip with large key_scope" {
    const original = Push{
        .key_scope = 0xFFFFFFFF,
        .key_suffix = "key",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePushHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
}

test "Push: round-trip minimal (scope=0, no suffix, no mapping)" {
    const original = Push{};
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 0), decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
    try testing.expectEqual(false, decoded.sender_mapping);
}

// ---------------------------------------------------------------------------
// Push wire vector tests
// ---------------------------------------------------------------------------

test "Push: wire vector — header=0x3D (N=1, M=0) + scope=0x00 + suffix" {
    const msg = Push{
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // 0x3D: header (MID=0x1D | N=0x20)
    // 0x00: key_scope = 0
    // 0x12: suffix length = 18
    // "demo/example/hello": 18 bytes
    try assertEqualBytes(
        &(.{ 0x3D, 0x00, 0x12 } ++ "demo/example/hello".*),
        encoded,
    );
}

test "Push: wire vector — scope-only (N=0, M=0), scope=5" {
    const msg = Push{ .key_scope = 5 };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // 0x1D: header (MID=0x1D, N=0, M=0)
    // 0x05: key_scope = 5
    try assertEqualBytes(&.{ 0x1D, 0x05 }, encoded);
}

test "Push: wire vector — N=1, M=1 header is 0x7D" {
    const msg = Push{
        .key_scope = 0,
        .key_suffix = "a",
        .sender_mapping = true,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // 0x7D: header (MID=0x1D | N=0x20 | M=0x40)
    // 0x00: key_scope
    // 0x01: suffix length = 1
    // "a": 1 byte
    try assertEqualBytes(&.{ 0x7D, 0x00, 0x01, 'a' }, encoded);
}

// ---------------------------------------------------------------------------
// Push decode with extensions (Z flag)
// ---------------------------------------------------------------------------

test "Push: decode with QoS extension (ZInt, ext 0x01)" {
    // Manually construct a Push wire message with Z=1 and a QoS extension.
    // Header: 0xBD = MID(0x1D) | N(0x20) | Z(0x80)
    // Scope: 0x00
    // Suffix: VLE(3) + "key"
    // Extension: QoS ext header=0x21 (ENC=ZInt, ID=0x01, Z=0), body=VLE(0x05)
    const wire = .{ 0xBD, 0x00, 0x03 } ++ "key".* ++ .{ 0x21, 0x05 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.push), hdr.Header.decode(header).mid);

    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 0), decoded.key_scope);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
    try testing.expectEqual(false, decoded.sender_mapping);
}

test "Push: decode with Timestamp extension (ZBuf, ext 0x02)" {
    // Header: 0xBD = MID(0x1D) | N(0x20) | Z(0x80)
    // Scope: 0x00
    // Suffix: VLE(3) + "key"
    // Extension: Timestamp ext header=0x42 (ENC=ZBuf, ID=0x02, Z=0), body=VLE(2) + 2 bytes
    const wire = .{ 0xBD, 0x00, 0x03 } ++ "key".* ++ .{ 0x42, 0x02, 0xAA, 0xBB };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 0), decoded.key_scope);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
}

test "Push: decode with multiple extensions (QoS + Timestamp)" {
    // Header: 0xBD = MID(0x1D) | N(0x20) | Z(0x80)
    // Scope: 0x00
    // Suffix: VLE(3) + "key"
    // Extension 1: QoS ext header=0xA1 (ENC=ZInt, ID=0x01, Z=1 more), body=VLE(0x05)
    // Extension 2: Timestamp ext header=0x42 (ENC=ZBuf, ID=0x02, Z=0), body=VLE(2) + 2 bytes
    const wire = .{ 0xBD, 0x00, 0x03 } ++ "key".* ++ .{ 0xA1, 0x05, 0x42, 0x02, 0xAA, 0xBB };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 0), decoded.key_scope);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
}

test "Push: decode without extensions (Z=0)" {
    // Header: 0x3D = MID(0x1D) | N(0x20), no Z
    // Scope: 0x00
    // Suffix: VLE(3) + "key"
    const wire = .{ 0x3D, 0x00, 0x03 } ++ "key".*;

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 0), decoded.key_scope);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
}

test "Push: decode with Unit extension (ENC=0b00)" {
    // Header: 0x9D = MID(0x1D) | Z(0x80), no N, no M
    // Scope: 0x05
    // Extension: header=0x01 (ENC=Unit, ID=0x01, Z=0), no body
    const wire = [_]u8{ 0x9D, 0x05, 0x01 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Push.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 5), decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
}

// ---------------------------------------------------------------------------
// Request header tests
// ---------------------------------------------------------------------------

fn encodeRequestHeaderHelper(msg: *const Request, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encodeHeader(&writer) catch unreachable;
    return writer.buffered();
}

test "Request: header with key suffix — 'demo/example/hello', rid=1" {
    const msg = Request{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);

    // Header: 0x3C (MID=0x1C | N=0x20)
    // request_id: VLE(1) = 0x01
    // Scope: VLE(0) = 0x00
    // Suffix: VLE(18) = 0x12, then "demo/example/hello"
    try testing.expectEqual(@as(u8, 0x3C), encoded[0]); // header
    try testing.expectEqual(@as(u8, 0x01), encoded[1]); // request_id
    try testing.expectEqual(@as(u8, 0x00), encoded[2]); // scope
    try testing.expectEqual(@as(u8, 0x12), encoded[3]); // suffix length = 18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[4..22]);
    try testing.expectEqual(@as(usize, 22), encoded.len);
}

test "Request: header without suffix (N=0)" {
    const msg = Request{
        .request_id = 42,
        .key_scope = 5,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);

    // Header: 0x1C (MID=0x1C, N=0)
    // request_id: VLE(42) = 0x2A
    // Scope: VLE(5) = 0x05
    try assertEqualBytes(&.{ 0x1C, 0x2A, 0x05 }, encoded);
}

test "Request: MID is request" {
    const msg = Request{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.request), hdr.Header.decode(encoded[0]).mid);
}

test "Request: N flag set when suffix present" {
    const msg = Request{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // N flag (bit 5)
}

test "Request: N flag clear when no suffix" {
    const msg = Request{ .request_id = 1, .key_scope = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // N flag not set
}

test "Request: M flag not set by default (receiver's mapping)" {
    const msg = Request{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // M flag not set
}

test "Request: M flag set when sender_mapping is true" {
    const msg = Request{ .request_id = 1, .key_scope = 1, .sender_mapping = true };
    var buf: [16]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // M flag set
}

test "Request: wire compatibility — header 0x3C matches spec (N=1, M=0)" {
    const msg = Request{ .request_id = 0, .key_scope = 0, .key_suffix = "key" };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    // 0x3C = MID(0x1C) | N(0x20)
    try testing.expectEqual(@as(u8, 0x3C), encoded[0]);
}

test "Request: wire compatibility — header 0x7C for N=1, M=1" {
    const msg = Request{ .request_id = 0, .key_scope = 0, .key_suffix = "key", .sender_mapping = true };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);
    // 0x7C = MID(0x1C) | N(0x20) | M(0x40)
    try testing.expectEqual(@as(u8, 0x7C), encoded[0]);
}

test "Request: request_id > 127 uses multi-byte VLE" {
    const msg = Request{ .request_id = 200, .key_scope = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);

    // Header: 0x1C (no suffix)
    // request_id: VLE(200) = 0xC8 0x01
    // Scope: VLE(0) = 0x00
    try assertEqualBytes(&.{ 0x1C, 0xC8, 0x01, 0x00 }, encoded);
}

test "Request: round-trip with key suffix" {
    const original = Request{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.request), hdr.Header.decode(header).mid);
    const decoded = try Request.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqualStrings("demo/example/hello", decoded.key_suffix.?);
    try testing.expectEqual(false, decoded.sender_mapping);
}

test "Request: round-trip without suffix" {
    const original = Request{
        .request_id = 999,
        .key_scope = 42,
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Request.decodeHeader(header, &reader, testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
}

test "Request: round-trip with sender_mapping" {
    const original = Request{
        .request_id = 7,
        .key_scope = 3,
        .sender_mapping = true,
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Request.decodeHeader(header, &reader, testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqual(true, decoded.sender_mapping);
}

test "Request: round-trip large request_id" {
    const original = Request{
        .request_id = 0xFFFFFFFF,
        .key_scope = 0,
        .key_suffix = "key",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Request.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqualStrings("key", decoded.key_suffix.?);
}

test "Request: wire vector — query 'demo/example/hello' with rid=1" {
    const msg = Request{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeRequestHeaderHelper(&msg, &buf);

    // 0x3C: header (MID=0x1C | N=0x20)
    // 0x01: request_id = 1
    // 0x00: key_scope = 0
    // 0x12: suffix length = 18
    // "demo/example/hello": 18 bytes
    try assertEqualBytes(
        &(.{ 0x3C, 0x01, 0x00, 0x12 } ++ "demo/example/hello".*),
        encoded,
    );
}

// ---------------------------------------------------------------------------
// Response header tests
// ---------------------------------------------------------------------------

fn encodeResponseHeaderHelper(msg: *const Response, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encodeHeader(&writer) catch unreachable;
    return writer.buffered();
}

test "Response: header with key suffix — 'demo/example/hello', rid=1" {
    const msg = Response{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);

    // Header: 0x3B (MID=0x1B | N=0x20)
    // request_id: VLE(1) = 0x01
    // Scope: VLE(0) = 0x00
    // Suffix: VLE(18) = 0x12, then "demo/example/hello"
    try testing.expectEqual(@as(u8, 0x3B), encoded[0]); // header
    try testing.expectEqual(@as(u8, 0x01), encoded[1]); // request_id
    try testing.expectEqual(@as(u8, 0x00), encoded[2]); // scope
    try testing.expectEqual(@as(u8, 0x12), encoded[3]); // suffix length = 18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[4..22]);
    try testing.expectEqual(@as(usize, 22), encoded.len);
}

test "Response: header without suffix (N=0)" {
    const msg = Response{
        .request_id = 1,
        .key_scope = 10,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);

    // Header: 0x1B (MID=0x1B, N=0)
    // request_id: VLE(1) = 0x01
    // Scope: VLE(10) = 0x0A
    try assertEqualBytes(&.{ 0x1B, 0x01, 0x0A }, encoded);
}

test "Response: MID is response" {
    const msg = Response{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.response), hdr.Header.decode(encoded[0]).mid);
}

test "Response: N flag set when suffix present" {
    const msg = Response{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // N flag (bit 5)
}

test "Response: N flag clear when no suffix" {
    const msg = Response{ .request_id = 1, .key_scope = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // N flag not set
}

test "Response: M flag not set by default" {
    const msg = Response{ .request_id = 1, .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // M flag not set
}

test "Response: M flag set when sender_mapping is true" {
    const msg = Response{ .request_id = 1, .key_scope = 1, .sender_mapping = true };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // M flag set
}

test "Response: wire compatibility — header 0x3B matches spec (N=1, M=0)" {
    const msg = Response{ .request_id = 0, .key_scope = 0, .key_suffix = "key" };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    // 0x3B = MID(0x1B) | N(0x20)
    try testing.expectEqual(@as(u8, 0x3B), encoded[0]);
}

test "Response: wire compatibility — header 0x7B for N=1, M=1" {
    const msg = Response{ .request_id = 0, .key_scope = 0, .key_suffix = "key", .sender_mapping = true };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);
    // 0x7B = MID(0x1B) | N(0x20) | M(0x40)
    try testing.expectEqual(@as(u8, 0x7B), encoded[0]);
}

test "Response: round-trip with key suffix" {
    const original = Response{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.response), hdr.Header.decode(header).mid);
    const decoded = try Response.decodeHeader(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqualStrings("demo/example/hello", decoded.key_suffix.?);
    try testing.expectEqual(false, decoded.sender_mapping);
}

test "Response: round-trip without suffix" {
    const original = Response{
        .request_id = 42,
        .key_scope = 7,
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Response.decodeHeader(header, &reader, testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(original.key_scope, decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
}

test "Response: round-trip with sender_mapping" {
    const original = Response{
        .request_id = 5,
        .key_scope = 2,
        .sender_mapping = true,
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Response.decodeHeader(header, &reader, testing.allocator);

    try testing.expectEqual(original.request_id, decoded.request_id);
    try testing.expectEqual(true, decoded.sender_mapping);
}

test "Response: wire vector — reply to 'demo/example/hello' with rid=1" {
    const msg = Response{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeResponseHeaderHelper(&msg, &buf);

    // 0x3B: header (MID=0x1B | N=0x20)
    // 0x01: request_id = 1
    // 0x00: key_scope = 0
    // 0x12: suffix length = 18
    // "demo/example/hello": 18 bytes
    try assertEqualBytes(
        &(.{ 0x3B, 0x01, 0x00, 0x12 } ++ "demo/example/hello".*),
        encoded,
    );
}

// ---------------------------------------------------------------------------
// ResponseFinal tests
// ---------------------------------------------------------------------------

fn encodeResponseFinalHelper(msg: *const ResponseFinal, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "ResponseFinal: encode with rid=1" {
    const msg = ResponseFinal{ .request_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);

    // Header: 0x1A (MID=0x1A, no flags)
    // request_id: VLE(1) = 0x01
    try assertEqualBytes(&.{ 0x1A, 0x01 }, encoded);
}

test "ResponseFinal: encode with rid=0" {
    const msg = ResponseFinal{ .request_id = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);

    try assertEqualBytes(&.{ 0x1A, 0x00 }, encoded);
}

test "ResponseFinal: MID is response_final" {
    const msg = ResponseFinal{ .request_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.response_final), hdr.Header.decode(encoded[0]).mid);
}

test "ResponseFinal: no flags set" {
    const msg = ResponseFinal{ .request_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0());
    try testing.expect(!h.flag1());
    try testing.expect(!h.flag2());
}

test "ResponseFinal: request_id > 127 uses multi-byte VLE" {
    const msg = ResponseFinal{ .request_id = 200 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);

    // Header: 0x1A
    // request_id: VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0x1A, 0xC8, 0x01 }, encoded);
}

test "ResponseFinal: round-trip with rid=1" {
    const original = ResponseFinal{ .request_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.response_final), hdr.Header.decode(header).mid);
    const decoded = try ResponseFinal.decode(header, &reader);

    try testing.expectEqual(original.request_id, decoded.request_id);
}

test "ResponseFinal: round-trip with large rid" {
    const original = ResponseFinal{ .request_id = 0xFFFFFFFF };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try ResponseFinal.decode(header, &reader);

    try testing.expectEqual(original.request_id, decoded.request_id);
}

test "ResponseFinal: wire vector — rid=1" {
    const msg = ResponseFinal{ .request_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeResponseFinalHelper(&msg, &buf);
    try assertEqualBytes(&.{ 0x1A, 0x01 }, encoded);
}

// ---------------------------------------------------------------------------
// Request/Response/ResponseFinal interaction tests
// ---------------------------------------------------------------------------

test "request_id echo: Response.request_id == Request.request_id" {
    const request = Request{
        .request_id = 42,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var req_buf: [64]u8 = undefined;
    const req_encoded = encodeRequestHeaderHelper(&request, &req_buf);

    // Decode the request to extract request_id
    var req_reader: Io.Reader = .fixed(req_encoded);
    const req_header = try req_reader.takeByte();
    const decoded_req = try Request.decodeHeader(req_header, &req_reader, testing.allocator);
    defer decoded_req.deinit(testing.allocator);

    // Build a response echoing the request_id
    const response = Response{
        .request_id = decoded_req.request_id,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var resp_buf: [64]u8 = undefined;
    const resp_encoded = encodeResponseHeaderHelper(&response, &resp_buf);

    // Decode the response
    var resp_reader: Io.Reader = .fixed(resp_encoded);
    const resp_header = try resp_reader.takeByte();
    const decoded_resp = try Response.decodeHeader(resp_header, &resp_reader, testing.allocator);
    defer decoded_resp.deinit(testing.allocator);

    // The request_id must match
    try testing.expectEqual(request.request_id, decoded_resp.request_id);
    try testing.expectEqual(decoded_req.request_id, decoded_resp.request_id);
}

test "ResponseFinal matches Request request_id" {
    const request = Request{
        .request_id = 77,
        .key_scope = 0,
        .key_suffix = "test/key",
    };
    var req_buf: [64]u8 = undefined;
    const req_encoded = encodeRequestHeaderHelper(&request, &req_buf);

    // Decode the request
    var req_reader: Io.Reader = .fixed(req_encoded);
    const req_header = try req_reader.takeByte();
    const decoded_req = try Request.decodeHeader(req_header, &req_reader, testing.allocator);
    defer decoded_req.deinit(testing.allocator);

    // Build a ResponseFinal with the same request_id
    const resp_final = ResponseFinal{
        .request_id = decoded_req.request_id,
    };
    var final_buf: [16]u8 = undefined;
    const final_encoded = encodeResponseFinalHelper(&resp_final, &final_buf);

    // Decode the ResponseFinal
    var final_reader: Io.Reader = .fixed(final_encoded);
    const final_header = try final_reader.takeByte();
    const decoded_final = try ResponseFinal.decode(final_header, &final_reader);

    // The request_id must match
    try testing.expectEqual(request.request_id, decoded_final.request_id);
}

test "full query sequence: Request → Response → ResponseFinal wire vectors" {
    // Simulate the wire sequence from §9: query "demo/example/hello" with rid=1

    // 1. Request header
    const request = Request{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var req_buf: [64]u8 = undefined;
    const req_encoded = encodeRequestHeaderHelper(&request, &req_buf);
    try assertEqualBytes(
        &(.{ 0x3C, 0x01, 0x00, 0x12 } ++ "demo/example/hello".*),
        req_encoded,
    );

    // 2. Response header (echoing rid=1)
    const response = Response{
        .request_id = 1,
        .key_scope = 0,
        .key_suffix = "demo/example/hello",
    };
    var resp_buf: [64]u8 = undefined;
    const resp_encoded = encodeResponseHeaderHelper(&response, &resp_buf);
    try assertEqualBytes(
        &(.{ 0x3B, 0x01, 0x00, 0x12 } ++ "demo/example/hello".*),
        resp_encoded,
    );

    // 3. ResponseFinal (rid=1)
    const resp_final = ResponseFinal{ .request_id = 1 };
    var final_buf: [16]u8 = undefined;
    const final_encoded = encodeResponseFinalHelper(&resp_final, &final_buf);
    try assertEqualBytes(&.{ 0x1A, 0x01 }, final_encoded);

    // Verify all three share the same request_id after decode
    var r1: Io.Reader = .fixed(req_encoded);
    const h1 = try r1.takeByte();
    const d1 = try Request.decodeHeader(h1, &r1, testing.allocator);
    defer d1.deinit(testing.allocator);

    var r2: Io.Reader = .fixed(resp_encoded);
    const h2 = try r2.takeByte();
    const d2 = try Response.decodeHeader(h2, &r2, testing.allocator);
    defer d2.deinit(testing.allocator);

    var r3: Io.Reader = .fixed(final_encoded);
    const h3 = try r3.takeByte();
    const d3 = try ResponseFinal.decode(h3, &r3);

    try testing.expectEqual(@as(u64, 1), d1.request_id);
    try testing.expectEqual(@as(u64, 1), d2.request_id);
    try testing.expectEqual(@as(u64, 1), d3.request_id);
}

// ---------------------------------------------------------------------------
// Interest tests
// ---------------------------------------------------------------------------

test "Interest: decode typical router interest (C=1, F=1, flags=0xFF)" {
    // Header: 0x79 = MID(0x19) | C(0x20) | F(0x40)
    // id: VLE(1) = 0x01
    // interest_flags: 0xFF (all flags set: K,S,Q,T,R,N,M,A)
    // key_scope: VLE(0) = 0x00 (R=1 so key_scope present)
    // key_suffix: VLE(4) + "test" (R=1 && N=1 so suffix present)
    const wire = [_]u8{ 0x79, 0x01, 0xFF, 0x00, 0x04 } ++ "test".*;

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.interest), hdr.Header.decode(header).mid);

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(decoded.future);
    try testing.expectEqual(@as(u8, 0xFF), decoded.interest_flags.?);
    try testing.expectEqual(@as(u64, 0), decoded.key_scope.?);
    try testing.expectEqualStrings("test", decoded.key_suffix.?);
    try testing.expect(!decoded.isFinal());
}

test "Interest: decode final interest (C=0, F=0)" {
    // Header: 0x19 = MID(0x19), no C, no F, no Z
    // id: VLE(5) = 0x05
    // No flags byte (final interest)
    const wire = [_]u8{ 0x19, 0x05 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.interest), hdr.Header.decode(header).mid);

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 5), decoded.id);
    try testing.expect(!decoded.current);
    try testing.expect(!decoded.future);
    try testing.expectEqual(@as(?u8, null), decoded.interest_flags);
    try testing.expectEqual(@as(?u64, null), decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
    try testing.expect(decoded.isFinal());
}

test "Interest: decode with C=1 only, flags=0x0F (K,S,Q,T but no R)" {
    // Header: 0x39 = MID(0x19) | C(0x20)
    // id: VLE(3) = 0x03
    // interest_flags: 0x0F (K=1, S=1, Q=1, T=1, R=0)
    // No key_scope or suffix (R=0)
    const wire = [_]u8{ 0x39, 0x03, 0x0F };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 3), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(!decoded.future);
    try testing.expectEqual(@as(u8, 0x0F), decoded.interest_flags.?);
    try testing.expectEqual(@as(?u64, null), decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
    try testing.expect(!decoded.isFinal());
}

test "Interest: decode with F=1 only, flags=0x0F" {
    // Header: 0x59 = MID(0x19) | F(0x40)
    // id: VLE(7) = 0x07
    // interest_flags: 0x0F
    const wire = [_]u8{ 0x59, 0x07, 0x0F };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 7), decoded.id);
    try testing.expect(!decoded.current);
    try testing.expect(decoded.future);
    try testing.expectEqual(@as(u8, 0x0F), decoded.interest_flags.?);
    try testing.expectEqual(@as(?u64, null), decoded.key_scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
    try testing.expect(!decoded.isFinal());
}

test "Interest: decode with R=1 but N=0 (key_scope only, no suffix)" {
    // Header: 0x79 = MID(0x19) | C(0x20) | F(0x40)
    // id: VLE(2) = 0x02
    // interest_flags: 0x10 (R=1 only)
    // key_scope: VLE(42) = 0x2A
    // No suffix (N=0)
    const wire = [_]u8{ 0x79, 0x02, 0x10, 0x2A };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 2), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(decoded.future);
    try testing.expectEqual(@as(u8, 0x10), decoded.interest_flags.?);
    try testing.expectEqual(@as(u64, 42), decoded.key_scope.?);
    try testing.expectEqual(@as(?[]const u8, null), decoded.key_suffix);
}

test "Interest: decode with extensions (Z=1)" {
    // Header: 0xF9 = MID(0x19) | C(0x20) | F(0x40) | Z(0x80)
    // id: VLE(1) = 0x01
    // interest_flags: 0x0F (no R, so no key_scope/suffix)
    // Extension: Unit ext header=0x01 (ENC=Unit, ID=0x01, Z=0), no body
    const wire = [_]u8{ 0xF9, 0x01, 0x0F, 0x01 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(decoded.future);
    try testing.expectEqual(@as(u8, 0x0F), decoded.interest_flags.?);
}

test "Interest: decode final interest with extensions (Z=1, C=0, F=0)" {
    // Header: 0x99 = MID(0x19) | Z(0x80)
    // id: VLE(10) = 0x0A
    // No flags byte (final)
    // Extension: ZInt ext header=0x21 (ENC=ZInt, ID=0x01, Z=0), body=VLE(0x05)
    const wire = [_]u8{ 0x99, 0x0A, 0x21, 0x05 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 10), decoded.id);
    try testing.expect(decoded.isFinal());
    try testing.expectEqual(@as(?u8, null), decoded.interest_flags);
}

test "Interest: decode with large id (multi-byte VLE)" {
    // Header: 0x19 = MID(0x19), final
    // id: VLE(200) = 0xC8 0x01
    const wire = [_]u8{ 0x19, 0xC8, 0x01 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 200), decoded.id);
    try testing.expect(decoded.isFinal());
}

test "Interest: wire vector — typical router interest C=1,F=1,flags=0x0F no key" {
    // Router sends: Interest(id=1, C=1, F=1, flags=0x0F)
    // No R flag, so no key_scope/suffix
    // Header: 0x79 = MID(0x19) | C(0x20) | F(0x40)
    // id: 0x01
    // flags: 0x0F
    const wire = [_]u8{ 0x79, 0x01, 0x0F };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.interest), hdr.Header.decode(header).mid);

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(decoded.future);
    try testing.expectEqual(@as(u8, 0x0F), decoded.interest_flags.?);
}

test "Interest: MID is interest" {
    // Just verify a header byte with MID=0x19 is parsed correctly
    const h = hdr.Header.decode(0x79);
    try testing.expectEqual(@as(u5, MID.interest), h.mid);
    try testing.expect(h.flag0()); // C
    try testing.expect(h.flag1()); // F
    try testing.expect(!h.flag2()); // no Z
}

test "Interest: decode with R=1 and N=1, key_suffix present" {
    // Header: 0x39 = MID(0x19) | C(0x20)
    // id: VLE(4) = 0x04
    // interest_flags: 0x31 (K=1, R=1, N=1)
    // key_scope: VLE(0) = 0x00
    // key_suffix: VLE(12) + "demo/test/**"
    const wire = [_]u8{ 0x39, 0x04, 0x31, 0x00, 0x0C } ++ "demo/test/**".*;

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();

    const decoded = try Interest.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 4), decoded.id);
    try testing.expect(decoded.current);
    try testing.expect(!decoded.future);
    try testing.expectEqual(@as(u8, 0x31), decoded.interest_flags.?);
    try testing.expectEqual(@as(u64, 0), decoded.key_scope.?);
    try testing.expectEqualStrings("demo/test/**", decoded.key_suffix.?);
}

// ---------------------------------------------------------------------------
// Declare header tests
// ---------------------------------------------------------------------------

fn encodeDeclareHeaderHelper(msg: *const Declare, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encodeHeader(&writer) catch unreachable;
    return writer.buffered();
}

test "Declare: encodeHeader with I=1, interest_id=1" {
    const msg = Declare{ .interest_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);

    // Header: 0x3E (MID=0x1E | I=0x20)
    // interest_id: VLE(1) = 0x01
    try assertEqualBytes(&.{ 0x3E, 0x01 }, encoded);
}

test "Declare: encodeHeader with I=0 (no interest_id)" {
    const msg = Declare{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);

    // Header: 0x1E (MID=0x1E, no flags)
    try assertEqualBytes(&.{0x1E}, encoded);
}

test "Declare: MID is declare" {
    const msg = Declare{ .interest_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.declare), hdr.Header.decode(encoded[0]).mid);
}

test "Declare: I flag set when interest_id present" {
    const msg = Declare{ .interest_id = 5 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // I flag (bit 5)
}

test "Declare: I flag clear when no interest_id" {
    const msg = Declare{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // I flag not set
}

test "Declare: no Z flag set (extensions not supported for encode)" {
    const msg = Declare{ .interest_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag2()); // Z flag not set
}

test "Declare: wire compatibility — header 0x3E matches spec (I=1)" {
    const msg = Declare{ .interest_id = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    // 0x3E = MID(0x1E) | I(0x20)
    try testing.expectEqual(@as(u8, 0x3E), encoded[0]);
}

test "Declare: interest_id > 127 uses multi-byte VLE" {
    const msg = Declare{ .interest_id = 200 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);

    // Header: 0x3E (MID=0x1E | I=0x20)
    // interest_id: VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0x3E, 0xC8, 0x01 }, encoded);
}

test "Declare: round-trip with I=1, interest_id=1" {
    const original = Declare{ .interest_id = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.declare), hdr.Header.decode(header).mid);
    const decoded = try Declare.decodeHeader(header, &reader);

    try testing.expectEqual(original.interest_id, decoded.interest_id);
}

test "Declare: round-trip with I=0 (no interest_id)" {
    const original = Declare{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Declare.decodeHeader(header, &reader);

    try testing.expectEqual(@as(?u64, null), decoded.interest_id);
}

test "Declare: round-trip with large interest_id" {
    const original = Declare{ .interest_id = 0xFFFFFFFF };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Declare.decodeHeader(header, &reader);

    try testing.expectEqual(original.interest_id, decoded.interest_id);
}

test "Declare: decode with extensions (Z=1)" {
    // Header: 0xBE = MID(0x1E) | I(0x20) | Z(0x80)
    // interest_id: VLE(1) = 0x01
    // Extension: Unit ext header=0x01 (ENC=Unit, ID=0x01, Z=0), no body
    const wire = [_]u8{ 0xBE, 0x01, 0x01 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.declare), hdr.Header.decode(header).mid);

    const decoded = try Declare.decodeHeader(header, &reader);

    try testing.expectEqual(@as(u64, 1), decoded.interest_id.?);
}

test "Declare: wire vector — I=1, interest_id=0" {
    const msg = Declare{ .interest_id = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeDeclareHeaderHelper(&msg, &buf);
    try assertEqualBytes(&.{ 0x3E, 0x00 }, encoded);
}

// ---------------------------------------------------------------------------
// DeclareFinal (declaration sub-message) tests
// ---------------------------------------------------------------------------

fn encodeDeclareSubFinalHelper(msg: *const DeclareFinal, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "DeclareFinal: encode produces 0x1A" {
    const msg = DeclareFinal{};
    var buf: [4]u8 = undefined;
    const encoded = encodeDeclareSubFinalHelper(&msg, &buf);

    try assertEqualBytes(&.{0x1A}, encoded);
}

test "DeclareFinal: round-trip encode/decode" {
    const original = DeclareFinal{};
    var buf: [4]u8 = undefined;
    const encoded = encodeDeclareSubFinalHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try DeclareFinal.decode(header, &reader);
    _ = decoded;

    // DeclareFinal has no fields; reaching here without error means success
}

test "DeclareFinal: decode validates sub-MID" {
    // Pass an invalid header byte (not 0x1A)
    const wire = [_]u8{0x01}; // Wrong MID

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    const result = DeclareFinal.decode(header, &reader);
    try testing.expectError(error.Unexpected, result);
}

test "DeclareFinal: decode with extensions (Z=1)" {
    // Header: 0x9A = sub-MID(0x1A) | Z(0x80)
    // Extension: Unit ext header=0x01 (ENC=Unit, ID=0x01, Z=0), no body
    const wire = [_]u8{ 0x9A, 0x01 };

    var reader: Io.Reader = .fixed(&wire);
    const header = try reader.takeByte();
    const decoded = try DeclareFinal.decode(header, &reader);
    _ = decoded;

    // Reaching here without error means extensions were skipped correctly
}

// ---------------------------------------------------------------------------
// Combined Declare + DeclareFinal tests
// ---------------------------------------------------------------------------

test "Declare + DeclareFinal: combined encoding for interest response" {
    // Simulate: Declare(I=1, interest_id=1) + DeclareFinal
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    const declare = Declare{ .interest_id = 1 };
    try declare.encodeHeader(&writer);

    const declare_final = DeclareFinal{};
    try declare_final.encode(&writer);

    const encoded = writer.buffered();

    // Expected: 0x3E (Declare header, I=1) + 0x01 (interest_id=1) + 0x1A (DeclareFinal)
    try assertEqualBytes(&.{ 0x3E, 0x01, 0x1A }, encoded);
}

test "Declare + DeclareFinal: combined round-trip" {
    // Encode
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    const original_declare = Declare{ .interest_id = 5 };
    try original_declare.encodeHeader(&writer);

    const original_final = DeclareFinal{};
    try original_final.encode(&writer);

    const encoded = writer.buffered();

    // Decode
    var reader: Io.Reader = .fixed(encoded);
    const declare_header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.declare), hdr.Header.decode(declare_header).mid);
    const decoded_declare = try Declare.decodeHeader(declare_header, &reader);
    try testing.expectEqual(@as(u64, 5), decoded_declare.interest_id.?);

    const sub_header = try reader.takeByte();
    const decoded_final = try DeclareFinal.decode(sub_header, &reader);
    _ = decoded_final;
}

test "Declare + DeclareFinal: wire vector for interest_id=0" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    const declare = Declare{ .interest_id = 0 };
    try declare.encodeHeader(&writer);

    const declare_final = DeclareFinal{};
    try declare_final.encode(&writer);

    const encoded = writer.buffered();

    // Expected: 0x3E (Declare header, I=1) + 0x00 (interest_id=0) + 0x1A (DeclareFinal)
    try assertEqualBytes(&.{ 0x3E, 0x00, 0x1A }, encoded);
}

test "Declare + DeclareFinal: wire vector for large interest_id" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    const declare = Declare{ .interest_id = 200 };
    try declare.encodeHeader(&writer);

    const declare_final = DeclareFinal{};
    try declare_final.encode(&writer);

    const encoded = writer.buffered();

    // Expected: 0x3E + VLE(200)=0xC8,0x01 + 0x1A
    try assertEqualBytes(&.{ 0x3E, 0xC8, 0x01, 0x1A }, encoded);
}

test {
    std.testing.refAllDecls(@This());
}
