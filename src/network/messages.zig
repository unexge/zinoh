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

test {
    std.testing.refAllDecls(@This());
}
