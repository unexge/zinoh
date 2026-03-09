//! Zenoh messages: Put, Del, Query, Reply, Err.
//!
//! Implements encode for Zenoh-layer messages per Zenoh protocol v0x09.
//! These messages are carried inside network messages (Push, Request, Response).

const std = @import("std");
const Io = std.Io;
const vle = @import("../codec/vle.zig");
const primitives = @import("../codec/primitives.zig");
const hdr = @import("../codec/header.zig");

/// Zenoh-layer message IDs.
pub const MID = hdr.ZenohMid;

/// Flag masks for Zenoh messages.
pub const Flag = struct {
    /// Bit 5 (0x20): T=timestamp present (Put, Del).
    pub const bit5: u8 = 0x20;
    /// Bit 6 (0x40): E=encoding present (Put, Err), P=parameters (Query).
    pub const bit6: u8 = 0x40;
    /// Bit 7 (0x80): Z=extensions present.
    pub const z_flag: u8 = 0x80;
};

// ═══════════════════════════════════════════════════════════════════════════
// Encoding (Data Encoding — §2.10)
// ═══════════════════════════════════════════════════════════════════════════

/// Data encoding: an encoding ID with an optional schema string.
///
/// Wire format (§2.10):
///   VLE: (id << 1) | has_schema
///   if has_schema: VLE-length-prefixed UTF-8 schema string
pub const Encoding = struct {
    id: u16 = 0,
    schema: ?[]const u8 = null,

    /// Encode this Encoding to the writer.
    pub fn encode(self: *const Encoding, writer: *Io.Writer) Io.Writer.Error!void {
        const has_schema = if (self.schema) |s| s.len > 0 else false;
        const encoded_id: u64 = (@as(u64, self.id) << 1) | @as(u64, @intFromBool(has_schema));
        try vle.encode(encoded_id, writer);
        if (has_schema) {
            try primitives.writeString(self.schema.?, writer);
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Put (MID = 0x01)
// ═══════════════════════════════════════════════════════════════════════════

/// Put message: carries a key-value sample.
///
/// Wire format (§9.1):
///   header: |Z|E|T| 0x01 |
///   if T=1: timestamp (VLE time + ZenohID)
///   if E=1: encoding (§2.10)
///   if Z=1: extensions
///   payload: VLE-length-prefixed bytes
pub const Put = struct {
    /// Optional encoding (sets E flag when present).
    encoding: ?Encoding = null,
    // timestamp: not yet implemented (would set T flag)
    /// Payload bytes.
    payload: []const u8,

    /// Encode this Put message to the writer.
    pub fn encode(self: *const Put, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|E|T| MID=0x01 |
        var header: u8 = @as(u8, MID.put);
        // T flag (bit 5): timestamp present — not yet supported
        if (self.encoding != null) header |= Flag.bit6; // E flag
        // Z flag (bit 7): extensions — not yet supported
        try writer.writeByte(header);

        // Encoding (if E=1)
        if (self.encoding) |enc| {
            try enc.encode(writer);
        }

        // Payload (VLE-length-prefixed)
        try primitives.writeSlice(self.payload, writer);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("../testing.zig").assertEqualBytes;

// ---------------------------------------------------------------------------
// Encoding tests
// ---------------------------------------------------------------------------

fn encodeEncodingHelper(enc: *const Encoding, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    enc.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Encoding: id=0, no schema → VLE(0) = 0x00" {
    const enc = Encoding{ .id = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    try assertEqualBytes(&.{0x00}, encoded);
}

test "Encoding: id=10, no schema → VLE(20) = 0x14" {
    const enc = Encoding{ .id = 10 };
    var buf: [16]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    // 10 << 1 = 20 = 0x14
    try assertEqualBytes(&.{0x14}, encoded);
}

test "Encoding: id=0, with schema → VLE(1) + VLE-string" {
    const enc = Encoding{ .id = 0, .schema = "text" };
    var buf: [32]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    // (0 << 1) | 1 = 1 = VLE(1) = 0x01
    // schema: VLE(4) + "text"
    try assertEqualBytes(&.{ 0x01, 0x04, 't', 'e', 'x', 't' }, encoded);
}

test "Encoding: id=10, with schema → VLE(21) + VLE-string" {
    const enc = Encoding{ .id = 10, .schema = "json" };
    var buf: [32]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    // (10 << 1) | 1 = 21 = 0x15
    // schema: VLE(4) + "json"
    try assertEqualBytes(&.{ 0x15, 0x04, 'j', 's', 'o', 'n' }, encoded);
}

test "Encoding: id=0, empty schema is same as no schema" {
    const enc = Encoding{ .id = 0, .schema = "" };
    var buf: [16]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    // Empty schema → has_schema=false → VLE(0)
    try assertEqualBytes(&.{0x00}, encoded);
}

// ---------------------------------------------------------------------------
// Put tests
// ---------------------------------------------------------------------------

fn encodePutHelper(msg: *const Put, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Put: minimal (no encoding, no timestamp) — 'Hello World!'" {
    const msg = Put{ .payload = "Hello World!" };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x01 (MID=0x01, T=0, E=0, Z=0)
    // Payload: VLE(12) = 0x0C + "Hello World!"
    try testing.expectEqual(@as(u8, 0x01), encoded[0]);
    try testing.expectEqual(@as(u8, 0x0C), encoded[1]);
    try assertEqualBytes(
        &(.{ 0x01, 0x0C } ++ "Hello World!".*),
        encoded,
    );
}

test "Put: empty payload" {
    const msg = Put{ .payload = "" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x01, Payload: VLE(0) = 0x00
    try assertEqualBytes(&.{ 0x01, 0x00 }, encoded);
}

test "Put: with encoding (E flag set)" {
    const msg = Put{
        .encoding = .{ .id = 10 },
        .payload = "data",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x41 (MID=0x01 | E=0x40)
    // Encoding: VLE(20) = 0x14
    // Payload: VLE(4) = 0x04 + "data"
    try assertEqualBytes(
        &.{ 0x41, 0x14, 0x04, 'd', 'a', 't', 'a' },
        encoded,
    );
}

test "Put: MID is put" {
    const msg = Put{ .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.put), hdr.Header.decode(encoded[0]).mid);
}

test "Put: E flag clear when no encoding" {
    const msg = Put{ .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // E flag (bit 6)
}

test "Put: E flag set when encoding present" {
    const msg = Put{ .encoding = .{ .id = 0 }, .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // E flag (bit 6)
}

test "Put: large payload (> 127 bytes uses multi-byte VLE length)" {
    var payload: [200]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    const msg = Put{ .payload = &payload };
    var buf: [256]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x01
    try testing.expectEqual(@as(u8, 0x01), encoded[0]);
    // VLE(200) = 0xC8 0x01 (200 = 0b11001000, 7 bits = 0b1001000 = 0x48 | 0x80, then 0x01)
    try testing.expectEqual(@as(u8, 0xC8), encoded[1]);
    try testing.expectEqual(@as(u8, 0x01), encoded[2]);
    // Payload follows
    try testing.expectEqualSlices(u8, &payload, encoded[3..203]);
}

test {
    std.testing.refAllDecls(@This());
}
