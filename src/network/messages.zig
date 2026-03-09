//! Network messages: Push, Request, Response, ResponseFinal.
//!
//! Implements encode for network-layer messages per Zenoh protocol v0x09.
//! Network messages are carried inside Frame (or Fragment) transport messages.

const std = @import("std");
const Io = std.Io;
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
/// This struct encodes only the Push header + key expression.
/// The inner Zenoh message (Put/Del) must be encoded separately after.
pub const Push = struct {
    /// Key expression numeric ID (0 if using string-only key).
    key_scope: u64 = 0,
    /// Key expression string suffix (sets N flag when non-null).
    key_suffix: ?[]const u8 = null,
    // sender_mapping: bool = false,  // M flag — not yet needed

    /// Encode the Push header and key expression to the writer.
    /// The caller must encode the inner Zenoh message (Put/Del) immediately after.
    pub fn encodeHeader(self: *const Push, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|M|N| MID=0x1D |
        var header: u8 = @as(u8, MID.push);
        if (self.key_suffix != null) header |= Flag.bit5; // N flag
        // M flag (bit 6): sender's mapping — not set (receiver's mapping)
        // Z flag (bit 7): extensions — not yet supported
        try writer.writeByte(header);

        // Key scope (VLE)
        try vle.encode(self.key_scope, writer);

        // Key suffix (if N=1)
        if (self.key_suffix) |suffix| {
            try primitives.writeString(suffix, writer);
        }
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

test "Push: M flag not set (receiver's mapping)" {
    const msg = Push{ .key_suffix = "test" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // M flag not set
}

test "Push: wire compatibility — header 0x3D matches spec (N=1, M=0)" {
    const msg = Push{ .key_scope = 0, .key_suffix = "key" };
    var buf: [32]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);
    // 0x3D = MID(0x1D) | N(0x20)
    try testing.expectEqual(@as(u8, 0x3D), encoded[0]);
}

test "Push: scope > 127 uses multi-byte VLE" {
    const msg = Push{ .key_scope = 200 };
    var buf: [16]u8 = undefined;
    const encoded = encodePushHeaderHelper(&msg, &buf);

    // Header: 0x1D (no suffix)
    // Scope: VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0x1D, 0xC8, 0x01 }, encoded);
}

test {
    std.testing.refAllDecls(@This());
}
