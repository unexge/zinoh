//! Key expression encoding/decoding for network-layer messages.
//!
//! A key expression identifies a resource in the Zenoh key space and appears
//! in Push, Request, and Response network messages.
//!
//! Wire format (PROTOCOL_BASIC.md §6, §7):
//!   key_scope: VLE-encoded numeric ID (u16 range, 0 if no pre-declared key)
//!   if N=1: key_suffix — VLE-length + UTF-8 string suffix
//!
//! Flag bits in the network message header:
//!   N (bit 5, 0x20): 1 if string suffix is present
//!   M (bit 6, 0x40): 1 if sender's mapping (client-side key expression ID)

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const vle = @import("../codec/vle.zig");
const primitives = @import("../codec/primitives.zig");

/// N flag mask (bit 5): key has string suffix.
pub const n_flag: u8 = 0x20;
/// M flag mask (bit 6): sender's mapping (client-side key expression ID).
pub const m_flag: u8 = 0x40;

/// A key expression consisting of a numeric scope ID and an optional string suffix.
///
/// The `scope` is a VLE-encoded numeric ID in the u16 range (0 if no
/// pre-declared key expression). The `suffix` is an optional UTF-8 string
/// that extends the key expression (present when the N flag is set).
/// `sender_mapping` indicates whether the scope ID was declared by the sender
/// (M flag) rather than the receiver.
pub const KeyExpr = struct {
    /// Key expression numeric ID (0 if using string-only key).
    scope: u16 = 0,
    /// Key expression string suffix (sets N flag when non-null).
    suffix: ?[]const u8 = null,
    /// Sender's mapping (M flag). If true, scope is from sender's key table.
    sender_mapping: bool = false,

    /// Free allocator-owned memory from a decoded KeyExpr.
    /// Must be called with the same allocator passed to `decode`.
    pub fn deinit(self: *const KeyExpr, allocator: Allocator) void {
        if (self.suffix) |s| allocator.free(@constCast(s));
    }

    /// Encode the key expression (scope + optional suffix) to the writer.
    ///
    /// This encodes only the key expression body — the caller is responsible
    /// for encoding the message header byte (with appropriate N/M flags).
    pub fn encode(self: *const KeyExpr, writer: *Io.Writer) Io.Writer.Error!void {
        // Scope: VLE-encoded u16
        try vle.encode(@intCast(self.scope), writer);

        // Suffix: VLE-length + UTF-8 string (only when suffix is present)
        if (self.suffix) |s| {
            try primitives.writeString(s, writer);
        }
    }

    /// Decode a key expression from the reader.
    ///
    /// `has_suffix` should be derived from the N flag (bit 5) of the message
    /// header that was already consumed by the caller.
    /// `sender_mapping` is not decoded from the wire (it lives in the header
    /// M flag) — the caller must set it on the returned KeyExpr if needed.
    /// Caller owns suffix memory (if non-null) and must call `deinit`.
    pub fn decode(reader: *Io.Reader, has_suffix: bool, allocator: Allocator) DecodeError!KeyExpr {
        const scope_raw = try vle.decode(reader);
        const scope = std.math.cast(u16, scope_raw) orelse return error.ScopeOverflow;

        var suffix: ?[]u8 = null;
        errdefer if (suffix) |s| allocator.free(s);
        if (has_suffix) {
            suffix = try primitives.readString(reader, allocator);
        }

        return KeyExpr{
            .scope = scope,
            .suffix = suffix,
        };
    }

    /// Returns true if this key expression has a string suffix (N flag = 1).
    pub fn hasName(self: *const KeyExpr) bool {
        return self.suffix != null;
    }

    /// Derive the N and M flag bits for a network message header.
    ///
    /// Returns a bitmask suitable for OR-ing into a header byte:
    ///   - Bit 5 (0x20): N flag — set when suffix is present
    ///   - Bit 6 (0x40): M flag — set when sender_mapping is true
    pub fn headerFlags(self: *const KeyExpr) u8 {
        var flags: u8 = 0;
        if (self.suffix != null) flags |= n_flag;
        if (self.sender_mapping) flags |= m_flag;
        return flags;
    }
};

/// Errors that can occur when decoding a KeyExpr.
pub const DecodeError = Io.Reader.ReadAllocError || error{ScopeOverflow};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("../testing.zig").assertEqualBytes;

/// Helper: encode a KeyExpr and return the encoded bytes.
fn encodeHelper(key: *const KeyExpr, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    key.encode(&writer) catch unreachable;
    return writer.buffered();
}

// ---------------------------------------------------------------------------
// Encode tests
// ---------------------------------------------------------------------------

test "KeyExpr: encode scope=0, suffix='demo/example/hello'" {
    const key = KeyExpr{
        .scope = 0,
        .suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(0) = 0x00
    // Suffix: VLE(18) = 0x12, then "demo/example/hello"
    try testing.expectEqual(@as(u8, 0x00), encoded[0]); // scope
    try testing.expectEqual(@as(u8, 0x12), encoded[1]); // suffix length = 18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[2..20]);
    try testing.expectEqual(@as(usize, 20), encoded.len);
}

test "KeyExpr: encode scope=5, no suffix" {
    const key = KeyExpr{
        .scope = 5,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(5) = 0x05
    try assertEqualBytes(&.{0x05}, encoded);
}

test "KeyExpr: encode scope=0, no suffix (minimal)" {
    const key = KeyExpr{};
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(0) = 0x00
    try assertEqualBytes(&.{0x00}, encoded);
}

test "KeyExpr: encode scope=42, suffix='test'" {
    const key = KeyExpr{
        .scope = 42,
        .suffix = "test",
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(42) = 0x2A
    // Suffix: VLE(4) = 0x04, then "test"
    try assertEqualBytes(&(.{0x2A, 0x04} ++ "test".*), encoded);
}

test "KeyExpr: encode scope > 127 uses multi-byte VLE" {
    const key = KeyExpr{
        .scope = 200,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0xC8, 0x01 }, encoded);
}

test "KeyExpr: encode scope=0xFFFF (max u16)" {
    const key = KeyExpr{
        .scope = 0xFFFF,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(65535) = 0xFF 0xFF 0x03
    try assertEqualBytes(&.{ 0xFF, 0xFF, 0x03 }, encoded);
}

test "KeyExpr: encode empty suffix" {
    const key = KeyExpr{
        .scope = 0,
        .suffix = "",
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // Scope: VLE(0) = 0x00
    // Suffix: VLE(0) = 0x00 (empty string)
    try assertEqualBytes(&.{ 0x00, 0x00 }, encoded);
}

// ---------------------------------------------------------------------------
// Decode tests
// ---------------------------------------------------------------------------

test "KeyExpr: decode scope=0, suffix='demo/example/hello'" {
    const wire = .{0x00, 0x12} ++ "demo/example/hello".*;
    var reader: Io.Reader = .fixed(&wire);
    const key = try KeyExpr.decode(&reader, true, testing.allocator);
    defer key.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0), key.scope);
    try testing.expectEqualStrings("demo/example/hello", key.suffix.?);
}

test "KeyExpr: decode scope=5, no suffix" {
    const wire = [_]u8{0x05};
    var reader: Io.Reader = .fixed(&wire);
    const key = try KeyExpr.decode(&reader, false, testing.allocator);
    defer key.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 5), key.scope);
    try testing.expectEqual(@as(?[]const u8, null), key.suffix);
}

test "KeyExpr: decode scope=200 (multi-byte VLE)" {
    const wire = [_]u8{ 0xC8, 0x01 };
    var reader: Io.Reader = .fixed(&wire);
    const key = try KeyExpr.decode(&reader, false, testing.allocator);
    defer key.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 200), key.scope);
}

test "KeyExpr: decode scope=0xFFFF (max u16)" {
    const wire = [_]u8{ 0xFF, 0xFF, 0x03 };
    var reader: Io.Reader = .fixed(&wire);
    const key = try KeyExpr.decode(&reader, false, testing.allocator);
    defer key.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0xFFFF), key.scope);
}

test "KeyExpr: decode scope overflow (> u16 max) returns error" {
    // VLE(65536) = 0x80 0x80 0x04
    const wire = [_]u8{ 0x80, 0x80, 0x04 };
    var reader: Io.Reader = .fixed(&wire);
    try testing.expectError(error.ScopeOverflow, KeyExpr.decode(&reader, false, testing.allocator));
}

test "KeyExpr: decode scope overflow (large value) returns error" {
    // VLE(0x1_0000) = 65536 → ScopeOverflow
    var buf: [vle.max_bytes]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    vle.encode(0x1_0000, &writer) catch unreachable;
    const wire = writer.buffered();

    var reader: Io.Reader = .fixed(wire);
    try testing.expectError(error.ScopeOverflow, KeyExpr.decode(&reader, false, testing.allocator));
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

test "KeyExpr: round-trip scope=0, suffix='demo/example/hello'" {
    const original = KeyExpr{
        .scope = 0,
        .suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.scope, decoded.scope);
    try testing.expectEqualStrings("demo/example/hello", decoded.suffix.?);
}

test "KeyExpr: round-trip scope=5, no suffix" {
    const original = KeyExpr{
        .scope = 5,
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 5), decoded.scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.suffix);
}

test "KeyExpr: round-trip scope=42, suffix='test/key'" {
    const original = KeyExpr{
        .scope = 42,
        .suffix = "test/key",
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(original.scope, decoded.scope);
    try testing.expectEqualStrings("test/key", decoded.suffix.?);
}

test "KeyExpr: round-trip scope=0, no suffix (minimal)" {
    const original = KeyExpr{};
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0), decoded.scope);
    try testing.expectEqual(@as(?[]const u8, null), decoded.suffix);
}

test "KeyExpr: round-trip scope=0xFFFF (max u16)" {
    const original = KeyExpr{
        .scope = 0xFFFF,
        .suffix = "key",
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0xFFFF), decoded.scope);
    try testing.expectEqualStrings("key", decoded.suffix.?);
}

test "KeyExpr: round-trip with long suffix" {
    const suffix = "a/very/long/key/expression/path/that/exceeds/one/hundred/and/twenty/eight/bytes/to/exercise/multi/byte/vle/length/encoding/in/the/suffix/field";
    const original = KeyExpr{
        .scope = 1,
        .suffix = suffix,
    };
    var buf: [256]u8 = undefined;
    const encoded = encodeHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const decoded = try KeyExpr.decode(&reader, original.hasName(), testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 1), decoded.scope);
    try testing.expectEqualStrings(suffix, decoded.suffix.?);
}

// ---------------------------------------------------------------------------
// Wire vector tests
// ---------------------------------------------------------------------------

test "KeyExpr: wire vector — scope=0, suffix='demo/example/hello'" {
    const key = KeyExpr{
        .scope = 0,
        .suffix = "demo/example/hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // 0x00: key_scope = 0
    // 0x12: suffix length = 18
    // "demo/example/hello": 18 bytes
    try assertEqualBytes(
        &(.{0x00, 0x12} ++ "demo/example/hello".*),
        encoded,
    );
}

test "KeyExpr: wire vector — scope=5, no suffix" {
    const key = KeyExpr{ .scope = 5 };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // 0x05: key_scope = 5
    try assertEqualBytes(&.{0x05}, encoded);
}

test "KeyExpr: wire vector — scope=0, suffix='a'" {
    const key = KeyExpr{
        .scope = 0,
        .suffix = "a",
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // 0x00: key_scope
    // 0x01: suffix length = 1
    // 'a': 1 byte
    try assertEqualBytes(&.{ 0x00, 0x01, 'a' }, encoded);
}

test "KeyExpr: wire vector — scope=200 (multi-byte VLE)" {
    const key = KeyExpr{ .scope = 200 };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // VLE(200) = 0xC8 0x01
    try assertEqualBytes(&.{ 0xC8, 0x01 }, encoded);
}

test "KeyExpr: wire vector — scope=0xFFFF" {
    const key = KeyExpr{ .scope = 0xFFFF };
    var buf: [16]u8 = undefined;
    const encoded = encodeHelper(&key, &buf);

    // VLE(65535) = 0xFF 0xFF 0x03
    try assertEqualBytes(&.{ 0xFF, 0xFF, 0x03 }, encoded);
}

// ---------------------------------------------------------------------------
// Flag derivation tests
// ---------------------------------------------------------------------------

test "KeyExpr: headerFlags — N=0, M=0 (no suffix, receiver's mapping)" {
    const key = KeyExpr{ .scope = 5 };
    try testing.expectEqual(@as(u8, 0x00), key.headerFlags());
}

test "KeyExpr: headerFlags — N=1, M=0 (suffix present, receiver's mapping)" {
    const key = KeyExpr{ .scope = 0, .suffix = "demo/example/hello" };
    try testing.expectEqual(n_flag, key.headerFlags());
}

test "KeyExpr: headerFlags — N=0, M=1 (no suffix, sender's mapping)" {
    const key = KeyExpr{ .scope = 5, .sender_mapping = true };
    try testing.expectEqual(m_flag, key.headerFlags());
}

test "KeyExpr: headerFlags — N=1, M=1 (suffix + sender's mapping)" {
    const key = KeyExpr{ .scope = 0, .suffix = "key", .sender_mapping = true };
    try testing.expectEqual(n_flag | m_flag, key.headerFlags());
}

test "KeyExpr: headerFlags — N flag is 0x20" {
    try testing.expectEqual(@as(u8, 0x20), n_flag);
}

test "KeyExpr: headerFlags — M flag is 0x40" {
    try testing.expectEqual(@as(u8, 0x40), m_flag);
}

test "KeyExpr: headerFlags OR'd with Push MID gives correct header byte" {
    const push_mid: u8 = 0x1D;

    // N=1, M=0 → 0x3D
    const key1 = KeyExpr{ .scope = 0, .suffix = "key" };
    try testing.expectEqual(@as(u8, 0x3D), push_mid | key1.headerFlags());

    // N=1, M=1 → 0x7D
    const key2 = KeyExpr{ .scope = 0, .suffix = "key", .sender_mapping = true };
    try testing.expectEqual(@as(u8, 0x7D), push_mid | key2.headerFlags());

    // N=0, M=0 → 0x1D
    const key3 = KeyExpr{ .scope = 5 };
    try testing.expectEqual(@as(u8, 0x1D), push_mid | key3.headerFlags());

    // N=0, M=1 → 0x5D
    const key4 = KeyExpr{ .scope = 5, .sender_mapping = true };
    try testing.expectEqual(@as(u8, 0x5D), push_mid | key4.headerFlags());
}

test "KeyExpr: headerFlags OR'd with Request MID gives correct header byte" {
    const request_mid: u8 = 0x1C;

    // N=1, M=0 → 0x3C
    const key1 = KeyExpr{ .scope = 0, .suffix = "key" };
    try testing.expectEqual(@as(u8, 0x3C), request_mid | key1.headerFlags());

    // N=1, M=1 → 0x7C
    const key2 = KeyExpr{ .scope = 0, .suffix = "key", .sender_mapping = true };
    try testing.expectEqual(@as(u8, 0x7C), request_mid | key2.headerFlags());
}

test "KeyExpr: headerFlags OR'd with Response MID gives correct header byte" {
    const response_mid: u8 = 0x1B;

    // N=1, M=0 → 0x3B
    const key1 = KeyExpr{ .scope = 0, .suffix = "key" };
    try testing.expectEqual(@as(u8, 0x3B), response_mid | key1.headerFlags());

    // N=1, M=1 → 0x7B
    const key2 = KeyExpr{ .scope = 0, .suffix = "key", .sender_mapping = true };
    try testing.expectEqual(@as(u8, 0x7B), response_mid | key2.headerFlags());
}

// ---------------------------------------------------------------------------
// hasName tests
// ---------------------------------------------------------------------------

test "KeyExpr: hasName returns true when suffix present" {
    const key = KeyExpr{ .suffix = "test" };
    try testing.expect(key.hasName());
}

test "KeyExpr: hasName returns false when no suffix" {
    const key = KeyExpr{ .scope = 5 };
    try testing.expect(!key.hasName());
}

test "KeyExpr: hasName returns true for empty string suffix" {
    const key = KeyExpr{ .suffix = "" };
    try testing.expect(key.hasName());
}

// ---------------------------------------------------------------------------
// sender_mapping preservation in decode (via headerFlags round-trip)
// ---------------------------------------------------------------------------

test "KeyExpr: sender_mapping is not encoded on wire (only in header flags)" {
    // sender_mapping doesn't affect the encoded key body — only the header flags.
    // Two keys with different sender_mapping produce the same wire bytes.
    const key1 = KeyExpr{ .scope = 5, .sender_mapping = false };
    const key2 = KeyExpr{ .scope = 5, .sender_mapping = true };

    var buf1: [16]u8 = undefined;
    var buf2: [16]u8 = undefined;
    const enc1 = encodeHelper(&key1, &buf1);
    const enc2 = encodeHelper(&key2, &buf2);

    try assertEqualBytes(enc1, enc2);
}

test "KeyExpr: headerFlags differ with sender_mapping" {
    const key1 = KeyExpr{ .scope = 5, .sender_mapping = false };
    const key2 = KeyExpr{ .scope = 5, .sender_mapping = true };

    try testing.expectEqual(@as(u8, 0x00), key1.headerFlags());
    try testing.expectEqual(@as(u8, 0x40), key2.headerFlags());
}

// ---------------------------------------------------------------------------
// deinit safety
// ---------------------------------------------------------------------------

test "KeyExpr: deinit with no suffix is safe" {
    const key = KeyExpr{ .scope = 0 };
    key.deinit(testing.allocator); // should not crash
}

test "KeyExpr: deinit frees suffix memory" {
    const wire = .{0x00, 0x03} ++ "abc".*;
    var reader: Io.Reader = .fixed(&wire);
    const key = try KeyExpr.decode(&reader, true, testing.allocator);
    // deinit should free without error (allocator tracks leaks in test mode)
    key.deinit(testing.allocator);
}

test {
    std.testing.refAllDecls(@This());
}
