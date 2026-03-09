//! Encoding primitives: uint16 LE, slices, strings.
//!
//! Zenoh protocol §2 fixed-width and length-prefixed types:
//! - **uint16 LE**: Fixed 2-byte little-endian encoding (batch_size, key expr IDs)
//! - **Slices**: VLE length prefix + raw bytes
//! - **Strings**: VLE length prefix + UTF-8 bytes (same wire format as slices)

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const vle = @import("vle.zig");

// ---------------------------------------------------------------------------
// uint16 LE
// ---------------------------------------------------------------------------

/// Write a u16 value in little-endian byte order (2 bytes, LSB first).
pub fn writeUint16LE(value: u16, writer: *Io.Writer) Io.Writer.Error!void {
    try writer.writeByte(@truncate(value));
    try writer.writeByte(@truncate(value >> 8));
}

/// Read a u16 value in little-endian byte order (2 bytes, LSB first).
pub fn readUint16LE(reader: *Io.Reader) Io.Reader.Error!u16 {
    const lo: u16 = try reader.takeByte();
    const hi: u16 = try reader.takeByte();
    return (hi << 8) | lo;
}

// ---------------------------------------------------------------------------
// Slices (VLE length prefix + raw bytes)
// ---------------------------------------------------------------------------

/// Write a byte slice: VLE-encoded length followed by raw bytes.
pub fn writeSlice(data: []const u8, writer: *Io.Writer) Io.Writer.Error!void {
    try vle.encode(@intCast(data.len), writer);
    try writer.writeAll(data);
}

/// Read a byte slice: VLE-encoded length followed by raw bytes.
/// Caller owns the returned memory and must free it with `allocator`.
pub fn readSlice(reader: *Io.Reader, allocator: Allocator) Io.Reader.ReadAllocError![]u8 {
    const len = try vle.decode(reader);
    return try reader.readAlloc(allocator, @intCast(len));
}

// ---------------------------------------------------------------------------
// Strings (same wire format as slices)
// ---------------------------------------------------------------------------

/// Write a string: VLE-encoded length followed by UTF-8 bytes.
/// Same wire format as `writeSlice`.
pub fn writeString(str: []const u8, writer: *Io.Writer) Io.Writer.Error!void {
    return writeSlice(str, writer);
}

/// Read a string: VLE-encoded length followed by UTF-8 bytes.
/// Same wire format as `readSlice`.
/// Caller owns the returned memory and must free it with `allocator`.
pub fn readString(reader: *Io.Reader, allocator: Allocator) Io.Reader.ReadAllocError![]u8 {
    return readSlice(reader, allocator);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// ---------------------------------------------------------------------------
// uint16 LE tests
// ---------------------------------------------------------------------------

/// Helper: encode a u16 and return the written bytes.
fn encodeUint16Helper(value: u16, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    writeUint16LE(value, &writer) catch unreachable;
    return writer.buffered();
}

/// Helper: round-trip a u16 through encode→decode.
fn roundTripUint16(value: u16) !u16 {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(value, &buf);
    var reader: Io.Reader = .fixed(encoded);
    return try readUint16LE(&reader);
}

test "uint16 LE: wire vector 0 → 0x00 0x00" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(0, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, encoded);
}

test "uint16 LE: wire vector 1 → 0x01 0x00" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(1, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, encoded);
}

test "uint16 LE: wire vector 255 → 0xFF 0x00" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(255, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x00 }, encoded);
}

test "uint16 LE: wire vector 256 → 0x00 0x01" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(256, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, encoded);
}

test "uint16 LE: wire vector 0xFFFF → 0xFF 0xFF" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(0xFFFF, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF }, encoded);
}

test "uint16 LE: wire vector 0x1234 → 0x34 0x12 (byte order)" {
    var buf: [2]u8 = undefined;
    const encoded = encodeUint16Helper(0x1234, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x34, 0x12 }, encoded);
}

test "uint16 LE: round-trip 0" {
    try testing.expectEqual(@as(u16, 0), try roundTripUint16(0));
}

test "uint16 LE: round-trip 1" {
    try testing.expectEqual(@as(u16, 1), try roundTripUint16(1));
}

test "uint16 LE: round-trip 255" {
    try testing.expectEqual(@as(u16, 255), try roundTripUint16(255));
}

test "uint16 LE: round-trip 256" {
    try testing.expectEqual(@as(u16, 256), try roundTripUint16(256));
}

test "uint16 LE: round-trip 0xFFFF" {
    try testing.expectEqual(@as(u16, 0xFFFF), try roundTripUint16(0xFFFF));
}

test "uint16 LE: error on truncated input (empty)" {
    var reader: Io.Reader = .fixed(&.{});
    try testing.expectError(error.EndOfStream, readUint16LE(&reader));
}

test "uint16 LE: error on truncated input (1 byte)" {
    var reader: Io.Reader = .fixed(&[_]u8{0x42});
    try testing.expectError(error.EndOfStream, readUint16LE(&reader));
}

// ---------------------------------------------------------------------------
// Slice tests
// ---------------------------------------------------------------------------

/// Helper: encode a slice and return the written bytes.
fn encodeSliceHelper(data: []const u8, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    writeSlice(data, &writer) catch unreachable;
    return writer.buffered();
}

test "slice: wire vector empty → 0x00" {
    var buf: [16]u8 = undefined;
    const encoded = encodeSliceHelper(&.{}, &buf);
    // VLE(0) = 0x00, no payload bytes
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, encoded);
}

test "slice: wire vector [0xDE, 0xAD] → 0x02 0xDE 0xAD" {
    var buf: [16]u8 = undefined;
    const data = [_]u8{ 0xDE, 0xAD };
    const encoded = encodeSliceHelper(&data, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0xDE, 0xAD }, encoded);
}

test "slice: wire vector 127-byte payload → VLE(127) = 0x7F + 127 bytes" {
    var payload: [127]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var buf: [256]u8 = undefined;
    const encoded = encodeSliceHelper(&payload, &buf);

    // VLE(127) is 1 byte: 0x7F
    try testing.expectEqual(@as(usize, 1 + 127), encoded.len);
    try testing.expectEqual(@as(u8, 0x7F), encoded[0]);
    try testing.expectEqualSlices(u8, &payload, encoded[1..]);
}

test "slice: wire vector 128-byte payload → VLE(128) = 0x80 0x01 + 128 bytes" {
    var payload: [128]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var buf: [256]u8 = undefined;
    const encoded = encodeSliceHelper(&payload, &buf);

    // VLE(128) is 2 bytes: 0x80 0x01
    try testing.expectEqual(@as(usize, 2 + 128), encoded.len);
    try testing.expectEqual(@as(u8, 0x80), encoded[0]);
    try testing.expectEqual(@as(u8, 0x01), encoded[1]);
    try testing.expectEqualSlices(u8, &payload, encoded[2..]);
}

test "slice: round-trip empty" {
    var buf: [16]u8 = undefined;
    const encoded = encodeSliceHelper(&.{}, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const result = try readSlice(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, &.{}, result);
}

test "slice: round-trip small" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var buf: [16]u8 = undefined;
    const encoded = encodeSliceHelper(&data, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const result = try readSlice(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, &data, result);
}

test "slice: round-trip 128+ bytes (VLE length > 1 byte)" {
    var payload: [200]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var buf: [256]u8 = undefined;
    const encoded = encodeSliceHelper(&payload, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const result = try readSlice(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, &payload, result);
}

test "slice: error on truncated length" {
    // Continuation byte but no follow-up
    var reader: Io.Reader = .fixed(&[_]u8{0x80});
    try testing.expectError(error.EndOfStream, readSlice(&reader, testing.allocator));
}

test "slice: error on truncated payload" {
    // Length = 5 but only 2 payload bytes
    var reader: Io.Reader = .fixed(&[_]u8{ 0x05, 0xAA, 0xBB });
    try testing.expectError(error.EndOfStream, readSlice(&reader, testing.allocator));
}

// ---------------------------------------------------------------------------
// String tests
// ---------------------------------------------------------------------------

test "string: wire vector empty → 0x00" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString("", &writer);
    const encoded = writer.buffered();
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, encoded);
}

test "string: wire vector 'hello' → 0x05 h e l l o" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString("hello", &writer);
    const encoded = writer.buffered();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 'h', 'e', 'l', 'l', 'o' }, encoded);
}

test "string: round-trip empty" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString("", &writer);
    var reader: Io.Reader = .fixed(writer.buffered());
    const result = try readString(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("", result);
}

test "string: round-trip ASCII" {
    const str = "zenoh is great!";
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString(str, &writer);
    var reader: Io.Reader = .fixed(writer.buffered());
    const result = try readString(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings(str, result);
}

test "string: round-trip multi-byte UTF-8" {
    const str = "日本語テスト 🦎";
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString(str, &writer);
    var reader: Io.Reader = .fixed(writer.buffered());
    const result = try readString(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings(str, result);
}

test "string: wire vector multi-byte UTF-8 length is byte length" {
    // "日" is 3 bytes in UTF-8: 0xE6 0x97 0xA5
    const str = "日";
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try writeString(str, &writer);
    const encoded = writer.buffered();
    // VLE(3) = 0x03, then 3 UTF-8 bytes
    try testing.expectEqual(@as(usize, 4), encoded.len);
    try testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try testing.expectEqualSlices(u8, str, encoded[1..]);
}

test "string: round-trip 128+ byte UTF-8 string" {
    // Build a string longer than 127 bytes to test multi-byte VLE length
    const base = "こんにちは世界！"; // 24 bytes in UTF-8
    var big_buf: [256]u8 = undefined;
    var len: usize = 0;
    // Repeat until we exceed 128 bytes
    while (len < 128) {
        @memcpy(big_buf[len..][0..base.len], base);
        len += base.len;
    }
    const str = big_buf[0..len];

    var enc_buf: [512]u8 = undefined;
    var writer: Io.Writer = .fixed(&enc_buf);
    try writeString(str, &writer);
    var reader: Io.Reader = .fixed(writer.buffered());
    const result = try readString(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings(str, result);
}

// ---------------------------------------------------------------------------
// Multiple values in sequence
// ---------------------------------------------------------------------------

test "sequential: write and read multiple primitives" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    // Write: uint16, slice, string, uint16
    try writeUint16LE(0x1234, &writer);
    try writeSlice(&[_]u8{ 0xAA, 0xBB, 0xCC }, &writer);
    try writeString("hi", &writer);
    try writeUint16LE(0xFFFF, &writer);

    var reader: Io.Reader = .fixed(writer.buffered());

    const v1 = try readUint16LE(&reader);
    try testing.expectEqual(@as(u16, 0x1234), v1);

    const s1 = try readSlice(&reader, testing.allocator);
    defer testing.allocator.free(s1);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, s1);

    const s2 = try readString(&reader, testing.allocator);
    defer testing.allocator.free(s2);
    try testing.expectEqualStrings("hi", s2);

    const v2 = try readUint16LE(&reader);
    try testing.expectEqual(@as(u16, 0xFFFF), v2);
}

test {
    testing.refAllDecls(@This());
}
