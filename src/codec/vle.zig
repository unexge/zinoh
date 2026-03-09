//! VLE (Variable Length Encoding) integer encode/decode.
//!
//! Zenoh protocol §2: each byte contributes 7 data bits (0–6),
//! bit 7 is a continuation flag (1 = more bytes, 0 = last byte).
//! The 9th byte (if needed) uses all 8 bits with no continuation flag,
//! allowing a full u64 to be encoded in at most 9 bytes.

const std = @import("std");
const Io = std.Io;

/// Maximum number of VLE bytes needed for a u64 value.
pub const max_bytes: usize = 9;

/// Encode a u64 value as VLE to a Writer.
///
/// Bytes 1–8 use 7 data bits + continuation flag in bit 7.
/// The 9th byte (if needed) uses all 8 data bits with no continuation.
pub fn encode(value: u64, writer: *Io.Writer) Io.Writer.Error!void {
    var v = value;
    var bytes_written: usize = 0;

    while (v > 0x7F and bytes_written < 8) {
        try writer.writeByte(@as(u8, @truncate(v & 0x7F)) | 0x80);
        v >>= 7;
        bytes_written += 1;
    }
    // Last byte: uses all 8 bits (0xFF mask) — for bytes 1–8 this is
    // equivalent to 0x7F since v <= 0x7F; for the 9th byte it may exceed 0x7F.
    try writer.writeByte(@as(u8, @truncate(v & 0xFF)));
}

/// Decode a VLE-encoded u64 from a Reader.
///
/// Reads up to 9 bytes. Bytes 1–8 contribute 7 data bits each.
/// The 9th byte contributes all 8 bits.
pub fn decode(reader: *Io.Reader) Io.Reader.Error!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    while (true) {
        const byte = try reader.takeByte();
        bytes_read += 1;

        if (bytes_read < max_bytes) {
            // Normal byte: 7 data bits, bit 7 is continuation flag.
            const data: u64 = @intCast(byte & 0x7F);
            result |= data << shift;

            if (byte & 0x80 == 0) {
                return result;
            }

            shift = @intCast(@as(u7, shift) + 7);
        } else if (bytes_read == max_bytes) {
            // 9th byte: all 8 bits are data, no continuation flag.
            const data: u64 = @intCast(byte);
            result |= data << shift;
            return result;
        } else {
            // The loop structure guarantees we always return at or before
            // byte 9 (max_bytes), so this branch is unreachable.
            unreachable;
        }
    }
}

/// Compute the number of bytes needed to VLE-encode `value` without actually writing.
pub fn encodedSize(value: u64) usize {
    if (value == 0) return 1;
    var v = value;
    var size: usize = 0;
    // Loop counts all bytes (continuation + final) by using `v > 0` instead of
    // `v > 0x7F` — the extra iteration accounts for the final byte that `encode`
    // writes outside its loop.
    while (v > 0 and size < 8) {
        size += 1;
        v >>= 7;
    }
    if (v > 0) {
        size += 1; // 9th byte for remaining bits
    }
    return size;
}

/// Encode a u64 value as VLE into a fixed buffer, returning the used slice.
/// Returns error if `buf` is too small.
pub fn encodeToSlice(value: u64, buf: []u8) error{NoSpaceLeft}![]u8 {
    var v = value;
    var i: usize = 0;

    while (v > 0x7F and i < 8) {
        if (i >= buf.len) return error.NoSpaceLeft;
        buf[i] = @as(u8, @truncate(v & 0x7F)) | 0x80;
        i += 1;
        v >>= 7;
    }
    if (i >= buf.len) return error.NoSpaceLeft;
    buf[i] = @as(u8, @truncate(v & 0xFF));
    return buf[0 .. i + 1];
}

// ───────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────

const testing = std.testing;

/// Helper: encode a value and return the encoded bytes as a slice.
fn encodeHelper(value: u64, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    encode(value, &writer) catch unreachable;
    return writer.buffered();
}

/// Helper: encode then decode, returning the decoded value.
fn roundTrip(value: u64) !u64 {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(value, &buf);
    var reader: Io.Reader = .fixed(encoded);
    return try decode(&reader);
}

// ── Wire vector tests: verify exact encoded bytes match spec table ──

test "wire vector: 0 → 0x00" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(0, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, encoded);
    try testing.expectEqual(@as(usize, 1), encodedSize(0));
}

test "wire vector: 10 → 0x0A" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(10, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{0x0A}, encoded);
    try testing.expectEqual(@as(usize, 1), encodedSize(10));
}

test "wire vector: 127 → 0x7F" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(127, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{0x7F}, encoded);
    try testing.expectEqual(@as(usize, 1), encodedSize(127));
}

test "wire vector: 128 → 0x80 0x01" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(128, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, encoded);
    try testing.expectEqual(@as(usize, 2), encodedSize(128));
}

test "wire vector: 10000 → 0x90 0x4E" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(10000, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x90, 0x4E }, encoded);
    try testing.expectEqual(@as(usize, 2), encodedSize(10000));
}

test "wire vector: 65535 → 0xFF 0xFF 0x03" {
    var buf: [max_bytes]u8 = undefined;
    const encoded = encodeHelper(65535, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0x03 }, encoded);
    try testing.expectEqual(@as(usize, 3), encodedSize(65535));
}

test "wire vector: max u64 → 9 bytes of 0xFF" {
    var buf: [max_bytes]u8 = undefined;
    const max_val: u64 = 0xFFFFFFFFFFFFFFFF;
    const encoded = encodeHelper(max_val, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, encoded);
    try testing.expectEqual(@as(usize, 9), encodedSize(max_val));
}

// ── Round-trip tests ──

test "round-trip: spec examples" {
    const spec_values = [_]u64{ 0, 10, 127, 128, 10000 };
    for (spec_values) |v| {
        try testing.expectEqual(v, try roundTrip(v));
    }
}

test "round-trip: 1-byte boundary (127)" {
    try testing.expectEqual(@as(u64, 127), try roundTrip(127));
}

test "round-trip: 2-byte boundary (128)" {
    try testing.expectEqual(@as(u64, 128), try roundTrip(128));
}

test "round-trip: max u64" {
    const max_val: u64 = 0xFFFFFFFFFFFFFFFF;
    try testing.expectEqual(max_val, try roundTrip(max_val));
}

test "round-trip: large value > 2^32" {
    const large: u64 = 0x1_0000_0001; // 2^32 + 1
    try testing.expectEqual(large, try roundTrip(large));
}

test "round-trip: powers of two" {
    var v: u64 = 1;
    for (0..63) |_| {
        try testing.expectEqual(v, try roundTrip(v));
        v <<= 1;
    }
}

// ── encodedSize tests ──

test "encodedSize: various values" {
    try testing.expectEqual(@as(usize, 1), encodedSize(0));
    try testing.expectEqual(@as(usize, 1), encodedSize(127));
    try testing.expectEqual(@as(usize, 2), encodedSize(128));
    try testing.expectEqual(@as(usize, 2), encodedSize(10000));
    try testing.expectEqual(@as(usize, 3), encodedSize(65535));
    try testing.expectEqual(@as(usize, 5), encodedSize(0xFFFFFFFF));
    try testing.expectEqual(@as(usize, 9), encodedSize(0xFFFFFFFFFFFFFFFF));
}

// ── encodeToSlice tests ──

test "encodeToSlice: basic values" {
    var buf: [max_bytes]u8 = undefined;

    const s0 = try encodeToSlice(0, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, s0);

    const s128 = try encodeToSlice(128, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01 }, s128);
}

test "encodeToSlice: max u64" {
    var buf: [max_bytes]u8 = undefined;
    const s = try encodeToSlice(0xFFFFFFFFFFFFFFFF, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, s);
}

test "encodeToSlice: buffer too small" {
    var buf: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, encodeToSlice(128, &buf));
}

// ── Error case: truncated input ──

test "error: truncated input (empty)" {
    var reader: Io.Reader = .fixed(&.{});
    try testing.expectError(error.EndOfStream, decode(&reader));
}

test "error: truncated input (continuation but no more bytes)" {
    var reader: Io.Reader = .fixed(&[_]u8{0x80}); // continuation flag set, but no more data
    try testing.expectError(error.EndOfStream, decode(&reader));
}

// ── Edge case: 9th byte behavior ──

test "decode: 9th byte is final (all 8 data bits, no continuation check)" {
    // Feed 10 bytes all with high bit set. The decoder treats byte 9 as final
    // (all 8 bits are data), so it returns successfully after consuming 9 bytes.
    var reader: Io.Reader = .fixed(&[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 });
    const result = try decode(&reader);
    // Bytes 1–8 each contribute 0 data bits (0x80 & 0x7F = 0).
    // Byte 9 contributes 0x80 << 56.
    try testing.expectEqual(@as(u64, 0x80 << 56), result);
}

test {
    testing.refAllDecls(@This());
}
