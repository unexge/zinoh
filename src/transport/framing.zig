//! TCP 2-byte length framing.
//!
//! Zenoh protocol §1: every message on the wire is prefixed with a 2-byte
//! little-endian length. The length indicates the number of payload bytes
//! that follow (not including the 2-byte prefix itself).
//! Maximum message size: 65,535 bytes.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const primitives = @import("../codec/primitives.zig");

/// Maximum payload size for a single frame (2^16 - 1 = 65,535 bytes).
pub const max_frame_size: usize = 65_535;

/// Errors that can occur when writing a frame.
pub const WriteError = Io.Writer.Error || error{MessageTooLarge};

/// Errors that can occur when reading a frame into a caller-provided buffer.
pub const ReadError = Io.Reader.Error || error{BufferTooSmall};

/// Write a framed message: 2-byte LE length prefix followed by payload.
///
/// Returns `error.MessageTooLarge` if `payload.len > max_frame_size`.
pub fn writeFrame(payload: []const u8, writer: *Io.Writer) WriteError!void {
    if (payload.len > max_frame_size) return error.MessageTooLarge;
    try primitives.writeUint16LE(@intCast(payload.len), writer);
    try writer.writeAll(payload);
}

/// Read a framed message into a caller-provided buffer.
///
/// Reads the 2-byte LE length prefix, then reads that many bytes into `buf`.
/// Returns the slice of `buf` containing the payload.
/// Returns `error.BufferTooSmall` if `buf.len` is smaller than the frame length.
pub fn readFrame(reader: *Io.Reader, buf: []u8) ReadError![]u8 {
    const len = try primitives.readUint16LE(reader);
    if (len > buf.len) return error.BufferTooSmall;
    const slice = buf[0..len];
    try reader.readSliceAll(slice);
    return slice;
}

/// Read a framed message, allocating the buffer.
///
/// Reads the 2-byte LE length prefix, allocates a buffer of that size,
/// then reads the payload into it.
/// Caller owns the returned memory and must free it with `allocator`.
pub fn readFrameAlloc(reader: *Io.Reader, allocator: Allocator) (Io.Reader.ReadAllocError || Allocator.Error)![]u8 {
    const len = try primitives.readUint16LE(reader);
    if (len == 0) {
        return try allocator.alloc(u8, 0);
    }
    return try reader.readAlloc(allocator, len);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Helper: encode a frame and return the written bytes.
fn encodeFrameHelper(payload: []const u8, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    writeFrame(payload, &writer) catch unreachable;
    return writer.buffered();
}

// ---------------------------------------------------------------------------
// Wire vector tests: verify exact framed bytes
// ---------------------------------------------------------------------------

test "wire vector: empty payload → 0x00 0x00" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&.{}, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, encoded);
}

test "wire vector: [0xAB] → 0x01 0x00 0xAB" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&[_]u8{0xAB}, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0xAB }, encoded);
}

test "wire vector: [0xDE, 0xAD] → 0x02 0x00 0xDE 0xAD" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&[_]u8{ 0xDE, 0xAD }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0xDE, 0xAD }, encoded);
}

test "wire vector: 256-byte payload → length prefix 0x00 0x01" {
    var payload: [256]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var buf: [258]u8 = undefined;
    const encoded = encodeFrameHelper(&payload, &buf);

    // Length prefix: 256 = 0x0100 LE → 0x00 0x01
    try testing.expectEqual(@as(usize, 2 + 256), encoded.len);
    try testing.expectEqual(@as(u8, 0x00), encoded[0]);
    try testing.expectEqual(@as(u8, 0x01), encoded[1]);
    try testing.expectEqualSlices(u8, &payload, encoded[2..]);
}

test "wire vector: 'hello' payload → 0x05 0x00 h e l l o" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper("hello", &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00, 'h', 'e', 'l', 'l', 'o' }, encoded);
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

test "round-trip: empty message" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&.{}, &buf);

    var reader: Io.Reader = .fixed(encoded);
    var read_buf: [max_frame_size]u8 = undefined;
    const result = try readFrame(&reader, &read_buf);
    try testing.expectEqualSlices(u8, &.{}, result);
}

test "round-trip: empty message (alloc)" {
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&.{}, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const result = try readFrameAlloc(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, &.{}, result);
}

test "round-trip: small message" {
    const payload = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&payload, &buf);

    var reader: Io.Reader = .fixed(encoded);
    var read_buf: [max_frame_size]u8 = undefined;
    const result = try readFrame(&reader, &read_buf);
    try testing.expectEqualSlices(u8, &payload, result);
}

test "round-trip: small message (alloc)" {
    const payload = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var buf: [16]u8 = undefined;
    const encoded = encodeFrameHelper(&payload, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const result = try readFrameAlloc(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, &payload, result);
}

test "round-trip: max-size message (65535 bytes)" {
    // We can't use a stack-allocated encode buffer for 65535+2 bytes easily,
    // so we use the allocator.
    const payload = try testing.allocator.alloc(u8, max_frame_size);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    // Encode: 2-byte prefix + 65535 payload
    const frame_buf = try testing.allocator.alloc(u8, 2 + max_frame_size);
    defer testing.allocator.free(frame_buf);
    const encoded = encodeFrameHelper(payload, frame_buf);
    try testing.expectEqual(@as(usize, 2 + max_frame_size), encoded.len);

    // Verify length prefix: 0xFFFF LE = 0xFF 0xFF
    try testing.expectEqual(@as(u8, 0xFF), encoded[0]);
    try testing.expectEqual(@as(u8, 0xFF), encoded[1]);

    // Decode with buffer
    var reader: Io.Reader = .fixed(encoded);
    const read_buf = try testing.allocator.alloc(u8, max_frame_size);
    defer testing.allocator.free(read_buf);
    const result = try readFrame(&reader, read_buf);
    try testing.expectEqualSlices(u8, payload, result);
}

test "round-trip: max-size message (alloc)" {
    const payload = try testing.allocator.alloc(u8, max_frame_size);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const frame_buf = try testing.allocator.alloc(u8, 2 + max_frame_size);
    defer testing.allocator.free(frame_buf);
    const encoded = encodeFrameHelper(payload, frame_buf);

    var reader: Io.Reader = .fixed(encoded);
    const result = try readFrameAlloc(&reader, testing.allocator);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, payload, result);
}

// ---------------------------------------------------------------------------
// Error tests
// ---------------------------------------------------------------------------

test "error: payload exceeds max_frame_size (65536 bytes)" {
    // Allocate a payload of max_frame_size + 1 bytes
    const payload = try testing.allocator.alloc(u8, max_frame_size + 1);
    defer testing.allocator.free(payload);
    @memset(payload, 0xAA);

    var buf: [4]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try testing.expectError(error.MessageTooLarge, writeFrame(payload, &writer));
}

test "error: payload exceeds max_frame_size (100000 bytes)" {
    const payload = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(payload);
    @memset(payload, 0xBB);

    var buf: [4]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try testing.expectError(error.MessageTooLarge, writeFrame(payload, &writer));
}

test "error: truncated read — empty input (no length prefix)" {
    var reader: Io.Reader = .fixed(&.{});
    var read_buf: [64]u8 = undefined;
    try testing.expectError(error.EndOfStream, readFrame(&reader, &read_buf));
}

test "error: truncated read — partial length prefix (1 byte)" {
    var reader: Io.Reader = .fixed(&[_]u8{0x05});
    var read_buf: [64]u8 = undefined;
    try testing.expectError(error.EndOfStream, readFrame(&reader, &read_buf));
}

test "error: truncated read — length says 5 but only 3 payload bytes" {
    // Frame header says 5 bytes, but only 3 payload bytes follow
    var reader: Io.Reader = .fixed(&[_]u8{ 0x05, 0x00, 0xAA, 0xBB, 0xCC });
    var read_buf: [64]u8 = undefined;
    try testing.expectError(error.EndOfStream, readFrame(&reader, &read_buf));
}

test "error: truncated read (alloc) — empty input" {
    var reader: Io.Reader = .fixed(&.{});
    try testing.expectError(error.EndOfStream, readFrameAlloc(&reader, testing.allocator));
}

test "error: truncated read (alloc) — partial length prefix" {
    var reader: Io.Reader = .fixed(&[_]u8{0x03});
    try testing.expectError(error.EndOfStream, readFrameAlloc(&reader, testing.allocator));
}

test "error: truncated read (alloc) — length says 5 but only 2 payload bytes" {
    var reader: Io.Reader = .fixed(&[_]u8{ 0x05, 0x00, 0xAA, 0xBB });
    try testing.expectError(error.EndOfStream, readFrameAlloc(&reader, testing.allocator));
}

test "error: buffer too small for readFrame" {
    // Frame says 10 bytes but buffer is only 5
    var reader: Io.Reader = .fixed(&[_]u8{ 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    var read_buf: [5]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, readFrame(&reader, &read_buf));
}

// ---------------------------------------------------------------------------
// Multiple frames in sequence
// ---------------------------------------------------------------------------

test "sequential: write and read multiple frames" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    // Write 3 frames
    try writeFrame("hello", &writer);
    try writeFrame(&.{}, &writer);
    try writeFrame(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, &writer);

    var reader: Io.Reader = .fixed(writer.buffered());
    var read_buf: [64]u8 = undefined;

    // Read frame 1
    const f1 = try readFrame(&reader, &read_buf);
    try testing.expectEqualSlices(u8, "hello", f1);

    // Read frame 2 (empty)
    const f2 = try readFrame(&reader, &read_buf);
    try testing.expectEqualSlices(u8, &.{}, f2);

    // Read frame 3
    const f3 = try readFrame(&reader, &read_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, f3);
}

test "sequential: write and read multiple frames (alloc)" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writeFrame("world", &writer);
    try writeFrame(&[_]u8{ 0x01, 0x02 }, &writer);

    var reader: Io.Reader = .fixed(writer.buffered());

    const f1 = try readFrameAlloc(&reader, testing.allocator);
    defer testing.allocator.free(f1);
    try testing.expectEqualSlices(u8, "world", f1);

    const f2 = try readFrameAlloc(&reader, testing.allocator);
    defer testing.allocator.free(f2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, f2);
}

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

test "boundary: max_frame_size is exactly 65535" {
    try testing.expectEqual(@as(usize, 65_535), max_frame_size);
}

test "boundary: payload of exactly max_frame_size succeeds" {
    const payload = try testing.allocator.alloc(u8, max_frame_size);
    defer testing.allocator.free(payload);
    @memset(payload, 0x42);

    const frame_buf = try testing.allocator.alloc(u8, 2 + max_frame_size);
    defer testing.allocator.free(frame_buf);
    var writer: Io.Writer = .fixed(frame_buf);
    // Should succeed without error
    try writeFrame(payload, &writer);
}

test "boundary: payload of max_frame_size + 1 fails" {
    const payload = try testing.allocator.alloc(u8, max_frame_size + 1);
    defer testing.allocator.free(payload);
    @memset(payload, 0x42);

    var buf: [4]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try testing.expectError(error.MessageTooLarge, writeFrame(payload, &writer));
}

test {
    testing.refAllDecls(@This());
}
