//! Test helper utilities for wire-vector tests.
//!
//! Provides hex-string parsing and byte-slice comparison with
//! readable hex-diff output on failure.
const std = @import("std");
const testing = std.testing;

/// Parse a hex string (e.g. "deadbeef" or "DE AD BE EF") into a byte slice.
/// Allocates using the provided allocator — caller owns the returned memory.
/// Spaces are ignored so both compact and spaced formats work.
pub fn hexToBytes(allocator: std.mem.Allocator, hex_string: []const u8) ![]u8 {
    // Count non-space hex chars.
    var hex_len: usize = 0;
    for (hex_string) |c| {
        if (c != ' ') hex_len += 1;
    }

    if (hex_len % 2 != 0) {
        return error.OddHexLength;
    }

    const out = try allocator.alloc(u8, hex_len / 2);
    errdefer allocator.free(out);

    var hi: ?u4 = null;
    var out_idx: usize = 0;
    for (hex_string) |c| {
        if (c == ' ') continue;
        const nibble = hexDigit(c) orelse return error.InvalidHexChar;
        if (hi) |h| {
            out[out_idx] = (@as(u8, h) << 4) | @as(u8, nibble);
            out_idx += 1;
            hi = null;
        } else {
            hi = nibble;
        }
    }

    return out;
}

fn hexDigit(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

const HexFmt = struct {
    hex: []const u8,
    truncated: bool,
};

/// Format a byte slice as a lowercase hex string for display.
/// Reports whether the output was truncated due to buffer size.
fn formatHex(buf: []u8, bytes: []const u8) HexFmt {
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    var count: usize = 0;
    for (bytes) |b| {
        if (i + 1 >= buf.len) break;
        buf[i] = hex_chars[b >> 4];
        buf[i + 1] = hex_chars[b & 0x0f];
        i += 2;
        count += 1;
    }
    return .{ .hex = buf[0..i], .truncated = count < bytes.len };
}

const Mismatch = struct {
    pos: usize,
    expected_byte: ?u8,
    actual_byte: ?u8,
};

/// Find the first position where two byte slices diverge.
/// Returns `null` when the slices are identical.
fn findMismatch(expected: []const u8, actual: []const u8) ?Mismatch {
    if (std.mem.eql(u8, expected, actual)) return null;

    const min_len = @min(expected.len, actual.len);
    for (0..min_len) |i| {
        if (expected[i] != actual[i]) {
            return .{ .pos = i, .expected_byte = expected[i], .actual_byte = actual[i] };
        }
    }

    // Lengths differ but the shared prefix matches.
    return .{
        .pos = min_len,
        .expected_byte = if (min_len < expected.len) expected[min_len] else null,
        .actual_byte = if (min_len < actual.len) actual[min_len] else null,
    };
}

/// Compare two byte slices. On mismatch, prints a hex diff showing the first
/// differing byte position along with both full slices in hex.
pub fn assertEqualBytes(expected: []const u8, actual: []const u8) !void {
    const m = findMismatch(expected, actual) orelse return;

    var exp_hex_buf: [2048]u8 = undefined;
    var act_hex_buf: [2048]u8 = undefined;
    const exp = formatHex(&exp_hex_buf, expected);
    const act = formatHex(&act_hex_buf, actual);
    const exp_suffix: []const u8 = if (exp.truncated) "…" else "";
    const act_suffix: []const u8 = if (act.truncated) "…" else "";

    std.debug.print("\n=== Byte slice mismatch ===\n", .{});
    std.debug.print("Expected ({d} bytes): {s}{s}\n", .{ expected.len, exp.hex, exp_suffix });
    std.debug.print("Actual   ({d} bytes): {s}{s}\n", .{ actual.len, act.hex, act_suffix });

    if (m.expected_byte) |eb| {
        if (m.actual_byte) |ab| {
            std.debug.print("First diff at byte {d}: expected 0x{x:0>2}, got 0x{x:0>2}\n", .{ m.pos, eb, ab });
        } else {
            std.debug.print("First diff at byte {d}: expected 0x{x:0>2}, got end-of-slice\n", .{ m.pos, eb });
        }
    } else if (m.actual_byte) |ab| {
        std.debug.print("First diff at byte {d}: expected end-of-slice, got 0x{x:0>2}\n", .{ m.pos, ab });
    }

    return error.TestExpectedEqual;
}

/// Convenience: parse `expected_hex` and compare against `actual_bytes`.
/// Uses `std.testing.allocator` for the temporary hex parse.
pub fn expectEqualHex(expected_hex: []const u8, actual_bytes: []const u8) !void {
    const expected = try hexToBytes(testing.allocator, expected_hex);
    defer testing.allocator.free(expected);
    try assertEqualBytes(expected, actual_bytes);
}

// ── Self-tests ──────────────────────────────────────────────────────

test "hexToBytes: compact lowercase" {
    const bytes = try hexToBytes(testing.allocator, "deadbeef");
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, bytes);
}

test "hexToBytes: spaced uppercase" {
    const bytes = try hexToBytes(testing.allocator, "DE AD BE EF");
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, bytes);
}

test "hexToBytes: mixed case" {
    const bytes = try hexToBytes(testing.allocator, "DeAdBeEf");
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, bytes);
}

test "hexToBytes: empty string" {
    const bytes = try hexToBytes(testing.allocator, "");
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, 0), bytes.len);
}

test "hexToBytes: single byte" {
    const bytes = try hexToBytes(testing.allocator, "ff");
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{0xff}, bytes);
}

test "hexToBytes: odd length is error" {
    const result = hexToBytes(testing.allocator, "abc");
    try testing.expectError(error.OddHexLength, result);
}

test "hexToBytes: invalid char is error" {
    const result = hexToBytes(testing.allocator, "zz");
    try testing.expectError(error.InvalidHexChar, result);
}

test "assertEqualBytes: matching slices" {
    try assertEqualBytes(&.{ 0x01, 0x02 }, &.{ 0x01, 0x02 });
}

test "assertEqualBytes: empty slices" {
    try assertEqualBytes(&.{}, &.{});
}

test "assertEqualBytes: value mismatch returns error" {
    try testing.expectError(error.TestExpectedEqual, assertEqualBytes(&.{ 0x01, 0x02 }, &.{ 0x01, 0x03 }));
}

test "assertEqualBytes: length mismatch returns error" {
    try testing.expectError(error.TestExpectedEqual, assertEqualBytes(&.{0x01}, &.{ 0x01, 0x02 }));
}

test "findMismatch: byte differs" {
    const m = findMismatch(&.{ 0x01, 0x02 }, &.{ 0x01, 0x03 }).?;
    try testing.expectEqual(@as(usize, 1), m.pos);
    try testing.expectEqual(@as(?u8, 0x02), m.expected_byte);
    try testing.expectEqual(@as(?u8, 0x03), m.actual_byte);
}

test "findMismatch: actual longer" {
    const m = findMismatch(&.{0x01}, &.{ 0x01, 0x02 }).?;
    try testing.expectEqual(@as(usize, 1), m.pos);
    try testing.expectEqual(@as(?u8, null), m.expected_byte);
    try testing.expectEqual(@as(?u8, 0x02), m.actual_byte);
}

test "findMismatch: expected longer" {
    const m = findMismatch(&.{ 0x01, 0x02 }, &.{0x01}).?;
    try testing.expectEqual(@as(usize, 1), m.pos);
    try testing.expectEqual(@as(?u8, 0x02), m.expected_byte);
    try testing.expectEqual(@as(?u8, null), m.actual_byte);
}

test "findMismatch: equal returns null" {
    try testing.expectEqual(@as(?Mismatch, null), findMismatch(&.{ 0x01, 0x02 }, &.{ 0x01, 0x02 }));
}

test "expectEqualHex: matching" {
    try expectEqualHex("0102", &.{ 0x01, 0x02 });
}

test "expectEqualHex: mismatch returns error" {
    try testing.expectError(error.TestExpectedEqual, expectEqualHex("0102", &.{ 0x01, 0x03 }));
}
