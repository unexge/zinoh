//! Zenoh messages: Put, Del, Query, Reply, Err.
//!
//! Implements encode/decode for Zenoh-layer messages per Zenoh protocol v0x09.
//! These messages are carried inside network messages (Push, Request, Response).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const vle = @import("../codec/vle.zig");
const primitives = @import("../codec/primitives.zig");
const hdr = @import("../codec/header.zig");
const transport = @import("../transport/messages.zig");
const ZenohId = transport.ZenohId;

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
// Timestamp (§2.9)
// ═══════════════════════════════════════════════════════════════════════════

/// Timestamp: a NTP64 time with a ZenohId identifying the source.
///
/// Wire format (§2.9):
///   VLE: time (NTP64 encoded as VLE)
///   u8: zid_len (length of the ZenohId bytes)
///   [zid_len]u8: ZenohId bytes
pub const Timestamp = struct {
    time: u64,
    id: ZenohId,

    /// Encode this Timestamp to the writer.
    pub fn encode(self: *const Timestamp, writer: *Io.Writer) Io.Writer.Error!void {
        try vle.encode(self.time, writer);
        try writer.writeByte(@intCast(self.id.len));
        try writer.writeAll(self.id.slice());
    }

    /// Decode a Timestamp from the reader.
    pub fn decode(reader: *Io.Reader) DecodeError!Timestamp {
        const time = try vle.decode(reader);
        const zid_len: u8 = try reader.takeByte();
        if (zid_len == 0 or zid_len > ZenohId.max_len) return error.InvalidZenohIdLength;
        var id = ZenohId{};
        id.len = @intCast(zid_len);
        try reader.readSliceAll(id.bytes[0..zid_len]);
        return Timestamp{
            .time = time,
            .id = id,
        };
    }
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

    /// Decode an Encoding from the reader.
    /// Caller owns the schema memory (if non-null) and must free with `allocator`.
    pub fn decode(reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Encoding {
        const raw = try vle.decode(reader);
        const has_schema = (raw & 1) != 0;
        const id: u16 = @intCast(raw >> 1);

        var schema: ?[]u8 = null;
        if (has_schema) {
            schema = try primitives.readString(reader, allocator);
        }

        return Encoding{
            .id = id,
            .schema = schema,
        };
    }

    /// Free allocator-owned memory from a decoded Encoding.
    pub fn deinit(self: *const Encoding, allocator: Allocator) void {
        if (self.schema) |s| allocator.free(@constCast(s));
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

pub const DecodeError = Io.Reader.Error || error{ InvalidMid, InvalidZenohIdLength };

pub const DecodeAllocError = Io.Reader.Error || Io.Reader.ReadAllocError || error{ InvalidMid, InvalidZenohIdLength };

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
    /// Optional timestamp (sets T flag when present).
    timestamp: ?Timestamp = null,
    /// Optional encoding (sets E flag when present).
    encoding: ?Encoding = null,
    /// Payload bytes.
    payload: []const u8,

    /// Free allocator-owned memory from a decoded Put.
    /// Must be called with the same allocator passed to `decode`.
    pub fn deinit(self: *const Put, allocator: Allocator) void {
        if (self.encoding) |enc| enc.deinit(allocator);
        allocator.free(@constCast(self.payload));
    }

    /// Encode this Put message to the writer.
    pub fn encode(self: *const Put, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|E|T| MID=0x01 |
        var header: u8 = @as(u8, MID.put);
        if (self.timestamp != null) header |= Flag.bit5; // T flag
        if (self.encoding != null) header |= Flag.bit6; // E flag
        // Z flag (bit 7): extensions — not yet supported
        try writer.writeByte(header);

        // Timestamp (if T=1)
        if (self.timestamp) |ts| {
            try ts.encode(writer);
        }

        // Encoding (if E=1)
        if (self.encoding) |enc| {
            try enc.encode(writer);
        }

        // Payload (VLE-length-prefixed)
        try primitives.writeSlice(self.payload, writer);
    }

    /// Decode a Put message from the reader. The header byte has already been
    /// parsed to determine this is a Put (MID=0x01).
    /// Caller owns returned memory and must call `deinit` with `allocator`.
    pub fn decode(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Put {
        const t_flag = (header & Flag.bit5) != 0;
        const e_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        // Timestamp (if T=1)
        var timestamp: ?Timestamp = null;
        if (t_flag) {
            timestamp = try Timestamp.decode(reader);
        }

        var encoding: ?Encoding = null;
        if (e_flag) {
            encoding = try Encoding.decode(reader, allocator);
        }
        errdefer if (encoding) |enc| enc.deinit(allocator);

        if (z_flag) {
            try skipExtensions(reader);
        }

        const payload = try primitives.readSlice(reader, allocator);

        return Put{
            .timestamp = timestamp,
            .encoding = encoding,
            .payload = payload,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Del (MID = 0x02)
// ═══════════════════════════════════════════════════════════════════════════

/// Del message: signals deletion of a key.
///
/// Wire format (§9.2):
///   header: |Z|X|T| 0x02 |
///   if T=1: timestamp (VLE time + ZenohID)
///   if Z=1: extensions
pub const Del = struct {
    /// Optional timestamp (sets T flag when present).
    timestamp: ?Timestamp = null,

    /// Encode this Del message to the writer.
    pub fn encode(self: *const Del, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|X|T| MID=0x02 |
        var header: u8 = @as(u8, MID.del);
        if (self.timestamp != null) header |= Flag.bit5; // T flag
        // Z flag (bit 7): extensions — not yet supported
        try writer.writeByte(header);

        // Timestamp (if T=1)
        if (self.timestamp) |ts| {
            try ts.encode(writer);
        }
    }

    /// Decode a Del message from the reader. The header byte has already been
    /// parsed to determine this is a Del (MID=0x02).
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!Del {
        const t_flag = (header & Flag.bit5) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        // Timestamp (if T=1)
        var timestamp: ?Timestamp = null;
        if (t_flag) {
            timestamp = try Timestamp.decode(reader);
        }

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Del{
            .timestamp = timestamp,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Query (MID = 0x03)
// ═══════════════════════════════════════════════════════════════════════════

/// Query message: carries query parameters inside a Request.
///
/// Wire format (§9.3):
///   header: |Z|P|C| 0x03 |
///   if C=1: consolidation (1 byte)
///   if P=1: parameters (VLE-length-prefixed UTF-8 selector parameters)
///   if Z=1: extensions (source_info, body/value, attachment)
pub const Query = struct {
    /// Optional consolidation mode (sets C flag when present).
    consolidation: ?u8 = null,
    /// Optional selector parameters (sets P flag when present).
    parameters: ?[]const u8 = null,

    /// Free allocator-owned memory from a decoded Query.
    /// Must be called with the same allocator passed to `decode`.
    pub fn deinit(self: *const Query, allocator: Allocator) void {
        if (self.parameters) |p| allocator.free(@constCast(p));
    }

    /// Encode this Query message to the writer.
    pub fn encode(self: *const Query, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|P|C| MID=0x03 |
        var header: u8 = @as(u8, MID.query);
        if (self.consolidation != null) header |= Flag.bit5; // C flag
        if (self.parameters != null) header |= Flag.bit6; // P flag
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Consolidation (if C=1)
        if (self.consolidation) |c| {
            try writer.writeByte(c);
        }

        // Parameters (if P=1)
        if (self.parameters) |params| {
            try primitives.writeString(params, writer);
        }
    }

    /// Decode a Query message from the reader. The header byte has already been
    /// parsed to determine this is a Query (MID=0x03).
    /// Caller owns returned memory and must call `deinit` with `allocator`.
    pub fn decode(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Query {
        const c_flag = (header & Flag.bit5) != 0;
        const p_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        var consolidation: ?u8 = null;
        if (c_flag) {
            consolidation = try reader.takeByte();
        }

        var parameters: ?[]u8 = null;
        if (p_flag) {
            parameters = try primitives.readString(reader, allocator);
        }
        errdefer if (parameters) |p| allocator.free(p);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Query{
            .consolidation = consolidation,
            .parameters = parameters,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Reply (MID = 0x04)
// ═══════════════════════════════════════════════════════════════════════════

/// Tagged union for the body of a Reply message: either a Put or a Del.
pub const ReplyBody = union(enum) {
    put: Put,
    del: Del,

    /// Free allocator-owned memory from a decoded ReplyBody.
    pub fn deinit(self: *const ReplyBody, allocator: Allocator) void {
        switch (self.*) {
            .put => |*p| p.deinit(allocator),
            .del => {},
        }
    }
};

/// Reply message: wraps a reply to a query (inside a Response).
///
/// Wire format (§9.4):
///   header: |Z|X|C| 0x04 |
///   if C=1: consolidation (1 byte)
///   if Z=1: extensions
///   ReplyBody: a Put or Del message (decoded by inner header)
pub const Reply = struct {
    /// Optional consolidation mode (sets C flag when present).
    consolidation: ?u8 = null,
    /// The reply body: a Put or Del message.
    body: ReplyBody,

    /// Free allocator-owned memory from a decoded Reply.
    /// Must be called with the same allocator passed to `decode`.
    pub fn deinit(self: *const Reply, allocator: Allocator) void {
        self.body.deinit(allocator);
    }

    /// Encode this Reply message to the writer.
    pub fn encode(self: *const Reply, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|X|C| MID=0x04 |
        var header: u8 = @as(u8, MID.reply);
        if (self.consolidation != null) header |= Flag.bit5; // C flag
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Consolidation (if C=1)
        if (self.consolidation) |c| {
            try writer.writeByte(c);
        }

        // ReplyBody: encode the inner Put or Del
        switch (self.body) {
            .put => |*p| try p.encode(writer),
            .del => |*d| try d.encode(writer),
        }
    }

    /// Decode a Reply message from the reader. The header byte has already been
    /// parsed to determine this is a Reply (MID=0x04).
    /// Caller owns returned memory and must call `deinit` with `allocator`.
    pub fn decode(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Reply {
        const c_flag = (header & Flag.bit5) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        var consolidation: ?u8 = null;
        if (c_flag) {
            consolidation = try reader.takeByte();
        }

        if (z_flag) {
            try skipExtensions(reader);
        }

        // Decode inner ReplyBody: read the next header byte to determine Put or Del
        const inner_header = try reader.takeByte();
        const inner_mid = hdr.Header.decode(inner_header).mid;

        const body: ReplyBody = switch (inner_mid) {
            MID.put => .{ .put = try Put.decode(inner_header, reader, allocator) },
            MID.del => .{ .del = try Del.decode(inner_header, reader) },
            else => return error.InvalidMid,
        };

        return Reply{
            .consolidation = consolidation,
            .body = body,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Err (MID = 0x05)
// ═══════════════════════════════════════════════════════════════════════════

/// Err message: error reply to a query (inside a Response).
///
/// Wire format (§9.5):
///   header: |Z|E|X| 0x05 |
///   if E=1: encoding of the error payload
///   if Z=1: extensions (source_info)
///   payload: VLE-length-prefixed error payload bytes
pub const Err = struct {
    /// Encoding of the error payload (sets E flag when present).
    encoding: ?Encoding = null,
    /// Error payload bytes.
    payload: []const u8,

    /// Free allocator-owned memory from a decoded Err.
    /// Must be called with the same allocator passed to `decode`.
    pub fn deinit(self: *const Err, allocator: Allocator) void {
        if (self.encoding) |enc| enc.deinit(allocator);
        allocator.free(@constCast(self.payload));
    }

    /// Encode this Err message to the writer.
    pub fn encode(self: *const Err, writer: *Io.Writer) Io.Writer.Error!void {
        // Header: |Z|E|X| MID=0x05 |
        var header: u8 = @as(u8, MID.err);
        if (self.encoding != null) header |= Flag.bit6; // E flag (bit 6)
        // Z flag (bit 7): extensions — not yet supported for encode
        try writer.writeByte(header);

        // Encoding (if E=1)
        if (self.encoding) |enc| {
            try enc.encode(writer);
        }

        // Payload (VLE-length-prefixed)
        try primitives.writeSlice(self.payload, writer);
    }

    /// Decode an Err message from the reader. The header byte has already been
    /// parsed to determine this is an Err (MID=0x05).
    /// Caller owns returned memory and must call `deinit` with `allocator`.
    pub fn decode(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!Err {
        const e_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        var encoding: ?Encoding = null;
        if (e_flag) {
            encoding = try Encoding.decode(reader, allocator);
        }
        errdefer if (encoding) |enc| enc.deinit(allocator);

        if (z_flag) {
            try skipExtensions(reader);
        }

        const payload = try primitives.readSlice(reader, allocator);

        return Err{
            .encoding = encoding,
            .payload = payload,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("../testing.zig").assertEqualBytes;

// ---------------------------------------------------------------------------
// Timestamp tests
// ---------------------------------------------------------------------------

fn encodeTimestampHelper(ts: *const Timestamp, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    ts.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Timestamp: encode time=0, 1-byte ZenohId" {
    const zid = ZenohId.init(&.{0x42}) catch unreachable;
    const ts = Timestamp{ .time = 0, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    // VLE(0) = 0x00, zid_len = 0x01, zid = 0x42
    try assertEqualBytes(&.{ 0x00, 0x01, 0x42 }, encoded);
}

test "Timestamp: encode time=1000, 3-byte ZenohId" {
    const zid = ZenohId.init(&.{ 0xAA, 0xBB, 0xCC }) catch unreachable;
    const ts = Timestamp{ .time = 1000, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    // VLE(1000) = 0xE8 0x07, zid_len = 0x03, zid = AA BB CC
    try assertEqualBytes(&.{ 0xE8, 0x07, 0x03, 0xAA, 0xBB, 0xCC }, encoded);
}

test "Timestamp: round-trip time=0, 1-byte ZenohId" {
    const zid = ZenohId.init(&.{0x42}) catch unreachable;
    const ts = Timestamp{ .time = 0, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Timestamp.decode(&reader);
    try testing.expectEqual(@as(u64, 0), decoded.time);
    try testing.expectEqualSlices(u8, &.{0x42}, decoded.id.slice());
}

test "Timestamp: round-trip time=1000, 3-byte ZenohId" {
    const zid = ZenohId.init(&.{ 0xAA, 0xBB, 0xCC }) catch unreachable;
    const ts = Timestamp{ .time = 1000, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Timestamp.decode(&reader);
    try testing.expectEqual(@as(u64, 1000), decoded.time);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC }, decoded.id.slice());
}

test "Timestamp: round-trip large time value" {
    const zid = ZenohId.init(&.{0x01}) catch unreachable;
    const ts = Timestamp{ .time = 0x123456789ABCDEF0, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Timestamp.decode(&reader);
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), decoded.time);
    try testing.expectEqualSlices(u8, &.{0x01}, decoded.id.slice());
}

test "Timestamp: round-trip 16-byte ZenohId (max length)" {
    const zid_bytes = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const zid = ZenohId.init(&zid_bytes) catch unreachable;
    const ts = Timestamp{ .time = 42, .id = zid };
    var buf: [32]u8 = undefined;
    const encoded = encodeTimestampHelper(&ts, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Timestamp.decode(&reader);
    try testing.expectEqual(@as(u64, 42), decoded.time);
    try testing.expectEqualSlices(u8, &zid_bytes, decoded.id.slice());
}

test "Timestamp: decode rejects zid_len=0" {
    // VLE(42) = 0x2A, then zid_len = 0x00 (invalid: must be >= 1)
    var reader: Io.Reader = .fixed(&.{ 0x2A, 0x00 });
    try testing.expectError(error.InvalidZenohIdLength, Timestamp.decode(&reader));
}

test "Timestamp: decode rejects zid_len > 16" {
    // VLE(42) = 0x2A, then zid_len = 17 (invalid: max is 16)
    var reader: Io.Reader = .fixed(&.{ 0x2A, 17 });
    try testing.expectError(error.InvalidZenohIdLength, Timestamp.decode(&reader));
}

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

test "Encoding: round-trip id=0, no schema" {
    const enc = Encoding{ .id = 0 };
    var buf: [16]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Encoding.decode(&reader, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), decoded.id);
    try testing.expectEqual(@as(?[]const u8, null), decoded.schema);
}

test "Encoding: round-trip id=10, no schema" {
    const enc = Encoding{ .id = 10 };
    var buf: [16]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Encoding.decode(&reader, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 10), decoded.id);
    try testing.expectEqual(@as(?[]const u8, null), decoded.schema);
}

test "Encoding: round-trip id=0, with schema 'text'" {
    const enc = Encoding{ .id = 0, .schema = "text" };
    var buf: [32]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Encoding.decode(&reader, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 0), decoded.id);
    try testing.expectEqualStrings("text", decoded.schema.?);
}

test "Encoding: round-trip id=10, with schema 'json'" {
    const enc = Encoding{ .id = 10, .schema = "json" };
    var buf: [32]u8 = undefined;
    const encoded = encodeEncodingHelper(&enc, &buf);
    var reader: Io.Reader = .fixed(encoded);
    const decoded = try Encoding.decode(&reader, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u16, 10), decoded.id);
    try testing.expectEqualStrings("json", decoded.schema.?);
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

test "Put: round-trip minimal (no encoding)" {
    const msg = Put{ .payload = "Hello World!" };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?Encoding, null), decoded.encoding);
    try testing.expectEqualStrings("Hello World!", decoded.payload);
}

test "Put: round-trip with encoding" {
    const msg = Put{
        .encoding = .{ .id = 10 },
        .payload = "data",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 10), decoded.encoding.?.id);
    try testing.expectEqual(@as(?[]const u8, null), decoded.encoding.?.schema);
    try testing.expectEqualStrings("data", decoded.payload);
}

test "Put: round-trip with encoding and schema" {
    const msg = Put{
        .encoding = .{ .id = 5, .schema = "text/plain" },
        .payload = "hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 5), decoded.encoding.?.id);
    try testing.expectEqualStrings("text/plain", decoded.encoding.?.schema.?);
    try testing.expectEqualStrings("hello", decoded.payload);
}

test "Put: round-trip empty payload" {
    const msg = Put{ .payload = "" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualStrings("", decoded.payload);
}

test "Put: with timestamp (T flag set)" {
    const zid = ZenohId.init(&.{0x42}) catch unreachable;
    const msg = Put{
        .timestamp = .{ .time = 100, .id = zid },
        .payload = "data",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x21 (MID=0x01 | T=0x20)
    try testing.expectEqual(@as(u8, 0x21), encoded[0]);
    // T flag set
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // T flag (bit 5)
}

test "Put: T flag clear when no timestamp" {
    const msg = Put{ .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // T flag (bit 5) not set
}

test "Put: round-trip with timestamp" {
    const zid = ZenohId.init(&.{ 0xDE, 0xAD }) catch unreachable;
    const msg = Put{
        .timestamp = .{ .time = 42, .id = zid },
        .payload = "hello",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expect(decoded.timestamp != null);
    try testing.expectEqual(@as(u64, 42), decoded.timestamp.?.time);
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, decoded.timestamp.?.id.slice());
    try testing.expectEqual(@as(?Encoding, null), decoded.encoding);
    try testing.expectEqualStrings("hello", decoded.payload);
}

test "Put: round-trip with all fields (timestamp + encoding + payload)" {
    const zid = ZenohId.init(&.{ 0x01, 0x02, 0x03 }) catch unreachable;
    const msg = Put{
        .timestamp = .{ .time = 1000, .id = zid },
        .encoding = .{ .id = 10, .schema = "application/json" },
        .payload = "{\"key\":\"value\"}",
    };
    var buf: [128]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header should have both T and E flags set: 0x61 (MID=0x01 | T=0x20 | E=0x40)
    try testing.expectEqual(@as(u8, 0x61), encoded[0]);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Put.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expect(decoded.timestamp != null);
    try testing.expectEqual(@as(u64, 1000), decoded.timestamp.?.time);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, decoded.timestamp.?.id.slice());
    try testing.expectEqual(@as(u16, 10), decoded.encoding.?.id);
    try testing.expectEqualStrings("application/json", decoded.encoding.?.schema.?);
    try testing.expectEqualStrings("{\"key\":\"value\"}", decoded.payload);
}

test "Put: wire vector — 'Hello World!' with default encoding" {
    // Put with default encoding (id=0, no schema) and payload "Hello World!"
    const msg = Put{
        .encoding = .{ .id = 0 },
        .payload = "Hello World!",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodePutHelper(&msg, &buf);

    // Header: 0x41 (MID=0x01 | E=0x40)
    // Encoding: VLE(0) = 0x00 (id=0, no schema → (0<<1)|0 = 0)
    // Payload: VLE(12) = 0x0C + "Hello World!"
    try assertEqualBytes(
        &(.{ 0x41, 0x00, 0x0C } ++ "Hello World!".*),
        encoded,
    );
}

// ---------------------------------------------------------------------------
// Del tests
// ---------------------------------------------------------------------------

fn encodeDelHelper(msg: *const Del, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Del: minimal encode" {
    const msg = Del{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);

    // Header: 0x02 (MID=0x02, T=0, Z=0)
    try assertEqualBytes(&.{0x02}, encoded);
}

test "Del: MID is del" {
    const msg = Del{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.del), hdr.Header.decode(encoded[0]).mid);
}

test "Del: round-trip" {
    const msg = Del{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Del.decode(header, &reader);
    try testing.expectEqual(@as(?Timestamp, null), decoded.timestamp);
}

test "Del: with timestamp (T flag set)" {
    const zid = ZenohId.init(&.{0x42}) catch unreachable;
    const msg = Del{
        .timestamp = .{ .time = 100, .id = zid },
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);

    // Header: 0x22 (MID=0x02 | T=0x20)
    try testing.expectEqual(@as(u8, 0x22), encoded[0]);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // T flag (bit 5)
}

test "Del: T flag clear when no timestamp" {
    const msg = Del{};
    var buf: [16]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // T flag not set
}

test "Del: round-trip with timestamp" {
    const zid = ZenohId.init(&.{ 0xDE, 0xAD }) catch unreachable;
    const msg = Del{
        .timestamp = .{ .time = 42, .id = zid },
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Del.decode(header, &reader);

    try testing.expect(decoded.timestamp != null);
    try testing.expectEqual(@as(u64, 42), decoded.timestamp.?.time);
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, decoded.timestamp.?.id.slice());
}

test "Del: wire vector — del with timestamp" {
    const zid = ZenohId.init(&.{0x01}) catch unreachable;
    const msg = Del{
        .timestamp = .{ .time = 0, .id = zid },
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeDelHelper(&msg, &buf);

    // Header: 0x22 (MID=0x02 | T=0x20)
    // Timestamp: VLE(0) = 0x00, zid_len = 0x01, zid = 0x01
    try assertEqualBytes(&.{ 0x22, 0x00, 0x01, 0x01 }, encoded);
}

// ---------------------------------------------------------------------------
// Query tests
// ---------------------------------------------------------------------------

fn encodeQueryHelper(msg: *const Query, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Query: minimal (no consolidation, no parameters)" {
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    // Header: 0x03 (MID=0x03, C=0, P=0, Z=0)
    try assertEqualBytes(&.{0x03}, encoded);
}

test "Query: MID is query" {
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.query), hdr.Header.decode(encoded[0]).mid);
}

test "Query: C flag set when consolidation present" {
    const msg = Query{ .consolidation = 1 };
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // C flag (bit 5)
}

test "Query: C flag clear when no consolidation" {
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // C flag not set
}

test "Query: P flag set when parameters present" {
    const msg = Query{ .parameters = "time>now()" };
    var buf: [64]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // P flag (bit 6)
}

test "Query: P flag clear when no parameters" {
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // P flag not set
}

test "Query: with consolidation only" {
    const msg = Query{ .consolidation = 2 };
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    // Header: 0x23 (MID=0x03 | C=0x20)
    // Consolidation: 0x02
    try assertEqualBytes(&.{ 0x23, 0x02 }, encoded);
}

test "Query: with parameters only" {
    const msg = Query{ .parameters = "key=val" };
    var buf: [32]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    // Header: 0x43 (MID=0x03 | P=0x40)
    // Parameters: VLE(7) = 0x07 + "key=val"
    try assertEqualBytes(
        &(.{ 0x43, 0x07 } ++ "key=val".*),
        encoded,
    );
}

test "Query: with consolidation and parameters" {
    const msg = Query{
        .consolidation = 3,
        .parameters = "x=1",
    };
    var buf: [32]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    // Header: 0x63 (MID=0x03 | C=0x20 | P=0x40)
    // Consolidation: 0x03
    // Parameters: VLE(3) = 0x03 + "x=1"
    try assertEqualBytes(
        &(.{ 0x63, 0x03, 0x03 } ++ "x=1".*),
        encoded,
    );
}

test "Query: round-trip minimal (no consolidation, no parameters)" {
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Query.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, null), decoded.consolidation);
    try testing.expectEqual(@as(?[]const u8, null), decoded.parameters);
}

test "Query: round-trip with consolidation" {
    const msg = Query{ .consolidation = 2 };
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Query.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, 2), decoded.consolidation);
    try testing.expectEqual(@as(?[]const u8, null), decoded.parameters);
}

test "Query: round-trip with parameters" {
    const msg = Query{ .parameters = "time>now()" };
    var buf: [64]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Query.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, null), decoded.consolidation);
    try testing.expectEqualStrings("time>now()", decoded.parameters.?);
}

test "Query: round-trip with consolidation and parameters" {
    const msg = Query{
        .consolidation = 1,
        .parameters = "key=value&other=stuff",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Query.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, 1), decoded.consolidation);
    try testing.expectEqualStrings("key=value&other=stuff", decoded.parameters.?);
}

test "Query: wire vector for 'demo/example/hello' query (minimal)" {
    // A minimal query: no consolidation, no parameters.
    // This is the Zenoh-layer part; the Request header wraps it.
    const msg = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&msg, &buf);

    // Header: 0x03 (MID=0x03, C=0, P=0, Z=0)
    try assertEqualBytes(&.{0x03}, encoded);
}

test "Query: wire vector with all consolidation modes" {
    const modes = [_]u8{ 0, 1, 2, 3 }; // Auto, None, Mono, Latest
    for (modes) |mode| {
        const msg = Query{ .consolidation = mode };
        var buf: [16]u8 = undefined;
        const encoded = encodeQueryHelper(&msg, &buf);

        // Header: 0x23 (MID=0x03 | C=0x20)
        try testing.expectEqual(@as(u8, 0x23), encoded[0]);
        // Consolidation byte
        try testing.expectEqual(mode, encoded[1]);
    }
}

// ---------------------------------------------------------------------------
// Reply tests
// ---------------------------------------------------------------------------

fn encodeReplyHelper(msg: *const Reply, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Reply: wrapping a Put (no consolidation)" {
    const msg = Reply{
        .body = .{ .put = Put{ .payload = "Hello" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    // Reply header: 0x04 (MID=0x04, C=0)
    // Put header: 0x01 (MID=0x01, T=0, E=0)
    // Put payload: VLE(5) = 0x05 + "Hello"
    try assertEqualBytes(
        &(.{ 0x04, 0x01, 0x05 } ++ "Hello".*),
        encoded,
    );
}

test "Reply: wrapping a Put with consolidation" {
    const msg = Reply{
        .consolidation = 2,
        .body = .{ .put = Put{ .payload = "data" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    // Reply header: 0x24 (MID=0x04 | C=0x20)
    // Consolidation: 0x02
    // Put header: 0x01
    // Put payload: VLE(4) = 0x04 + "data"
    try assertEqualBytes(
        &(.{ 0x24, 0x02, 0x01, 0x04 } ++ "data".*),
        encoded,
    );
}

test "Reply: wrapping a Del (no consolidation)" {
    const msg = Reply{
        .body = .{ .del = Del{} },
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    // Reply header: 0x04 (MID=0x04, C=0)
    // Del header: 0x02 (MID=0x02)
    try assertEqualBytes(&.{ 0x04, 0x02 }, encoded);
}

test "Reply: MID is reply" {
    const msg = Reply{
        .body = .{ .put = Put{ .payload = "x" } },
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.reply), hdr.Header.decode(encoded[0]).mid);
}

test "Reply: C flag set when consolidation present" {
    const msg = Reply{
        .consolidation = 1,
        .body = .{ .put = Put{ .payload = "x" } },
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // C flag (bit 5)
}

test "Reply: C flag clear when no consolidation" {
    const msg = Reply{
        .body = .{ .put = Put{ .payload = "x" } },
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0()); // C flag not set
}

test "Reply: round-trip wrapping a Put" {
    const msg = Reply{
        .body = .{ .put = Put{ .payload = "Hello World!" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Reply.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, null), decoded.consolidation);
    switch (decoded.body) {
        .put => |p| try testing.expectEqualStrings("Hello World!", p.payload),
        .del => return error.TestExpectedEqual,
    }
}

test "Reply: round-trip wrapping a Put with encoding" {
    const msg = Reply{
        .body = .{ .put = Put{
            .encoding = .{ .id = 10 },
            .payload = "data",
        } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Reply.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    switch (decoded.body) {
        .put => |p| {
            try testing.expectEqual(@as(u16, 10), p.encoding.?.id);
            try testing.expectEqualStrings("data", p.payload);
        },
        .del => return error.TestExpectedEqual,
    }
}

test "Reply: round-trip wrapping a Del" {
    const msg = Reply{
        .body = .{ .del = Del{} },
    };
    var buf: [16]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Reply.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, null), decoded.consolidation);
    switch (decoded.body) {
        .del => {},
        .put => return error.TestExpectedEqual,
    }
}

test "Reply: round-trip with consolidation wrapping a Put" {
    const msg = Reply{
        .consolidation = 3,
        .body = .{ .put = Put{ .payload = "latest" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Reply.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u8, 3), decoded.consolidation);
    switch (decoded.body) {
        .put => |p| try testing.expectEqualStrings("latest", p.payload),
        .del => return error.TestExpectedEqual,
    }
}

test "Reply: wire vector — Reply(Put('Hello')) response" {
    // Simulates what a router sends back for a query reply.
    const msg = Reply{
        .body = .{ .put = Put{ .payload = "Hello" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&msg, &buf);

    // Reply header: 0x04
    // Put header: 0x01
    // Put payload: VLE(5) + "Hello"
    try assertEqualBytes(
        &(.{ 0x04, 0x01, 0x05 } ++ "Hello".*),
        encoded,
    );
}

// ---------------------------------------------------------------------------
// Err tests
// ---------------------------------------------------------------------------

fn encodeErrHelper(msg: *const Err, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

test "Err: minimal (no encoding)" {
    const msg = Err{ .payload = "not found" };
    var buf: [64]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    // Header: 0x05 (MID=0x05, E=0, Z=0)
    // Payload: VLE(9) = 0x09 + "not found"
    try assertEqualBytes(
        &(.{ 0x05, 0x09 } ++ "not found".*),
        encoded,
    );
}

test "Err: with encoding" {
    const msg = Err{
        .encoding = .{ .id = 10 },
        .payload = "error details",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    // Header: 0x45 (MID=0x05 | E=0x40)
    // Encoding: VLE(20) = 0x14
    // Payload: VLE(13) = 0x0D + "error details"
    try assertEqualBytes(
        &(.{ 0x45, 0x14, 0x0D } ++ "error details".*),
        encoded,
    );
}

test "Err: MID is err" {
    const msg = Err{ .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.err), hdr.Header.decode(encoded[0]).mid);
}

test "Err: E flag set when encoding present" {
    const msg = Err{ .encoding = .{ .id = 0 }, .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag1()); // E flag (bit 6)
}

test "Err: E flag clear when no encoding" {
    const msg = Err{ .payload = "x" };
    var buf: [16]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag1()); // E flag not set
}

test "Err: round-trip minimal (no encoding)" {
    const msg = Err{ .payload = "not found" };
    var buf: [64]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Err.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?Encoding, null), decoded.encoding);
    try testing.expectEqualStrings("not found", decoded.payload);
}

test "Err: round-trip with encoding" {
    const msg = Err{
        .encoding = .{ .id = 10 },
        .payload = "error details",
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Err.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 10), decoded.encoding.?.id);
    try testing.expectEqualStrings("error details", decoded.payload);
}

test "Err: round-trip with encoding and schema" {
    const msg = Err{
        .encoding = .{ .id = 5, .schema = "application/json" },
        .payload = "{\"error\":\"timeout\"}",
    };
    var buf: [128]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Err.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 5), decoded.encoding.?.id);
    try testing.expectEqualStrings("application/json", decoded.encoding.?.schema.?);
    try testing.expectEqualStrings("{\"error\":\"timeout\"}", decoded.payload);
}

test "Err: round-trip empty payload" {
    const msg = Err{ .payload = "" };
    var buf: [16]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Err.decode(header, &reader, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualStrings("", decoded.payload);
}

test "Err: wire vector — error 'not found' without encoding" {
    const msg = Err{ .payload = "not found" };
    var buf: [64]u8 = undefined;
    const encoded = encodeErrHelper(&msg, &buf);

    // Header: 0x05 (MID=0x05, E=0)
    // Payload: VLE(9) + "not found"
    try assertEqualBytes(
        &(.{ 0x05, 0x09 } ++ "not found".*),
        encoded,
    );
}

// ---------------------------------------------------------------------------
// Cross-message wire vector tests
// ---------------------------------------------------------------------------

test "wire vector: Query for 'demo/example/hello' (minimal, inside Request)" {
    // Build the complete inner Zenoh message for a minimal query.
    // The Request header is tested in network/messages.zig;
    // here we verify the Query payload by itself.
    const query = Query{};
    var buf: [16]u8 = undefined;
    const encoded = encodeQueryHelper(&query, &buf);

    // A minimal Query is just the header byte: 0x03
    try assertEqualBytes(&.{0x03}, encoded);
}

test "wire vector: Reply(Put('Hello')) for 'demo/example/hello'" {
    // Complete Reply(Put) as received from a router.
    const reply = Reply{
        .body = .{ .put = Put{ .payload = "Hello" } },
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeReplyHelper(&reply, &buf);

    try assertEqualBytes(
        &(.{ 0x04, 0x01, 0x05 } ++ "Hello".*),
        encoded,
    );
}

test {
    std.testing.refAllDecls(@This());
}
