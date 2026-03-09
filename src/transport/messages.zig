//! Transport messages: Init, Open, KeepAlive, Close, Frame.
//!
//! Implements encode/decode for the session handshake (InitSyn, InitAck,
//! OpenSyn, OpenAck) and session-lifetime messages (KeepAlive, Close)
//! per Zenoh protocol v0x09.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const vle = @import("../codec/vle.zig");
const primitives = @import("../codec/primitives.zig");
const hdr = @import("../codec/header.zig");

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol version we support.
pub const protocol_version: u8 = 0x09;

/// Message IDs (bits 0-4 of header byte).
/// Re-exported from codec/header.zig — the single source of truth.
pub const MID = hdr.TransportMid;

/// Header flag masks.
pub const Flag = struct {
    /// Bit 5 (0x20): A=Ack for Init/Open, R=Reliable for Frame, S=Session for Close.
    pub const bit5: u8 = 0x20;
    /// Bit 6 (0x40): S=Size params for Init, T=Time-in-seconds for Open.
    pub const bit6: u8 = 0x40;
    /// Bit 7 (0x80): Z=Extensions present.
    pub const z_flag: u8 = 0x80;
};

/// Extension IDs.
pub const ExtId = struct {
    /// Patch extension: ZInt encoding (bits 5-6 = 0b01 → 0x20) + ID 0x07 = 0x27.
    pub const patch: u8 = 0x27;
};

/// Default values when S flag is not set.
pub const Defaults = struct {
    pub const resolution: u8 = 0x2A; // 32-bit for fsn, rid, kid (0b00_10_10_10)
    pub const batch_size: u16 = 65535; // unicast default
};

// ═══════════════════════════════════════════════════════════════════════════
// WhatAmI
// ═══════════════════════════════════════════════════════════════════════════

/// Zenoh node role.
pub const WhatAmI = enum(u2) {
    router = 0b00,
    peer = 0b01,
    client = 0b10,
};

// ═══════════════════════════════════════════════════════════════════════════
// Resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Bit-width resolution encoding for SN, request ID, key expression ID.
/// 0b00=8-bit, 0b01=16-bit, 0b10=32-bit, 0b11=64-bit.
pub const ResolutionBits = enum(u2) {
    bits_8 = 0b00,
    bits_16 = 0b01,
    bits_32 = 0b10,
    bits_64 = 0b11,
};

/// Resolution byte: encodes frame SN, request ID, and key expression ID resolutions.
/// Layout: |x|x|kid(2)|rid(2)|fsn(2)|
pub const Resolution = struct {
    frame_sn: ResolutionBits = .bits_32,
    request_id: ResolutionBits = .bits_32,
    key_expr_id: ResolutionBits = .bits_32,

    /// Encode to a single byte.
    pub fn toByte(self: Resolution) u8 {
        return @as(u8, @intFromEnum(self.frame_sn)) |
            (@as(u8, @intFromEnum(self.request_id)) << 2) |
            (@as(u8, @intFromEnum(self.key_expr_id)) << 4);
    }

    /// Decode from a single byte.
    pub fn fromByte(byte: u8) Resolution {
        return .{
            .frame_sn = @enumFromInt(@as(u2, @truncate(byte))),
            .request_id = @enumFromInt(@as(u2, @truncate(byte >> 2))),
            .key_expr_id = @enumFromInt(@as(u2, @truncate(byte >> 4))),
        };
    }

    /// Check if all fields are at their defaults (32-bit).
    pub fn isDefault(self: Resolution) bool {
        return self.frame_sn == .bits_32 and
            self.request_id == .bits_32 and
            self.key_expr_id == .bits_32;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ZenohId
// ═══════════════════════════════════════════════════════════════════════════

/// A Zenoh unique identifier: 1–16 bytes.
pub const ZenohId = struct {
    bytes: [max_len]u8 = .{0} ** max_len,
    len: u5 = 0, // 0 means uninitialized; valid range after init: 1-16

    pub const max_len: usize = 16;

    /// Create a ZenohId from a byte slice (1-16 bytes).
    pub fn init(data: []const u8) error{InvalidLength}!ZenohId {
        if (data.len == 0 or data.len > max_len) return error.InvalidLength;
        var zid = ZenohId{};
        zid.len = @intCast(data.len);
        @memcpy(zid.bytes[0..data.len], data);
        return zid;
    }

    /// Get the active bytes.
    pub fn slice(self: *const ZenohId) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Encode the WhatAmI + ZenohId combined byte and the ID bytes.
    /// Combined byte layout: |zid_len(4)|x|x|whatami(2)|
    /// where zid_len = (real_len - 1).
    pub fn encodeWithWhatAmI(self: *const ZenohId, whatami: WhatAmI, writer: *Io.Writer) Io.Writer.Error!void {
        const zid_len_enc: u8 = @as(u8, @as(u4, @intCast(self.len - 1))) << 4;
        const wai: u8 = @intFromEnum(whatami);
        try writer.writeByte(zid_len_enc | wai);
        try writer.writeAll(self.slice());
    }

    /// Decode WhatAmI + ZenohId from reader.
    /// Returns both the WhatAmI and the ZenohId.
    pub fn decodeWithWhatAmI(reader: *Io.Reader) DecodeError!struct { WhatAmI, ZenohId } {
        const combined = try reader.takeByte();
        const wai: WhatAmI = @enumFromInt(@as(u2, @truncate(combined)));
        const zid_len: u8 = (combined >> 4) + 1;
        if (zid_len > max_len) return error.InvalidLength;

        var zid = ZenohId{};
        zid.len = @intCast(zid_len);
        const buf = zid.bytes[0..zid_len];
        try reader.readSliceAll(buf);
        return .{ wai, zid };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Extension helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Encode a ZInt extension (e.g., patch).
/// Header: |more(1)|ENC=01(2)|M(1)|ID(4)| → for patch: 0x27 (no more) or 0xA7 (more follow).
fn encodeZIntExtension(ext_id: u8, value: u64, more: bool, writer: *Io.Writer) Io.Writer.Error!void {
    const header = ext_id | if (more) @as(u8, 0x80) else @as(u8, 0x00);
    try writer.writeByte(header);
    try vle.encode(value, writer);
}

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
            var i: u64 = 0;
            while (i < buf_len) : (i += 1) {
                _ = try reader.takeByte();
            }
        },
        0b11 => {}, // reserved — treat as Unit for forward compat
    }
}

/// Skip all extensions from reader. Each extension header has a more bit indicating more follow.
fn skipExtensions(reader: *Io.Reader) DecodeError!void {
    while (true) {
        const ext_header = try reader.takeByte();
        const enc: u2 = @truncate((ext_header >> 5) & 0x03);
        const has_more = (ext_header & 0x80) != 0;

        try skipExtensionBody(enc, reader);

        if (!has_more) break;
    }
}

/// Decode extensions, extracting known ones (like patch).
/// Returns the patch value if found.
fn decodeInitExtensions(reader: *Io.Reader) DecodeError!?u64 {
    var patch: ?u64 = null;

    while (true) {
        const ext_header = try reader.takeByte();
        const id = ext_header & 0x0F;
        const enc: u2 = @truncate((ext_header >> 5) & 0x03);
        const has_more = (ext_header & 0x80) != 0;

        // Patch extension: ID=0x07, ENC=ZInt(0b01)
        if (id == 0x07 and enc == 0b01) {
            patch = try vle.decode(reader);
        } else {
            try skipExtensionBody(enc, reader);
        }

        if (!has_more) break;
    }

    return patch;
}

// ═══════════════════════════════════════════════════════════════════════════
// Error types
// ═══════════════════════════════════════════════════════════════════════════

pub const EncodeError = Io.Writer.Error;

pub const DecodeError = Io.Reader.Error || error{InvalidLength};

pub const DecodeAllocError = Io.Reader.Error || Io.Reader.ReadAllocError || error{InvalidLength};

// ═══════════════════════════════════════════════════════════════════════════
// InitSyn
// ═══════════════════════════════════════════════════════════════════════════

/// InitSyn message: client → router to start session establishment.
/// MID = 0x01, A=0.
pub const InitSyn = struct {
    version: u8 = protocol_version,
    whatami: WhatAmI = .client,
    zid: ZenohId,
    resolution: ?Resolution = null,
    batch_size: ?u16 = null,
    patch: ?u64 = null,

    /// Returns true if S flag should be set (non-default size params).
    fn hasSizeParams(self: *const InitSyn) bool {
        return self.resolution != null or self.batch_size != null;
    }

    /// Returns true if Z flag should be set (extensions present).
    fn hasExtensions(self: *const InitSyn) bool {
        return self.patch != null;
    }

    /// Encode this InitSyn to the writer.
    pub fn encode(self: *const InitSyn, writer: *Io.Writer) EncodeError!void {
        // Header byte: |Z|S|A=0| MID=0x01 |
        var header: u8 = @as(u8, MID.init);
        // A flag = 0 (Syn)
        if (self.hasSizeParams()) header |= Flag.bit6; // S flag
        if (self.hasExtensions()) header |= Flag.z_flag; // Z flag
        try writer.writeByte(header);

        // Version
        try writer.writeByte(self.version);

        // WhatAmI + ZenohId
        try self.zid.encodeWithWhatAmI(self.whatami, writer);

        // S-flag fields: resolution + batch_size
        if (self.hasSizeParams()) {
            const res = self.resolution orelse Resolution{};
            try writer.writeByte(res.toByte());
            const bs = self.batch_size orelse Defaults.batch_size;
            try primitives.writeUint16LE(bs, writer);
        }

        // Z-flag: extensions (patch)
        if (self.patch) |p| {
            try encodeZIntExtension(ExtId.patch, p, false, writer);
        }
    }

    /// Decode an InitSyn from the reader. The header byte has already been parsed
    /// to determine this is an InitSyn (MID=0x01, A=0).
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!InitSyn {
        const s_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const version = try reader.takeByte();
        const wai_zid = try ZenohId.decodeWithWhatAmI(reader);

        var result = InitSyn{
            .version = version,
            .whatami = wai_zid[0],
            .zid = wai_zid[1],
        };

        if (s_flag) {
            const res_byte = try reader.takeByte();
            result.resolution = Resolution.fromByte(res_byte);
            result.batch_size = try primitives.readUint16LE(reader);
        }

        if (z_flag) {
            result.patch = try decodeInitExtensions(reader);
        }

        return result;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// InitAck
// ═══════════════════════════════════════════════════════════════════════════

/// InitAck message: router → client in response to InitSyn.
/// MID = 0x01, A=1.
pub const InitAck = struct {
    version: u8 = protocol_version,
    whatami: WhatAmI = .router,
    zid: ZenohId,
    resolution: ?Resolution = null,
    batch_size: ?u16 = null,
    cookie: []const u8,
    patch: ?u64 = null,

    /// Returns true if S flag should be set.
    fn hasSizeParams(self: *const InitAck) bool {
        return self.resolution != null or self.batch_size != null;
    }

    /// Returns true if Z flag should be set.
    fn hasExtensions(self: *const InitAck) bool {
        return self.patch != null;
    }

    /// Encode this InitAck to the writer.
    pub fn encode(self: *const InitAck, writer: *Io.Writer) EncodeError!void {
        // Header: |Z|S|A=1| MID=0x01 |
        var header: u8 = @as(u8, MID.init) | Flag.bit5; // A=1
        if (self.hasSizeParams()) header |= Flag.bit6;
        if (self.hasExtensions()) header |= Flag.z_flag;
        try writer.writeByte(header);

        // Version
        try writer.writeByte(self.version);

        // WhatAmI + ZenohId
        try self.zid.encodeWithWhatAmI(self.whatami, writer);

        // S-flag fields
        if (self.hasSizeParams()) {
            const res = self.resolution orelse Resolution{};
            try writer.writeByte(res.toByte());
            const bs = self.batch_size orelse Defaults.batch_size;
            try primitives.writeUint16LE(bs, writer);
        }

        // Cookie (always present in InitAck)
        try primitives.writeSlice(self.cookie, writer);

        // Z-flag: extensions
        if (self.patch) |p| {
            try encodeZIntExtension(ExtId.patch, p, false, writer);
        }
    }

    /// Decode an InitAck from the reader. Header byte already parsed.
    pub fn decodeAlloc(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!InitAck {
        const s_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const version = try reader.takeByte();
        const wai_zid = try ZenohId.decodeWithWhatAmI(reader);

        var result = InitAck{
            .version = version,
            .whatami = wai_zid[0],
            .zid = wai_zid[1],
            .cookie = &.{},
        };

        if (s_flag) {
            const res_byte = try reader.takeByte();
            result.resolution = Resolution.fromByte(res_byte);
            result.batch_size = try primitives.readUint16LE(reader);
        }

        // Cookie
        result.cookie = try primitives.readSlice(reader, allocator);
        errdefer allocator.free(result.cookie);

        if (z_flag) {
            result.patch = try decodeInitExtensions(reader);
        }

        return result;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// OpenSyn
// ═══════════════════════════════════════════════════════════════════════════

/// OpenSyn message: client → router to open the initialized session.
/// MID = 0x02, A=0.
pub const OpenSyn = struct {
    lease: u64,
    /// If true, lease is in seconds; if false, milliseconds.
    lease_in_seconds: bool = true,
    initial_sn: u64,
    cookie: []const u8,

    /// Encode this OpenSyn to the writer.
    pub fn encode(self: *const OpenSyn, writer: *Io.Writer) EncodeError!void {
        // Header: |Z=0|T|A=0| MID=0x02 |
        var header: u8 = @as(u8, MID.open);
        if (self.lease_in_seconds) header |= Flag.bit6; // T flag
        try writer.writeByte(header);

        // Lease
        try vle.encode(self.lease, writer);

        // Initial SN
        try vle.encode(self.initial_sn, writer);

        // Cookie
        try primitives.writeSlice(self.cookie, writer);
    }

    /// Decode an OpenSyn from the reader. Header byte already parsed.
    pub fn decodeAlloc(header: u8, reader: *Io.Reader, allocator: Allocator) DecodeAllocError!OpenSyn {
        const t_flag = (header & Flag.bit6) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const lease = try vle.decode(reader);
        const initial_sn = try vle.decode(reader);
        const cookie = try primitives.readSlice(reader, allocator);
        errdefer allocator.free(cookie);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return OpenSyn{
            .lease = lease,
            .lease_in_seconds = t_flag,
            .initial_sn = initial_sn,
            .cookie = cookie,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// OpenAck
// ═══════════════════════════════════════════════════════════════════════════

/// OpenAck message: router → client confirming session is established.
/// MID = 0x02, A=1.
pub const OpenAck = struct {
    lease: u64,
    /// If true, lease is in seconds; if false, milliseconds.
    lease_in_seconds: bool = true,
    initial_sn: u64,

    /// Encode this OpenAck to the writer.
    pub fn encode(self: *const OpenAck, writer: *Io.Writer) EncodeError!void {
        // Header: |Z=0|T|A=1| MID=0x02 |
        var header: u8 = @as(u8, MID.open) | Flag.bit5; // A=1
        if (self.lease_in_seconds) header |= Flag.bit6; // T flag
        try writer.writeByte(header);

        // Lease
        try vle.encode(self.lease, writer);

        // Initial SN
        try vle.encode(self.initial_sn, writer);
    }

    /// Decode an OpenAck from the reader. Header byte already parsed.
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!OpenAck {
        const t_flag = (header & Flag.bit6) != 0;
        // z_flag would indicate extensions; skip if present
        const z_flag = (header & Flag.z_flag) != 0;

        const lease = try vle.decode(reader);
        const initial_sn = try vle.decode(reader);

        if (z_flag) {
            try skipExtensions(reader);
        }

        return OpenAck{
            .lease = lease,
            .lease_in_seconds = t_flag,
            .initial_sn = initial_sn,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// KeepAlive
// ═══════════════════════════════════════════════════════════════════════════

/// KeepAlive message: sent periodically (every lease/3) to prevent lease expiration.
/// MID = 0x04, no flags, no body — just the 1-byte header.
pub const KeepAlive = struct {
    /// Encode this KeepAlive to the writer (1 byte: header only).
    pub fn encode(_: *const KeepAlive, writer: *Io.Writer) EncodeError!void {
        try writer.writeByte(@as(u8, MID.keep_alive));
    }

    /// Decode a KeepAlive from the reader. The header byte has already been parsed
    /// to determine this is a KeepAlive (MID=0x04).
    /// If the Z flag is set, any extensions are skipped for forward compatibility.
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!KeepAlive {
        const z_flag = (header & Flag.z_flag) != 0;
        if (z_flag) {
            try skipExtensions(reader);
        }
        return KeepAlive{};
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Close
// ═══════════════════════════════════════════════════════════════════════════

/// Reason code for Close message.
pub const CloseReason = enum(u8) {
    generic = 0x00,
    unsupported = 0x01,
    invalid = 0x02,
    _,
};

/// Close message: sent to terminate a session or link.
/// MID = 0x03, S flag (bit 5) = 1 for session close (vs link-only close).
/// Body: 1-byte reason code.
pub const Close = struct {
    /// If true, this closes the entire session; if false, only the link.
    session: bool = true,
    reason: CloseReason = .generic,

    /// Encode this Close to the writer.
    pub fn encode(self: *const Close, writer: *Io.Writer) EncodeError!void {
        // Header: |Z=0|x|S| MID=0x03 |
        var header: u8 = @as(u8, MID.close);
        if (self.session) header |= Flag.bit5; // S flag
        try writer.writeByte(header);

        // Reason code
        try writer.writeByte(@intFromEnum(self.reason));
    }

    /// Decode a Close from the reader. The header byte has already been parsed
    /// to determine this is a Close (MID=0x03).
    pub fn decode(header: u8, reader: *Io.Reader) DecodeError!Close {
        const s_flag = (header & Flag.bit5) != 0;
        const z_flag = (header & Flag.z_flag) != 0;

        const reason_byte = try reader.takeByte();

        if (z_flag) {
            try skipExtensions(reader);
        }

        return Close{
            .session = s_flag,
            .reason = @enumFromInt(reason_byte),
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Header parsing helper
// ═══════════════════════════════════════════════════════════════════════════

/// Extract the MID from a header byte (bits 0-4).
pub fn getMid(byte: u8) u5 {
    return hdr.Header.decode(byte).mid;
}

/// Check if the A flag (bit 5) is set.
pub fn isAck(byte: u8) bool {
    return hdr.Header.decode(byte).isAck();
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("../testing.zig").assertEqualBytes;

// ---------------------------------------------------------------------------
// Helper: encode a message and return the written bytes.
// ---------------------------------------------------------------------------

fn encodeInitSynHelper(msg: *const InitSyn, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

fn encodeInitAckHelper(msg: *const InitAck, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

fn encodeOpenSynHelper(msg: *const OpenSyn, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

fn encodeOpenAckHelper(msg: *const OpenAck, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

fn encodeKeepAliveHelper(msg: *const KeepAlive, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

fn encodeCloseHelper(msg: *const Close, buf: []u8) []const u8 {
    var writer: Io.Writer = .fixed(buf);
    msg.encode(&writer) catch unreachable;
    return writer.buffered();
}

// ---------------------------------------------------------------------------
// WhatAmI tests
// ---------------------------------------------------------------------------

test "WhatAmI: enum values" {
    try testing.expectEqual(@as(u2, 0b00), @intFromEnum(WhatAmI.router));
    try testing.expectEqual(@as(u2, 0b01), @intFromEnum(WhatAmI.peer));
    try testing.expectEqual(@as(u2, 0b10), @intFromEnum(WhatAmI.client));
}

// ---------------------------------------------------------------------------
// Resolution tests
// ---------------------------------------------------------------------------

test "Resolution: default is all 32-bit" {
    const res = Resolution{};
    try testing.expect(res.isDefault());
    try testing.expectEqual(@as(u8, 0x2A), res.toByte()); // 0b00_10_10_10 = 0x2A
}

test "Resolution: toByte/fromByte round-trip" {
    const res = Resolution{
        .frame_sn = .bits_8,
        .request_id = .bits_16,
        .key_expr_id = .bits_64,
    };
    const byte = res.toByte();
    const decoded = Resolution.fromByte(byte);
    try testing.expectEqual(res.frame_sn, decoded.frame_sn);
    try testing.expectEqual(res.request_id, decoded.request_id);
    try testing.expectEqual(res.key_expr_id, decoded.key_expr_id);
}

test "Resolution: all-zeros byte → 8-bit for everything" {
    const res = Resolution.fromByte(0x00);
    try testing.expectEqual(ResolutionBits.bits_8, res.frame_sn);
    try testing.expectEqual(ResolutionBits.bits_8, res.request_id);
    try testing.expectEqual(ResolutionBits.bits_8, res.key_expr_id);
}

test "Resolution: 0xFF byte → 64-bit for everything" {
    const res = Resolution.fromByte(0xFF);
    try testing.expectEqual(ResolutionBits.bits_64, res.frame_sn);
    try testing.expectEqual(ResolutionBits.bits_64, res.request_id);
    try testing.expectEqual(ResolutionBits.bits_64, res.key_expr_id);
}

test "Resolution: non-default is detected" {
    const res = Resolution{ .frame_sn = .bits_16 };
    try testing.expect(!res.isDefault());
}

// ---------------------------------------------------------------------------
// ZenohId tests
// ---------------------------------------------------------------------------

test "ZenohId: init and slice" {
    const zid = try ZenohId.init(&.{ 0x01, 0x02, 0x03 });
    try testing.expectEqual(@as(u5, 3), zid.len);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, zid.slice());
}

test "ZenohId: max length (16 bytes)" {
    const data = [_]u8{0xFF} ** 16;
    const zid = try ZenohId.init(&data);
    try testing.expectEqual(@as(u5, 16), zid.len);
}

test "ZenohId: empty is error" {
    try testing.expectError(error.InvalidLength, ZenohId.init(&.{}));
}

test "ZenohId: 17 bytes is error" {
    const data = [_]u8{0x00} ** 17;
    try testing.expectError(error.InvalidLength, ZenohId.init(&data));
}

test "ZenohId: encodeWithWhatAmI wire format" {
    const zid = try ZenohId.init(&.{ 0xAB, 0xCD });
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try zid.encodeWithWhatAmI(.client, &writer);
    const encoded = writer.buffered();
    // zid_len = 2-1 = 1, shifted left 4 = 0x10
    // whatami = client = 0b10 = 0x02
    // combined = 0x12
    try assertEqualBytes(&.{ 0x12, 0xAB, 0xCD }, encoded);
}

test "ZenohId: decodeWithWhatAmI round-trip" {
    const original_zid = try ZenohId.init(&.{ 0x01, 0x02, 0x03, 0x04 });
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try original_zid.encodeWithWhatAmI(.peer, &writer);

    var reader: Io.Reader = .fixed(writer.buffered());
    const result = try ZenohId.decodeWithWhatAmI(&reader);
    try testing.expectEqual(WhatAmI.peer, result[0]);
    try testing.expectEqualSlices(u8, original_zid.slice(), result[1].slice());
}

// ---------------------------------------------------------------------------
// InitSyn tests
// ---------------------------------------------------------------------------

test "InitSyn: encode minimal (no S, no Z)" {
    const zid = try ZenohId.init(&.{0x01});
    const msg = InitSyn{
        .zid = zid,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Header: MID=0x01, A=0, S=0, Z=0 → 0x01
    // Version: 0x09
    // Combined: zid_len=0(1-1=0)<<4 | client=0x02 → 0x02
    // ZenohId: 0x01
    try assertEqualBytes(&.{ 0x01, 0x09, 0x02, 0x01 }, encoded);
}

test "InitSyn: encode with S flag (resolution + batch_size)" {
    const zid = try ZenohId.init(&.{0x42});
    const msg = InitSyn{
        .zid = zid,
        .resolution = Resolution{},
        .batch_size = 2048,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Header: 0x41 (MID=0x01 | S=0x40)
    // Version: 0x09
    // Combined: 0x02 (zid_len=0, client)
    // ZenohId: 0x42
    // Resolution: 0x2A (all 32-bit)
    // Batch size: 2048 = 0x00 0x08 LE
    try assertEqualBytes(&.{ 0x41, 0x09, 0x02, 0x42, 0x2A, 0x00, 0x08 }, encoded);
}

test "InitSyn: encode with Z flag (patch extension)" {
    const zid = try ZenohId.init(&.{0x01});
    const msg = InitSyn{
        .zid = zid,
        .patch = 1,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Header: 0x81 (MID=0x01 | Z=0x80)
    // Version: 0x09
    // Combined: 0x02
    // ZenohId: 0x01
    // Ext header: 0x27 (patch, ZInt, no more)
    // Ext value: VLE(1) = 0x01
    try assertEqualBytes(&.{ 0x81, 0x09, 0x02, 0x01, 0x27, 0x01 }, encoded);
}

test "InitSyn: encode with S+Z flags (typical zenoh-pico)" {
    const zid = try ZenohId.init(&.{0xAB});
    const msg = InitSyn{
        .zid = zid,
        .resolution = Resolution{},
        .batch_size = 2048,
        .patch = 1,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Header: 0xC1 (MID=0x01 | S=0x40 | Z=0x80)
    // Version: 0x09
    // Combined: 0x02 (client, zid_len=0)
    // ZenohId: 0xAB
    // Resolution: 0x2A
    // Batch size: 0x00 0x08
    // Patch ext: 0x27 0x01
    try assertEqualBytes(&.{ 0xC1, 0x09, 0x02, 0xAB, 0x2A, 0x00, 0x08, 0x27, 0x01 }, encoded);
}

test "InitSyn: round-trip minimal" {
    const zid = try ZenohId.init(&.{ 0x01, 0x02, 0x03 });
    const original = InitSyn{
        .zid = zid,
        .whatami = .peer,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.init), getMid(header));
    try testing.expect(!isAck(header));
    const decoded = try InitSyn.decode(header, &reader);

    try testing.expectEqual(original.version, decoded.version);
    try testing.expectEqual(original.whatami, decoded.whatami);
    try testing.expectEqualSlices(u8, original.zid.slice(), decoded.zid.slice());
    try testing.expectEqual(original.resolution, decoded.resolution);
    try testing.expectEqual(original.batch_size, decoded.batch_size);
    try testing.expectEqual(original.patch, decoded.patch);
}

test "InitSyn: round-trip with S+Z" {
    const zid = try ZenohId.init(&.{ 0xDE, 0xAD, 0xBE, 0xEF });
    const original = InitSyn{
        .zid = zid,
        .whatami = .client,
        .resolution = Resolution{ .frame_sn = .bits_16, .request_id = .bits_32, .key_expr_id = .bits_64 },
        .batch_size = 4096,
        .patch = 3,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try InitSyn.decode(header, &reader);

    try testing.expectEqual(original.version, decoded.version);
    try testing.expectEqual(original.whatami, decoded.whatami);
    try testing.expectEqualSlices(u8, original.zid.slice(), decoded.zid.slice());
    try testing.expectEqual(original.resolution.?.frame_sn, decoded.resolution.?.frame_sn);
    try testing.expectEqual(original.resolution.?.request_id, decoded.resolution.?.request_id);
    try testing.expectEqual(original.resolution.?.key_expr_id, decoded.resolution.?.key_expr_id);
    try testing.expectEqual(original.batch_size, decoded.batch_size);
    try testing.expectEqual(original.patch, decoded.patch);
}

test "InitSyn: round-trip S flag without Z" {
    const zid = try ZenohId.init(&.{0xFF});
    const original = InitSyn{
        .zid = zid,
        .resolution = Resolution{},
        .batch_size = 8192,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try InitSyn.decode(header, &reader);

    try testing.expectEqual(original.batch_size, decoded.batch_size);
    try testing.expect(decoded.resolution != null);
    try testing.expectEqual(@as(?u64, null), decoded.patch);
}

test "InitSyn: round-trip Z flag without S" {
    const zid = try ZenohId.init(&.{0x42});
    const original = InitSyn{
        .zid = zid,
        .patch = 0,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try InitSyn.decode(header, &reader);

    try testing.expectEqual(@as(?Resolution, null), decoded.resolution);
    try testing.expectEqual(@as(?u16, null), decoded.batch_size);
    try testing.expectEqual(@as(?u64, 0), decoded.patch);
}

// ---------------------------------------------------------------------------
// InitAck tests
// ---------------------------------------------------------------------------

test "InitAck: encode minimal (no S, no Z) with cookie" {
    const zid = try ZenohId.init(&.{0x99});
    const cookie = [_]u8{ 0xCA, 0xFE };
    const msg = InitAck{
        .zid = zid,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitAckHelper(&msg, &buf);

    // Header: 0x21 (MID=0x01 | A=0x20)
    // Version: 0x09
    // Combined: 0x00 (zid_len=0, router=0b00)
    // ZenohId: 0x99
    // Cookie: VLE(2)=0x02, 0xCA, 0xFE
    try assertEqualBytes(&.{ 0x21, 0x09, 0x00, 0x99, 0x02, 0xCA, 0xFE }, encoded);
}

test "InitAck: encode with S+Z flags" {
    const zid = try ZenohId.init(&.{ 0x11, 0x22 });
    const cookie = [_]u8{0xBB};
    const msg = InitAck{
        .zid = zid,
        .resolution = Resolution{},
        .batch_size = 2048,
        .cookie = &cookie,
        .patch = 1,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitAckHelper(&msg, &buf);

    // Header: 0xE1 (MID=0x01 | A=0x20 | S=0x40 | Z=0x80)
    // Version: 0x09
    // Combined: 0x10 (zid_len=1 → (2-1=1)<<4=0x10, router=0b00)
    // ZenohId: 0x11, 0x22
    // Resolution: 0x2A
    // Batch size: 0x00, 0x08
    // Cookie: VLE(1)=0x01, 0xBB
    // Patch ext: 0x27, 0x01
    try assertEqualBytes(&.{ 0xE1, 0x09, 0x10, 0x11, 0x22, 0x2A, 0x00, 0x08, 0x01, 0xBB, 0x27, 0x01 }, encoded);
}

test "InitAck: round-trip" {
    const zid = try ZenohId.init(&.{ 0xAA, 0xBB, 0xCC });
    const cookie = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const original = InitAck{
        .zid = zid,
        .whatami = .router,
        .resolution = Resolution{ .frame_sn = .bits_16 },
        .batch_size = 1024,
        .cookie = &cookie,
        .patch = 2,
    };
    var buf: [128]u8 = undefined;
    const encoded = encodeInitAckHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.init), getMid(header));
    try testing.expect(isAck(header));
    const decoded = try InitAck.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    try testing.expectEqual(original.version, decoded.version);
    try testing.expectEqual(original.whatami, decoded.whatami);
    try testing.expectEqualSlices(u8, original.zid.slice(), decoded.zid.slice());
    try testing.expectEqual(original.resolution.?.frame_sn, decoded.resolution.?.frame_sn);
    try testing.expectEqual(original.batch_size, decoded.batch_size);
    try testing.expectEqualSlices(u8, &cookie, decoded.cookie);
    try testing.expectEqual(original.patch, decoded.patch);
}

test "InitAck: round-trip no S no Z" {
    const zid = try ZenohId.init(&.{0x77});
    const cookie = [_]u8{ 0xDE, 0xAD };
    const original = InitAck{
        .zid = zid,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitAckHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try InitAck.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    try testing.expectEqual(@as(?Resolution, null), decoded.resolution);
    try testing.expectEqual(@as(?u16, null), decoded.batch_size);
    try testing.expectEqualSlices(u8, &cookie, decoded.cookie);
    try testing.expectEqual(@as(?u64, null), decoded.patch);
}

test "InitAck: empty cookie" {
    const zid = try ZenohId.init(&.{0x01});
    const msg = InitAck{
        .zid = zid,
        .cookie = &.{},
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitAckHelper(&msg, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try InitAck.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    try testing.expectEqual(@as(usize, 0), decoded.cookie.len);
}

// ---------------------------------------------------------------------------
// OpenSyn tests
// ---------------------------------------------------------------------------

test "OpenSyn: encode with T=1 (seconds)" {
    const cookie = [_]u8{ 0xAA, 0xBB };
    const msg = OpenSyn{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 0,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenSynHelper(&msg, &buf);

    // Header: 0x42 (MID=0x02 | T=0x40)
    // Lease: VLE(10) = 0x0A
    // Initial SN: VLE(0) = 0x00
    // Cookie: VLE(2)=0x02, 0xAA, 0xBB
    try assertEqualBytes(&.{ 0x42, 0x0A, 0x00, 0x02, 0xAA, 0xBB }, encoded);
}

test "OpenSyn: encode with T=0 (milliseconds)" {
    const cookie = [_]u8{0xFF};
    const msg = OpenSyn{
        .lease = 10000,
        .lease_in_seconds = false,
        .initial_sn = 42,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenSynHelper(&msg, &buf);

    // Header: 0x02 (MID=0x02, T=0)
    // Lease: VLE(10000) = 0x90, 0x4E
    // Initial SN: VLE(42) = 0x2A
    // Cookie: VLE(1)=0x01, 0xFF
    try assertEqualBytes(&.{ 0x02, 0x90, 0x4E, 0x2A, 0x01, 0xFF }, encoded);
}

test "OpenSyn: round-trip" {
    const cookie = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const original = OpenSyn{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 12345,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.open), getMid(header));
    try testing.expect(!isAck(header));
    const decoded = try OpenSyn.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    try testing.expectEqual(original.lease, decoded.lease);
    try testing.expectEqual(original.lease_in_seconds, decoded.lease_in_seconds);
    try testing.expectEqual(original.initial_sn, decoded.initial_sn);
    try testing.expectEqualSlices(u8, &cookie, decoded.cookie);
}

test "OpenSyn: round-trip milliseconds" {
    const cookie = [_]u8{0x42};
    const original = OpenSyn{
        .lease = 5000,
        .lease_in_seconds = false,
        .initial_sn = 0,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenSynHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try OpenSyn.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    try testing.expectEqual(original.lease, decoded.lease);
    try testing.expectEqual(false, decoded.lease_in_seconds);
    try testing.expectEqual(original.initial_sn, decoded.initial_sn);
}

// ---------------------------------------------------------------------------
// OpenAck tests
// ---------------------------------------------------------------------------

test "OpenAck: encode with T=1 (seconds)" {
    const msg = OpenAck{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 0,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenAckHelper(&msg, &buf);

    // Header: 0x62 (MID=0x02 | A=0x20 | T=0x40)
    // Lease: VLE(10) = 0x0A
    // Initial SN: VLE(0) = 0x00
    try assertEqualBytes(&.{ 0x62, 0x0A, 0x00 }, encoded);
}

test "OpenAck: encode with T=0 (milliseconds)" {
    const msg = OpenAck{
        .lease = 30000,
        .lease_in_seconds = false,
        .initial_sn = 100,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenAckHelper(&msg, &buf);

    // Header: 0x22 (MID=0x02 | A=0x20, T=0)
    // Lease: VLE(30000) = 0xB0, 0xEA, 0x01
    // Initial SN: VLE(100) = 0x64
    try assertEqualBytes(&.{ 0x22, 0xB0, 0xEA, 0x01, 0x64 }, encoded);
}

test "OpenAck: round-trip" {
    const original = OpenAck{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 999,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenAckHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.open), getMid(header));
    try testing.expect(isAck(header));
    const decoded = try OpenAck.decode(header, &reader);

    try testing.expectEqual(original.lease, decoded.lease);
    try testing.expectEqual(original.lease_in_seconds, decoded.lease_in_seconds);
    try testing.expectEqual(original.initial_sn, decoded.initial_sn);
}

test "OpenAck: round-trip milliseconds" {
    const original = OpenAck{
        .lease = 15000,
        .lease_in_seconds = false,
        .initial_sn = 0,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeOpenAckHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try OpenAck.decode(header, &reader);

    try testing.expectEqual(original.lease, decoded.lease);
    try testing.expectEqual(false, decoded.lease_in_seconds);
}

// ---------------------------------------------------------------------------
// Wire vector: typical zenoh-pico InitSyn
// ---------------------------------------------------------------------------

test "wire vector: typical InitSyn (version=9, client, 1-byte ZID, batch=2048, patch=1)" {
    const zid = try ZenohId.init(&.{0x01});
    const msg = InitSyn{
        .version = 0x09,
        .whatami = .client,
        .zid = zid,
        .resolution = Resolution{}, // all 32-bit
        .batch_size = 2048,
        .patch = 1,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Expected bytes:
    // 0xC1: header (MID=0x01 | S=0x40 | Z=0x80)
    // 0x09: version
    // 0x02: combined (zid_len=0, client=0b10)
    // 0x01: zenoh ID byte
    // 0x2A: resolution (all 32-bit: 0b00_10_10_10)
    // 0x00, 0x08: batch_size=2048 LE
    // 0x27: patch ext header (ZInt, ID=0x07)
    // 0x01: patch value
    try assertEqualBytes(&.{ 0xC1, 0x09, 0x02, 0x01, 0x2A, 0x00, 0x08, 0x27, 0x01 }, encoded);
}

// ---------------------------------------------------------------------------
// Cookie pass-through: InitAck cookie echoed in OpenSyn
// ---------------------------------------------------------------------------

test "cookie pass-through: InitAck cookie echoed in OpenSyn" {
    // Simulate receiving an InitAck with a cookie
    const router_zid = try ZenohId.init(&.{ 0xAA, 0xBB });
    const cookie_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    const init_ack = InitAck{
        .zid = router_zid,
        .cookie = &cookie_data,
    };

    // Encode and decode the InitAck
    var ack_buf: [128]u8 = undefined;
    const ack_encoded = encodeInitAckHelper(&init_ack, &ack_buf);
    var ack_reader: Io.Reader = .fixed(ack_encoded);
    const ack_header = try ack_reader.takeByte();
    const decoded_ack = try InitAck.decodeAlloc(ack_header, &ack_reader, testing.allocator);
    defer testing.allocator.free(decoded_ack.cookie);

    // Use the decoded cookie in OpenSyn
    const open_syn = OpenSyn{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 42,
        .cookie = decoded_ack.cookie,
    };

    // Encode and decode the OpenSyn
    var open_buf: [128]u8 = undefined;
    const open_encoded = encodeOpenSynHelper(&open_syn, &open_buf);
    var open_reader: Io.Reader = .fixed(open_encoded);
    const open_header = try open_reader.takeByte();
    const decoded_open = try OpenSyn.decodeAlloc(open_header, &open_reader, testing.allocator);
    defer testing.allocator.free(decoded_open.cookie);

    // Verify the cookie survived the round-trip
    try testing.expectEqualSlices(u8, &cookie_data, decoded_open.cookie);
}

// ---------------------------------------------------------------------------
// Header parsing tests
// ---------------------------------------------------------------------------

test "getMid: extracts correct MID" {
    try testing.expectEqual(@as(u5, 0x01), getMid(0x01)); // InitSyn
    try testing.expectEqual(@as(u5, 0x01), getMid(0x21)); // InitAck
    try testing.expectEqual(@as(u5, 0x01), getMid(0xC1)); // InitSyn with S+Z
    try testing.expectEqual(@as(u5, 0x02), getMid(0x42)); // OpenSyn with T
    try testing.expectEqual(@as(u5, 0x02), getMid(0x62)); // OpenAck with T
}

test "isAck: detects A flag" {
    try testing.expect(!isAck(0x01)); // InitSyn
    try testing.expect(isAck(0x21)); // InitAck
    try testing.expect(!isAck(0xC1)); // InitSyn S+Z
    try testing.expect(isAck(0xE1)); // InitAck S+Z
    try testing.expect(!isAck(0x02)); // OpenSyn
    try testing.expect(!isAck(0x42)); // OpenSyn T
    try testing.expect(isAck(0x22)); // OpenAck
    try testing.expect(isAck(0x62)); // OpenAck T
}

// ---------------------------------------------------------------------------
// Multi-byte ZenohId wire vectors
// ---------------------------------------------------------------------------

test "InitSyn: 16-byte ZenohId" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const zid = try ZenohId.init(&data);
    const msg = InitSyn{
        .zid = zid,
        .whatami = .router,
    };
    var buf: [64]u8 = undefined;
    const encoded = encodeInitSynHelper(&msg, &buf);

    // Header: 0x01, Version: 0x09
    // Combined: zid_len=(16-1)=15=0xF0, router=0b00 → 0xF0
    try testing.expectEqual(@as(u8, 0x01), encoded[0]);
    try testing.expectEqual(@as(u8, 0x09), encoded[1]);
    try testing.expectEqual(@as(u8, 0xF0), encoded[2]);
    try testing.expectEqualSlices(u8, &data, encoded[3..19]);
    try testing.expectEqual(@as(usize, 19), encoded.len);
}

// ---------------------------------------------------------------------------
// Full handshake sequence wire test
// ---------------------------------------------------------------------------

test "full handshake sequence: encode all 4 messages" {
    // 1. InitSyn (client → router)
    const client_zid = try ZenohId.init(&.{ 0xC1, 0x1E });
    const init_syn = InitSyn{
        .zid = client_zid,
        .whatami = .client,
        .resolution = Resolution{},
        .batch_size = 2048,
        .patch = 1,
    };

    var syn_buf: [64]u8 = undefined;
    const syn_encoded = encodeInitSynHelper(&init_syn, &syn_buf);
    try testing.expect(syn_encoded.len > 0);

    // 2. InitAck (router → client)
    const router_zid = try ZenohId.init(&.{ 0xA1, 0x0A });
    const cookie = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const init_ack = InitAck{
        .zid = router_zid,
        .whatami = .router,
        .resolution = Resolution{},
        .batch_size = 2048,
        .cookie = &cookie,
        .patch = 1,
    };

    var ack_buf: [64]u8 = undefined;
    const ack_encoded = encodeInitAckHelper(&init_ack, &ack_buf);
    try testing.expect(ack_encoded.len > 0);

    // 3. OpenSyn (client → router) — echoes cookie
    const open_syn = OpenSyn{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 0,
        .cookie = &cookie,
    };

    var osyn_buf: [64]u8 = undefined;
    const osyn_encoded = encodeOpenSynHelper(&open_syn, &osyn_buf);
    try testing.expect(osyn_encoded.len > 0);

    // 4. OpenAck (router → client)
    const open_ack = OpenAck{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 0,
    };

    var oack_buf: [64]u8 = undefined;
    const oack_encoded = encodeOpenAckHelper(&open_ack, &oack_buf);
    try testing.expect(oack_encoded.len > 0);

    // Verify each can be decoded back
    {
        var reader: Io.Reader = .fixed(syn_encoded);
        const h = try reader.takeByte();
        _ = try InitSyn.decode(h, &reader);
    }
    {
        var reader: Io.Reader = .fixed(ack_encoded);
        const h = try reader.takeByte();
        const d = try InitAck.decodeAlloc(h, &reader, testing.allocator);
        defer testing.allocator.free(d.cookie);
    }
    {
        var reader: Io.Reader = .fixed(osyn_encoded);
        const h = try reader.takeByte();
        const d = try OpenSyn.decodeAlloc(h, &reader, testing.allocator);
        defer testing.allocator.free(d.cookie);
    }
    {
        var reader: Io.Reader = .fixed(oack_encoded);
        const h = try reader.takeByte();
        _ = try OpenAck.decode(h, &reader);
    }
}

// ---------------------------------------------------------------------------
// KeepAlive tests
// ---------------------------------------------------------------------------

test "KeepAlive: wire bytes = [0x04]" {
    const msg = KeepAlive{};
    var buf: [8]u8 = undefined;
    const encoded = encodeKeepAliveHelper(&msg, &buf);
    try assertEqualBytes(&.{0x04}, encoded);
}

test "KeepAlive: encoded length is 1 byte" {
    const msg = KeepAlive{};
    var buf: [8]u8 = undefined;
    const encoded = encodeKeepAliveHelper(&msg, &buf);
    try testing.expectEqual(@as(usize, 1), encoded.len);
}

test "KeepAlive: MID is keep_alive" {
    const msg = KeepAlive{};
    var buf: [8]u8 = undefined;
    const encoded = encodeKeepAliveHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.keep_alive), getMid(encoded[0]));
}

test "KeepAlive: round-trip" {
    const original = KeepAlive{};
    var buf: [8]u8 = undefined;
    const encoded = encodeKeepAliveHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.keep_alive), getMid(header));
    _ = try KeepAlive.decode(header, &reader);
}

test "KeepAlive: no flags set in header" {
    const msg = KeepAlive{};
    var buf: [8]u8 = undefined;
    const encoded = encodeKeepAliveHelper(&msg, &buf);
    // Header should be exactly MID with no flags
    const h = hdr.Header.decode(encoded[0]);
    try testing.expectEqual(@as(u3, 0), h.flags);
    try testing.expectEqual(@as(u5, MID.keep_alive), h.mid);
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

test "Close: encode session close with generic reason" {
    const msg = Close{ .session = true, .reason = .generic };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    // Header: MID=0x03 | S=0x20 → 0x23
    // Reason: 0x00
    try assertEqualBytes(&.{ 0x23, 0x00 }, encoded);
}

test "Close: encode session close with unsupported reason" {
    const msg = Close{ .session = true, .reason = .unsupported };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    try assertEqualBytes(&.{ 0x23, 0x01 }, encoded);
}

test "Close: encode session close with invalid reason" {
    const msg = Close{ .session = true, .reason = .invalid };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    try assertEqualBytes(&.{ 0x23, 0x02 }, encoded);
}

test "Close: encode link-only close (S=0)" {
    const msg = Close{ .session = false, .reason = .generic };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    // Header: MID=0x03, S=0 → 0x03
    // Reason: 0x00
    try assertEqualBytes(&.{ 0x03, 0x00 }, encoded);
}

test "Close: MID is close" {
    const msg = Close{};
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    try testing.expectEqual(@as(u5, MID.close), getMid(encoded[0]));
}

test "Close: S-flag set for session close" {
    const msg = Close{ .session = true };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(h.flag0()); // S flag is bit 5
}

test "Close: S-flag clear for link close" {
    const msg = Close{ .session = false };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    const h = hdr.Header.decode(encoded[0]);
    try testing.expect(!h.flag0());
}

test "Close: round-trip session close generic" {
    const original = Close{ .session = true, .reason = .generic };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    try testing.expectEqual(@as(u5, MID.close), getMid(header));
    const decoded = try Close.decode(header, &reader);

    try testing.expectEqual(original.session, decoded.session);
    try testing.expectEqual(original.reason, decoded.reason);
}

test "Close: round-trip session close unsupported" {
    const original = Close{ .session = true, .reason = .unsupported };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Close.decode(header, &reader);

    try testing.expectEqual(true, decoded.session);
    try testing.expectEqual(CloseReason.unsupported, decoded.reason);
}

test "Close: round-trip session close invalid" {
    const original = Close{ .session = true, .reason = .invalid };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Close.decode(header, &reader);

    try testing.expectEqual(true, decoded.session);
    try testing.expectEqual(CloseReason.invalid, decoded.reason);
}

test "Close: round-trip link-only close" {
    const original = Close{ .session = false, .reason = .generic };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Close.decode(header, &reader);

    try testing.expectEqual(false, decoded.session);
    try testing.expectEqual(CloseReason.generic, decoded.reason);
}

test "Close: round-trip unknown reason code (forward compat)" {
    // CloseReason is non-exhaustive, so unknown codes survive round-trip
    const original = Close{ .session = true, .reason = @enumFromInt(0xFF) };
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&original, &buf);

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const decoded = try Close.decode(header, &reader);

    try testing.expectEqual(true, decoded.session);
    try testing.expectEqual(@as(u8, 0xFF), @intFromEnum(decoded.reason));
}

test "Close: encoded length is 2 bytes" {
    const msg = Close{};
    var buf: [8]u8 = undefined;
    const encoded = encodeCloseHelper(&msg, &buf);
    try testing.expectEqual(@as(usize, 2), encoded.len);
}

// ---------------------------------------------------------------------------
// CloseReason tests
// ---------------------------------------------------------------------------

test "CloseReason: enum values match spec" {
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(CloseReason.generic));
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(CloseReason.unsupported));
    try testing.expectEqual(@as(u8, 0x02), @intFromEnum(CloseReason.invalid));
}

test {
    std.testing.refAllDecls(@This());
}
