//! Message header format shared by all transport, network, and Zenoh messages.
//!
//! Every message starts with a 1-byte header:
//!
//! ```
//!  7 6 5 4 3 2 1 0
//! +-+-+-+-+-+-+-+-+
//! |  Flags  | MID |
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! - Bits 0–4 (MID): Message ID, masked with 0x1F
//! - Bits 5–7 (Flags): Message-type-specific flags

const std = @import("std");
const testing = std.testing;

/// A parsed 1-byte message header containing the message ID and flags.
pub const Header = struct {
    mid: u5,
    flags: u3,

    /// Pack this header into a single byte.
    /// Layout: flags in bits 7-5, mid in bits 4-0.
    pub fn encode(self: Header) u8 {
        return (@as(u8, self.flags) << 5) | @as(u8, self.mid);
    }

    /// Unpack a header from a single byte.
    pub fn decode(byte: u8) Header {
        return .{
            .mid = @truncate(byte & 0x1F),
            .flags = @truncate(byte >> 5),
        };
    }

    // ── Flag accessors ──────────────────────────────────────────────────

    /// Bit 5 (flag bit 0): A=Ack for Init/Open, R=Reliable for Frame,
    /// S=Session for Close.
    pub fn flag0(self: Header) bool {
        return (self.flags & 0b001) != 0;
    }

    /// Bit 6 (flag bit 1): S=Size params for Init, T=Time-in-seconds for Open.
    pub fn flag1(self: Header) bool {
        return (self.flags & 0b010) != 0;
    }

    /// Bit 7 (flag bit 2): Z=Extensions present.
    pub fn flag2(self: Header) bool {
        return (self.flags & 0b100) != 0;
    }

    /// Returns true when the A(ck) flag (bit 5) is set.
    /// Used by Init and Open messages to distinguish Syn from Ack.
    pub fn isAck(self: Header) bool {
        return self.flag0();
    }

    /// Returns true when the Z (extensions-present) flag (bit 7) is set.
    pub fn hasExtensions(self: Header) bool {
        return self.flag2();
    }

    /// Returns true when the R(eliable) flag (bit 5) is set.
    /// Used by Frame messages.
    pub fn isReliable(self: Header) bool {
        return self.flag0();
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Message ID constants
// ═══════════════════════════════════════════════════════════════════════════

/// Transport-layer message IDs (MID values for bits 0–4).
pub const TransportMid = struct {
    pub const init: u5 = 0x01;
    pub const open: u5 = 0x02;
    pub const close: u5 = 0x03;
    pub const keep_alive: u5 = 0x04;
    pub const frame: u5 = 0x05;
    pub const fragment: u5 = 0x06;
};

/// Network-layer message IDs (MID values for bits 0–4).
pub const NetworkMid = struct {
    pub const interest: u5 = 0x19;
    pub const response_final: u5 = 0x1A;
    pub const response: u5 = 0x1B;
    pub const request: u5 = 0x1C;
    pub const push: u5 = 0x1D;
    pub const declare: u5 = 0x1E;
};

/// Declaration sub-message IDs (MID values for bits 0–4).
/// These appear inside a Declare network message and are disambiguated
/// by protocol layer context (they may overlap with network MIDs numerically).
pub const DeclareMid = struct {
    pub const declare_final: u5 = 0x1A;
};

/// Zenoh-layer message IDs (MID values for bits 0–4).
/// Note: these overlap with transport MIDs numerically;
/// disambiguation is by protocol layer context.
pub const ZenohMid = struct {
    pub const put: u5 = 0x01;
    pub const del: u5 = 0x02;
    pub const query: u5 = 0x03;
    pub const reply: u5 = 0x04;
    pub const err: u5 = 0x05;
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// Encode / decode round-trip
// ---------------------------------------------------------------------------

test "Header: encode/decode round-trip — zero flags" {
    const h = Header{ .mid = TransportMid.init, .flags = 0 };
    const byte = h.encode();
    try testing.expectEqual(@as(u8, 0x01), byte);
    const decoded = Header.decode(byte);
    try testing.expectEqual(h.mid, decoded.mid);
    try testing.expectEqual(h.flags, decoded.flags);
}

test "Header: encode/decode round-trip — all flags set" {
    const h = Header{ .mid = TransportMid.frame, .flags = 0b111 };
    const byte = h.encode();
    try testing.expectEqual(@as(u8, 0xE5), byte); // 0b111_00101
    const decoded = Header.decode(byte);
    try testing.expectEqual(h.mid, decoded.mid);
    try testing.expectEqual(h.flags, decoded.flags);
}

test "Header: encode/decode round-trip — all MID bits set" {
    const h = Header{ .mid = 0x1F, .flags = 0 };
    const byte = h.encode();
    try testing.expectEqual(@as(u8, 0x1F), byte);
    const decoded = Header.decode(byte);
    try testing.expectEqual(@as(u5, 0x1F), decoded.mid);
    try testing.expectEqual(@as(u3, 0), decoded.flags);
}

test "Header: encode/decode round-trip — exhaustive flag combinations" {
    // Test all 8 flag combinations for a given MID.
    const mid: u5 = TransportMid.close;
    for (0..8) |f| {
        const flags: u3 = @intCast(f);
        const h = Header{ .mid = mid, .flags = flags };
        const byte = h.encode();
        const decoded = Header.decode(byte);
        try testing.expectEqual(h.mid, decoded.mid);
        try testing.expectEqual(h.flags, decoded.flags);
    }
}

test "Header: encode/decode round-trip — various MID+flag combos" {
    const cases = [_]struct { mid: u5, flags: u3 }{
        .{ .mid = TransportMid.init, .flags = 0b000 }, // InitSyn
        .{ .mid = TransportMid.init, .flags = 0b001 }, // InitAck
        .{ .mid = TransportMid.init, .flags = 0b110 }, // InitSyn S+Z
        .{ .mid = TransportMid.init, .flags = 0b111 }, // InitAck S+Z
        .{ .mid = TransportMid.open, .flags = 0b010 }, // OpenSyn T
        .{ .mid = TransportMid.open, .flags = 0b011 }, // OpenAck T
        .{ .mid = TransportMid.frame, .flags = 0b001 }, // Frame reliable
        .{ .mid = NetworkMid.push, .flags = 0b001 }, // Push N=1
        .{ .mid = NetworkMid.request, .flags = 0b000 },
        .{ .mid = ZenohMid.put, .flags = 0b000 },
        .{ .mid = ZenohMid.query, .flags = 0b100 },
    };
    for (cases) |c| {
        const h = Header{ .mid = c.mid, .flags = c.flags };
        const decoded = Header.decode(h.encode());
        try testing.expectEqual(h.mid, decoded.mid);
        try testing.expectEqual(h.flags, decoded.flags);
    }
}

// ---------------------------------------------------------------------------
// Flag extraction
// ---------------------------------------------------------------------------

test "Header: isAck — Init with A=1" {
    // INIT with A flag set → 0x21
    const h = Header.decode(0x21);
    try testing.expectEqual(TransportMid.init, h.mid);
    try testing.expect(h.isAck());
    try testing.expect(!h.hasExtensions());
}

test "Header: isAck — Init without A flag" {
    const h = Header.decode(0x01);
    try testing.expectEqual(TransportMid.init, h.mid);
    try testing.expect(!h.isAck());
}

test "Header: hasExtensions — Z flag set" {
    // 0x81 = MID=0x01 | Z=0x80
    const h = Header.decode(0x81);
    try testing.expectEqual(TransportMid.init, h.mid);
    try testing.expect(h.hasExtensions());
    try testing.expect(!h.isAck());
}

test "Header: isAck and hasExtensions both set" {
    // 0xE1 = MID=0x01 | A=0x20 | S=0x40 | Z=0x80
    const h = Header.decode(0xE1);
    try testing.expectEqual(TransportMid.init, h.mid);
    try testing.expect(h.isAck());
    try testing.expect(h.hasExtensions());
    try testing.expect(h.flag1()); // S flag
}

test "Header: isReliable — Frame with R=1" {
    // 0x25 = MID=0x05 | R=0x20
    const h = Header.decode(0x25);
    try testing.expectEqual(TransportMid.frame, h.mid);
    try testing.expect(h.isReliable());
}

test "Header: isReliable — Frame with R=0" {
    const h = Header.decode(0x05);
    try testing.expectEqual(TransportMid.frame, h.mid);
    try testing.expect(!h.isReliable());
}

test "Header: individual flag bits" {
    // Only flag bit 1 set (bit 6) → flags = 0b010
    const h = Header{ .mid = 0, .flags = 0b010 };
    try testing.expect(!h.flag0());
    try testing.expect(h.flag1());
    try testing.expect(!h.flag2());

    // Only flag bit 2 set (bit 7) → flags = 0b100
    const h2 = Header{ .mid = 0, .flags = 0b100 };
    try testing.expect(!h2.flag0());
    try testing.expect(!h2.flag1());
    try testing.expect(h2.flag2());
}

// ---------------------------------------------------------------------------
// MID masking — verify all defined message IDs decode correctly
// ---------------------------------------------------------------------------

test "Header: MID masking — transport message IDs" {
    // Verify each transport MID is correctly extracted regardless of flags.
    const mids = [_]u5{
        TransportMid.init,
        TransportMid.open,
        TransportMid.close,
        TransportMid.keep_alive,
        TransportMid.frame,
        TransportMid.fragment,
    };
    for (mids) |mid| {
        // With no flags
        try testing.expectEqual(mid, Header.decode(@as(u8, mid)).mid);
        // With all flags set
        try testing.expectEqual(mid, Header.decode(@as(u8, mid) | 0xE0).mid);
        // With random flags 0b101
        try testing.expectEqual(mid, Header.decode(@as(u8, mid) | 0xA0).mid);
    }
}

test "Header: MID masking — network message IDs" {
    const mids = [_]u5{
        NetworkMid.interest,
        NetworkMid.response_final,
        NetworkMid.response,
        NetworkMid.request,
        NetworkMid.push,
        NetworkMid.declare,
    };
    for (mids) |mid| {
        try testing.expectEqual(mid, Header.decode(@as(u8, mid)).mid);
        try testing.expectEqual(mid, Header.decode(@as(u8, mid) | 0xE0).mid);
    }
}

test "Header: MID masking — Zenoh message IDs" {
    const mids = [_]u5{
        ZenohMid.put,
        ZenohMid.del,
        ZenohMid.query,
        ZenohMid.reply,
        ZenohMid.err,
    };
    for (mids) |mid| {
        try testing.expectEqual(mid, Header.decode(@as(u8, mid)).mid);
        try testing.expectEqual(mid, Header.decode(@as(u8, mid) | 0xE0).mid);
    }
}

// ---------------------------------------------------------------------------
// MID constant values
// ---------------------------------------------------------------------------

test "TransportMid: constant values match spec" {
    try testing.expectEqual(@as(u5, 0x01), TransportMid.init);
    try testing.expectEqual(@as(u5, 0x02), TransportMid.open);
    try testing.expectEqual(@as(u5, 0x03), TransportMid.close);
    try testing.expectEqual(@as(u5, 0x04), TransportMid.keep_alive);
    try testing.expectEqual(@as(u5, 0x05), TransportMid.frame);
    try testing.expectEqual(@as(u5, 0x06), TransportMid.fragment);
}

test "NetworkMid: constant values match spec" {
    try testing.expectEqual(@as(u5, 0x19), NetworkMid.interest);
    try testing.expectEqual(@as(u5, 0x1A), NetworkMid.response_final);
    try testing.expectEqual(@as(u5, 0x1B), NetworkMid.response);
    try testing.expectEqual(@as(u5, 0x1C), NetworkMid.request);
    try testing.expectEqual(@as(u5, 0x1D), NetworkMid.push);
    try testing.expectEqual(@as(u5, 0x1E), NetworkMid.declare);
}

test "ZenohMid: constant values match spec" {
    try testing.expectEqual(@as(u5, 0x01), ZenohMid.put);
    try testing.expectEqual(@as(u5, 0x02), ZenohMid.del);
    try testing.expectEqual(@as(u5, 0x03), ZenohMid.query);
    try testing.expectEqual(@as(u5, 0x04), ZenohMid.reply);
    try testing.expectEqual(@as(u5, 0x05), ZenohMid.err);
}

test "DeclareMid: constant values match spec" {
    try testing.expectEqual(@as(u5, 0x1A), DeclareMid.declare_final);
}

// ---------------------------------------------------------------------------
// Wire-format compatibility with existing transport/messages.zig
// ---------------------------------------------------------------------------

test "Header: wire compatibility — InitSyn header byte is 0x01" {
    const h = Header{ .mid = TransportMid.init, .flags = 0 };
    try testing.expectEqual(@as(u8, 0x01), h.encode());
}

test "Header: wire compatibility — InitAck header byte is 0x21" {
    const h = Header{ .mid = TransportMid.init, .flags = 0b001 };
    try testing.expectEqual(@as(u8, 0x21), h.encode());
}

test "Header: wire compatibility — InitSyn S+Z header byte is 0xC1" {
    const h = Header{ .mid = TransportMid.init, .flags = 0b110 };
    try testing.expectEqual(@as(u8, 0xC1), h.encode());
}

test "Header: wire compatibility — InitAck S+Z header byte is 0xE1" {
    const h = Header{ .mid = TransportMid.init, .flags = 0b111 };
    try testing.expectEqual(@as(u8, 0xE1), h.encode());
}

test "Header: wire compatibility — OpenSyn T header byte is 0x42" {
    const h = Header{ .mid = TransportMid.open, .flags = 0b010 };
    try testing.expectEqual(@as(u8, 0x42), h.encode());
}

test "Header: wire compatibility — OpenAck T header byte is 0x62" {
    const h = Header{ .mid = TransportMid.open, .flags = 0b011 };
    try testing.expectEqual(@as(u8, 0x62), h.encode());
}

test "Header: wire compatibility — Frame reliable header byte is 0x25" {
    const h = Header{ .mid = TransportMid.frame, .flags = 0b001 };
    try testing.expectEqual(@as(u8, 0x25), h.encode());
}

test "Header: wire compatibility — Push N=1 M=0 header byte is 0x3D" {
    // From protocol doc: Push header=0x3D (N=1, M=0)
    const h = Header.decode(0x3D);
    try testing.expectEqual(NetworkMid.push, h.mid);
    try testing.expect(h.flag0()); // N=1
    try testing.expect(!h.flag1()); // M=0
    try testing.expect(!h.flag2()); // no extensions
}

test "Header: decode byte 0x00 gives mid=0, flags=0" {
    const h = Header.decode(0x00);
    try testing.expectEqual(@as(u5, 0), h.mid);
    try testing.expectEqual(@as(u3, 0), h.flags);
}

test "Header: decode byte 0xFF gives mid=31, flags=7" {
    const h = Header.decode(0xFF);
    try testing.expectEqual(@as(u5, 0x1F), h.mid);
    try testing.expectEqual(@as(u3, 0b111), h.flags);
}
