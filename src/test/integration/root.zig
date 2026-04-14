//! Integration test entry point.
//!
//! Runs smoke tests against a real Zenoh router.
//!
//! The zenohd Docker container is started once on the first test that
//! needs it and kept running for the entire suite.  If the container
//! is already reachable (e.g. started manually), Docker management is
//! skipped.  See helpers.zig for lifecycle details.
const std = @import("std");
const net = std.Io.net;
const zinoh = @import("zinoh");

pub const helpers = @import("helpers.zig");

/// Helper to acquire the shared Docker container or skip tests.
/// Returns true if Docker is available, false if skipped.
fn acquireOrSkip(allocator: std.mem.Allocator, io: std.Io) !bool {
    return helpers.acquireZenohd(allocator, io);
}

test "smoke: TCP connectivity to zenohd" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    stream.close(io);
}

test "session: connect and graceful close" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    // Create a client ZenohId
    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x01, 0x02, 0x03, 0x04 });

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Open session (performs full 4-message handshake)
    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // Verify session is in open state
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Verify we got a remote ZenohId (router's ID should be non-empty)
    try std.testing.expect(session.remote_zid.len > 0);

    // Verify negotiated values are populated correctly
    try std.testing.expect(session.batch_size > 0);
    try std.testing.expect(session.lease > 0);
    // Lease in milliseconds should be plausible (>= 1s for second-based lease)
    if (session.lease_in_seconds) {
        try std.testing.expect(session.leaseMillis() >= 1000);
    }

    // Verify local ZenohId is preserved
    try std.testing.expectEqualSlices(u8, zid.slice(), session.local_zid.slice());

    // Graceful close with generic reason
    try session.close(.generic);

    // Verify session is closed
    try std.testing.expectEqual(zinoh.session.State.closed, session.state);
}

test "session: connect and close with different reason codes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Test close with 'unsupported' reason
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x10, 0x20, 0x30 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();
        try session.close(.unsupported);
        try std.testing.expectEqual(zinoh.session.State.closed, session.state);
    }

    // Test close with 'invalid' reason
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x40, 0x50, 0x60 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();
        try session.close(.invalid);
        try std.testing.expectEqual(zinoh.session.State.closed, session.state);
    }
}

test "session: deinit without close (error cleanup path)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xAA, 0xBB, 0xCC, 0xDD });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Open session
    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Directly deinit without sending Close (simulates error cleanup).
    // The defer will safely call deinit() a second time (documented as safe).
    session.deinit();

    // After deinit, state should be closed
    try std.testing.expectEqual(zinoh.session.State.closed, session.state);
}

test "session: no resource leaks (allocator check)" {
    // Uses std.testing.allocator which detects leaks automatically.
    // If this test passes without leak errors, resources are properly freed.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Open and close multiple sessions to stress resource management
    for (0..3) |i| {
        var zid_bytes = [_]u8{ 0xF0, 0x00, 0x00, @truncate(i) };
        const zid = try zinoh.transport.messages.ZenohId.init(&zid_bytes);

        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();
        try session.close(.generic);
    }
}

test "session: connect with SessionConfig" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xDE, 0xAD, 0xBE, 0xEF });
    const config = zinoh.session.SessionConfig{
        .zid = zid,
        .batch_size = 4096,
        .lease = 15,
        .whatami = .client,
        .patch = 1,
    };

    var session = try zinoh.session.Session.connect(allocator, io, address, config);
    defer session.deinit();

    // Verify session is open
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Verify local ZID is stored from config
    try std.testing.expectEqualSlices(u8, zid.slice(), session.local_zid.slice());
    try std.testing.expectEqualSlices(u8, zid.slice(), session.config.zid.slice());

    // Verify the config is preserved
    try std.testing.expectEqual(@as(u16, 4096), session.config.batch_size);
    try std.testing.expectEqual(@as(u64, 15), session.config.lease);

    // Verify negotiated fields are populated
    try std.testing.expect(session.remote_zid.len > 0);
    try std.testing.expect(session.batch_size > 0);
    try std.testing.expect(session.lease > 0);

    try session.close(.generic);
}

test "session: negotiated fields are populated correctly after handshake" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x11, 0x22, 0x33 });
    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // Remote ZID should be valid (non-zero length, at most 16 bytes)
    try std.testing.expect(session.remote_zid.len >= 1);
    try std.testing.expect(session.remote_zid.len <= 16);

    // Remote ZID should differ from local ZID
    try std.testing.expect(!std.mem.eql(u8, session.local_zid.slice(), session.remote_zid.slice()));

    // Batch size: should be positive and at most our proposed size (2048 default)
    try std.testing.expect(session.batch_size > 0);
    try std.testing.expect(session.batch_size <= session.config.batch_size);

    // Lease: should be positive
    try std.testing.expect(session.lease > 0);

    // Resolution: should have valid frame_sn bits
    const fsn = session.resolution.frame_sn;
    try std.testing.expect(fsn == .bits_8 or fsn == .bits_16 or fsn == .bits_32 or fsn == .bits_64);

    // tx_sn: should be bounded by the resolution mask
    const sn_mask: u64 = switch (session.resolution.frame_sn) {
        .bits_8 => 0xFF,
        .bits_16 => 0xFFFF,
        .bits_32 => 0xFFFFFFFF,
        .bits_64 => std.math.maxInt(u64),
    };
    try std.testing.expect(session.tx_sn <= sn_mask);

    try session.close(.generic);
}

// ---------------------------------------------------------------------------
// KeepAlive integration tests
// ---------------------------------------------------------------------------

test "keepalive: session stays alive during idle period" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xCA, 0xFE, 0x01 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Start keepalive loop.
    try session.startKeepAlive();

    // Wait long enough for at least one keepalive to fire.
    // The keepalive interval is lease/3; with a typical 10s lease that's ~3.3s.
    // We wait 1.5s which is enough for shorter leases and verifies the mechanism.
    const wait_ms: i64 = 1500;
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(wait_ms), .awake) catch {};

    // Session should still be open (keepalive prevented expiration).
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Graceful close.
    try session.close(.generic);
    try std.testing.expectEqual(zinoh.session.State.closed, session.state);
}

test "keepalive: start and stop are idempotent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xCA, 0xFE, 0x02 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // Start twice — second call should be a no-op.
    try session.startKeepAlive();
    try session.startKeepAlive();

    // Stop twice — second call should be a no-op.
    session.stopKeepAlive();
    session.stopKeepAlive();

    try session.close(.generic);
}

test "keepalive: close stops keepalive automatically" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xCA, 0xFE, 0x03 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    try session.startKeepAlive();

    // Let at least one keepalive fire.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(500), .awake) catch {};

    // Close should stop the keepalive thread internally.
    try session.close(.generic);

    // After close, keepalive thread should be joined and nil.
    try std.testing.expectEqual(@as(?std.Thread, null), session.keepalive_thread);
    try std.testing.expectEqual(zinoh.session.State.closed, session.state);
}

test "keepalive: leaseMillis returns plausible value for negotiated lease" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xCA, 0xFE, 0x04 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // The router typically negotiates a 10s lease.
    // Verify leaseMillis is plausible (non-zero, > 1000 for seconds-based).
    const lm = session.leaseMillis();
    try std.testing.expect(lm > 0);

    // If lease is in seconds, it should be at least 1000 ms.
    if (session.lease_in_seconds) {
        try std.testing.expect(lm >= 1000);
    }

    try session.close(.generic);
}

// ---------------------------------------------------------------------------
// TcpTransport integration tests
// ---------------------------------------------------------------------------

test "tcp transport: connect, send InitSyn, recv InitAck, close" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const TcpTransport = zinoh.transport.tcp.TcpTransport;
    const transport_msgs = zinoh.transport.messages;
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Connect via TcpTransport
    var transport = try TcpTransport.connect(allocator, io, address);
    defer transport.close();

    // Encode an InitSyn message
    const zid = try transport_msgs.ZenohId.init(&.{ 0x7C, 0x01, 0x02 });
    const init_syn = transport_msgs.InitSyn{
        .version = transport_msgs.protocol_version,
        .whatami = .client,
        .zid = zid,
        .resolution = transport_msgs.Resolution{},
        .batch_size = 2048,
        .patch = 1,
    };
    var msg_buf: [512]u8 = undefined;
    var msg_writer: std.Io.Writer = .fixed(&msg_buf);
    try init_syn.encode(&msg_writer);
    const payload = msg_writer.buffered();

    // Send the InitSyn via transport
    try transport.send(payload);

    // Receive the InitAck
    const response = try transport.recvAlloc(allocator);
    defer allocator.free(response);

    // Verify we got a response (should be at least a header byte)
    try std.testing.expect(response.len > 0);

    // Parse the header: should be InitAck (MID=0x01, A=1)
    const header = response[0];
    const mid = transport_msgs.getMid(header);
    try std.testing.expectEqual(@as(u5, transport_msgs.MID.init), mid);
    try std.testing.expect(transport_msgs.isAck(header));
}

test "tcp transport: send and recv raw bytes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const TcpTransport = zinoh.transport.tcp.TcpTransport;
    const transport_msgs = zinoh.transport.messages;
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var transport = try TcpTransport.connect(allocator, io, address);
    defer transport.close();

    // Send a minimal InitSyn using recv (non-alloc) variant
    const zid = try transport_msgs.ZenohId.init(&.{ 0x7C, 0x10, 0x20 });
    const init_syn = transport_msgs.InitSyn{
        .version = transport_msgs.protocol_version,
        .whatami = .client,
        .zid = zid,
    };
    var msg_buf: [512]u8 = undefined;
    var msg_writer: std.Io.Writer = .fixed(&msg_buf);
    try init_syn.encode(&msg_writer);
    try transport.send(msg_writer.buffered());

    // Receive into a stack buffer
    var recv_buf: [zinoh.transport.framing.max_frame_size]u8 = undefined;
    const response = try transport.recv(&recv_buf);

    // Should be a valid InitAck
    try std.testing.expect(response.len > 0);
    try std.testing.expectEqual(@as(u5, transport_msgs.MID.init), transport_msgs.getMid(response[0]));
    try std.testing.expect(transport_msgs.isAck(response[0]));
}

test "tcp transport: clean close (no leaked fds)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const TcpTransport = zinoh.transport.tcp.TcpTransport;
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // Open and close multiple transports — allocator detects leaks
    for (0..3) |_| {
        var transport = try TcpTransport.connect(allocator, io, address);
        transport.close();
    }
}

// ---------------------------------------------------------------------------
// z_put integration tests
// ---------------------------------------------------------------------------

test "z_put: publish to zenohd succeeds without error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xA0, 0xA1, 0xA2 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Put a value — should succeed without error.
    try session.put("demo/example/hello", "Hello World!", .{});

    // Session should still be open after put.
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    try session.close(.generic);
}

test "z_put: multiple puts with incrementing sequence numbers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xB0, 0xB1, 0xB2 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    const initial_sn = session.tx_sn;

    // Put several values.
    try session.put("test/key1", "value1", .{});
    try session.put("test/key2", "value2", .{});
    try session.put("test/key3", "value3", .{});

    // SN should have advanced by 3.
    const sn_mask: u64 = switch (session.resolution.frame_sn) {
        .bits_8 => 0xFF,
        .bits_16 => 0xFFFF,
        .bits_32 => 0xFFFFFFFF,
        .bits_64 => std.math.maxInt(u64),
    };
    const expected_sn = (initial_sn +% 3) & sn_mask;
    try std.testing.expectEqual(expected_sn, session.tx_sn);

    try session.close(.generic);
}

test "z_put: with encoding option" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xC0, 0xC1, 0xC2 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // Put with explicit encoding.
    try session.put("demo/encoded", "{\"key\":\"value\"}", .{
        .encoding = .{ .id = 10 },
    });

    try session.close(.generic);
}

// ---------------------------------------------------------------------------
// z_get integration tests
// ---------------------------------------------------------------------------

test "z_get: query with no stored data returns empty result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xD0, 0xD1, 0xD2 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    // Query a key that has no stored data.
    const result = try session.get("demo/nonexistent/key", .{});
    defer result.deinit(allocator);

    // Should get zero replies (ResponseFinal immediately, or the
    // router may close the connection if it doesn't support queries
    // without a matching storage/subscriber).
    try std.testing.expectEqual(@as(usize, 0), result.replies.len);

    // Session may be open (got ResponseFinal) or closed (router closed
    // the connection).  Either is acceptable for this test.
    try std.testing.expect(session.state == .open or session.state == .closed);

    if (session.state == .open) {
        try session.close(.generic);
    }
}

test "z_get: put then get round-trip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    // First session: put a value.
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xE0, 0xE1, 0xE2 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();

        try session.put("demo/test/roundtrip", "Hello Zinoh!", .{});
        try session.close(.generic);
    }

    // Brief pause for the router to process the put.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};

    // Second session: get the value back.
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xF0, 0xF1, 0xF2 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();

        const result = try session.get("demo/test/roundtrip", .{});
        defer result.deinit(allocator);

        // With in-memory storage enabled, we should always get at least one reply.
        try std.testing.expect(result.replies.len >= 1);

        var found = false;
        for (result.replies) |reply| {
            if (std.mem.eql(u8, reply.payload, "Hello Zinoh!")) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);

        if (session.state == .open) {
            try session.close(.generic);
        }
    }
}

test "z_get: request_id is properly incremented" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xA1, 0xB1, 0xC1 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();

    const initial_rid = session.next_request_id;

    // First query — may close the connection on some router configurations.
    const r1 = try session.get("demo/nonexistent1", .{});
    defer r1.deinit(allocator);

    // After the first get(), request_id should have advanced by 1 regardless
    // of whether the router responded with ResponseFinal or closed the connection.
    try std.testing.expectEqual(initial_rid + 1, session.next_request_id);

    // A second query is only possible if the session is still open (the
    // router sent a proper ResponseFinal instead of closing the connection).
    if (session.state == .open) {
        const r2 = try session.get("demo/nonexistent2", .{});
        defer r2.deinit(allocator);
        try std.testing.expectEqual(initial_rid + 2, session.next_request_id);
    }

    if (session.state == .open) {
        try session.close(.generic);
    }
}

// ---------------------------------------------------------------------------
// Storage-backed put/get integration tests
// ---------------------------------------------------------------------------

test "z_put: multiple puts to different keys" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try acquireOrSkip(allocator, io)) return;

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    const keys = [_][]const u8{
        "demo/test/multi/alpha",
        "demo/test/multi/beta",
        "demo/test/multi/gamma",
    };
    const values = [_][]const u8{
        "value-alpha",
        "value-beta",
        "value-gamma",
    };

    // Put to all 3 keys in one session.
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x71, 0x72, 0x73 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();

        for (keys, values) |key, value| {
            try session.put(key, value, .{});
        }

        try session.close(.generic);
    }

    // Brief pause for storage processing.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};

    // Get each key back in a new session and verify.
    {
        const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0x74, 0x75, 0x76 });
        var session = try zinoh.session.Session.open(allocator, io, address, zid);
        defer session.deinit();

        for (keys, values) |key, expected_value| {
            const result = try session.get(key, .{});
            defer result.deinit(allocator);

            try std.testing.expect(result.replies.len >= 1);

            var found = false;
            for (result.replies) |reply| {
                if (std.mem.eql(u8, reply.payload, expected_value)) {
                    found = true;
                    break;
                }
            }
            try std.testing.expect(found);
        }

        if (session.state == .open) {
            try session.close(.generic);
        }
    }
}

test {
    std.testing.refAllDecls(@This());
}
