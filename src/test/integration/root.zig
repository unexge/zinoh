//! Integration test entry point.
//!
//! Manages the zenohd Docker container lifecycle and runs smoke tests
//! against a real Zenoh router.
const std = @import("std");
const net = std.Io.net;
const zinoh = @import("zinoh");

pub const helpers = @import("helpers.zig");

/// Helper to start Docker or skip tests if Docker is not available.
/// Returns true if Docker started successfully, false if skipped.
fn ensureZenohd(allocator: std.mem.Allocator, io: std.Io) !bool {
    helpers.startZenohd(allocator, io) catch |err| {
        switch (err) {
            error.DockerNotAvailable => {
                std.log.warn(
                    \\
                    \\==========================================================
                    \\  SKIPPED: Docker is not available.
                    \\  Install Docker and ensure the daemon is running to
                    \\  execute integration tests.
                    \\==========================================================
                    \\
                , .{});
                return false;
            },
            else => return err,
        }
    };
    return true;
}

test "smoke: TCP connectivity to zenohd" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    stream.close(io);
}

test "session: connect and graceful close" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

    // Graceful close with generic reason
    try session.close(.generic);

    // Verify session is closed
    try std.testing.expectEqual(zinoh.session.State.closed, session.state);
}

test "session: connect and close with different reason codes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

// ---------------------------------------------------------------------------
// KeepAlive integration tests
// ---------------------------------------------------------------------------

test "keepalive: session stays alive during idle period" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

    const zid = try zinoh.transport.messages.ZenohId.init(&.{ 0xCA, 0xFE, 0x01 });
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };

    var session = try zinoh.session.Session.open(allocator, io, address, zid);
    defer session.deinit();
    try std.testing.expectEqual(zinoh.session.State.open, session.state);

    // Start keepalive loop.
    try session.startKeepAlive();

    // Wait for several keepalive intervals (lease is typically 10s,
    // so lease/3 ≈ 3.3s; we wait ~5s to see at least one KeepAlive).
    const wait_ms: i64 = 5000;
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

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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
    // Unit-test helper: construct a minimal session-like struct just to
    // verify leaseMillis(). We use the Session's leaseMillis function
    // through a real session that we immediately close.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    if (!try ensureZenohd(allocator, io)) return;
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

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

test {
    std.testing.refAllDecls(@This());
}
