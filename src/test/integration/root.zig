//! Integration test entry point.
//!
//! Manages the zenohd Docker container lifecycle and runs smoke tests
//! against a real Zenoh router.
const std = @import("std");
const net = std.Io.net;

pub const helpers = @import("helpers.zig");

test "smoke: TCP connectivity to zenohd" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

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
                return;
            },
            else => return err,
        }
    };

    // Always stop the container, even if the test fails below.
    defer helpers.stopZenohd(allocator, io);

    try helpers.waitForReady(io);

    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(helpers.zenoh_port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    stream.close(io);
}

test {
    std.testing.refAllDecls(@This());
}
