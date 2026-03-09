//! Docker lifecycle helpers for integration tests.
//!
//! Manages a `zenoh-test` Docker container running `eclipse/zenoh:latest`,
//! providing start, wait-for-ready, and stop operations.
const std = @import("std");
const process = std.process;
const net = std.Io.net;
const Io = std.Io;

const container_name = "zenoh-test";
pub const zenoh_port: u16 = 7447;
const docker_image = "eclipse/zenoh:latest";

/// Maximum time to wait for zenohd to become ready (seconds).
const ready_timeout_s: i64 = 30;
/// Interval between readiness polls (milliseconds).
const poll_interval_ms: i64 = 250;

pub const DockerError = error{
    DockerNotAvailable,
    ContainerStartFailed,
    ReadyTimeout,
};

/// Starts the zenohd Docker container in detached mode.
///
/// Runs: `docker run --name zenoh-test --rm -d -p 7447:7447 eclipse/zenoh:latest`
///
/// If Docker is not available or the container fails to start, returns an error
/// with a descriptive log message.
pub fn startZenohd(allocator: std.mem.Allocator, io: Io) DockerError!void {
    // First, ensure any leftover container from a previous run is removed.
    // This is best-effort — we ignore errors (container might not exist).
    if (process.run(allocator, io, .{
        .argv = &.{ "docker", "rm", "-f", container_name },
        .stderr_limit = Io.Limit.limited(4096),
        .stdout_limit = Io.Limit.limited(4096),
    })) |cleanup_result| {
        allocator.free(cleanup_result.stdout);
        allocator.free(cleanup_result.stderr);
    } else |_| {}

    const result = process.run(allocator, io, .{
        .argv = &.{
            "docker", "run",
            "--name", container_name,
            "--rm",
            "-d",
            "-p", "7447:7447",
            docker_image,
        },
        .stderr_limit = Io.Limit.limited(4096),
        .stdout_limit = Io.Limit.limited(4096),
    }) catch {
        std.log.err("Failed to run docker command. Is Docker installed and running?", .{});
        return DockerError.DockerNotAvailable;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.log.err("docker run exited with code {d}: {s}", .{ code, result.stderr });
                return DockerError.ContainerStartFailed;
            }
        },
        else => {
            std.log.err("docker run terminated abnormally: {s}", .{result.stderr});
            return DockerError.ContainerStartFailed;
        },
    }
}

/// Polls TCP port 7447 on localhost until a connection succeeds or timeout.
///
/// Retries every 250ms for up to 30 seconds. Returns `ReadyTimeout` if
/// zenohd does not become reachable within the timeout period.
pub fn waitForReady(io: Io) DockerError!void {
    const max_attempts: usize = @intCast(@divTrunc(ready_timeout_s * 1000, poll_interval_ms));
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(zenoh_port) };

    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        if (address.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
            std.log.info("zenohd is ready on port {d} (after {d} attempts)", .{ zenoh_port, attempt + 1 });
            return;
        } else |_| {
            Io.sleep(io, Io.Duration.fromMilliseconds(poll_interval_ms), .awake) catch {};
        }
    }

    std.log.err("zenohd did not become ready on port {d} within {d}s", .{ zenoh_port, ready_timeout_s });
    return DockerError.ReadyTimeout;
}

/// Stops the zenohd Docker container.
///
/// Runs: `docker stop zenoh-test`
///
/// Idempotent — ignores errors if the container is already stopped or doesn't exist.
pub fn stopZenohd(allocator: std.mem.Allocator, io: Io) void {
    const result = process.run(allocator, io, .{
        .argv = &.{ "docker", "stop", container_name },
        .stderr_limit = Io.Limit.limited(4096),
        .stdout_limit = Io.Limit.limited(4096),
    }) catch {
        std.log.warn("Failed to run 'docker stop {s}' (container may already be stopped)", .{container_name});
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code == 0) {
                std.log.info("zenohd container '{s}' stopped successfully", .{container_name});
            } else {
                std.log.warn("docker stop exited with code {d} (container may already be stopped)", .{code});
            }
        },
        else => {
            std.log.warn("docker stop terminated abnormally (container may already be stopped)", .{});
        },
    }
}

test {
    std.testing.refAllDecls(@This());
}
