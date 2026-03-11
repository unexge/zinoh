//! Docker lifecycle helpers for integration tests.
//!
//! Manages a `zenoh-test` Docker container running `eclipse/zenoh:latest`,
//! providing start, wait-for-ready, and stop operations.
//!
//! The container is started once and reused across all tests in the suite.
//! A reference count tracks active users; the container is torn down when
//! the last user calls `releaseZenohd()`.
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

/// Module-level state: tracks whether the Docker container has been started
/// and how many tests are currently using it.
var container_started: bool = false;
var container_ref_count: usize = 0;
/// Tracks whether Docker was detected as unavailable so we only warn once.
var docker_unavailable: bool = false;

/// Acquires a reference to the zenohd Docker container.
///
/// On the first call, starts the container and waits for it to become ready.
/// On subsequent calls, simply increments the reference count.
///
/// Returns `true` if the container is available, `false` if Docker is not
/// available (tests should skip in that case).
pub fn acquireZenohd(allocator: std.mem.Allocator, io: Io) DockerError!bool {
    if (docker_unavailable) return false;

    if (!container_started) {
        startZenohd(allocator, io) catch |err| {
            switch (err) {
                error.DockerNotAvailable => {
                    docker_unavailable = true;
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
        waitForReady(io) catch |err| {
            // If we can't become ready, force-remove the container.
            forceRemove(allocator, io);
            return err;
        };
        container_started = true;
    }

    container_ref_count += 1;
    return true;
}

/// Releases a reference to the zenohd Docker container.
///
/// When the last reference is released, the container is force-removed
/// (instant teardown, no 10-second SIGTERM grace period).
pub fn releaseZenohd(allocator: std.mem.Allocator, io: Io) void {
    if (container_ref_count == 0) return;
    container_ref_count -= 1;

    if (container_ref_count == 0 and container_started) {
        forceRemove(allocator, io);
        container_started = false;
    }
}

/// Starts the zenohd Docker container in detached mode.
///
/// Runs: `docker run --name zenoh-test --rm -d -p 7447:7447 eclipse/zenoh:latest`
///
/// If Docker is not available or the container fails to start, returns an error
/// with a descriptive log message.
fn startZenohd(allocator: std.mem.Allocator, io: Io) DockerError!void {
    // First, ensure any leftover container from a previous run is removed.
    // This is best-effort — we ignore errors (container might not exist).
    forceRemove(allocator, io);

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
fn waitForReady(io: Io) DockerError!void {
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

/// Force-remove the Docker container (instant, no grace period).
///
/// Uses `docker rm -f` which sends SIGKILL immediately, avoiding the
/// 10-second SIGTERM grace period of `docker stop`.
///
/// Idempotent — ignores errors if the container doesn't exist.
fn forceRemove(allocator: std.mem.Allocator, io: Io) void {
    const result = process.run(allocator, io, .{
        .argv = &.{ "docker", "rm", "-f", container_name },
        .stderr_limit = Io.Limit.limited(4096),
        .stdout_limit = Io.Limit.limited(4096),
    }) catch {
        std.log.warn("Failed to run 'docker rm -f {s}' (container may already be removed)", .{container_name});
        return;
    };
    allocator.free(result.stdout);
    allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code == 0) {
                std.log.info("zenohd container '{s}' removed successfully", .{container_name});
            }
        },
        else => {},
    }
}

test {
    std.testing.refAllDecls(@This());
}
