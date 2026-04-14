//! Docker lifecycle helpers for integration tests.
//!
//! Manages a `zenoh-test` Docker container running `eclipse/zenoh:latest`,
//! providing start and wait-for-ready operations.
//!
//! The container is started once (on the first test that needs it) and
//! kept running for the entire test suite.  If zenohd is already
//! reachable (e.g. started manually), Docker management is skipped.
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
/// Extra delay after first successful TCP connect, to allow zenohd
/// to fully initialize its protocol handler.  TCP accept can succeed
/// before the application layer is ready to perform the Zenoh handshake.
const post_ready_delay_ms: i64 = 1000;

pub const DockerError = error{
    DockerNotAvailable,
    ContainerStartFailed,
    ReadyTimeout,
};

/// Lifecycle state for the shared Docker container.
const ContainerState = enum {
    /// No container has been started yet.
    not_started,
    /// A task is currently starting the container (used to serialize
    /// concurrent acquires in an event-loop environment).
    starting,
    /// Container is running and ready for connections.
    ready,
    /// Docker is not available; tests should skip.
    unavailable,
};

/// Module-level state for the shared Docker container.
/// Uses a state machine instead of ref-counting to ensure the container
/// is started exactly once and never torn down during the test suite.
var container_state: ContainerState = .not_started;

/// Acquires a reference to the zenohd Docker container.
///
/// On the first call, either detects an already-running container
/// (e.g., started manually) or starts one via Docker.  Subsequent
/// calls return immediately.
///
/// Returns `true` if zenohd is available, `false` if Docker is not
/// available (tests should skip in that case).
pub fn acquireZenohd(allocator: std.mem.Allocator, io: Io) DockerError!bool {
    switch (container_state) {
        .ready => return true,
        .unavailable => return false,
        .starting => {
            // Another task is currently starting the container.
            // Wait for it to finish (handles event-loop concurrency
            // where I/O yield points can interleave tasks).
            while (container_state == .starting) {
                Io.sleep(io, Io.Duration.fromMilliseconds(poll_interval_ms), .awake) catch {};
            }
            return container_state == .ready;
        },
        .not_started => {},
    }

    // Transition to .starting before any I/O (yield point) to prevent
    // other tasks from also entering the startup path.
    container_state = .starting;

    // Check if zenohd is already running (e.g. started manually).
    if (isPortReachable(io)) {
        std.log.info("zenohd already reachable on port {d}; skipping Docker start", .{zenoh_port});
        container_state = .ready;
        return true;
    }

    // Not running — try to start via Docker.
    startZenohd(allocator, io) catch |err| {
        switch (err) {
            error.DockerNotAvailable => {
                container_state = .unavailable;
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
            else => {
                container_state = .not_started;
                return err;
            },
        }
    };

    waitForReady(io) catch |err| {
        forceRemove(allocator, io);
        container_state = .not_started;
        return err;
    };

    container_state = .ready;
    return true;
}


/// Starts the zenohd Docker container in detached mode.
///
/// Runs: `docker run --name zenoh-test --rm -d -p 7447:7447 eclipse/zenoh:latest`
///
/// Any leftover container from a previous (crashed) run is force-removed first.
fn startZenohd(allocator: std.mem.Allocator, io: Io) DockerError!void {
    // Remove any leftover container from a previous (crashed) run.
    forceRemove(allocator, io);

    const result = process.run(allocator, io, .{
        .argv = &.{
            "docker", "run",
            "--name", container_name,
            "--rm",
            "-d",
            "-p", "7447:7447",
            docker_image,
            "--cfg=plugins/storage_manager/storages/demo:{key_expr:\"demo/**\",volume:{id:\"memory\"}}",
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

/// Check whether port 7447 is currently accepting TCP connections.
fn isPortReachable(io: Io) bool {
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(zenoh_port) };
    if (address.connect(io, .{ .mode = .stream })) |stream| {
        stream.close(io);
        return true;
    } else |_| {
        return false;
    }
}

/// Polls TCP port 7447 on localhost until a connection succeeds or timeout.
///
/// After the first successful TCP connection, waits an additional
/// `post_ready_delay_ms` for zenohd to fully initialize its protocol
/// handler (TCP accept can succeed before the application layer is ready).
fn waitForReady(io: Io) DockerError!void {
    const max_attempts: usize = @intCast(@divTrunc(ready_timeout_s * 1000, poll_interval_ms));
    const address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(zenoh_port) };

    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        if (address.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
            std.log.info("zenohd is ready on port {d} (after {d} attempts)", .{ zenoh_port, attempt + 1 });
            // Brief extra wait for the protocol handler to initialize.
            Io.sleep(io, Io.Duration.fromMilliseconds(post_ready_delay_ms), .awake) catch {};
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
