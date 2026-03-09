//! Session: Zenoh client session over TCP.
//!
//! Manages the full lifecycle of a Zenoh session: TCP connection, 4-message
//! handshake (InitSyn → InitAck → OpenSyn → OpenAck), steady-state
//! communication, and graceful close.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Atomic = std.atomic.Value;

const transport = @import("transport/messages.zig");
const framing = @import("transport/framing.zig");

const InitSyn = transport.InitSyn;
const InitAck = transport.InitAck;
const OpenSyn = transport.OpenSyn;
const OpenAck = transport.OpenAck;
const Close = transport.Close;
const CloseReason = transport.CloseReason;
const KeepAlive = transport.KeepAlive;
const ZenohId = transport.ZenohId;
const Resolution = transport.Resolution;

/// Default client batch size (matches zenoh-pico).
const default_batch_size: u16 = 2048;

/// Default lease in seconds.
const default_lease: u64 = 10;

/// Default patch level.
const default_patch: u64 = 1;

/// Buffer size for TCP I/O operations.
const io_buffer_size: usize = 4096;

/// Polling interval for interruptible sleep in the keepalive loop (ms).
const keepalive_poll_interval_ms: i64 = 100;

/// Session state.
pub const State = enum {
    /// Not connected.
    disconnected,
    /// TCP connected, handshake not yet complete.
    connecting,
    /// Session established (handshake complete).
    open,
    /// Close message sent, waiting for TCP teardown.
    closing,
    /// Fully closed and cleaned up.
    closed,
};

/// Errors that can occur during session operations.
pub const OpenError = net.IpAddress.ConnectError || SendError || RecvError ||
    Io.Reader.ReadAllocError || error{
    /// The router responded with an unexpected protocol version.
    VersionMismatch,
    /// Expected an Ack but got a Syn, or vice versa.
    UnexpectedMessage,
    /// The handshake message had an unexpected MID.
    InvalidMid,
    /// ZenohId length was invalid.
    InvalidLength,
};

pub const SendError = Io.Writer.Error;

pub const RecvError = Io.Reader.Error || framing.ReadError;

pub const CloseError = SendError || net.ShutdownError;

/// A Zenoh client session.
///
/// Manages TCP connection, handshake, and session lifecycle.
/// Use `open()` to connect and establish a session, `close()` for
/// graceful shutdown, and `deinit()` for resource cleanup without
/// sending a Close message (e.g., after errors).
pub const Session = struct {
    allocator: Allocator,
    io: Io,
    stream: net.Stream,
    state: State,

    /// Our Zenoh ID.
    local_zid: ZenohId,
    /// Remote (router) Zenoh ID, set after handshake.
    remote_zid: ZenohId,
    /// Negotiated resolution parameters.
    resolution: Resolution,
    /// Negotiated batch size.
    batch_size: u16,
    /// Negotiated lease (in seconds if lease_in_seconds is true).
    lease: u64,
    /// Whether lease is in seconds (true) or milliseconds (false).
    lease_in_seconds: bool,
    /// Our transmit sequence number (next SN to use).
    tx_sn: u64,
    /// Remote's initial sequence number.
    rx_sn: u64,

    /// I/O buffers for TCP read/write — allocated on open, freed on deinit.
    read_buf: []u8,
    write_buf: []u8,

    /// Mutex protecting writes to the TCP stream.
    /// Must be held when writing to `stream` (including KeepAlive sends).
    write_mutex: Io.Mutex = Io.Mutex.init,

    /// KeepAlive thread handle, set when keepalive loop is running.
    keepalive_thread: ?Thread = null,
    /// Atomic flag to signal the keepalive thread to stop.
    keepalive_stop: Atomic(bool) = Atomic(bool).init(false),

    /// Timestamp (monotonic, milliseconds) of the last message received.
    /// Updated on every incoming message; used for lease expiration detection.
    last_received_ms: Atomic(i64) = Atomic(i64).init(0),

    /// Open a new session to a Zenoh router at the given address.
    ///
    /// Performs TCP connection and the full 4-message handshake:
    ///   1. Send InitSyn
    ///   2. Receive InitAck
    ///   3. Send OpenSyn (echoing cookie)
    ///   4. Receive OpenAck
    ///
    /// On success, the session is in `State.open` and ready for use.
    pub fn open(allocator: Allocator, io: Io, address: net.IpAddress, local_zid: ZenohId) OpenError!Session {
        // Allocate I/O buffers.
        const read_buf = allocator.alloc(u8, io_buffer_size) catch
            return @as(OpenError, error.SystemResources);
        errdefer allocator.free(read_buf);

        const write_buf = allocator.alloc(u8, io_buffer_size) catch
            return @as(OpenError, error.SystemResources);
        errdefer allocator.free(write_buf);

        // Connect TCP.
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        var session = Session{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .state = .connecting,
            .local_zid = local_zid,
            .remote_zid = .{},
            .resolution = Resolution{},
            .batch_size = default_batch_size,
            .lease = default_lease,
            .lease_in_seconds = true,
            .tx_sn = 0,
            .rx_sn = 0,
            .read_buf = read_buf,
            .write_buf = write_buf,
        };

        try session.performHandshake();

        return session;
    }

    /// Perform the 4-message handshake.
    fn performHandshake(self: *Session) OpenError!void {
        // 1. Send InitSyn
        const init_syn = InitSyn{
            .version = transport.protocol_version,
            .whatami = .client,
            .zid = self.local_zid,
            .resolution = Resolution{},
            .batch_size = default_batch_size,
            .patch = default_patch,
        };
        try self.sendMessage(InitSyn, &init_syn);

        // 2. Receive InitAck
        var frame_buf: [framing.max_frame_size]u8 = undefined;
        const init_ack_bytes = try self.recvFrame(&frame_buf);
        const init_ack = try self.decodeInitAck(init_ack_bytes);
        defer self.allocator.free(init_ack.cookie);

        // Validate version
        if (init_ack.version != transport.protocol_version) {
            return error.VersionMismatch;
        }

        // Store negotiated parameters
        self.remote_zid = init_ack.zid;
        if (init_ack.resolution) |res| {
            self.resolution = res;
        }
        if (init_ack.batch_size) |bs| {
            self.batch_size = bs;
        }

        // 3. Send OpenSyn (echo cookie)
        // Generate a random initial SN bounded by the negotiated frame SN resolution.
        var sn_bytes: [8]u8 = undefined;
        self.io.random(&sn_bytes);
        const sn_mask: u64 = switch (self.resolution.frame_sn) {
            .bits_8 => 0xFF,
            .bits_16 => 0xFFFF,
            .bits_32 => 0xFFFFFFFF,
            .bits_64 => std.math.maxInt(u64),
        };
        self.tx_sn = std.mem.readInt(u64, &sn_bytes, .little) & sn_mask;

        const open_syn = OpenSyn{
            .lease = default_lease,
            .lease_in_seconds = true,
            .initial_sn = self.tx_sn,
            .cookie = init_ack.cookie,
        };
        try self.sendMessage(OpenSyn, &open_syn);

        // 4. Receive OpenAck
        const open_ack_bytes = try self.recvFrame(&frame_buf);
        const open_ack = try self.decodeOpenAck(open_ack_bytes);

        // Store router's lease and initial SN
        self.lease = open_ack.lease;
        self.lease_in_seconds = open_ack.lease_in_seconds;
        self.rx_sn = open_ack.initial_sn;

        self.recordReceived();

        self.state = .open;
    }

    /// Decode an InitAck from raw frame bytes.
    fn decodeInitAck(self: *Session, bytes: []const u8) OpenError!InitAck {
        var reader: Io.Reader = .fixed(bytes);
        const header = reader.takeByte() catch return error.EndOfStream;
        const mid = transport.getMid(header);

        if (mid != transport.MID.init) return error.InvalidMid;
        if (!transport.isAck(header)) return error.UnexpectedMessage;

        return InitAck.decodeAlloc(header, &reader, self.allocator) catch |err| switch (err) {
            error.InvalidLength => return error.InvalidLength,
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
            error.OutOfMemory => return error.SystemResources,
        };
    }

    /// Decode an OpenAck from raw frame bytes.
    fn decodeOpenAck(_: *Session, bytes: []const u8) OpenError!OpenAck {
        var reader: Io.Reader = .fixed(bytes);
        const header = reader.takeByte() catch return error.EndOfStream;
        const mid = transport.getMid(header);

        if (mid != transport.MID.open) return error.InvalidMid;
        if (!transport.isAck(header)) return error.UnexpectedMessage;

        return OpenAck.decode(header, &reader) catch |err| switch (err) {
            error.InvalidLength => return error.InvalidLength,
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
    }

    /// Send a transport message, framed with 2-byte LE length prefix.
    /// Acquires the write mutex to prevent concurrent writes to the TCP stream.
    fn sendMessage(self: *Session, comptime T: type, msg: *const T) SendError!void {
        // Encode message into a scratch buffer (outside mutex — no shared state).
        var msg_buf: [512]u8 = undefined;
        var msg_writer: Io.Writer = .fixed(&msg_buf);
        try msg.encode(&msg_writer);
        const payload = msg_writer.buffered();

        // Acquire write mutex to serialise access to the TCP stream.
        self.write_mutex.lock(self.io) catch return error.WriteFailed;
        defer self.write_mutex.unlock(self.io);

        // Write framed: 2-byte LE length prefix + payload
        var stream_writer = self.stream.writer(self.io, self.write_buf);
        framing.writeFrame(payload, &stream_writer.interface) catch |err| switch (err) {
            error.WriteFailed => return error.WriteFailed,
            error.MessageTooLarge => unreachable, // our messages are well under 64KB
        };
        try stream_writer.interface.flush();
    }

    /// Receive a framed message from the TCP stream.
    /// Returns the payload bytes within `buf`.
    fn recvFrame(self: *Session, buf: []u8) RecvError![]u8 {
        var stream_reader = self.stream.reader(self.io, self.read_buf);
        return framing.readFrame(&stream_reader.interface, buf);
    }

    /// Gracefully close the session.
    ///
    /// Steps:
    ///   1. Send Close message with the given reason
    ///   2. Shut down the TCP connection (send FIN)
    ///   3. Close the TCP stream
    ///   4. Clean up session state
    ///
    /// After close(), the session is in `State.closed` and cannot be reused.
    /// Use `deinit()` to free allocated resources.
    ///
    /// If the session is not in `State.open`, this is a no-op that transitions
    /// directly to `State.closed`.
    pub fn close(self: *Session, reason: CloseReason) CloseError!void {
        self.stopKeepAlive();

        if (self.state != .open and self.state != .connecting) {
            self.state = .closed;
            return;
        }

        self.state = .closing;

        // Send Close message
        const close_msg = Close{
            .session = true,
            .reason = reason,
        };
        self.sendMessage(Close, &close_msg) catch |err| {
            // Even if sending fails, we still close the connection
            self.stream.close(self.io);
            self.state = .closed;
            return err;
        };

        // Graceful TCP shutdown: send FIN
        self.stream.shutdown(self.io, .send) catch |err| {
            // If shutdown fails, just close
            self.stream.close(self.io);
            self.state = .closed;
            return err;
        };

        // Close the TCP stream
        self.stream.close(self.io);
        self.state = .closed;
    }

    /// Clean up session resources without sending a Close message.
    ///
    /// Use this for cleanup after errors, or after `close()` has been called.
    /// Safe to call multiple times.
    pub fn deinit(self: *Session) void {
        self.stopKeepAlive();

        if (self.state != .closed) {
            // Close TCP without sending Close message
            self.stream.close(self.io);
            self.state = .closed;
        }

        // Free I/O buffers
        self.allocator.free(self.read_buf);
        self.allocator.free(self.write_buf);
        self.read_buf = &.{};
        self.write_buf = &.{};
    }

    // ═══════════════════════════════════════════════════════════════════
    // KeepAlive
    // ═══════════════════════════════════════════════════════════════════

    /// Start the periodic KeepAlive loop.
    ///
    /// Spawns a background thread that sends a KeepAlive message every
    /// `lease / 3` and monitors for lease expiration (no incoming message
    /// within the full lease period).
    ///
    /// Call `stopKeepAlive()` (or `close()` / `deinit()`) to stop it.
    pub fn startKeepAlive(self: *Session) Thread.SpawnError!void {
        if (self.keepalive_thread != null) return; // already running
        self.keepalive_stop.store(false, .release);
        // Ensure last_received is set to now so the first lease check
        // doesn't falsely expire.
        self.recordReceived();
        self.keepalive_thread = try Thread.spawn(.{}, keepAliveLoop, .{self});
    }

    /// Stop the periodic KeepAlive loop.
    ///
    /// Signals the keepalive thread to exit and waits for it to finish.
    /// Safe to call even if keepalive is not running.
    pub fn stopKeepAlive(self: *Session) void {
        self.keepalive_stop.store(true, .release);
        if (self.keepalive_thread) |thread| {
            thread.join();
            self.keepalive_thread = null;
        }
    }

    /// Return the negotiated lease duration in milliseconds.
    pub fn leaseMillis(self: *const Session) u64 {
        if (self.lease_in_seconds) {
            return self.lease * 1000;
        } else {
            return self.lease;
        }
    }

    /// Record the current monotonic time as the last-received timestamp.
    /// Should be called whenever a message is received from the remote.
    pub fn recordReceived(self: *Session) void {
        const now_ms = Io.Timestamp.now(self.io, .awake).toMilliseconds();
        self.last_received_ms.store(now_ms, .release);
    }

    /// Check whether the remote lease has expired.
    /// Returns true if the time since the last received message exceeds
    /// the negotiated lease duration.
    pub fn isLeaseExpired(self: *Session) bool {
        const last_ms = self.last_received_ms.load(.acquire);
        if (last_ms == 0) return false; // no timestamp recorded yet
        const now_ms = Io.Timestamp.now(self.io, .awake).toMilliseconds();
        const elapsed_ms = now_ms - last_ms;
        return elapsed_ms >= @as(i64, @intCast(self.leaseMillis()));
    }

    /// Background thread: sends KeepAlive at lease/3 intervals.
    ///
    /// NOTE: Lease expiration detection is not performed here because there
    /// is no receive loop to update `last_received_ms`. It will be enabled
    /// once incoming message handling is implemented.
    fn keepAliveLoop(self: *Session) void {
        const lease_third = self.leaseMillis() / 3;
        // Floor at 100ms to prevent a tight spin if lease is very small or zero.
        const interval_ms: i64 = @intCast(@max(lease_third, 100));

        while (!self.keepalive_stop.load(.acquire)) {
            if (!self.sleepInterruptible(interval_ms)) return;

            if (self.keepalive_stop.load(.acquire)) return;

            self.sendKeepAlive() catch {
                // Write failed — connection likely dead.
                return;
            };
        }
    }

    /// Sleep for `total_ms` milliseconds, checking the stop flag every
    /// `keepalive_poll_interval_ms`.  Returns false if interrupted (stop
    /// requested or sleep error).
    fn sleepInterruptible(self: *Session, total_ms: i64) bool {
        var remaining: i64 = total_ms;
        while (remaining > 0) {
            if (self.keepalive_stop.load(.acquire)) return false;
            const chunk = @min(remaining, keepalive_poll_interval_ms);
            Io.sleep(self.io, Io.Duration.fromMilliseconds(chunk), .awake) catch return false;
            remaining -= chunk;
        }
        return true;
    }

    /// Encode and send a single KeepAlive message on the wire.
    fn sendKeepAlive(self: *Session) SendError!void {
        const ka = KeepAlive{};
        try self.sendMessage(KeepAlive, &ka);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;
const assertEqualBytes = @import("testing.zig").assertEqualBytes;

// ---------------------------------------------------------------------------
// Close wire-bytes unit tests
// ---------------------------------------------------------------------------

test "Session close: Close message wire bytes for session close with generic reason" {
    const close_msg = Close{ .session = true, .reason = .generic };
    var buf: [8]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try close_msg.encode(&writer);
    const encoded = writer.buffered();
    // MID=0x03, S=1 → header=0x23, reason=0x00
    try assertEqualBytes(&.{ 0x23, 0x00 }, encoded);
}

test "Session close: Close message wire bytes for session close with unsupported reason" {
    const close_msg = Close{ .session = true, .reason = .unsupported };
    var buf: [8]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try close_msg.encode(&writer);
    const encoded = writer.buffered();
    try assertEqualBytes(&.{ 0x23, 0x01 }, encoded);
}

test "Session close: Close message wire bytes for session close with invalid reason" {
    const close_msg = Close{ .session = true, .reason = .invalid };
    var buf: [8]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try close_msg.encode(&writer);
    const encoded = writer.buffered();
    try assertEqualBytes(&.{ 0x23, 0x02 }, encoded);
}

test "Session close: Close message framed wire bytes (with 2-byte length prefix)" {
    // The Close message on the wire with TCP framing should be:
    // [0x02, 0x00] (length=2 LE) + [0x23, 0x00] (Close S=1, reason=generic)
    const close_msg = Close{ .session = true, .reason = .generic };
    var msg_buf: [8]u8 = undefined;
    var msg_writer: Io.Writer = .fixed(&msg_buf);
    try close_msg.encode(&msg_writer);
    const payload = msg_writer.buffered();

    var frame_buf: [16]u8 = undefined;
    var frame_writer: Io.Writer = .fixed(&frame_buf);
    try framing.writeFrame(payload, &frame_writer);
    const framed = frame_writer.buffered();

    try assertEqualBytes(&.{ 0x02, 0x00, 0x23, 0x00 }, framed);
}

test "Session close: Close with different reason codes produce correct wire bytes" {
    const reasons = [_]struct { reason: CloseReason, expected_byte: u8 }{
        .{ .reason = .generic, .expected_byte = 0x00 },
        .{ .reason = .unsupported, .expected_byte = 0x01 },
        .{ .reason = .invalid, .expected_byte = 0x02 },
        .{ .reason = @enumFromInt(0x42), .expected_byte = 0x42 },
        .{ .reason = @enumFromInt(0xFF), .expected_byte = 0xFF },
    };

    for (reasons) |r| {
        const close_msg = Close{ .session = true, .reason = r.reason };
        var buf: [8]u8 = undefined;
        var writer: Io.Writer = .fixed(&buf);
        try close_msg.encode(&writer);
        const encoded = writer.buffered();
        try testing.expectEqual(@as(usize, 2), encoded.len);
        try testing.expectEqual(@as(u8, 0x23), encoded[0]); // header: MID=0x03 | S=0x20
        try testing.expectEqual(r.expected_byte, encoded[1]);
    }
}

// ---------------------------------------------------------------------------
// State transition tests
// ---------------------------------------------------------------------------

test "Session State: all states are distinct" {
    const states = [_]State{ .disconnected, .connecting, .open, .closing, .closed };
    for (states, 0..) |s1, i| {
        for (states, 0..) |s2, j| {
            if (i == j) {
                try testing.expectEqual(s1, s2);
            } else {
                try testing.expect(s1 != s2);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KeepAlive wire-bytes unit tests
// ---------------------------------------------------------------------------

test "KeepAlive: wire bytes through sendKeepAlive encoding" {
    // Verify KeepAlive encodes to a single 0x04 byte
    const ka = KeepAlive{};
    var buf: [8]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try ka.encode(&writer);
    const encoded = writer.buffered();
    try assertEqualBytes(&.{0x04}, encoded);
}

test "KeepAlive: framed wire bytes (with 2-byte length prefix)" {
    // On the wire: [0x01, 0x00] (length=1 LE) + [0x04] (KeepAlive)
    const ka = KeepAlive{};
    var msg_buf: [8]u8 = undefined;
    var msg_writer: Io.Writer = .fixed(&msg_buf);
    try ka.encode(&msg_writer);
    const payload = msg_writer.buffered();

    var frame_buf: [16]u8 = undefined;
    var frame_writer: Io.Writer = .fixed(&frame_buf);
    try framing.writeFrame(payload, &frame_writer);
    const framed = frame_writer.buffered();

    try assertEqualBytes(&.{ 0x01, 0x00, 0x04 }, framed);
}

test {
    testing.refAllDecls(@This());
}
