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
const Frame = transport.Frame;

const network = @import("network/messages.zig");
const Push = network.Push;
const Request = network.Request;
const Response = network.Response;
const ResponseFinal = network.ResponseFinal;
const Interest = network.Interest;
const Declare = network.Declare;
const DeclareFinal = network.DeclareFinal;

const zenoh_msgs = @import("zenoh/messages.zig");
const ZPut = zenoh_msgs.Put;
const ZQuery = zenoh_msgs.Query;
const ZReply = zenoh_msgs.Reply;
const ZErr = zenoh_msgs.Err;
const hdr = @import("codec/header.zig");

/// Buffer size for TCP I/O operations.
const io_buffer_size: usize = 4096;

/// Polling interval for interruptible sleep in the keepalive loop (ms).
const keepalive_poll_interval_ms: i64 = 100;

/// Configuration for establishing a Zenoh session.
///
/// Provides all client-side parameters used during the 4-message handshake
/// (InitSyn/OpenSyn). Negotiated values may differ from these after the
/// router responds with InitAck/OpenAck.
pub const SessionConfig = struct {
    /// Local Zenoh ID for this client.
    zid: ZenohId,
    /// Desired batch size (may be lowered by router during negotiation).
    batch_size: u16 = 2048,
    /// Desired lease duration in seconds (router may negotiate a different value).
    lease: u64 = 10,
    /// Node role for this endpoint.
    whatami: transport.WhatAmI = .client,
    /// Protocol patch level.
    patch: u64 = 1,
    /// Initial resolution proposal. If null, defaults are used.
    resolution: ?Resolution = null,
};

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

pub const PutError = framing.WriteError || error{SessionNotOpen};

pub const GetError = framing.WriteError || framing.ReadError ||
    error{ SessionNotOpen, OutOfMemory };

/// Options for `Session.put()`.
pub const PutOptions = struct {
    /// Optional encoding for the payload.
    encoding: ?zenoh_msgs.Encoding = null,
};

/// Options for `Session.get()`.
pub const GetOptions = struct {
    /// Optional consolidation mode.
    consolidation: ?u8 = null,
    /// Optional selector parameters.
    parameters: ?[]const u8 = null,
};

/// A single reply received from a `get()` query.
pub const GetReply = struct {
    /// Key expression of the reply (may be null if no suffix in Response).
    key: ?[]u8 = null,
    /// Payload bytes.
    payload: []u8,
    /// Encoding ID of the payload.
    encoding_id: u16 = 0,

    /// Free the memory owned by this reply.
    pub fn deinit(self: *const GetReply, allocator: Allocator) void {
        if (self.key) |k| allocator.free(k);
        allocator.free(self.payload);
    }
};

/// Result of a `Session.get()` query.
pub const GetResult = struct {
    /// All replies received before the ResponseFinal.
    replies: []GetReply,

    /// Free all replies and the result itself.
    pub fn deinit(self: *const GetResult, allocator: Allocator) void {
        for (self.replies) |*r| r.deinit(allocator);
        allocator.free(self.replies);
    }
};

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

    /// Session configuration (client-side parameters).
    config: SessionConfig,

    /// Our Zenoh ID (copied from config.zid at creation time).
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
    /// Next unique request ID for get() operations.
    next_request_id: u64 = 1,

    /// I/O buffers for TCP read/write — allocated on open, freed on deinit.
    read_buf: []u8,
    write_buf: []u8,

    /// Persistent stream reader — preserves buffer state across calls.
    /// Created once during connect, reused for all reads.
    stream_reader: net.Stream.Reader,

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
    /// The `config` parameter provides client-side settings; negotiated
    /// values (from the router's responses) are stored in the session.
    pub fn connect(allocator: Allocator, io: Io, address: net.IpAddress, config: SessionConfig) OpenError!Session {
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
            .config = config,
            .local_zid = config.zid,
            .remote_zid = .{},
            .resolution = config.resolution orelse Resolution{},
            .batch_size = config.batch_size,
            .lease = config.lease,
            .lease_in_seconds = true,
            .tx_sn = 0,
            .rx_sn = 0,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .stream_reader = stream.reader(io, read_buf),
        };

        try session.performHandshake();
        try session.performInterestDeclare();

        return session;
    }

    /// Open a new session to a Zenoh router (convenience wrapper).
    ///
    /// Creates a `SessionConfig` with the given `local_zid` and default
    /// parameters, then calls `connect()`.
    pub fn open(allocator: Allocator, io: Io, address: net.IpAddress, local_zid: ZenohId) OpenError!Session {
        return connect(allocator, io, address, .{ .zid = local_zid });
    }

    /// Perform the 4-message handshake.
    fn performHandshake(self: *Session) OpenError!void {
        // 1. Send InitSyn
        const init_syn = InitSyn{
            .version = transport.protocol_version,
            .whatami = self.config.whatami,
            .zid = self.config.zid,
            .resolution = self.config.resolution orelse Resolution{},
            .batch_size = self.config.batch_size,
            .patch = self.config.patch,
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
            self.batch_size = @min(bs, self.config.batch_size);
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
            .lease = self.config.lease,
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

    /// Perform the Interest/Declare exchange after handshake.
    ///
    /// After the 4-message handshake, the router sends an Interest asking
    /// the client to declare its resources. We respond with a single
    /// Declare(DeclareFinal) — "I have nothing to declare" — and then
    /// drain the router's own declarations until we see its DeclareFinal.
    ///
    /// This exchange must complete before the router will route any data
    /// (Push/Request) for this session.
    ///
    /// If the router does not send an Interest (e.g., older routers at
    /// patch level ≤ 1), the method returns successfully without performing
    /// the exchange. In this case, data routing may still work depending
    /// on the router version.
    fn performInterestDeclare(self: *Session) OpenError!void {
        var frame_buf: [framing.max_frame_size]u8 = undefined;
        var interest_responded = false;

        while (true) {
            const payload = self.recvFrame(&frame_buf) catch |err| switch (err) {
                error.EndOfStream => {
                    // Connection closed before we could complete the exchange.
                    // If we haven't seen Interest, the exchange may not be
                    // needed. Return OK so the caller can proceed.
                    if (!interest_responded) return;
                    // If we responded to Interest but didn't see DeclareFinal,
                    // the session may be in an inconsistent state.
                    self.state = .closed;
                    return error.EndOfStream;
                },
                else => return @as(OpenError, err),
            };
            self.recordReceived();

            if (payload.len == 0) continue;

            var reader: Io.Reader = .fixed(payload);

            // Parse the transport header.
            const transport_hdr_byte = reader.takeByte() catch continue;
            const transport_mid = hdr.Header.decode(transport_hdr_byte).mid;

            // KeepAlive — if we haven't seen Interest yet, the router is
            // not going to send one (Interest would arrive before KeepAlive
            // in the protocol flow). Skip the exchange.
            if (transport_mid == transport.MID.keep_alive) {
                if (!interest_responded) return;
                continue;
            }

            // Close — the router is terminating the session.
            if (transport_mid == transport.MID.close) {
                self.state = .closed;
                return error.UnexpectedMessage;
            }

            // Only process Frame messages from here.
            if (transport_mid != transport.MID.frame) continue;

            // Decode Frame header (consume SN).
            _ = Frame.decodeHeader(transport_hdr_byte, &reader) catch continue;

            // Parse the network message header.
            const net_hdr_byte = reader.takeByte() catch continue;
            const net_mid = hdr.Header.decode(net_hdr_byte).mid;

            if (net_mid == network.MID.interest) {
                // Decode Interest to extract the id.
                const interest = try Interest.decode(net_hdr_byte, &reader, self.allocator);
                defer interest.deinit(self.allocator);

                // Respond with Frame → Declare(I=1, interest_id) → DeclareFinal.
                try self.sendDeclareResponse(interest.id);
                interest_responded = true;
                continue;
            }

            if (net_mid == network.MID.declare) {
                // Parse Declare header (consume interest_id if present).
                _ = Declare.decodeHeader(net_hdr_byte, &reader) catch continue;

                // Parse the inner declaration sub-message.
                const decl_hdr_byte = reader.takeByte() catch continue;
                const decl_mid = hdr.Header.decode(decl_hdr_byte).mid;

                if (decl_mid == network.DeclareMID.declare_final) {
                    // Router's DeclareFinal — exchange is complete
                    // (only if we've already responded to the Interest).
                    if (interest_responded) break;
                }
                // Other declarations (DeclareSubscriber, etc.) — skip.
                continue;
            }

            // Other network messages — skip. If we haven't seen Interest
            // yet and we're getting unexpected messages, don't loop forever.
            if (!interest_responded) return;
        }
    }

    /// Send a Declare(DeclareFinal) response for the given interest_id.
    ///
    /// Assembles and sends: Frame(reliable, sn) → Declare(I=1, interest_id) → DeclareFinal
    fn sendDeclareResponse(self: *Session, interest_id: u64) SendError!void {
        var msg_buf: [512]u8 = undefined;
        const assembled = encodeDeclareResponse(self.nextSn(), interest_id, &msg_buf) catch
            unreachable; // 512 bytes is more than enough for this message

        // Send framed (with 2-byte LE length prefix).
        self.write_mutex.lock(self.io) catch return error.WriteFailed;
        defer self.write_mutex.unlock(self.io);

        var stream_writer = self.stream.writer(self.io, self.write_buf);
        framing.writeFrame(assembled, &stream_writer.interface) catch |err| switch (err) {
            error.WriteFailed => return error.WriteFailed,
            error.MessageTooLarge => unreachable, // our message is well under 64KB
        };
        try stream_writer.interface.flush();
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
    /// Uses the persistent stream reader to preserve buffer state.
    fn recvFrame(self: *Session, buf: []u8) RecvError![]u8 {
        return framing.readFrame(&self.stream_reader.interface, buf);
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

    // ═══════════════════════════════════════════════════════════════════
    // Sequence Number Management
    // ═══════════════════════════════════════════════════════════════════

    /// Return the current transmit sequence number and advance it,
    /// wrapping according to the negotiated frame SN resolution.
    fn nextSn(self: *Session) u64 {
        const sn = self.tx_sn;
        const sn_mask: u64 = switch (self.resolution.frame_sn) {
            .bits_8 => 0xFF,
            .bits_16 => 0xFFFF,
            .bits_32 => 0xFFFFFFFF,
            .bits_64 => std.math.maxInt(u64),
        };
        self.tx_sn = (self.tx_sn +% 1) & sn_mask;
        return sn;
    }

    /// Return the next unique request ID and advance.
    fn nextRequestId(self: *Session) u64 {
        const rid = self.next_request_id;
        self.next_request_id +%= 1;
        return rid;
    }

    // ═══════════════════════════════════════════════════════════════════
    // High-level API: put
    // ═══════════════════════════════════════════════════════════════════

    /// Publish a value to the given key expression.
    ///
    /// Assembles and sends a Frame(reliable) → Push(key) → Put(payload)
    /// message on the wire. The sequence number is auto-incremented.
    ///
    /// Example wire sequence:
    /// ```
    ///   Frame:  header=0x25 (reliable), sn=<VLE>
    ///     Push: header=0x3D (N=1, M=0), scope=0x00, suffix=key
    ///       Put: header=0x01, payload=<payload bytes>
    /// ```
    pub fn put(self: *Session, key: []const u8, payload: []const u8, opts: PutOptions) PutError!void {
        if (self.state != .open) return error.SessionNotOpen;

        // Assemble the composite message into a scratch buffer.
        var msg_buf: [framing.max_frame_size]u8 = undefined;
        var writer: Io.Writer = .fixed(&msg_buf);

        // 1. Frame header (reliable, next SN)
        const frame = Frame{ .reliable = true, .seq_num = self.nextSn() };
        try frame.encodeHeader(&writer);

        // 2. Push header (scope=0, suffix=key)
        const push = Push{
            .key_scope = 0,
            .key_suffix = key,
        };
        try push.encodeHeader(&writer);

        // 3. Put message (optional encoding + payload)
        const put_msg = ZPut{
            .encoding = opts.encoding,
            .timestamp = null,
            .payload = payload,
        };
        try put_msg.encode(&writer);

        const assembled = writer.buffered();

        // Send framed (with 2-byte LE length prefix).
        self.write_mutex.lock(self.io) catch return error.WriteFailed;
        defer self.write_mutex.unlock(self.io);

        var stream_writer = self.stream.writer(self.io, self.write_buf);
        framing.writeFrame(assembled, &stream_writer.interface) catch |err| switch (err) {
            error.WriteFailed => return error.WriteFailed,
            error.MessageTooLarge => return error.MessageTooLarge,
        };
        try stream_writer.interface.flush();
    }

    // ═══════════════════════════════════════════════════════════════════
    // High-level API: get
    // ═══════════════════════════════════════════════════════════════════

    /// Query a value from the given key expression.
    ///
    /// Sends Frame(reliable) → Request(Query) and waits for
    /// Frame → Response(Reply(Put)) followed by Frame → ResponseFinal.
    ///
    /// Returns a `GetResult` containing all received replies.
    /// The caller owns the result and must call `result.deinit(allocator)`.
    pub fn get(self: *Session, key: []const u8, opts: GetOptions) GetError!GetResult {
        if (self.state != .open) return error.SessionNotOpen;

        const request_id = self.nextRequestId();

        // Assemble the outgoing Request(Query) message.
        {
            var msg_buf: [framing.max_frame_size]u8 = undefined;
            var writer: Io.Writer = .fixed(&msg_buf);

            // 1. Frame header (reliable, next SN)
            const frame = Frame{ .reliable = true, .seq_num = self.nextSn() };
            try frame.encodeHeader(&writer);

            // 2. Request header
            const request = Request{
                .request_id = request_id,
                .key_scope = 0,
                .key_suffix = key,
            };
            try request.encodeHeader(&writer);

            // 3. Query message
            const query = ZQuery{
                .consolidation = opts.consolidation,
                .parameters = opts.parameters,
            };
            try query.encode(&writer);

            const assembled = writer.buffered();

            // Send framed.
            self.write_mutex.lock(self.io) catch return error.WriteFailed;
            defer self.write_mutex.unlock(self.io);

            var stream_writer = self.stream.writer(self.io, self.write_buf);
            framing.writeFrame(assembled, &stream_writer.interface) catch |err| switch (err) {
                error.WriteFailed => return error.WriteFailed,
                error.MessageTooLarge => return error.MessageTooLarge,
            };
            try stream_writer.interface.flush();
        }

        // Receive loop: read frames until ResponseFinal with matching request_id.
        var replies = std.ArrayList(GetReply).empty;
        errdefer {
            for (replies.items) |*r| r.deinit(self.allocator);
            replies.deinit(self.allocator);
        }

        var frame_buf: [framing.max_frame_size]u8 = undefined;
        while (true) {
            const payload = framing.readFrame(&self.stream_reader.interface, &frame_buf) catch |err| switch (err) {
                error.EndOfStream => {
                    // Connection closed before ResponseFinal — return whatever
                    // replies we have collected so far.  This can happen when
                    // the router doesn't support the query or closes the
                    // session for another reason.
                    self.state = .closed;
                    break;
                },
                else => return error.ReadFailed,
            };
            self.recordReceived();

            if (payload.len == 0) continue;

            var reader: Io.Reader = .fixed(payload);

            // Parse the transport Frame header.
            const frame_hdr_byte = reader.takeByte() catch continue;
            const frame_mid = hdr.Header.decode(frame_hdr_byte).mid;

            // Skip KeepAlive messages.
            if (frame_mid == transport.MID.keep_alive) continue;

            // Handle Close messages — the router is terminating the session.
            if (frame_mid == transport.MID.close) {
                self.state = .closed;
                break;
            }

            if (frame_mid != transport.MID.frame) continue;

            _ = Frame.decodeHeader(frame_hdr_byte, &reader) catch continue;

            // Parse the network message header.
            const net_hdr_byte = reader.takeByte() catch continue;
            const net_mid = hdr.Header.decode(net_hdr_byte).mid;

            if (net_mid == network.MID.response_final) {
                // ResponseFinal — end of replies.
                const resp_final = ResponseFinal.decode(net_hdr_byte, &reader) catch continue;
                if (resp_final.request_id == request_id) break;
                // Not for our request — keep reading.
                continue;
            }

            if (net_mid == network.MID.response) {
                // Response — contains a Reply(Put) or Reply(Del) or Err.
                const resp = Response.decodeHeader(net_hdr_byte, &reader, self.allocator) catch continue;
                defer resp.deinit(self.allocator);

                if (resp.request_id != request_id) continue;

                // Parse the inner Zenoh message (Reply or Err).
                const zenoh_hdr_byte = reader.takeByte() catch continue;
                const zenoh_mid = hdr.Header.decode(zenoh_hdr_byte).mid;

                if (zenoh_mid == zenoh_msgs.MID.reply) {
                    const reply = ZReply.decode(zenoh_hdr_byte, &reader, self.allocator) catch continue;

                    switch (reply.body) {
                        .put => |p| {
                            // Copy key suffix if present.
                            var reply_key: ?[]u8 = null;
                            if (resp.key_suffix) |ks| {
                                reply_key = self.allocator.dupe(u8, ks) catch {
                                    reply.deinit(self.allocator);
                                    return error.OutOfMemory;
                                };
                            }

                            // Transfer ownership of payload from the decoded Put.
                            const get_reply = GetReply{
                                .key = reply_key,
                                .payload = self.allocator.dupe(u8, p.payload) catch {
                                    if (reply_key) |k| self.allocator.free(k);
                                    reply.deinit(self.allocator);
                                    return error.OutOfMemory;
                                },
                                .encoding_id = if (p.encoding) |enc| enc.id else 0,
                            };
                            // Free the decoded reply (we've copied what we need).
                            reply.deinit(self.allocator);

                            replies.append(self.allocator, get_reply) catch {
                                get_reply.deinit(self.allocator);
                                return error.OutOfMemory;
                            };
                        },
                        .del => {
                            reply.deinit(self.allocator);
                        },
                    }
                } else if (zenoh_mid == zenoh_msgs.MID.err) {
                    // Err reply — skip for now (could be stored in result).
                    const err_msg = ZErr.decode(zenoh_hdr_byte, &reader, self.allocator) catch continue;
                    err_msg.deinit(self.allocator);
                }
                continue;
            }

            // Unknown network message — skip.
        }

        return GetResult{
            .replies = try replies.toOwnedSlice(self.allocator),
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // Wire encoding helpers (for unit testing)
    // ═══════════════════════════════════════════════════════════════════

    /// Encode a put message into a buffer (without TCP framing).
    /// Returns the assembled Frame → Push → Put bytes.
    /// This is exposed for unit testing of wire format.
    pub fn encodePutMessage(
        sn: u64,
        key: []const u8,
        payload: []const u8,
        opts: PutOptions,
        buf: []u8,
    ) Io.Writer.Error![]const u8 {
        var writer: Io.Writer = .fixed(buf);

        const frame = Frame{ .reliable = true, .seq_num = sn };
        try frame.encodeHeader(&writer);

        const push = Push{ .key_scope = 0, .key_suffix = key };
        try push.encodeHeader(&writer);

        const put_msg = ZPut{
            .encoding = opts.encoding,
            .timestamp = null,
            .payload = payload,
        };
        try put_msg.encode(&writer);

        return writer.buffered();
    }

    /// Encode a get request message into a buffer (without TCP framing).
    /// Returns the assembled Frame → Request → Query bytes.
    /// This is exposed for unit testing of wire format.
    pub fn encodeGetMessage(
        sn: u64,
        request_id: u64,
        key: []const u8,
        opts: GetOptions,
        buf: []u8,
    ) Io.Writer.Error![]const u8 {
        var writer: Io.Writer = .fixed(buf);

        const frame = Frame{ .reliable = true, .seq_num = sn };
        try frame.encodeHeader(&writer);

        const request = Request{
            .request_id = request_id,
            .key_scope = 0,
            .key_suffix = key,
        };
        try request.encodeHeader(&writer);

        const query = ZQuery{
            .consolidation = opts.consolidation,
            .parameters = opts.parameters,
        };
        try query.encode(&writer);

        return writer.buffered();
    }

    /// Encode a Declare(DeclareFinal) response into a buffer (without TCP framing).
    /// Returns the assembled Frame → Declare(I=1, interest_id) → DeclareFinal bytes.
    /// This is exposed for unit testing of wire format.
    pub fn encodeDeclareResponse(
        sn: u64,
        interest_id: u64,
        buf: []u8,
    ) Io.Writer.Error![]const u8 {
        var writer: Io.Writer = .fixed(buf);

        const frame = Frame{ .reliable = true, .seq_num = sn };
        try frame.encodeHeader(&writer);

        const declare = Declare{ .interest_id = interest_id };
        try declare.encodeHeader(&writer);

        const declare_final = DeclareFinal{};
        try declare_final.encode(&writer);

        return writer.buffered();
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

// ---------------------------------------------------------------------------
// SessionConfig tests
// ---------------------------------------------------------------------------

test "SessionConfig: default values" {
    const zid = try ZenohId.init(&.{0x01});
    const config = SessionConfig{ .zid = zid };
    try testing.expectEqual(@as(u16, 2048), config.batch_size);
    try testing.expectEqual(@as(u64, 10), config.lease);
    try testing.expectEqual(transport.WhatAmI.client, config.whatami);
    try testing.expectEqual(@as(u64, 1), config.patch);
    try testing.expectEqual(@as(?Resolution, null), config.resolution);
}

test "SessionConfig: custom values" {
    const zid = try ZenohId.init(&.{ 0x01, 0x02 });
    const config = SessionConfig{
        .zid = zid,
        .batch_size = 4096,
        .lease = 30,
        .whatami = .peer,
        .patch = 2,
        .resolution = Resolution{ .frame_sn = .bits_16 },
    };
    try testing.expectEqual(@as(u16, 4096), config.batch_size);
    try testing.expectEqual(@as(u64, 30), config.lease);
    try testing.expectEqual(transport.WhatAmI.peer, config.whatami);
    try testing.expectEqual(@as(u64, 2), config.patch);
    try testing.expect(config.resolution != null);
}

// ---------------------------------------------------------------------------
// Handshake decode error tests (version mismatch, unexpected message, etc.)
// ---------------------------------------------------------------------------

test "InitAck: encode/decode round-trip preserves wrong version for detection" {
    // Construct an InitAck with a wrong version (0x08 instead of 0x09).
    // Verify that after encode/decode the version field is preserved,
    // which is how performHandshake detects a version mismatch.
    const router_zid = try ZenohId.init(&.{0xAA});
    const cookie = [_]u8{ 0x01, 0x02 };
    const init_ack = InitAck{
        .version = 0x08, // wrong version
        .whatami = .router,
        .zid = router_zid,
        .cookie = &cookie,
    };
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try init_ack.encode(&writer);
    const encoded = writer.buffered();

    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const mid = transport.getMid(header);
    try testing.expectEqual(@as(u5, transport.MID.init), mid);
    try testing.expect(transport.isAck(header));

    const decoded = try InitAck.decodeAlloc(header, &reader, testing.allocator);
    defer testing.allocator.free(decoded.cookie);

    // The decoded version should differ from the protocol version,
    // which performHandshake would reject as VersionMismatch.
    try testing.expectEqual(@as(u8, 0x08), decoded.version);
    try testing.expect(decoded.version != transport.protocol_version);
}

test "Close vs InitAck: MID distinguishes Close from Init" {
    // Encode a Close message and verify its MID differs from Init,
    // which is how decodeInitAck detects receiving the wrong message type.
    const close_msg = Close{ .session = true, .reason = .generic };
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try close_msg.encode(&writer);
    const encoded = writer.buffered();

    // Try to decode as InitAck — should detect wrong MID.
    var reader: Io.Reader = .fixed(encoded);
    const header = try reader.takeByte();
    const mid = transport.getMid(header);

    // MID should be Close (0x03), not Init (0x01).
    // decodeInitAck would return InvalidMid for this header.
    try testing.expectEqual(@as(u5, transport.MID.close), mid);
    try testing.expect(mid != transport.MID.init);
}

test "OpenSyn: Ack flag is not set (distinguishes Syn from Ack)" {
    // Encode an OpenSyn and verify the A flag is clear,
    // which is how decodeOpenAck detects receiving a Syn instead of an Ack.
    const cookie = [_]u8{ 0x01, 0x02 };
    const open_syn = OpenSyn{
        .lease = 10,
        .lease_in_seconds = true,
        .initial_sn = 0,
        .cookie = &cookie,
    };
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try open_syn.encode(&writer);
    const encoded = writer.buffered();

    // A flag must not be set (it's a Syn, not an Ack).
    // decodeOpenAck would return UnexpectedMessage for this header.
    try testing.expect(!transport.isAck(encoded[0]));
    // But MID is correct (Open)
    try testing.expectEqual(@as(u5, transport.MID.open), transport.getMid(encoded[0]));
}

// ---------------------------------------------------------------------------
// z_put wire-bytes unit tests
// ---------------------------------------------------------------------------

test "z_put: assembled wire bytes for 'Hello World!' to 'demo/example/hello' (sn=0)" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodePutMessage(
        0,
        "demo/example/hello",
        "Hello World!",
        .{},
        &buf,
    );

    // Frame: header=0x25 (reliable, MID=0x05, R=1), sn=VLE(0) = 0x00
    try testing.expectEqual(@as(u8, 0x25), encoded[0]); // Frame header
    try testing.expectEqual(@as(u8, 0x00), encoded[1]); // sn=0

    // Push: header=0x3D (MID=0x1D | N=0x20), scope=0x00, suffix="demo/example/hello"
    try testing.expectEqual(@as(u8, 0x3D), encoded[2]); // Push header
    try testing.expectEqual(@as(u8, 0x00), encoded[3]); // scope=0
    try testing.expectEqual(@as(u8, 0x12), encoded[4]); // suffix length=18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[5..23]);

    // Put: header=0x01 (MID=0x01, no E, no T), payload VLE(12) + "Hello World!"
    try testing.expectEqual(@as(u8, 0x01), encoded[23]); // Put header
    try testing.expectEqual(@as(u8, 0x0C), encoded[24]); // payload length=12
    try testing.expectEqualSlices(u8, "Hello World!", encoded[25..37]);
    try testing.expectEqual(@as(usize, 37), encoded.len);
}

test "z_put: assembled wire bytes with encoding" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodePutMessage(
        42,
        "test/key",
        "data",
        .{ .encoding = .{ .id = 10 } },
        &buf,
    );

    // Frame: header=0x25 (reliable), sn=VLE(42) = 0x2A
    try testing.expectEqual(@as(u8, 0x25), encoded[0]);
    try testing.expectEqual(@as(u8, 0x2A), encoded[1]);

    // Push: header=0x3D, scope=0x00, suffix="test/key"
    try testing.expectEqual(@as(u8, 0x3D), encoded[2]);
    try testing.expectEqual(@as(u8, 0x00), encoded[3]);
    try testing.expectEqual(@as(u8, 0x08), encoded[4]); // suffix length=8
    try testing.expectEqualSlices(u8, "test/key", encoded[5..13]);

    // Put: header=0x41 (MID=0x01 | E=0x40), encoding=VLE(20)=0x14, payload VLE(4) + "data"
    try testing.expectEqual(@as(u8, 0x41), encoded[13]); // Put header with E flag
    try testing.expectEqual(@as(u8, 0x14), encoded[14]); // encoding id=10 → (10<<1)|0 = 20 = 0x14
    try testing.expectEqual(@as(u8, 0x04), encoded[15]); // payload length=4
    try testing.expectEqualSlices(u8, "data", encoded[16..20]);
    try testing.expectEqual(@as(usize, 20), encoded.len);
}

test "z_put: empty payload" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodePutMessage(
        0,
        "test",
        "",
        .{},
        &buf,
    );

    // Frame + Push + Put with empty payload
    // Frame: 0x25, 0x00
    // Push: 0x3D, 0x00, 0x04, "test"
    // Put: 0x01, 0x00 (empty payload)
    try assertEqualBytes(
        &(.{ 0x25, 0x00, 0x3D, 0x00, 0x04 } ++ "test".* ++ .{ 0x01, 0x00 }),
        encoded,
    );
}

test "z_put: sn > 127 uses multi-byte VLE" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodePutMessage(
        200,
        "k",
        "v",
        .{},
        &buf,
    );

    // Frame: 0x25, VLE(200) = 0xC8 0x01
    try testing.expectEqual(@as(u8, 0x25), encoded[0]);
    try testing.expectEqual(@as(u8, 0xC8), encoded[1]);
    try testing.expectEqual(@as(u8, 0x01), encoded[2]);
}

test "z_put: Frame is always reliable" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodePutMessage(
        0,
        "key",
        "val",
        .{},
        &buf,
    );

    // The R bit (bit 5) should be set in the Frame header.
    const h = hdr.Header.decode(encoded[0]);
    try testing.expectEqual(@as(u5, transport.MID.frame), h.mid);
    try testing.expect(h.flag0()); // R flag
}

// ---------------------------------------------------------------------------
// z_get wire-bytes unit tests
// ---------------------------------------------------------------------------

test "z_get: assembled wire bytes for query 'demo/example/hello' (sn=0, rid=1)" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodeGetMessage(
        0,
        1,
        "demo/example/hello",
        .{},
        &buf,
    );

    // Frame: header=0x25 (reliable), sn=VLE(0) = 0x00
    try testing.expectEqual(@as(u8, 0x25), encoded[0]);
    try testing.expectEqual(@as(u8, 0x00), encoded[1]);

    // Request: header=0x3C (MID=0x1C | N=0x20), rid=VLE(1)=0x01, scope=0x00, suffix="demo/example/hello"
    try testing.expectEqual(@as(u8, 0x3C), encoded[2]);
    try testing.expectEqual(@as(u8, 0x01), encoded[3]); // request_id
    try testing.expectEqual(@as(u8, 0x00), encoded[4]); // scope
    try testing.expectEqual(@as(u8, 0x12), encoded[5]); // suffix length=18
    try testing.expectEqualSlices(u8, "demo/example/hello", encoded[6..24]);

    // Query: header=0x03 (MID=0x03, C=0, P=0)
    try testing.expectEqual(@as(u8, 0x03), encoded[24]);
    try testing.expectEqual(@as(usize, 25), encoded.len);
}

test "z_get: assembled wire bytes with consolidation and parameters" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodeGetMessage(
        5,
        42,
        "test/key",
        .{ .consolidation = 2, .parameters = "x=1" },
        &buf,
    );

    // Frame: 0x25, VLE(5)=0x05
    try testing.expectEqual(@as(u8, 0x25), encoded[0]);
    try testing.expectEqual(@as(u8, 0x05), encoded[1]);

    // Request: 0x3C, rid=VLE(42)=0x2A, scope=0x00, suffix VLE(8) + "test/key"
    try testing.expectEqual(@as(u8, 0x3C), encoded[2]);
    try testing.expectEqual(@as(u8, 0x2A), encoded[3]);
    try testing.expectEqual(@as(u8, 0x00), encoded[4]);
    try testing.expectEqual(@as(u8, 0x08), encoded[5]);
    try testing.expectEqualSlices(u8, "test/key", encoded[6..14]);

    // Query: 0x63 (MID=0x03 | C=0x20 | P=0x40), consolidation=0x02, parameters VLE(3) + "x=1"
    try testing.expectEqual(@as(u8, 0x63), encoded[14]);
    try testing.expectEqual(@as(u8, 0x02), encoded[15]); // consolidation
    try testing.expectEqual(@as(u8, 0x03), encoded[16]); // parameters length
    try testing.expectEqualSlices(u8, "x=1", encoded[17..20]);
    try testing.expectEqual(@as(usize, 20), encoded.len);
}

test "z_get: Frame is always reliable" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodeGetMessage(
        0,
        1,
        "key",
        .{},
        &buf,
    );

    const h = hdr.Header.decode(encoded[0]);
    try testing.expectEqual(@as(u5, transport.MID.frame), h.mid);
    try testing.expect(h.flag0()); // R flag
}

// ---------------------------------------------------------------------------
// Declare response wire-bytes unit tests
// ---------------------------------------------------------------------------

test "declare_response: wire bytes for interest_id=1, sn=0" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodeDeclareResponse(0, 1, &buf);

    // Frame: header=0x25 (reliable, MID=0x05, R=1), sn=VLE(0) = 0x00
    try testing.expectEqual(@as(u8, 0x25), encoded[0]); // Frame header
    try testing.expectEqual(@as(u8, 0x00), encoded[1]); // sn=0

    // Declare: header=0x3E (MID=0x1E | I=0x20), interest_id=VLE(1) = 0x01
    try testing.expectEqual(@as(u8, 0x3E), encoded[2]); // Declare header with I flag
    try testing.expectEqual(@as(u8, 0x01), encoded[3]); // interest_id=1

    // DeclareFinal: header=0x1A (sub-MID=0x1A, no flags)
    try testing.expectEqual(@as(u8, 0x1A), encoded[4]); // DeclareFinal header

    try testing.expectEqual(@as(usize, 5), encoded.len);
}

test "declare_response: interest_id > 127 uses multi-byte VLE" {
    var buf: [256]u8 = undefined;
    const encoded = try Session.encodeDeclareResponse(0, 200, &buf);

    // Frame: 0x25, 0x00
    try testing.expectEqual(@as(u8, 0x25), encoded[0]);
    try testing.expectEqual(@as(u8, 0x00), encoded[1]);

    // Declare: 0x3E, VLE(200) = 0xC8 0x01
    try testing.expectEqual(@as(u8, 0x3E), encoded[2]);
    try testing.expectEqual(@as(u8, 0xC8), encoded[3]);
    try testing.expectEqual(@as(u8, 0x01), encoded[4]);

    // DeclareFinal: 0x1A
    try testing.expectEqual(@as(u8, 0x1A), encoded[5]);

    try testing.expectEqual(@as(usize, 6), encoded.len);
}

// ---------------------------------------------------------------------------
// SN auto-increment tests
// ---------------------------------------------------------------------------

test "z_put: sequential puts use incrementing SNs" {
    // Verify the SN encoding differs for consecutive calls.
    var buf1: [256]u8 = undefined;
    const e1 = try Session.encodePutMessage(0, "k", "v", .{}, &buf1);
    var buf2: [256]u8 = undefined;
    const e2 = try Session.encodePutMessage(1, "k", "v", .{}, &buf2);

    // sn=0 → 0x00, sn=1 → 0x01
    try testing.expectEqual(@as(u8, 0x00), e1[1]);
    try testing.expectEqual(@as(u8, 0x01), e2[1]);
}

// ---------------------------------------------------------------------------
// GetResult / GetReply memory management tests
// ---------------------------------------------------------------------------

test "GetResult: deinit frees all reply memory" {
    const allocator = testing.allocator;

    var replies = try allocator.alloc(GetReply, 2);
    replies[0] = .{
        .key = try allocator.dupe(u8, "demo/hello"),
        .payload = try allocator.dupe(u8, "Hello"),
        .encoding_id = 0,
    };
    replies[1] = .{
        .key = null,
        .payload = try allocator.dupe(u8, "World"),
        .encoding_id = 10,
    };

    const result = GetResult{ .replies = replies };
    result.deinit(allocator);
    // If no leak detected by testing.allocator, this passes.
}

test "GetResult: empty result deinit is safe" {
    const allocator = testing.allocator;
    const empty = try allocator.alloc(GetReply, 0);
    const result = GetResult{ .replies = empty };
    result.deinit(allocator);
}

// ---------------------------------------------------------------------------
// PutOptions / GetOptions tests
// ---------------------------------------------------------------------------

test "PutOptions: default values" {
    const opts = PutOptions{};
    try testing.expectEqual(@as(?zenoh_msgs.Encoding, null), opts.encoding);
}

test "GetOptions: default values" {
    const opts = GetOptions{};
    try testing.expectEqual(@as(?u8, null), opts.consolidation);
    try testing.expectEqual(@as(?[]const u8, null), opts.parameters);
}

test {
    testing.refAllDecls(@This());
}
