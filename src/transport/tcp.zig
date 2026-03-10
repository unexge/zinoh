//! TCP transport layer for Zenoh protocol.
//!
//! Provides a `TcpTransport` struct that manages a TCP connection to a Zenoh
//! router, using 2-byte LE length-prefixed framing for message boundaries.
//! Integrates with the Zig 0.16 `std.Io.Evented` runtime (io_uring backed).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const framing = @import("framing.zig");

/// Default buffer size for TCP I/O operations.
pub const default_buffer_size: usize = 4096;

/// Default Zenoh router address: tcp/127.0.0.1:7447.
pub const default_address: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(7447) };

/// Errors that can occur when connecting.
pub const ConnectError = net.IpAddress.ConnectError || Allocator.Error;

/// Errors that can occur when sending a framed message.
pub const SendError = framing.WriteError;

/// Errors that can occur when receiving a framed message into a caller buffer.
pub const RecvError = framing.ReadError;

/// Errors that can occur when receiving a framed message with allocation.
pub const RecvAllocError = Io.Reader.ReadAllocError || Allocator.Error;

/// TCP transport for Zenoh protocol communication.
///
/// Wraps a TCP stream with 2-byte LE length-prefixed framing. Provides
/// send/recv methods that handle message boundaries automatically.
///
/// ## Example
/// ```
/// const tcp = @import("transport/tcp.zig");
/// var transport = try tcp.TcpTransport.connect(allocator, io, tcp.default_address);
/// defer transport.close();
///
/// try transport.send("hello");
/// var buf: [65535]u8 = undefined;
/// const response = try transport.recv(&buf);
/// ```
pub const TcpTransport = struct {
    stream: net.Stream,
    io: Io,
    read_buf: []u8,
    write_buf: []u8,
    allocator: Allocator,

    /// Establish a TCP connection to the given address.
    ///
    /// Allocates internal I/O buffers and connects via the evented runtime.
    /// On success, the transport is ready for send/recv operations.
    /// Call `close()` when done to release all resources.
    pub fn connect(allocator: Allocator, io: Io, address: net.IpAddress) ConnectError!TcpTransport {
        const read_buf = try allocator.alloc(u8, default_buffer_size);
        errdefer allocator.free(read_buf);

        const write_buf = try allocator.alloc(u8, default_buffer_size);
        errdefer allocator.free(write_buf);

        const stream = try address.connect(io, .{ .mode = .stream });

        return .{
            .stream = stream,
            .io = io,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .allocator = allocator,
        };
    }

    /// Send a framed message: 2-byte LE length prefix followed by payload.
    ///
    /// The payload must not exceed `framing.max_frame_size` (65,535 bytes).
    pub fn send(self: *TcpTransport, payload: []const u8) SendError!void {
        var stream_writer = self.stream.writer(self.io, self.write_buf);
        try framing.writeFrame(payload, &stream_writer.interface);
        try stream_writer.interface.flush();
    }

    /// Receive a framed message into a caller-provided buffer.
    ///
    /// Reads the 2-byte LE length prefix, then reads that many bytes
    /// into `buf`. Returns the slice of `buf` containing the payload.
    /// Returns `error.BufferTooSmall` if `buf.len` is smaller than the
    /// frame length.
    pub fn recv(self: *TcpTransport, buf: []u8) RecvError![]u8 {
        var stream_reader = self.stream.reader(self.io, self.read_buf);
        return framing.readFrame(&stream_reader.interface, buf);
    }

    /// Receive a framed message, allocating the buffer.
    ///
    /// Reads the 2-byte LE length prefix, allocates a buffer of that
    /// size, then reads the payload into it. Caller owns the returned
    /// memory and must free it with `allocator`.
    pub fn recvAlloc(self: *TcpTransport, allocator: Allocator) RecvAllocError![]u8 {
        var stream_reader = self.stream.reader(self.io, self.read_buf);
        return framing.readFrameAlloc(&stream_reader.interface, allocator);
    }

    /// Close the TCP connection and free all resources.
    ///
    /// After close(), the transport cannot be reused.
    pub fn close(self: *TcpTransport) void {
        self.stream.close(self.io);
        self.allocator.free(self.read_buf);
        self.allocator.free(self.write_buf);
        self.read_buf = &.{};
        self.write_buf = &.{};
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// ---------------------------------------------------------------------------
// Constants and defaults
// ---------------------------------------------------------------------------

test "default_address is tcp/127.0.0.1:7447" {
    const addr = default_address;
    try testing.expectEqual(net.IpAddress.Family.ip4, @as(net.IpAddress.Family, addr));
    try testing.expectEqual(@as(u16, 7447), addr.ip4.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &addr.ip4.bytes);
}

// ---------------------------------------------------------------------------
// Loopback TCP tests: verify TcpTransport with a real TCP connection
// ---------------------------------------------------------------------------

test "loopback: connect, send, recv, close" {
    const io = testing.io;
    const allocator = testing.allocator;

    // Start a TCP server on an ephemeral port
    const server_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    var server = net.IpAddress.listen(server_addr, io, .{ .reuse_address = true }) catch |err| {
        std.log.warn("loopback test skipped: cannot listen ({any})", .{err});
        return;
    };
    defer server.deinit(io);

    // Get the actual port the server bound to
    const bound_addr = server.socket.address;

    // Connect a TcpTransport to the server
    var transport = try TcpTransport.connect(allocator, io, bound_addr);
    defer transport.close();

    // Accept the connection on the server side
    var client_stream = try server.accept(io);
    defer client_stream.close(io);

    // Send a framed message from the transport
    const payload = "hello zenoh";
    try transport.send(payload);

    // Read the framed message on the server side (raw)
    var server_read_buf: [default_buffer_size]u8 = undefined;
    var server_reader = client_stream.reader(io, &server_read_buf);
    var recv_buf: [64]u8 = undefined;
    const received = try framing.readFrame(&server_reader.interface, &recv_buf);
    try testing.expectEqualSlices(u8, payload, received);

    // Send a framed response from the server side
    var server_write_buf: [default_buffer_size]u8 = undefined;
    var server_writer = client_stream.writer(io, &server_write_buf);
    const response = "ack";
    try framing.writeFrame(response, &server_writer.interface);
    try server_writer.interface.flush();

    // Receive the response via the transport
    var transport_recv_buf: [64]u8 = undefined;
    const resp = try transport.recv(&transport_recv_buf);
    try testing.expectEqualSlices(u8, response, resp);
}

test "loopback: recvAlloc works correctly" {
    const io = testing.io;
    const allocator = testing.allocator;

    const server_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    var server = net.IpAddress.listen(server_addr, io, .{ .reuse_address = true }) catch |err| {
        std.log.warn("loopback test skipped: cannot listen ({any})", .{err});
        return;
    };
    defer server.deinit(io);

    const bound_addr = server.socket.address;

    var transport = try TcpTransport.connect(allocator, io, bound_addr);
    defer transport.close();

    var client_stream = try server.accept(io);
    defer client_stream.close(io);

    // Server sends a framed message
    var server_write_buf: [default_buffer_size]u8 = undefined;
    var server_writer = client_stream.writer(io, &server_write_buf);
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    try framing.writeFrame(&payload, &server_writer.interface);
    try server_writer.interface.flush();

    // Transport receives with allocation
    const result = try transport.recvAlloc(allocator);
    defer allocator.free(result);
    try testing.expectEqualSlices(u8, &payload, result);
}

test "loopback: multiple messages in sequence" {
    const io = testing.io;
    const allocator = testing.allocator;

    const server_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    var server = net.IpAddress.listen(server_addr, io, .{ .reuse_address = true }) catch |err| {
        std.log.warn("loopback test skipped: cannot listen ({any})", .{err});
        return;
    };
    defer server.deinit(io);

    const bound_addr = server.socket.address;

    var transport = try TcpTransport.connect(allocator, io, bound_addr);
    defer transport.close();

    var client_stream = try server.accept(io);
    defer client_stream.close(io);

    // Send multiple messages from transport
    try transport.send("first");
    try transport.send("second");
    try transport.send("third");

    // Read them all on the server side
    var server_read_buf: [default_buffer_size]u8 = undefined;
    var server_reader = client_stream.reader(io, &server_read_buf);
    var recv_buf: [64]u8 = undefined;

    const r1 = try framing.readFrame(&server_reader.interface, &recv_buf);
    try testing.expectEqualSlices(u8, "first", r1);

    const r2 = try framing.readFrame(&server_reader.interface, &recv_buf);
    try testing.expectEqualSlices(u8, "second", r2);

    const r3 = try framing.readFrame(&server_reader.interface, &recv_buf);
    try testing.expectEqualSlices(u8, "third", r3);
}

test "loopback: empty message" {
    const io = testing.io;
    const allocator = testing.allocator;

    const server_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    var server = net.IpAddress.listen(server_addr, io, .{ .reuse_address = true }) catch |err| {
        std.log.warn("loopback test skipped: cannot listen ({any})", .{err});
        return;
    };
    defer server.deinit(io);

    const bound_addr = server.socket.address;

    var transport = try TcpTransport.connect(allocator, io, bound_addr);
    defer transport.close();

    var client_stream = try server.accept(io);
    defer client_stream.close(io);

    // Send an empty framed message
    try transport.send(&.{});

    // Read it on the server side
    var server_read_buf: [default_buffer_size]u8 = undefined;
    var server_reader = client_stream.reader(io, &server_read_buf);
    var recv_buf: [64]u8 = undefined;
    const result = try framing.readFrame(&server_reader.interface, &recv_buf);
    try testing.expectEqualSlices(u8, &.{}, result);
}

test "loopback: clean close releases resources" {
    const io = testing.io;
    const allocator = testing.allocator;

    const server_addr: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    var server = net.IpAddress.listen(server_addr, io, .{ .reuse_address = true }) catch |err| {
        std.log.warn("loopback test skipped: cannot listen ({any})", .{err});
        return;
    };
    defer server.deinit(io);

    const bound_addr = server.socket.address;

    // Open and close multiple transports (leak detection via testing.allocator)
    for (0..3) |_| {
        var transport = try TcpTransport.connect(allocator, io, bound_addr);
        var client_stream = try server.accept(io);
        client_stream.close(io);
        transport.close();
    }
}

test {
    testing.refAllDecls(@This());
}
