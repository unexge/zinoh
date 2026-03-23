const std = @import("std");
const zinoh = @import("zinoh");

const Session = zinoh.session.Session;
const ZenohId = zinoh.transport.messages.ZenohId;
const net = std.Io.net;

/// Default Zenoh router endpoint.
const default_endpoint = "127.0.0.1:7447";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = std.heap.smp_allocator;

    const stdout = std.Io.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var fw = stdout.writerStreaming(io, &stdout_buf);
    const w = &fw.interface;

    var args_iter = init.minimal.args.iterate();
    _ = args_iter.next(); // skip program name
    const endpoint = args_iter.next() orelse default_endpoint;

    const address = net.IpAddress.parseLiteral(endpoint) catch {
        try w.print("error: invalid endpoint '{s}' (expected host:port)\n", .{endpoint});
        try fw.flush();
        return;
    };

    try w.print("zinoh: connecting to {s} ...\n", .{endpoint});
    try fw.flush();

    const zid_len = 4;
    comptime std.debug.assert(zid_len >= 1 and zid_len <= ZenohId.max_len);
    var zid_bytes: [zid_len]u8 = undefined;
    io.random(&zid_bytes);
    const zid = ZenohId.init(&zid_bytes) catch unreachable;

    var session = Session.open(allocator, io, address, zid) catch |err| {
        try w.print("error: failed to open session: {}\n", .{err});
        try fw.flush();
        return;
    };
    defer session.deinit();

    // Display ZID in big-endian hex (Zenoh convention: most-significant byte first).
    const zid_slice = session.remote_zid.slice();
    var zid_display: [ZenohId.max_len]u8 = .{0} ** ZenohId.max_len;
    for (zid_slice, 0..) |b, i| {
        zid_display[zid_slice.len - 1 - i] = b;
    }
    try w.print("zinoh: session established (remote zid: {x})\n", .{
        zid_display[0..zid_slice.len],
    });
    try fw.flush();

    const key = "demo/example/zinoh-greeting";
    const payload = "Hello from zinoh!";

    session.put(key, payload, .{}) catch |err| {
        try w.print("error: put failed: {}\n", .{err});
        try fw.flush();
        return;
    };

    try w.print("zinoh: published '{s}' to key '{s}'\n", .{ payload, key });
    try w.print("zinoh: querying '{s}' ...\n", .{key});
    try fw.flush();

    const result = session.get(key, .{}) catch |err| {
        try w.print("error: get failed: {}\n", .{err});
        try fw.flush();
        return;
    };
    defer result.deinit(allocator);

    if (result.replies.len == 0) {
        try w.print("zinoh: no replies received\n", .{});
    } else {
        for (result.replies) |reply| {
            try w.print("zinoh: reply key='{s}' payload='{s}'\n", .{
                reply.key orelse "(none)",
                reply.payload,
            });
        }
    }
    try fw.flush();

    if (session.state == .open) {
        session.close(.generic) catch |err| {
            try w.print("warning: close error: {}\n", .{err});
            try fw.flush();
        };
    }

    if (session.state == .closed) {
        try w.print("zinoh: session closed\n", .{});
        try fw.flush();
    }
}
