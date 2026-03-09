//! Benchmark harness for zinoh codec throughput measurement.
//!
//! Usage:
//!   zig build bench                     # Run all benchmarks
//!   zig build bench -- vle              # Run benchmarks matching "vle"
//!   zig build bench -- vle encode       # Run benchmarks matching "vle" or "encode"
const std = @import("std");
const zinoh = @import("zinoh");

// ---------------------------------------------------------------------------
// Timing helpers (monotonic clock)
// ---------------------------------------------------------------------------

const linux = std.os.linux;

fn nanotime() u64 {
    var ts: linux.timespec = undefined;
    // MONOTONIC clock cannot fail on Linux; discard the return code.
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---------------------------------------------------------------------------
// Benchmark definition
// ---------------------------------------------------------------------------

const BenchFn = *const fn () void;

const Benchmark = struct {
    name: []const u8,
    func: BenchFn,
    /// If non-zero, the harness reports bytes/sec in addition to ops/sec.
    bytes_per_op: usize = 0,
};

// ---------------------------------------------------------------------------
// Benchmark registry — add new benchmarks here
// ---------------------------------------------------------------------------

const vle = zinoh.codec.vle;
const primitives = zinoh.codec.primitives;

const benchmarks = [_]Benchmark{
    .{
        .name = "noop (baseline)",
        .func = benchNoop,
    },
    // VLE encode benchmarks
    .{
        .name = "vle encode small (0)",
        .func = benchVleEncodeSmall,
        .bytes_per_op = 1,
    },
    .{
        .name = "vle encode small (127)",
        .func = benchVleEncodeSmall127,
        .bytes_per_op = 1,
    },
    .{
        .name = "vle encode medium (128)",
        .func = benchVleEncodeMedium128,
        .bytes_per_op = 2,
    },
    .{
        .name = "vle encode medium (16383)",
        .func = benchVleEncodeMedium16383,
        .bytes_per_op = 2,
    },
    .{
        .name = "vle encode large (>2^32)",
        .func = benchVleEncodeLarge,
        .bytes_per_op = 5,
    },
    .{
        .name = "vle encode max u64",
        .func = benchVleEncodeMaxU64,
        .bytes_per_op = 9,
    },
    // VLE decode benchmarks
    .{
        .name = "vle decode small (0)",
        .func = benchVleDecodeSmall,
        .bytes_per_op = 1,
    },
    .{
        .name = "vle decode small (127)",
        .func = benchVleDecodeSmall127,
        .bytes_per_op = 1,
    },
    .{
        .name = "vle decode medium (128)",
        .func = benchVleDecodeMedium128,
        .bytes_per_op = 2,
    },
    .{
        .name = "vle decode medium (16383)",
        .func = benchVleDecodeMedium16383,
        .bytes_per_op = 2,
    },
    .{
        .name = "vle decode large (>2^32)",
        .func = benchVleDecodeLarge,
        .bytes_per_op = 5,
    },
    .{
        .name = "vle decode max u64",
        .func = benchVleDecodeMaxU64,
        .bytes_per_op = 9,
    },
    // uint16 LE encode benchmarks
    .{
        .name = "uint16 LE encode 0",
        .func = benchUint16LEEncode0,
        .bytes_per_op = 2,
    },
    .{
        .name = "uint16 LE encode 0xFFFF",
        .func = benchUint16LEEncodeMax,
        .bytes_per_op = 2,
    },
    // uint16 LE decode benchmarks
    .{
        .name = "uint16 LE decode 0",
        .func = benchUint16LEDecode0,
        .bytes_per_op = 2,
    },
    .{
        .name = "uint16 LE decode 0xFFFF",
        .func = benchUint16LEDecodeMax,
        .bytes_per_op = 2,
    },
    // Slice encode benchmarks
    .{
        .name = "slice encode empty",
        .func = benchSliceEncodeEmpty,
        .bytes_per_op = 1,
    },
    .{
        .name = "slice encode 16 bytes",
        .func = benchSliceEncode16,
        .bytes_per_op = 17,
    },
    .{
        .name = "slice encode 256 bytes",
        .func = benchSliceEncode256,
        .bytes_per_op = 258,
    },
    // Slice decode benchmarks
    .{
        .name = "slice decode empty",
        .func = benchSliceDecodeEmpty,
        .bytes_per_op = 1,
    },
    .{
        .name = "slice decode 16 bytes",
        .func = benchSliceDecode16,
        .bytes_per_op = 17,
    },
    .{
        .name = "slice decode 256 bytes",
        .func = benchSliceDecode256,
        .bytes_per_op = 258,
    },
    // String encode benchmarks
    .{
        .name = "string encode empty",
        .func = benchStringEncodeEmpty,
        .bytes_per_op = 1,
    },
    .{
        .name = "string encode 'hello'",
        .func = benchStringEncodeHello,
        .bytes_per_op = 6,
    },
    .{
        .name = "string encode 128-byte UTF-8",
        .func = benchStringEncode128,
        .bytes_per_op = 130,
    },
    // String decode benchmarks
    .{
        .name = "string decode empty",
        .func = benchStringDecodeEmpty,
        .bytes_per_op = 1,
    },
    .{
        .name = "string decode 'hello'",
        .func = benchStringDecodeHello,
        .bytes_per_op = 6,
    },
    .{
        .name = "string decode 128-byte UTF-8",
        .func = benchStringDecode128,
        .bytes_per_op = 130,
    },
};

// ---------------------------------------------------------------------------
// Benchmark implementations
// ---------------------------------------------------------------------------

fn benchNoop() void {
    // Intentionally empty — measures harness overhead.
    std.mem.doNotOptimizeAway(@as(u8, 0));
}

// --- VLE encode benchmarks ---

fn vleEncodeBench(value: u64) void {
    var buf: [vle.max_bytes]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    vle.encode(value, &writer) catch unreachable;
    std.mem.doNotOptimizeAway(writer.buffered());
}

fn benchVleEncodeSmall() void {
    vleEncodeBench(0);
}

fn benchVleEncodeSmall127() void {
    vleEncodeBench(127);
}

fn benchVleEncodeMedium128() void {
    vleEncodeBench(128);
}

fn benchVleEncodeMedium16383() void {
    vleEncodeBench(16383);
}

fn benchVleEncodeLarge() void {
    vleEncodeBench(0x1_0000_0001); // > 2^32
}

fn benchVleEncodeMaxU64() void {
    vleEncodeBench(0xFFFFFFFFFFFFFFFF);
}

// --- VLE decode benchmarks ---

fn vleDecodeBench(comptime encoded: []const u8) void {
    var reader: std.Io.Reader = .fixed(encoded);
    const result = vle.decode(&reader) catch unreachable;
    std.mem.doNotOptimizeAway(result);
}

fn benchVleDecodeSmall() void {
    vleDecodeBench(&[_]u8{0x00});
}

fn benchVleDecodeSmall127() void {
    vleDecodeBench(&[_]u8{0x7F});
}

fn benchVleDecodeMedium128() void {
    vleDecodeBench(&[_]u8{ 0x80, 0x01 });
}

fn benchVleDecodeMedium16383() void {
    vleDecodeBench(&[_]u8{ 0xFF, 0x7F });
}

fn benchVleDecodeLarge() void {
    // 0x1_0000_0001 encoded
    vleDecodeBench(&[_]u8{ 0x81, 0x80, 0x80, 0x80, 0x10 });
}

fn benchVleDecodeMaxU64() void {
    vleDecodeBench(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
}

// --- uint16 LE encode benchmarks ---

fn uint16LEEncodeBench(value: u16) void {
    var buf: [2]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    primitives.writeUint16LE(value, &writer) catch unreachable;
    std.mem.doNotOptimizeAway(writer.buffered());
}

fn benchUint16LEEncode0() void {
    uint16LEEncodeBench(0);
}

fn benchUint16LEEncodeMax() void {
    uint16LEEncodeBench(0xFFFF);
}

// --- uint16 LE decode benchmarks ---

fn uint16LEDecodeBench(comptime encoded: *const [2]u8) void {
    var reader: std.Io.Reader = .fixed(encoded);
    const result = primitives.readUint16LE(&reader) catch unreachable;
    std.mem.doNotOptimizeAway(result);
}

fn benchUint16LEDecode0() void {
    uint16LEDecodeBench(&[_]u8{ 0x00, 0x00 });
}

fn benchUint16LEDecodeMax() void {
    uint16LEDecodeBench(&[_]u8{ 0xFF, 0xFF });
}

// --- Slice encode benchmarks ---

fn sliceEncodeBench(comptime data: []const u8) void {
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    primitives.writeSlice(data, &writer) catch unreachable;
    std.mem.doNotOptimizeAway(writer.buffered());
}

fn benchSliceEncodeEmpty() void {
    sliceEncodeBench(&[_]u8{});
}

fn benchSliceEncode16() void {
    sliceEncodeBench(&([_]u8{0xAB} ** 16));
}

fn benchSliceEncode256() void {
    sliceEncodeBench(&([_]u8{0xCD} ** 256));
}

// --- Slice decode benchmarks ---

fn sliceDecodeBench(comptime encoded: []const u8, allocator: std.mem.Allocator) void {
    var reader: std.Io.Reader = .fixed(encoded);
    const result = primitives.readSlice(&reader, allocator) catch unreachable;
    std.mem.doNotOptimizeAway(result.ptr);
    allocator.free(result);
}

// Comptime helper to build encoded slice wire data.
fn encodeSliceComptime(comptime data: []const u8) *const [vle.encodedSize(data.len) + data.len]u8 {
    comptime {
        const vle_len = vle.encodedSize(data.len);
        const total = vle_len + data.len;
        var vle_buf: [vle.max_bytes]u8 = undefined;
        const vle_bytes = vle.encodeToSlice(data.len, &vle_buf) catch unreachable;
        std.debug.assert(vle_bytes.len == vle_len);
        var result: [total]u8 = undefined;
        @memcpy(result[0..vle_len], vle_bytes);
        @memcpy(result[vle_len..][0..data.len], data);
        const final = result;
        return &final;
    }
}

const encoded_slice_empty = encodeSliceComptime(&[_]u8{});
const encoded_slice_16 = encodeSliceComptime(&([_]u8{0xAB} ** 16));
const encoded_slice_256 = encodeSliceComptime(&([_]u8{0xCD} ** 256));

// Use a fixed-buffer allocator for decode benchmarks to avoid hitting the system allocator.
var bench_decode_backing: [1024]u8 = undefined;

fn benchSliceDecodeEmpty() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    sliceDecodeBench(encoded_slice_empty, fba.allocator());
}

fn benchSliceDecode16() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    sliceDecodeBench(encoded_slice_16, fba.allocator());
}

fn benchSliceDecode256() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    sliceDecodeBench(encoded_slice_256, fba.allocator());
}

// --- String encode benchmarks ---

fn stringEncodeBench(comptime str: []const u8) void {
    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    primitives.writeString(str, &writer) catch unreachable;
    std.mem.doNotOptimizeAway(writer.buffered());
}

fn benchStringEncodeEmpty() void {
    stringEncodeBench("");
}

fn benchStringEncodeHello() void {
    stringEncodeBench("hello");
}

fn benchStringEncode128() void {
    // 128 bytes of UTF-8 text (repeating pattern)
    stringEncodeBench("こんにちは世界！" ** 5 ++ "12345678");
}

// --- String decode benchmarks ---

const encoded_string_empty = encodeSliceComptime("");
const encoded_string_hello = encodeSliceComptime("hello");
const encoded_string_128 = encodeSliceComptime("こんにちは世界！" ** 5 ++ "12345678");

fn stringDecodeBench(comptime encoded: []const u8, allocator: std.mem.Allocator) void {
    var reader: std.Io.Reader = .fixed(encoded);
    const result = primitives.readString(&reader, allocator) catch unreachable;
    std.mem.doNotOptimizeAway(result.ptr);
    allocator.free(result);
}

fn benchStringDecodeEmpty() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    stringDecodeBench(encoded_string_empty, fba.allocator());
}

fn benchStringDecodeHello() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    stringDecodeBench(encoded_string_hello, fba.allocator());
}

fn benchStringDecode128() void {
    var fba = std.heap.FixedBufferAllocator.init(&bench_decode_backing);
    stringDecodeBench(encoded_string_128, fba.allocator());
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const min_bench_time_ns: u64 = 500 * std.time.ns_per_ms;
const warmup_iterations: u64 = 1_000;

/// Calibrate iteration count so the benchmark runs for at least `min_bench_time_ns`.
fn calibrate(func: BenchFn) u64 {
    const max_iters: u64 = 1_000_000_000;
    var iters: u64 = 1;
    while (iters < max_iters) {
        const start = nanotime();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            func();
        }
        const elapsed = nanotime() - start;
        if (elapsed >= min_bench_time_ns) return iters;
        // Scale up: aim for 2× the minimum time, but at least double iterations.
        const next = if (elapsed == 0)
            iters *| 100
        else
            @max(iters *| 2, iters *| ((min_bench_time_ns * 2) / elapsed));
        iters = @min(next, max_iters);
    }
    return iters;
}

fn runBenchmark(b: Benchmark, w: *std.Io.Writer) !void {
    // Warm up
    for (0..warmup_iterations) |_| {
        b.func();
    }

    // Calibrate
    const iters = calibrate(b.func);

    // Measure
    const start = nanotime();
    for (0..iters) |_| {
        b.func();
    }
    const elapsed = nanotime() - start;

    // Compute stats
    const ns_per_op: f64 = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iters));
    const ops_per_sec: f64 = if (elapsed > 0) @as(f64, @floatFromInt(iters)) * @as(f64, @floatFromInt(std.time.ns_per_s)) / @as(f64, @floatFromInt(elapsed)) else 0;

    // Print row
    try w.print("  {s:<30} {d:>12} iters   {d:>10.1} ns/op   {d:>12.0} ops/sec", .{
        b.name,
        iters,
        ns_per_op,
        ops_per_sec,
    });

    if (b.bytes_per_op > 0) {
        const bytes_per_sec = ops_per_sec * @as(f64, @floatFromInt(b.bytes_per_op));
        const mb_per_sec = bytes_per_sec / (1024.0 * 1024.0);
        try w.print("   {d:>8.1} MiB/s", .{mb_per_sec});
    }

    try w.print("\n", .{});
}

fn matchesFilter(name: []const u8, filters: []const [:0]const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |filter| {
        if (std.mem.indexOf(u8, name, filter) != null) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    // Collect CLI filter arguments
    var args_iter = init.minimal.args.iterate();
    _ = args_iter.next(); // skip program name

    var filters: [64][:0]const u8 = undefined;
    var filter_count: usize = 0;
    while (args_iter.next()) |arg| {
        if (filter_count < filters.len) {
            filters[filter_count] = arg;
            filter_count += 1;
        }
    }
    const active_filters = filters[0..filter_count];

    // Set up stdout writer
    const stdout = std.Io.File.stdout();
    var buf: [8192]u8 = undefined;
    var fw = stdout.writerStreaming(init.io, &buf);
    var w = &fw.interface;

    // Header
    try w.print("\n", .{});
    try w.print("  zinoh benchmarks\n", .{});
    try w.print("  {s}\n", .{"=" ** 78});

    if (filter_count > 0) {
        try w.print("  filter:", .{});
        for (active_filters) |f| {
            try w.print(" \"{s}\"", .{f});
        }
        try w.print("\n", .{});
    }
    try w.print("\n", .{});
    try fw.flush();

    // Run benchmarks
    var ran: usize = 0;
    for (&benchmarks) |*b| {
        if (!matchesFilter(b.name, active_filters)) continue;
        try runBenchmark(b.*, w);
        try fw.flush();
        ran += 1;
    }

    // Footer
    try w.print("\n", .{});
    if (ran == 0) {
        try w.print("  (no benchmarks matched filter)\n\n", .{});
    } else {
        try w.print("  {d} benchmark(s) completed.\n\n", .{ran});
    }
    try fw.flush();
}
