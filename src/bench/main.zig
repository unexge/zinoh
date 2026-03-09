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

const benchmarks = [_]Benchmark{
    .{
        .name = "noop (baseline)",
        .func = benchNoop,
    },
    .{
        .name = "vle encode 0",
        .func = benchVleEncode0,
        .bytes_per_op = 1,
    },
};

// ---------------------------------------------------------------------------
// Benchmark implementations
// ---------------------------------------------------------------------------

fn benchNoop() void {
    // Intentionally empty — measures harness overhead.
    std.mem.doNotOptimizeAway(@as(u8, 0));
}

fn benchVleEncode0() void {
    // Placeholder VLE encode benchmark. Exercises the import path and
    // provides a real measurement once vle.encode is implemented.
    _ = zinoh.codec.vle;
    std.mem.doNotOptimizeAway(@as(u8, 0));
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
