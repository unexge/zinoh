//! Integration test entry point.
const std = @import("std");

pub const helpers = @import("helpers.zig");

test {
    std.testing.refAllDecls(@This());
}
