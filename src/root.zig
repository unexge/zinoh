//! zinoh — A Zenoh client written in Zig.
//!
//! Public API re-exports for all submodules.
const std = @import("std");

pub const codec = struct {
    pub const vle = @import("codec/vle.zig");
    pub const primitives = @import("codec/primitives.zig");
    pub const header = @import("codec/header.zig");
};

pub const transport = struct {
    pub const messages = @import("transport/messages.zig");
    pub const framing = @import("transport/framing.zig");
};

pub const network = struct {
    pub const messages = @import("network/messages.zig");
};

pub const zenoh = struct {
    pub const messages = @import("zenoh/messages.zig");
};

pub const session = @import("session.zig");

pub const testing = @import("testing.zig");

test {
    std.testing.refAllDecls(@This());
    // Recursively discover tests in inline namespace structs.
    std.testing.refAllDecls(codec);
    std.testing.refAllDecls(transport);
    std.testing.refAllDecls(network);
    std.testing.refAllDecls(zenoh);
}
