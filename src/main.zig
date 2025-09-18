pub fn main() !void {
    signal.watch();

    var dbga = std.heap.DebugAllocator(.{}){};
    const gpa = switch (builtin.mode) {
        .Debug => dbga.allocator(),
        else => std.heap.c_allocator,
    };
    defer switch (builtin.mode) {
        .Debug => _ = dbga.deinit(),
        else => {},
    };

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = 1024 * 4,
        .fd_nr = 1024,
        .recv_buffers = .{ .count = 2, .size = 4096 * 128 },
    });
    defer io.deinit(gpa);

    var server: Server = .{ .gpa = gpa, .io = &io };
    try server.init();
    defer server.deinit();

    while (true) {
        io.tick() catch |err| switch (err) {
            error.SignalInterrupt => {},
            else => return err,
        };
        if (signal.get()) |sig| switch (sig) {
            posix.SIG.TERM, posix.SIG.INT => break,
            posix.SIG.USR1 => {
                log.info("metric: {}", .{server.metric});
            },
            else => {
                log.info("ignoring signal {}", .{sig});
            },
        };
    }
    signal.reset();

    // Stop listening for new connections.
    try server.close();
    // Wait for existing connections to finish.
    while (!server.closed()) {
        try io.tick();
    }
}

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const Io = @import("Io.zig");
const Server = @import("Server.zig");
const signal = @import("signal.zig");
const log = std.log.scoped(.main);
