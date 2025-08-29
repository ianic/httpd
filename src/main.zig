const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const assert = std.debug.assert;

const Loop = @import("Loop.zig");
const Operation = Loop.Operation;

const log = std.log.scoped(.main);

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    var loop = try Loop.init(gpa, .{ .entries = 256, .fd_nr = 1024 });
    defer loop.deinit(gpa);

    const addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 8080);
    var listener = Listener{ .addr = addr, .id = rsv_user_data.listener };
    try listener.complete(&loop, .none, 0);

    while (true) {
        const cmp = try loop.peekCompletion();
        if (cmp.id == listener.id) {
            try listener.complete(&loop, cmp.op, cmp.res);
        } else {
            unreachable;
        }
        loop.advance();
    }
}

const Listener = struct {
    id: u32,
    fd: posix.fd_t = -1,
    addr: net.Address,

    fn complete(self: *Listener, loop: *Loop, op: Operation, res: anyerror!i32) !void {
        switch (op) {
            .none => {
                try loop.socket(self.id, &self.addr);
            },
            .socket => {
                self.fd = try res;
                try loop.listen(self.id, &self.addr, self.fd);
            },
            .listen => {
                assert(0 == try res);
                try loop.accept(self.id, self.fd);
            },
            .accept => {
                const fd = try res;
                log.debug("accept fd: {}", .{fd});
                try loop.accept(self.id, self.fd);
            },
            else => unreachable,
        }
    }
};

// Reserved values for user_data
const rsv_user_data = struct {
    const none: u32 = 0xff_ff_ff_ff;
    const listener: u32 = 0xff_ff_ff_fe;
};
