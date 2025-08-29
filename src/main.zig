const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const assert = std.debug.assert;
const Loop = @import("Loop.zig");

const log = std.log.scoped(.main);

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    var loop = try Loop.init(gpa, .{ .entries = 256, .fd_nr = 1024 });
    defer loop.deinit(gpa);
    const ring = &loop.ring;

    const addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 8080);
    var listener = Listener{ .addr = addr };
    try listener.complete(ring, .initial, 0);

    while (true) {
        _ = try ring.submit_and_wait(1);
        while (true) {
            const ready = ring.cq_ready();
            if (ready == 0) break;
            // Peek list of ready cqes
            const head = ring.cq.head.* & ring.cq.mask;
            const tail = @min(ring.cq.cqes.len - head, ready);
            const cqes = ring.cq.cqes[head..][0..tail];
            for (cqes) |cqe| {
                const idx: u32 = @truncate(cqe.user_data);
                const op: Operation = @enumFromInt(@as(u8, @truncate(cqe.user_data >> 32)));
                log.debug("op: {}, idx: {} cqe: {} ready: {}", .{ op, idx, cqe, ready });
                if (idx == rsv_user_data.none) continue;
                if (idx == rsv_user_data.listener) {
                    try listener.complete(
                        ring,
                        op,
                        if (cqe.res < 0) error.OperationFailed else cqe.res,
                    );
                } else {
                    unreachable;
                }
            }
            ring.cq_advance(@intCast(cqes.len));
            if (cqes.len == ready) break;
        }
    }
}

const Listener = struct {
    fd: posix.fd_t = -1,
    addr: net.Address,
    state: State = .initial,

    const State = enum(u8) {
        initial,
        socket,
    };

    fn socket(self: *Listener, ring: *linux.IoUring) !void {
        _ = try ring.socket_direct_alloc(userData(.socket, rsv_user_data.listener), self.addr.any.family, linux.SOCK.STREAM, 0, 0);
    }

    fn listen(self: *Listener, ring: *linux.IoUring) !void {
        const reuse_address = true;
        const kernel_backlog: u31 = 128;
        var sqe: *linux.io_uring_sqe = undefined;
        if (reuse_address) {
            sqe = try ring.setsockopt(userData(.setsockopt, rsv_user_data.none), self.fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
            sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
            sqe = try ring.setsockopt(userData(.setsockopt, rsv_user_data.none), self.fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
            sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        }
        sqe = try ring.bind(userData(.bind, rsv_user_data.none), self.fd, &self.addr.any, self.addr.getOsSockLen(), 0);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try ring.listen(userData(.listen, rsv_user_data.listener), self.fd, kernel_backlog, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    fn accept(self: *Listener, ring: *linux.IoUring) !void {
        var sqe = try ring.accept_direct(userData(.accept, rsv_user_data.listener), self.fd, null, null, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    fn complete(self: *Listener, ring: *linux.IoUring, op: Operation, res: anyerror!i32) !void {
        switch (op) {
            .initial => {
                try self.socket(ring);
            },
            .socket => {
                self.fd = try res;
                try self.listen(ring);
            },
            .listen => {
                assert(0 == try res);
                try self.accept(ring);
            },
            .accept => {
                const fd = try res;
                log.debug("accept fd: {}", .{fd});
                try self.accept(ring);
            },
            else => unreachable,
        }
    }
};

const Operation = enum(u8) {
    initial,
    socket,
    setsockopt,
    bind,
    listen,
    accept,
};

// Reserved values for user_data
const rsv_user_data = struct {
    const none: u32 = 0xff_ff_ff_ff;
    const listener: u32 = 0xff_ff_ff_fe;
};

fn userData(op: Operation, idx: u32) u64 {
    return @as(u64, @intFromEnum(op)) << 32 | idx;
}

fn decodeUserData(user_data: u64) struct { Operation, u32 } {
    return .{
        @enumFromInt(@as(u8, @truncate(user_data >> 32))),
        @truncate(user_data),
    };
}

const yes_socket_option = std.mem.asBytes(&@as(u32, 1));

const testing = std.testing;

test userData {
    try testing.expectEqual(0x01_ff_ff_ff_fe, userData(.socket, rsv_user_data.listener));
    const op, const ids = decodeUserData(0x01_ff_ff_ff_fe);
    try testing.expectEqual(.socket, op);
    try testing.expectEqual(ids, rsv_user_data.listener);
}
