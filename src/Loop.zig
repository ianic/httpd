const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const mem = std.mem;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.loop);

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,

    recv_buffers: struct {
        size: u32 = 0,
        count: u16 = 0,
    } = .{},
};

const Loop = @This();

ring: linux.IoUring = undefined,
recv_buffer_group: linux.IoUring.BufferGroup = undefined,
cqes_buf: [128]linux.io_uring_cqe = undefined,
cqes: []linux.io_uring_cqe = &.{},

pub fn init(loop: *Loop, allocator: Allocator, opt: Options) !void {
    assert(opt.recv_buffers.size > 0 and opt.recv_buffers.count > 0);

    loop.ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer loop.ring.deinit();
    try loop.ring.register_files_sparse(opt.fd_nr);

    loop.recv_buffer_group = try linux.IoUring.BufferGroup.init(
        &loop.ring,
        allocator,
        0,
        opt.recv_buffers.size,
        opt.recv_buffers.count,
    );
}

pub fn deinit(self: *Loop, allocator: Allocator) void {
    self.recv_buffer_group.deinit(allocator);
    self.ring.deinit();
}

pub const Completion = struct {
    id: u32,
    operation: Operation,
    result: anyerror!i32,
    cqe: linux.io_uring_cqe,

    pub const none: Completion = .{ .id = 0, .operation = .none, .result = 0, .cqe = mem.zeroes(linux.io_uring_cqe) };
};

pub fn peek(self: *Loop) !Completion {
    while (true) {
        if (self.cqes.len == 0) {
            _ = try self.ring.submit();
            const n = try self.ring.copy_cqes(&self.cqes_buf, 1);
            self.cqes = self.cqes_buf[0..n];
        }
        const cqe = self.cqes[0];
        if (cqe.user_data == rsv_user_data.none) {
            continue;
        }
        const op, const id = decodeUserData(cqe.user_data);
        return .{
            .operation = op,
            .id = id,
            .result = if (cqe.res < 0) error.OperationFailed else cqe.res,
            .cqe = cqe,
        };
    }
}

pub fn advance(self: *Loop) void {
    self.cqes = self.cqes[1..];
}

pub fn socket(self: *Loop, id: u32, addr: *net.Address) !void {
    _ = try self.ring.socket_direct_alloc(userData(.socket, id), addr.any.family, linux.SOCK.STREAM, 0, 0);
}

pub fn listen(self: *Loop, id: u32, addr: *net.Address, fd: posix.fd_t) !void {
    const reuse_address = true;
    const kernel_backlog: u31 = 128;
    var sqe: *linux.io_uring_sqe = undefined;
    if (reuse_address) {
        sqe = try self.ring.setsockopt(userData(.setsockopt, rsv_user_data.none), fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try self.ring.setsockopt(userData(.setsockopt, rsv_user_data.none), fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = try self.ring.bind(userData(.bind, rsv_user_data.none), fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try self.ring.listen(userData(.listen, id), fd, kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn accept(self: *Loop, id: u32, fd: posix.fd_t) !void {
    var sqe = try self.ring.accept_direct(userData(.accept, id), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn recv(self: *Loop, id: u32, fd: posix.fd_t) !void {
    var sqe = try self.recv_buffer_group.recv(userData(.recv, id), fd, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn getRecvBuffer(self: *Loop, completion: Completion) ![]const u8 {
    return try self.recv_buffer_group.get(completion.cqe);
}

pub fn putRecvBuffer(self: *Loop, completion: Completion) !void {
    try self.recv_buffer_group.put(completion.cqe);
}

/// Close file descriptor
pub fn close(self: *Loop, id: u32, fd: linux.fd_t) !void {
    _ = try self.ring.close_direct(userData(.close, id), @intCast(fd));
}

/// Cancel any fd operations
pub fn cancel(self: *Loop, id: u32, fd: linux.fd_t) !void {
    var sqe = try self.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = userData(.cancel, id);
}

// Reserved values for user_data
const rsv_user_data = struct {
    const none: u32 = 0xff_ff_ff_ff;
    const listener: u32 = 0xff_ff_ff_fe;
};

pub const Operation = enum(u8) {
    none,
    socket,
    setsockopt,
    bind,
    listen,
    accept,
    recv,
    close,
    cancel,
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
