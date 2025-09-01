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

pub const Callback = *const fn (c: *Completion, cqe: linux.io_uring_cqe) anyerror!void;
pub const Completion = struct {
    callback: Callback = undefined,
};

var noop: Completion = .{ .callback = noopCallback };
fn noopCallback(_: *Completion, _: linux.io_uring_cqe) !void {}

const Io = @This();

ring: linux.IoUring = undefined,
recv_buffer_group: linux.IoUring.BufferGroup = undefined,
cqes_buf: [128]linux.io_uring_cqe = undefined,
cqes: []linux.io_uring_cqe = &.{},

pub fn init(io: *Io, allocator: Allocator, opt: Options) !void {
    assert(opt.recv_buffers.size > 0 and opt.recv_buffers.count > 0);

    io.ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer io.ring.deinit();
    try io.ring.register_files_sparse(opt.fd_nr);

    io.recv_buffer_group = try linux.IoUring.BufferGroup.init(
        &io.ring,
        allocator,
        0,
        opt.recv_buffers.size,
        opt.recv_buffers.count,
    );
}

pub fn deinit(io: *Io, allocator: Allocator) void {
    io.recv_buffer_group.deinit(allocator);
    io.ring.deinit();
}

pub fn loop(io: *Io) !void {
    while (true) {
        if (io.cqes.len == 0) {
            _ = io.ring.submit() catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return err,
            };
            const n = io.ring.copy_cqes(&io.cqes_buf, 1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return err,
            };
            io.cqes = io.cqes_buf[0..n];
        }
        const cqe = io.cqes[0];

        var c: *Completion = @ptrFromInt(cqe.user_data);
        try c.callback(c, cqe);
        io.cqes = io.cqes[1..];
    }
}

pub fn socket(io: *Io, c: *Completion, cb: Callback, addr: *const net.Address) !void {
    c.callback = cb;
    _ = try io.ring.socket_direct_alloc(@intFromPtr(c), addr.any.family, linux.SOCK.STREAM, 0, 0);
}

pub fn listen(io: *Io, c: *Completion, cb: Callback, addr: *const net.Address, fd: posix.fd_t) !void {
    // TODO move this into option
    const reuse_address = true;
    const kernel_backlog: u31 = 128;

    c.callback = cb;
    var sqe: *linux.io_uring_sqe = undefined;
    if (reuse_address) {
        sqe = try io.ring.setsockopt(@intFromPtr(&noop), fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try io.ring.setsockopt(@intFromPtr(&noop), fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = try io.ring.bind(@intFromPtr(&noop), fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.listen(@intFromPtr(c), fd, kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn ktlsUgrade(io: *Io, c: *Completion, cb: Callback, fd: posix.fd_t, tx_opt: []const u8, rx_opt: []const u8) !void {
    const TX = @as(c_int, 1);
    const RX = @as(c_int, 2);
    c.callback = cb;
    var sqe = try io.ring.setsockopt(@intFromPtr(&noop), fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(@intFromPtr(&noop), fd, linux.SOL.TLS, TX, tx_opt);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(@intFromPtr(c), fd, linux.SOL.TLS, RX, rx_opt);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn accept(io: *Io, c: *Completion, cb: Callback, fd: posix.fd_t) !void {
    c.callback = cb;
    var sqe = try io.ring.accept_direct(@intFromPtr(c), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn recv(io: *Io, c: *Completion, cb: Callback, fd: posix.fd_t) !void {
    c.callback = cb;
    var sqe = try io.recv_buffer_group.recv(@intFromPtr(c), fd, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn getRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) ![]const u8 {
    return try io.recv_buffer_group.get(cqe);
}

pub fn putRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) !void {
    try io.recv_buffer_group.put(cqe);
}

/// Close file descriptor
pub fn close(io: *Io, c: *Completion, cb: Callback, fd: linux.fd_t) !void {
    c.callback = cb;
    _ = try io.ring.close_direct(@intFromPtr(c), @intCast(fd));
}

/// Cancel any fd operations
pub fn cancel(io: *Io, c: *Completion, cb: Callback, fd: linux.fd_t) !void {
    c.callback = cb;
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = @intFromPtr(c);
}

pub fn send(io: *Io, c: *Completion, cb: Callback, fd: linux.fd_t, buffer: []const u8) !void {
    c.callback = cb;
    var sqe = try io.ring.send(@intFromPtr(c), fd, buffer, linux.MSG.NOSIGNAL);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

const yes_socket_option = std.mem.asBytes(&@as(u32, 1));

const SyscallError = @import("errno.zig").Error;

pub fn result(cqe: linux.io_uring_cqe) SyscallError!i32 {
    switch (cqe.err()) {
        .SUCCESS => return cqe.res,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}
