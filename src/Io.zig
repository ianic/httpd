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

pub fn peek(io: *Io) !linux.io_uring_cqe {
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
        if (cqe.user_data == UserData.skip) {
            io.advance();
            continue;
        }
        return cqe;
    }
}

pub fn advance(io: *Io) void {
    io.cqes = io.cqes[1..];
}

pub fn socket(io: *Io, ud: u64, addr: *const net.Address) !void {
    _ = try io.ring.socket_direct_alloc(userData(.socket, ud), addr.any.family, linux.SOCK.STREAM, 0, 0);
}

pub fn listen(io: *Io, ud: u64, addr: *const net.Address, fd: posix.fd_t) !void {
    const reuse_address = true;
    const kernel_backlog: u31 = 128;
    var sqe: *linux.io_uring_sqe = undefined;
    if (reuse_address) {
        sqe = try io.ring.setsockopt(UserData.skip, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try io.ring.setsockopt(UserData.skip, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = try io.ring.bind(UserData.skip, fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.listen(userData(.listen, ud), fd, kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn ktlsUgrade(io: *Io, ud: u64, fd: posix.fd_t, tx_opt: []const u8, rx_opt: []const u8) !void {
    const TX = @as(c_int, 1);
    const RX = @as(c_int, 2);

    var sqe = try io.ring.setsockopt(UserData.skip, fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(UserData.skip, fd, linux.SOL.TLS, TX, tx_opt);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(userData(.ktls_upgrade, ud), fd, linux.SOL.TLS, RX, rx_opt);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn accept(io: *Io, ud: u64, fd: posix.fd_t) !void {
    var sqe = try io.ring.accept_direct(userData(.accept, ud), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn recv(io: *Io, ud: u64, fd: posix.fd_t) !void {
    var sqe = try io.recv_buffer_group.recv(userData(.recv, ud), fd, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn getRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) ![]const u8 {
    return try io.recv_buffer_group.get(cqe);
}

pub fn putRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) !void {
    try io.recv_buffer_group.put(cqe);
}

/// Close file descriptor
pub fn close(io: *Io, ud: u64, fd: linux.fd_t) !void {
    _ = try io.ring.close_direct(userData(.close, ud), @intCast(fd));
}

/// Cancel any fd operations
pub fn cancel(io: *Io, ud: u64, fd: linux.fd_t) !void {
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = userData(.cancel, ud);
}

pub fn send(io: *Io, ud: u64, fd: linux.fd_t, buffer: []const u8) !void {
    var sqe = try io.ring.send(userData(.send, ud), fd, buffer, linux.MSG.NOSIGNAL);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Append operation to user data. Preserve other 56 bits.
fn userData(operation: Operation, ud: u64) u64 {
    var udo: UserData = @bitCast(ud);
    udo.operation = operation;
    return @bitCast(udo);
}

const UserData = packed struct {
    operation: Operation, // 8
    _: u56,

    // Reserved values
    const skip: u64 = 0xff_ff_ff_ff_ff_ff_ff_ff;
};

pub const Operation = enum(u8) {
    nop,
    socket,
    setsockopt,
    bind,
    listen,
    accept,
    recv,
    close,
    cancel,
    send,
    ktls_upgrade,
};

fn decodeUserData(user_data: u64) struct { Operation, u32 } {
    return .{
        @enumFromInt(@as(u8, @truncate(user_data >> 32))),
        @truncate(user_data),
    };
}

const yes_socket_option = std.mem.asBytes(&@as(u32, 1));

const SyscallError = @import("errno.zig").Error;

pub fn result(cqe: linux.io_uring_cqe) SyscallError!i32 {
    switch (cqe.err()) {
        .SUCCESS => return cqe.res,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}
