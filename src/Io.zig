const Io = @This();

ring: linux.IoUring = undefined,
recv_buffer_group: linux.IoUring.BufferGroup = undefined,
cqes_buf: [128]linux.io_uring_cqe = undefined,
cqes: []linux.io_uring_cqe = &.{},
metric: Metric = .{},
dev_null_fd: fd_t = -1,

pub fn init(io: *Io, allocator: Allocator, opt: Options) !void {
    assert(opt.recv_buffers.size > 0 and opt.recv_buffers.count > 0);

    io.ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer io.ring.deinit();
    try io.ring.register_files_sparse(opt.fd_nr);
    io.dev_null_fd = try posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
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
    posix.close(io.dev_null_fd);
    io.ring.deinit();
}

pub fn tick(io: *Io) !void {
    if (io.cqes.len == 0) {
        _ = try io.ring.submit();
        const n = try io.ring.copy_cqes(&io.cqes_buf, 1);
        io.cqes = io.cqes_buf[0..n];
    }
    while (io.cqes.len > 0) {
        const cqe = io.cqes[0];
        if (cqe.user_data != 0) {
            const completion: *Completion = @ptrFromInt(cqe.user_data);
            const callback = completion.callback;
            // Reset completion.callback so that completion can be reused during callback.
            completion.callback = Completion.noopCallback;
            io.metric.active -= 1;
            try callback(completion, cqe);
        }
        io.cqes = io.cqes[1..];
    }
}

pub fn drain(io: *Io) !void {
    while (io.metric.active > 0) {
        io.tick() catch |err| switch (err) {
            error.SignalInterrupt => return,
            else => return err,
        };
    }
}

pub fn socket(io: *Io, c: *Completion, addr: *const net.Address) !void {
    _ = try io.ring.socket_direct_alloc(@intFromPtr(c), addr.any.family, linux.SOCK.STREAM, 0, 0);
    io.metric.sumbitted();
}

pub const ListenOption = struct {
    reuse_address: bool = true,
    kernel_backlog: u31 = 128,
};

pub fn listen(io: *Io, c: *Completion, addr: *const net.Address, fd: fd_t, opt: ListenOption) !void {
    var sqe: *linux.io_uring_sqe = undefined;
    if (opt.reuse_address) {
        sqe = try io.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try io.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = try io.ring.bind(0, fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.listen(@intFromPtr(c), fd, opt.kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

pub fn ktlsUgrade(io: *Io, c: *Completion, fd: fd_t, tx_opt: []const u8, rx_opt: []const u8) !void {
    const TX = @as(c_int, 1);
    const RX = @as(c_int, 2);

    var sqe = try io.ring.setsockopt(0, fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(0, fd, linux.SOL.TLS, TX, tx_opt);
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(@intFromPtr(c), fd, linux.SOL.TLS, RX, rx_opt);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

pub fn accept(io: *Io, c: *Completion, fd: fd_t) !void {
    var sqe = try io.ring.accept_direct(@intFromPtr(c), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

pub fn recv(io: *Io, c: *Completion, fd: fd_t) !void {
    var sqe = try io.recv_buffer_group.recv(@intFromPtr(c), fd, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

pub fn getRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) ![]const u8 {
    return try io.recv_buffer_group.get(cqe);
}

pub fn putRecvBuffer(io: *Io, cqe: linux.io_uring_cqe) !void {
    try io.recv_buffer_group.put(cqe);
}

pub fn peek(io: *Io, c: *Completion, fd: fd_t, buffer: []u8) !void {
    const flags: MsgFlags = .{ .peek = true };
    var sqe = try io.ring.recv(@intFromPtr(c), fd, .{ .buffer = buffer }, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

/// Discard len bytes from fd to the /dev/null, without copying them to the userspace.
pub fn discard(io: *Io, c: *Completion, fd_in: fd_t, pipe_fds: [2]fd_t, len: u32) !void {
    const fd_out = io.dev_null_fd;
    var sqe = try io.ring.splice(0, fd_in, splice_no_offset, pipe_fds[1], splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + SPLICE_F_NONBLOCK;
    sqe.flags |= linux.IOSQE_IO_HARDLINK;
    sqe = try io.ring.splice(@intFromPtr(c), pipe_fds[0], splice_no_offset, fd_out, splice_no_offset, len);
    sqe.rw_flags = SPLICE_F_NONBLOCK;
    io.metric.sumbitted();
}

/// Close file descriptor
pub fn close(io: *Io, c: ?*Completion, fd: fd_t) !void {
    var sqe = try io.ring.close_direct(0, @intCast(fd));
    if (c) |ptr| {
        sqe.user_data = @intFromPtr(ptr);
        io.metric.sumbitted();
    } else {
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }
}

/// Cancel any fd operations
pub fn cancel(io: *Io, c: ?*Completion, fd: fd_t) !void {
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (c) |ptr| {
        sqe.user_data = @intFromPtr(ptr);
        io.metric.sumbitted();
    } else {
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }
}

pub const MsgFlags = packed struct {
    _reserved1: u1 = 0,
    peek: bool = false,
    _reserved2: u3 = 0,
    trunc: bool = false,
    _reserved3: u8 = 0,
    no_signal: bool = true,
    more: bool = false,
    _reserved4: u16 = 0,
};

pub fn send(io: *Io, c: *Completion, fd: fd_t, buffer: []const u8, flags: MsgFlags) !void {
    var sqe = try io.ring.send(@intFromPtr(c), fd, buffer, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

pub fn statx(io: *Io, c: *Completion, dir: fd_t, path: [:0]const u8, stat: *linux.Statx) !void {
    _ = try io.ring.statx(@intFromPtr(c), dir, path, 0, linux.STATX_SIZE, stat);
    io.metric.sumbitted();
}

pub fn openAt(io: *Io, c: *Completion, dir: fd_t, path: [*:0]const u8, flags: linux.O, mode: linux.mode_t) !void {
    _ = try io.ring.openat_direct(@intFromPtr(c), dir, path, flags, mode, linux.IORING_FILE_INDEX_ALLOC);
    io.metric.sumbitted();
}

pub fn openRead(io: *Io, c: *Completion, dir: fd_t, path: [*:0]const u8) !void {
    return io.openAt(c, dir, path, .{ .ACCMODE = .RDONLY, .CREAT = false }, 0o666);
}

pub fn sendfile(io: *Io, c: *Completion, fd_out: fd_t, fd_in: fd_t, pipe_fds: [2]fd_t, offset: u64, len: u32) !void {
    var sqe = try io.ring.splice(0, fd_in, offset, pipe_fds[1], splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + SPLICE_F_NONBLOCK;
    sqe.flags |= linux.IOSQE_IO_HARDLINK;
    sqe = try io.ring.splice(@intFromPtr(c), pipe_fds[0], splice_no_offset, fd_out, splice_no_offset, len);
    sqe.rw_flags = SPLICE_F_NONBLOCK;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    io.metric.sumbitted();
}

// from musl/include/fcnt.h
const SPLICE_F_NONBLOCK = 0x02;
const splice_no_offset = std.math.maxInt(u64);

const yes_socket_option = std.mem.asBytes(&@as(u32, 1));

const SyscallError = @import("errno.zig").Error;

pub fn result(cqe: linux.io_uring_cqe) SyscallError!i32 {
    switch (cqe.err()) {
        .SUCCESS => return cqe.res,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}

const Metric = struct {
    active: usize = 0,

    fn sumbitted(self: *Metric) void {
        self.active += 1;
    }
};

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
    callback: Callback = noopCallback,

    /// Complete by calling this callback
    pub fn with(self: *Completion, callback: Callback) *Completion {
        assert(self.callback == noopCallback);
        self.callback = callback;
        return self;
    }

    /// True if operation for this completion is still in the subission queue,
    /// in the kernel or in the completion queeue.
    /// False if callback is fired and completion can be reused.
    pub fn active(self: *Completion) bool {
        return self.callback != noopCallback;
    }

    var noop: Completion = .{ .callback = noopCallback };
    fn noopCallback(_: *Completion, _: linux.io_uring_cqe) !void {}
};

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const fd_t = linux.fd_t;
const log = std.log.scoped(.io);
