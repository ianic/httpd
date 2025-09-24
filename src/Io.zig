const Io = @This();

ring: linux.IoUring = undefined,
recv_buffer_group: linux.IoUring.BufferGroup = undefined,
cqes_buf: []linux.io_uring_cqe = undefined,
cqes: []linux.io_uring_cqe = &.{},
metric: Metric = .{},
dev_null_fd: fd_t = -1,

pub fn init(io: *Io, allocator: Allocator, opt: Options) !void {
    assert(opt.recv_buffers.size > 0 and opt.recv_buffers.count > 0);

    io.ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer io.ring.deinit();
    try io.ring.register_files_sparse(opt.fd_nr);

    io.cqes_buf = try allocator.alloc(linux.io_uring_cqe, @min(128, opt.entries / 2));
    errdefer allocator.free(io.cqes_buf);

    io.dev_null_fd = try posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    io.recv_buffer_group = try linux.IoUring.BufferGroup.init(
        &io.ring,
        allocator,
        0,
        opt.recv_buffers.size,
        opt.recv_buffers.count,
    );
    close_notify.init();
    //if (io.ring.sq.sqes.len != opt.entries or io.ring.cq.cqes.len != @as(usize, @intCast(opt.entries)) * 2)
    log.debug(
        "sqes: {}, cqes: {}, cqes_buf: {}, fds: {}, recv buffers: {}",
        .{ io.ring.sq.sqes.len, io.ring.cq.cqes.len, io.cqes_buf.len, opt.fd_nr, opt.recv_buffers },
    );
}

pub fn deinit(io: *Io, allocator: Allocator) void {
    io.recv_buffer_group.deinit(allocator);
    posix.close(io.dev_null_fd);
    allocator.free(io.cqes_buf);
    io.ring.deinit();
}

/// Sumbit prepared submissions, get and process pending completions.
/// Completions are processed in chunks of max cqes_buf.len. If there are no
/// pending compeltions io_uring will wait for at least one completion to appear
/// in the completion queue.
pub fn tick(io: *Io) !void {
    io.getCqes() catch |err| switch (err) {
        error.SignalInterrupt => return,
        else => return err,
    };

    var timer = try time.Timer.start();
    while (io.cqes.len > 0) {
        const cqe = io.cqes[0];
        if (cqe.user_data != 0) {
            const completion: *Completion = @ptrFromInt(cqe.user_data);
            const callback = completion.callback;
            // Reset completion.callback so that completion can be reused during callback.
            completion.callback = Completion.noCallback;
            try callback(completion, cqe);
            io.metric.completed(cqe);
        } else {
            _ = result(cqe) catch |err| {
                switch (err) {
                    error.TimerExpired => {}, // timer triggers cancel of linked operation (recv)
                    error.OperationCanceled => {}, // timer is canceled by linked operation
                    else => log.debug("noop completion failed {}", .{err}),
                }
            };
        }
        io.cqes = io.cqes[1..];
    }
    io.metric.tick_duration +%= timer.read();
}

fn getCqes(io: *Io) !void {
    if (io.cqes.len > 0) {
        @branchHint(.unlikely);
        return;
    }
    _ = try io.ring.submit();
    const n = try io.ring.copy_cqes(io.cqes_buf, 1);
    io.cqes = io.cqes_buf[0..n];
    try io.ensureSqCapacity(n);
}

/// Number of unused submission queue entries
/// Matches liburing io_uring_sq_space_left
fn sqSpaceLeft(io: *Io) u32 {
    return @as(u32, @intCast(io.ring.sq.sqes.len)) - io.ring.sq_ready();
}

/// Ensure that error.SubmissionQueueFull never happens that There is enough
/// space in submission queue for count operations.
fn ensureSqCapacity(io: *Io, count: u32) !void {
    assert(count <= io.ring.sq.sqes.len);
    while (io.sqSpaceLeft() < count) {
        io.metric.err.ensure_sq_capacity +%= 1;
        _ = io.ring.submit() catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => return err,
        };
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

pub fn socket(io: *Io, c: *Completion, cb: Callback, addr: *const net.Address) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.socket_direct_alloc(cid(io, c, cb), addr.any.family, linux.SOCK.STREAM, 0, 0);
}

pub const ListenOption = struct {
    reuse_address: bool = true,
    kernel_backlog: u31 = 128,
};

pub fn listen(io: *Io, c: *Completion, cb: Callback, addr: *const net.Address, fd: fd_t, opt: ListenOption) !void {
    try io.ensureSqCapacity(4);
    var sqe: *linux.io_uring_sqe = undefined;
    if (opt.reuse_address) {
        sqe = try io.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = try io.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = try io.ring.bind(0, fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.listen(cid(io, c, cb), fd, opt.kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn ktlsUgrade(io: *Io, c: *Completion, cb: Callback, fd: fd_t, tx_opt: []const u8, rx_opt: []const u8) !void {
    try io.ensureSqCapacity(3);
    const TX = @as(c_int, 1);
    const RX = @as(c_int, 2);

    var sqe = try io.ring.setsockopt(0, fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(0, fd, linux.SOL.TLS, TX, tx_opt);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(cid(io, c, cb), fd, linux.SOL.TLS, RX, rx_opt);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn tcpNodelay(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.setsockopt(0, fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, yes_socket_option);
    sqe.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn accept(io: *Io, c: *Completion, cb: Callback, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.accept_direct(cid(io, c, cb), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub const RecvBuffer = union(enum) {
    /// recv directly into this buffer
    buffer: []u8,
    /// select buffer the provided buffer group
    provided: void,
};

pub fn recv(io: *Io, c: *Completion, cb: Callback, fd: fd_t, buffer: RecvBuffer, timeout: ?*const linux.kernel_timespec) !void {
    try io.ensureSqCapacity(2);
    var sqe = switch (buffer) {
        .buffer => |b| try io.ring.recv(cid(io, c, cb), fd, .{ .buffer = b }, 0),
        .provided => try io.recv_buffer_group.recv(cid(io, c, cb), fd, 0),
    };
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (timeout) |ts| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        _ = try io.ring.link_timeout(0, ts, 0);
    }
}

pub fn recvProvided(io: *Io, c: *Completion, cb: Callback, fd: fd_t, timeout: ?*const linux.kernel_timespec) !void {
    return io.recv(c, cb, fd, .{ .provided = {} }, timeout);
}

pub fn recvDirect(io: *Io, c: *Completion, cb: Callback, fd: fd_t, buffer: []u8, timeout: ?*const linux.kernel_timespec) !void {
    return io.recv(c, cb, fd, .{ .buffer = buffer }, timeout);
}

pub fn getProvidedBuffer(io: *Io, cqe: linux.io_uring_cqe) ![]const u8 {
    return try io.recv_buffer_group.get(cqe);
}

pub fn putProvidedBuffer(io: *Io, cqe: linux.io_uring_cqe) void {
    io.recv_buffer_group.put(cqe) catch unreachable;
}

pub fn peek(io: *Io, c: *Completion, cb: Callback, fd: fd_t, buffer: []u8) !void {
    try io.ensureSqCapacity(1);
    const flags: MsgFlags = .{ .peek = true };
    var sqe = try io.ring.recv(cid(io, c, cb), fd, .{ .buffer = buffer }, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Discard len bytes from fd to the /dev/null, without copying them to the userspace.
pub fn discard(io: *Io, c: *Completion, cb: Callback, fd_in: fd_t, pipe_fds: [2]fd_t, len: u32) !void {
    try io.ensureSqCapacity(2);
    const fd_out = io.dev_null_fd;
    var sqe = try io.ring.splice(0, fd_in, splice_no_offset, pipe_fds[1], splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + splice_f_nonblock;
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.splice(cid(io, c, cb), pipe_fds[0], splice_no_offset, fd_out, splice_no_offset, len);
    sqe.rw_flags = splice_f_nonblock;
}

/// Sends tls close notify alert before closing fd. Clean close of tls connection.
pub fn closeTls(io: *Io, c: *Completion, cb: Callback, fd: fd_t) !void {
    try io.ensureSqCapacity(2);
    var sqe = try io.ring.sendmsg(0, fd, &close_notify.msg, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
    try io.close(c, cb, fd);
}

/// Close file descriptor
pub fn close(io: *Io, c: *Completion, cb: Callback, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.close_direct(cid(io, c, cb), @intCast(fd));
}

/// Background close, fire and forget, without completion notification.
pub fn closeBg(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.close_direct(0, @intCast(fd));
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Cancel any fd operations
pub fn cancel(io: *Io, c: *Completion, cb: Callback, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = cid(io, c, cb);
}

/// Background version of cancel.
pub fn cancelBg(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
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

pub fn send(io: *Io, c: *Completion, cb: Callback, fd: fd_t, buffer: []const u8, flags: MsgFlags) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.send(cid(io, c, cb), fd, buffer, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn sendmsg(io: *Io, c: *Completion, cb: Callback, fd: fd_t, msg: *const posix.msghdr_const, flags: MsgFlags) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.sendmsg(cid(io, c, cb), fd, msg, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn statx(io: *Io, c: *Completion, cb: Callback, dir: fd_t, path: [:0]const u8, stat: *linux.Statx) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.statx(cid(io, c, cb), dir, path, 0, linux.STATX_SIZE, stat);
}

pub fn openAt(io: *Io, c: *Completion, cb: Callback, dir: fd_t, path: [*:0]const u8, flags: linux.O, mode: linux.mode_t) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.openat_direct(cid(io, c, cb), dir, path, flags, mode, linux.IORING_FILE_INDEX_ALLOC);
}

pub fn openRead(io: *Io, c: *Completion, cb: Callback, dir: fd_t, path: [:0]const u8, stat: ?*linux.Statx) !void {
    try io.ensureSqCapacity(2);
    if (stat) |s| {
        var sqe = try io.ring.statx(0, dir, path, 0, linux.STATX_BASIC_STATS, s);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    return io.openAt(c, cb, dir, path, .{ .ACCMODE = .RDONLY, .CREAT = false }, 0o666);
}

pub fn sendfile(io: *Io, c: *Completion, cb: Callback, fd_out: fd_t, fd_in: fd_t, pipe_fds: [2]fd_t, offset: u64, len: u32) !void {
    try io.ensureSqCapacity(2);
    var sqe = try io.ring.splice(0, fd_in, offset, pipe_fds[1], splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + splice_f_nonblock;
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.splice(cid(io, c, cb), pipe_fds[0], splice_no_offset, fd_out, splice_no_offset, len);
    sqe.rw_flags = splice_f_nonblock;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn result(cqe: linux.io_uring_cqe) errno.Error!i32 {
    switch (cqe.err()) {
        .SUCCESS => return cqe.res,
        else => |e| return errno.toError(e),
    }
}

pub const Callback = *const fn (c: *Completion, cqe: linux.io_uring_cqe) anyerror!void;
pub const Completion = struct {
    callback: Callback = Completion.noCallback,

    /// True if operation for this completion is still in the subission queue,
    /// in the kernel or in the completion queeue.
    /// False if callback is fired and completion can be reused.
    pub fn active(self: *Completion) bool {
        return self.callback != noCallback;
    }

    fn noCallback(_: *Completion, _: linux.io_uring_cqe) !void {
        unreachable;
    }
};

/// Completion identifier for sqe user_data field.
fn cid(io: *Io, c: *Completion, cb: Callback) u64 {
    assert(c.callback == Completion.noCallback); // must be unused
    c.callback = cb;
    io.metric.submitted();
    return @intFromPtr(c);
}

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

const Metric = struct {
    tick_duration: usize = 0,
    total: usize = 0,
    active: usize = 0, // number of in_kernel completions

    err: struct {
        no_recv_buffer: usize = 0,
        file_not_found: usize = 0,
        interrupt: usize = 0,
        file_table_overflow: usize = 0,
        canceled: usize = 0,
        eof: usize = 0,
        other: usize = 0,

        ensure_sq_capacity: usize = 0,
    } = .{},

    fn submitted(self: *Metric) void {
        self.active += 1;
        self.total +%= 1;
    }

    fn completed(self: *Metric, cqe: linux.io_uring_cqe) void {
        self.active -= 1;
        if (cqe.res >= 0) {
            @branchHint(.likely);
            return;
        }
        // count number of errors
        _ = result(cqe) catch |err| switch (err) {
            error.NoBufferSpaceAvailable => self.err.no_recv_buffer +%= 1,
            error.NoSuchFileOrDirectory => self.err.file_not_found +%= 1,
            error.SignalInterrupt => self.err.interrupt +%= 1,
            error.FileTableOverflow => self.err.file_table_overflow +%= 1,
            error.OperationCanceled => self.err.canceled +%= 1,
            error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer, error.IOError => self.err.eof +%= 1,
            else => {
                log.info("error metric unhandled {}", .{err});
                self.err.other +%= 1;
            },
        };
    }
};

var close_notify: CloseNotify = undefined;

// linux.msghdr with 2 bytes close notify alert in iov and alert record type in control
// reference: https://docs.kernel.org/networking/tls.html#send-tls-control-messages
const CloseNotify = struct {
    const tls_alert_payload = [2]u8{ 1, 0 }; // alert body: warning (1), close notify (0)

    const cmsghdr = extern struct {
        len: u32,
        _: u32 = 0,
        level: i32,
        typ: i32,
        record_type: u8,
    };

    cmsg: cmsghdr,
    iov: [1]posix.iovec_const,
    msg: linux.msghdr_const,

    fn init(self: *CloseNotify) void {
        self.iov = .{
            posix.iovec_const{
                .base = &tls_alert_payload,
                .len = tls_alert_payload.len,
            },
        };
        self.cmsg = .{
            .record_type = 21, // alert
            .level = linux.SOL.TLS,
            .typ = 1, // TLS_SET_RECORD_TYPE
            .len = @sizeOf(cmsghdr),
        };
        self.msg = .{
            .name = null,
            .control = &self.cmsg,
            .controllen = @sizeOf(cmsghdr),
            .namelen = 0,
            .flags = 0,
            .iov = &self.iov,
            .iovlen = 1,
        };
    }
};

// from musl/include/fcnt.h
const splice_f_nonblock = 0x02;
const splice_no_offset = math.maxInt(u64);
const yes_socket_option = mem.asBytes(&@as(u32, 1));

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const mem = std.mem;
const math = std.math;
const time = std.time;
const Allocator = std.mem.Allocator;
const fd_t = linux.fd_t;
const errno = @import("errno.zig");
const log = std.log.scoped(.io);
