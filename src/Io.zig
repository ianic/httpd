const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const mem = std.mem;
const math = std.math;
const time = std.time;
const Allocator = mem.Allocator;
const fd_t = linux.fd_t;

const errno = @import("errno.zig");
const log = std.log.scoped(.io);

const Io = @This();

// from musl/include/fcnt.h
const splice_f_nonblock = 0x02;
const splice_no_offset = math.maxInt(u64);
const yes_socket_option = mem.asBytes(&@as(u32, 1));

ring: linux.IoUring = undefined,
recv_buffer_group: linux.IoUring.BufferGroup = undefined,
cqes_buf: []linux.io_uring_cqe = undefined,
cqes: []linux.io_uring_cqe = &.{},
metric: Metric = .{},

pub fn init(io: *Io, allocator: Allocator, opt: Options) !void {
    assert(opt.recv_buffers.size > 0 and opt.recv_buffers.count > 0);

    io.ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer io.ring.deinit();
    try io.ring.register_files_sparse(opt.fd_nr);

    io.cqes_buf = try allocator.alloc(linux.io_uring_cqe, @min(128, opt.entries / 2));
    errdefer allocator.free(io.cqes_buf);

    io.recv_buffer_group = try linux.IoUring.BufferGroup.init(
        &io.ring,
        allocator,
        0,
        opt.recv_buffers.size,
        opt.recv_buffers.count,
    );
    close_notify.init();
    // if (io.ring.sq.sqes.len != opt.entries or io.ring.cq.cqes.len != @as(usize, @intCast(opt.entries)) * 2)
    //     log.debug(
    //         "sqes: {}, cqes: {}, cqes_buf: {}, fds: {}, recv buffers: {}",
    //         .{ io.ring.sq.sqes.len, io.ring.cq.cqes.len, io.cqes_buf.len, opt.fd_nr, opt.recv_buffers },
    //     );
}

pub fn deinit(io: *Io, allocator: Allocator) void {
    io.recv_buffer_group.deinit(allocator);
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
        io.cqes = io.cqes[1..];
        if (cqe.user_data != 0) {
            const op: *Op = @ptrFromInt(cqe.user_data);
            const callback = op.reset(); // op can be reused during callback
            try callback(.{ .ptr = op, .cqe = cqe });
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

pub fn socket(io: *Io, op: *Op, cb: Op.Callback, addr: *const net.Address) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.socket_direct_alloc(op.prep(cb, io), addr.any.family, linux.SOCK.STREAM, 0, 0);
}

pub const ListenOption = struct {
    reuse_address: bool = true,
    kernel_backlog: u31 = 128,
};

pub fn listen(io: *Io, op: *Op, cb: Op.Callback, addr: *const net.Address, fd: fd_t, opt: ListenOption) !void {
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
    sqe = try io.ring.listen(op.prep(cb, io), fd, opt.kernel_backlog, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn ktlsUgrade(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, tx_opt: []const u8, rx_opt: []const u8) !void {
    try io.ensureSqCapacity(3);
    const TX = @as(c_int, 1);
    const RX = @as(c_int, 2);

    var sqe = try io.ring.setsockopt(0, fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls");
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(0, fd, linux.SOL.TLS, TX, tx_opt);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = try io.ring.setsockopt(op.prep(cb, io), fd, linux.SOL.TLS, RX, rx_opt);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn tcpNodelay(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.setsockopt(0, fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, yes_socket_option);
    sqe.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn accept(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.accept_direct(op.prep(cb, io), fd, null, null, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub const RecvBuffer = union(enum) {
    /// recv directly into this buffer
    buffer: []u8,
    /// select buffer the provided buffer group
    provided: void,
};

pub fn recv(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, buffer: RecvBuffer, flags: MsgFlags, timeout: ?*const linux.kernel_timespec) !void {
    try io.ensureSqCapacity(2);
    var sqe = switch (buffer) {
        .buffer => |b| try io.ring.recv(op.prep(cb, io), fd, .{ .buffer = b }, @bitCast(flags)),
        .provided => try io.recv_buffer_group.recv(op.prep(cb, io), fd, 0),
    };
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (timeout) |ts| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        _ = try io.ring.link_timeout(0, ts, 0);
    }
}

pub fn recvProvided(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, timeout: ?*const linux.kernel_timespec) !void {
    return io.recv(op, cb, fd, .{ .provided = {} }, .{}, timeout);
}

pub fn recvDirect(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, buffer: []u8, timeout: ?*const linux.kernel_timespec) !void {
    return io.recv(op, cb, fd, .{ .buffer = buffer }, .{}, timeout);
}

pub fn getProvidedBuffer(io: *Io, res: Result) ![]const u8 {
    return try io.recv_buffer_group.get(res.cqe);
}

pub fn putProvidedBuffer(io: *Io, res: Result) void {
    io.recv_buffer_group.put(res.cqe) catch unreachable;
}

pub fn peek(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, buffer: []u8) !void {
    try io.ensureSqCapacity(1);
    const flags: MsgFlags = .{ .peek = true };
    var sqe = try io.ring.recv(op.prep(cb, io), fd, .{ .buffer = buffer }, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Sends tls close notify alert
pub fn tlsCloseNotify(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.sendmsg(0, fd, &close_notify.msg, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Close file descriptor
pub fn close(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.close_direct(0, @intCast(fd));
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Cancel all operations of fd
pub fn cancel(io: *Io, fd: fd_t) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.get_sqe();
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn send(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, buffer: []const u8, flags: MsgFlags) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.send(op.prep(cb, io), fd, buffer, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn sendmsg(io: *Io, op: *Op, cb: Op.Callback, fd: fd_t, msg: *const posix.msghdr_const, flags: MsgFlags) !void {
    try io.ensureSqCapacity(1);
    var sqe = try io.ring.sendmsg(op.prep(cb, io), fd, msg, @bitCast(flags));
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn statx(io: *Io, op: *Op, cb: Op.Callback, dir: fd_t, path: [:0]const u8, stat: *linux.Statx) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.statx(op.prep(cb, io), dir, path, 0, linux.STATX_BASIC_STATS, stat);
}

pub fn openAt(io: *Io, op: *Op, cb: Op.Callback, dir: fd_t, path: [*:0]const u8, flags: linux.O, mode: linux.mode_t) !void {
    try io.ensureSqCapacity(1);
    _ = try io.ring.openat_direct(op.prep(cb, io), dir, path, flags, mode, linux.IORING_FILE_INDEX_ALLOC);
}

pub fn openRead(io: *Io, op: *Op, cb: Op.Callback, dir: fd_t, path: [:0]const u8, stat: ?*linux.Statx) !void {
    try io.ensureSqCapacity(2);
    if (stat) |s| {
        var sqe = try io.ring.statx(0, dir, path, 0, linux.STATX_BASIC_STATS, s);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    return io.openAt(op, cb, dir, path, .{ .ACCMODE = .RDONLY, .CREAT = false }, 0o666);
}

pub fn sendfile(io: *Io, op: *Op, cb: Op.Callback, fd_out: fd_t, fd_in: fd_t, pipe_fds: [2]fd_t, offset: u64, len: u32) !void {
    try io.ensureSqCapacity(2);
    var sqe = try io.ring.splice(0, fd_in, offset, pipe_fds[1], splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + splice_f_nonblock;
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_CQE_SKIP_SUCCESS | linux.IOSQE_FIXED_FILE;
    sqe = try io.ring.splice(op.prep(cb, io), pipe_fds[0], splice_no_offset, fd_out, splice_no_offset, len);
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + splice_f_nonblock;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn pipe(io: *Io, op: *Op, cb: Op.Callback, fds: *[2]fd_t) !void {
    try io.ensureSqCapacity(1);

    const ring = &io.ring;
    const sqe = try ring.get_sqe();
    const OP_PIPE = 62;
    sqe.prep_rw(@enumFromInt(OP_PIPE), 0, @intFromPtr(fds), 0, 0);
    const file_index: u32 = linux.IORING_FILE_INDEX_ALLOC;
    sqe.splice_fd_in = @bitCast(file_index); //  sqe_file_index: u32
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.user_data = op.prep(cb, io);
}

pub fn result(cqe: linux.io_uring_cqe) errno.Error!i32 {
    switch (cqe.err()) {
        .SUCCESS => return cqe.res,
        else => |e| return errno.toError(e),
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

pub const Result = struct {
    ptr: *Op,
    cqe: linux.io_uring_cqe,

    fn value(r: Result) errno.Error!i32 {
        switch (r.cqe.err()) {
            .SUCCESS => return r.cqe.res,
            else => |e| return errno.toError(e),
        }
    }

    pub fn fd(r: Result) errno.Error!fd_t {
        return try r.value();
    }

    pub fn ok(r: Result) errno.Error!void {
        assert(try r.value() == 0);
    }

    pub fn bytes(r: Result) errno.Error!usize {
        return @intCast(try r.value());
    }

    pub fn parentPtr(r: Result, comptime T: type, comptime field_name: []const u8) *T {
        return @alignCast(@fieldParentPtr(field_name, r.ptr));
    }
};

pub const Op = struct {
    const Callback = *const fn (Result) anyerror!void;

    callback: ?Callback = null,

    /// True if operation for this completion is still in the submission queue,
    /// in the kernel or in the completion queue.
    /// False if callback is fired and completion can be reused.
    pub fn active(self: *Op) bool {
        return self.callback != null;
    }

    /// Arms operation with callback and returns sqe user_data
    fn prep(self: *Op, cb: Op.Callback, io: *Io) u64 {
        assert(!self.active());
        self.callback = cb;
        io.metric.submitted();
        return @intFromPtr(self);
    }

    fn reset(self: *Op) Op.Callback {
        assert(self.active());
        defer self.callback = null;
        return self.callback.?;
    }
};

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_COOP_TASKRUN | linux.IORING_SETUP_TASKRUN_FLAG,
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

test "pipe" {
    const testing = std.testing;
    const gpa = testing.allocator;

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = 128,
        .fd_nr = 128,
        .recv_buffers = .{ .count = 1, .size = 4096 },
    });
    defer io.deinit(gpa);

    var handler: struct {
        op: Op = .{},
        res: ?Result = null,
        fds: [2]fd_t = .{ -1, -1 },
        fn onComplete(res: Result) anyerror!void {
            const self: *@This() = @fieldParentPtr("op", res.ptr);
            self.res = res;
        }
    } = .{};

    try io.pipe(&handler.op, @TypeOf(handler).onComplete, &handler.fds);
    while (handler.res == null) {
        try io.tick();
    }
    try handler.res.?.ok();
    try testing.expect(handler.fds[0] >= 0);
    try testing.expect(handler.fds[1] > 0);
    //std.debug.print("fds: {any}\n", .{handler.fds});
}
