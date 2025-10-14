/// TLS server handshake. After successfull upgrade to the https returns file
/// descriptor to the server.
const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const time = std.time;
const linux = std.os.linux;
const fd_t = linux.fd_t;

const tls = @import("tls");
const Io = @import("Io.zig");
const Server = @import("Server.zig");
const SendBytes = @import("Connection.zig").SendBytes;
const log = std.log.scoped(.handshake);

const Handshake = @This();
const recv_timeout = 10; // timeout of the single recv/peek operation
const handshake_timeout = 30; // timeout of the entire handshake
// Guards against inifinte peek loop.
// Peek operation can return n bytes which are not valid handshake message. If
// the connection is broken we will never recive more bytes nor get EndOfStrem
// resulting in infite loop.

server: *Server,
io: *Io,
fd: fd_t,
op: Io.Op = .{},
/// tls keys in kernel format
ktls: tls.Ktls = undefined,
/// tls handsake algorithm
hs: tls.nonblock.Server = undefined,
/// buffer used for both read client messages and write server flight messages
buffer: [tls.output_buffer_len]u8 = undefined,
recv_op: Recv = undefined,
send_op: SendBytes = undefined,
timer: time.Timer = undefined,

pub fn init(self: *Handshake, config: tls.config.Server) !void {
    self.hs = .init(config);
    self.recv_op = .{
        .io = self.io,
        .fd = self.fd,
        .buffer = &self.buffer,
        .vtable = .{
            .ptr = self,
            .success = onRecv,
            .fail = onError,
        },
    };
    self.send_op = .{
        .io = self.io,
        .fd = self.fd,
        .vtable = .{
            .ptr = self,
            .success = onSend,
            .fail = onError,
        },
    };
    self.timer = try time.Timer.start();
    try self.recv();
}

fn onRecv(ptr: *anyopaque, buf: []const u8) anyerror!void {
    const self: *Handshake = @ptrCast(@alignCast(ptr));
    if (self.hs.done()) {
        try self.upgrade();
        return;
    }

    var hs_timer = try time.Timer.start();
    const hs_res = self.hs.run(buf, &self.buffer) catch |err| return try self.shutdown(err);
    self.server.metric.handshake.duration +%= hs_timer.read();
    self.recv_op.take(hs_res.recv_pos);

    if (hs_res.send_pos > 0) {
        // server flight
        try self.send_op.prep(hs_res.send, false);
        return;
    }
    if (self.hs.done()) {
        // Hanshake done. Discard peeked bytes consumed in handshake leave
        // the rest in the tcp buffer to be decompressed by kernel and
        // consumed in connection.
        try self.recv_op.recvExact(hs_res.recv_pos);
        return;
    }
    // short read, get more
    try self.recv();
}

fn recv(self: *Handshake) !void {
    if (self.timer.read() > handshake_timeout * time.ns_per_s) {
        try self.shutdown(error.OperationCanceled);
        return;
    }
    if (self.hs.state == .init) {
        // Read client hello message in the buffer
        try self.recv_op.recv();
        return;
    }
    // Peek client flight 2. We will later read bytes consumed in handshake
    // leaving possible encrypted message part in the tcp buffer.
    try self.recv_op.peek();
}

fn shutdown(self: *Handshake, maybe_err: ?anyerror) !void {
    if (maybe_err) |err| switch (err) {
        // timeout or server close
        error.OperationCanceled,
        // clean tcp connection close
        error.EndOfFile,
        error.EndOfStream,
        // broken tcp connection
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.IOError,
        => {},
        else => {
            // unexpected error
            log.warn("{} failed {}", .{ self.fd, err });
            if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace);
        },
    };

    try self.io.close(self.fd);
    self.deinit();
}

fn onSend(ptr: *anyopaque) !void {
    const self: *Handshake = @ptrCast(@alignCast(ptr));
    try self.recv();
}

fn onError(ptr: *anyopaque, err: anyerror) !void {
    const self: *Handshake = @ptrCast(@alignCast(ptr));
    try self.shutdown(err);
}

fn upgrade(self: *Handshake) !void {
    // upgrade connection, push cipher to the kernel
    self.ktls = tls.Ktls.init(self.hs.cipher().?);
    try self.io.ktlsUgrade(&self.op, onUpgrade, self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
}

fn onUpgrade(res: Io.Result) !void {
    const self = res.parentPtr(Handshake, "op");
    res.ok() catch |err| return try self.shutdown(err);
    // cipher keys are int the kernel
    // create connection to handle cleartext stream
    try self.server.connect(.https, self.fd);
    self.deinit();
}

fn deinit(self: *Handshake) void {
    self.server.destroy(self);
}

const Recv = struct {
    const Self = @This();

    io: *Io,
    op: Io.Op = .{},
    fd: fd_t,
    vtable: struct {
        ptr: *anyopaque,
        success: *const fn (*anyopaque, []const u8) anyerror!void,
        fail: *const fn (*anyopaque, anyerror) anyerror!void,
    },

    buffer: []u8,
    end: usize = 0,
    count: usize = 0,

    offset: usize = 0,
    recv_timeout: linux.kernel_timespec = .{ .sec = recv_timeout, .nsec = 0 },
    kind: enum {
        recv,
        peek,
    } = undefined,

    pub fn recv(self: *Self) !void {
        self.kind = .recv;
        self.count = 0;
        try self.prep();
    }

    pub fn recvExact(self: *Self, n: usize) !void {
        self.count = if (self.kind == .peek) n - self.end else n;
        self.kind = .recv;
        try self.prep();
    }

    pub fn peek(self: *Self) !void {
        self.kind = .peek;
        self.count = 0;
        try self.prep();
    }

    fn prep(self: *Self) !void {
        const n = if (self.count > 0) self.count else self.buffer.len - self.end;
        const buf = self.buffer[self.end..][0..n];
        try self.io.recv(&self.op, onComplete, self.fd, .{ .buffer = buf }, .{ .peek = self.kind == .peek }, &self.recv_timeout);
    }

    fn onComplete(res: Io.Result) !void {
        const self = res.parentPtr(Self, "op");
        self.onCompleteFallible(res) catch |err| {
            try self.vtable.fail(self.vtable.ptr, err);
        };
    }

    fn onCompleteFallible(self: *Self, res: Io.Result) !void {
        const n = res.bytes() catch |err| return switch (err) {
            error.SignalInterrupt => try self.prep(),
            else => err,
        };
        if (n == 0) {
            return error.EndOfStream;
        }
        if (self.kind == .peek) {
            _ = try self.vtable.success(self.vtable.ptr, self.buffer[0 .. self.end + n]);
            return;
        }
        self.end += n;
        if (self.count > 0) {
            self.count -= n;
            if (self.count > 0) return try self.prep();
        }
        try self.vtable.success(self.vtable.ptr, self.buffer[0..self.end]);
    }

    // n bytes is consumed from the buffer
    pub fn take(self: *Self, n: usize) void {
        if (n == 0 or self.kind == .peek) return;
        assert(n <= self.end);
        if (n == self.end) {
            self.end = 0;
            return;
        }
        std.mem.copyForwards(u8, self.buffer, self.buffer[n..self.end]);
        self.offset = n;
    }
};
