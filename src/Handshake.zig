/// TLS server handshake. After successfull upgrade to the https return file
/// descriptor to the server.
const Handshake = @This();

server: *Server,
io: *Io,
/// retrun point of the io operation
completion: Io.Completion = .{},
/// pipe used in discard
pipe: ?Server.Pipe = null,
/// tcp connection fd
fd: fd_t,
/// timeout for the receive operation
recv_timeout: linux.kernel_timespec = .{ .sec = 30, .nsec = 0 },

/// tls handsake algorithm
hs: tls.nonblock.Server = undefined,
/// tls keys in kernel format
ktls: tls.Ktls = undefined,

/// buffer used for both read client messages and write server flight messages
buffer: [tls.output_buffer_len]u8 = undefined,
/// 0..pos part of the buffer read, written
pos: usize = 0,
/// pointer to the part of the buffer used in send, needed in the case of short send
send_buf: []const u8 = &.{},
/// Number of peeks; if the socket is closed but there is something in the
/// buffer peeek will retrun that bytes over and over. This limits number of
/// peeks.
peek_count: usize = 0,

inline fn parent(completion: *Io.Completion) *Handshake {
    return @alignCast(@fieldParentPtr("completion", completion));
}

pub fn init(self: *Handshake, config: tls.config.Server) !void {
    self.hs = .init(config);
    try self.recv();
}

fn recv(self: *Handshake) !void {
    if (self.hs.state == .init) {
        // Read client hello message in the buffer
        try self.io.recvDirect(&self.completion, onRecv, self.fd, self.buffer[self.pos..], &self.recv_timeout);
        return;
    }
    // Peek client flight into buffer. We will later discard bytes consumed
    // in handshake leaving other bytes for connection to consume.
    self.pos = 0;
    try self.io.peek(&self.completion, onRecv, self.fd, &self.buffer);
    self.peek_count += 1;
}

fn close(self: *Handshake) !void {
    try self.io.close(self.fd);
    self.deinit();
}

fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const n = Io.result(cqe) catch |err| {
        switch (err) {
            error.SignalInterrupt => try self.recv(),
            error.OperationCanceled => try self.close(), // recv timeout
            error.IOError => try self.close(), // connection closed
            else => {
                log.info("handshake recv failed {}", .{err});
                try self.close();
            },
        }
        return;
    };
    if (n == 0) {
        try self.close();
        return;
    }
    self.pos += @intCast(n);

    var t = try std.time.Timer.start();
    const res = self.hs.run(self.buffer[0..self.pos], &self.buffer) catch |err| {
        log.info("tls handsake failed {}", .{err});
        // if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
        try self.close();
        return;
    };
    self.server.metric.handshake.duration +%= t.read();

    if (res.send_pos > 0) {
        // server flight
        self.send_buf = res.send;
        try self.io.send(completion, onSend, self.fd, self.send_buf, .{});
        return;
    }
    if (self.hs.done()) {
        // Hanshake done. Discard peeked bytes consumed in handshake leave
        // the rest in the tcp buffer to be decompressed by kernel and
        // consumed in connection.
        self.pipe = try self.server.pipes.get(self.pos);
        self.pos = res.recv_pos;
        try self.io.discard(completion, onDiscard, self.fd, self.pipe.?.fds, @intCast(self.pos));
        return;
    }
    if (self.peek_count > 32) {
        try self.close();
        return;
    }
    // short read, get more
    try self.recv();
}

fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const n = Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.SignalInterrupt => break :brk 0,
            // client gone
            error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
            else => log.info("handshake send failed {}", .{err}),
        }
        try self.close();
        return;
    };
    if (n < self.send_buf.len) {
        // short send, send rest
        self.send_buf = self.send_buf[@intCast(n)..];
        try self.io.send(completion, onSend, self.fd, self.send_buf, .{});
        return;
    }
    // server flight sent, get client flight 2
    try self.recv();
}

fn onDiscard(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const n = Io.result(cqe) catch |err| {
        log.err("discard failed {}", .{err});
        try self.close();
        return;
    };
    self.pos -= @intCast(n);
    if (self.pos > 0) {
        // short discard
        try self.io.discard(completion, onDiscard, self.fd, self.pipe.?.fds, @intCast(self.pos));
        return;
    }
    // discard done
    // upgrade connection, push cipher to the kernel
    try self.server.pipes.put(self.pipe.?);
    self.pipe = null;
    self.ktls = tls.Ktls.init(self.hs.cipher().?);
    try self.io.ktlsUgrade(completion, onUpgrade, self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
}

fn onUpgrade(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    _ = Io.result(cqe) catch |err| {
        log.err("kernel tls upgrade failed {}", .{err});
        try self.close();
        return;
    };
    // cipher keys are int the kernel
    // create connection to handle cleartext stream
    try self.server.connect(.https, self.fd);
    self.deinit();
}

fn deinit(self: *Handshake) void {
    if (self.pipe) |p| self.server.pipes.put(p) catch {};
    self.server.destroy(self);
}

const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const linux = std.os.linux;
const fd_t = linux.fd_t;

const tls = @import("tls");
const Io = @import("Io.zig");
const Server = @import("Server.zig");
const log = std.log.scoped(.handshake);
