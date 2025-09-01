const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const http = std.http;
const assert = std.debug.assert;
const fd_t = posix.fd_t;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = @import("Io.zig");
const log = std.log.scoped(.main);
const tls = @import("tls");
const mem = std.mem;
const signal = @import("signal.zig");
const Ktls = @import("Ktls.zig");

pub fn main() !void {
    signal.watch();

    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = 256,
        .fd_nr = 1024,
        .recv_buffers = .{ .count = 1, .size = 4096 },
    });
    defer io.deinit(gpa);

    const cert_dir = try std.fs.cwd().openDir("../tls.zig/example/cert", .{});
    var auth = try tls.config.CertKeyPair.fromFilePath(gpa, cert_dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer auth.deinit(gpa);
    const tls_config: tls.config.Server = .{
        .auth = &auth,
        // only ciphers supported by both handshake library and kernel
        .cipher_suites = &[_]tls.config.CipherSuite{
            .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            .CHACHA20_POLY1305_SHA256,
        },
    };

    const http_addr = try std.net.Address.resolveIp("127.0.0.1", 8080);
    const https_addr = try std.net.Address.resolveIp("127.0.0.1", 8443);
    var http_listener: Listener = .{ .gpa = gpa, .io = &io, .addr = http_addr };
    try http_listener.init();
    var https_listener: Listener = .{ .gpa = gpa, .io = &io, .addr = https_addr, .protocol = .{ .https = tls_config } };
    try https_listener.init();

    while (true) {
        io.tick() catch |err| switch (err) {
            error.SignalInterrupt => {},
            else => return err,
        };
        if (signal.get()) |sig| switch (sig) {
            posix.SIG.TERM, posix.SIG.INT => break,
            else => {
                log.info("ignoring signal {}", .{sig});
            },
        };
    }

    try http_listener.close();
    try https_listener.close();
    try io.drain();
}

const Listener = struct {
    const Protocol = union(enum) {
        http: void,
        https: tls.config.Server,
    };

    gpa: Allocator,
    io: *Io,
    addr: net.Address,
    protocol: Protocol = .http,
    fd: fd_t = -1,
    completion: Io.Completion = .{},

    fn init(self: *Listener) !void {
        try self.io.socket(self.completion.with(onSocket), &self.addr);
    }

    fn onSocket(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        self.fd = try Io.result(cqe);
        try self.io.listen(completion.with(onListen), &self.addr, self.fd);
    }

    fn onListen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        assert(0 == try Io.result(cqe));
        try self.accept();
    }

    fn accept(self: *Listener) !void {
        try self.io.accept(self.completion.with(onAccept), self.fd);
    }

    fn onAccept(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        const fd: fd_t = Io.result(cqe) catch |err| switch (err) {
            error.OperationCanceled => return,
            else => return err,
        };
        try self.accept();
        switch (self.protocol) {
            .http => {
                const conn = try self.gpa.create(Connection);
                conn.* = .{ .gpa = self.gpa, .io = self.io, .fd = fd };
                try conn.init();
            },
            .https => |config| {
                const handshake = try self.gpa.create(Handshake);
                handshake.* = .{ .gpa = self.gpa, .io = self.io, .fd = fd };
                try handshake.init(config);
            },
        }
    }

    fn close(self: *Listener) !void {
        try self.io.cancel(&Io.Completion.noop, self.fd);
    }
};

const Handshake = struct {
    gpa: Allocator,
    io: *Io,
    fd: fd_t,
    hs: tls.nonblock.Server = undefined,
    input_buf: UnusedDataBuffer = .{},
    output_buf: [tls.output_buffer_len]u8 = undefined,
    ktls: Ktls = undefined,
    completion: Io.Completion = .{},

    fn init(self: *Handshake, config: tls.config.Server) !void {
        self.hs = .init(config);
        try self.recv();
    }

    fn recv(self: *Handshake) !void {
        try self.io.recv(self.completion.with(onRecv), self.fd);
    }

    fn close(self: *Handshake) !void {
        try self.io.close(self.completion.with(onClose), self.fd);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        const n = Io.result(cqe) catch |err| {
            switch (err) {
                error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                    try self.recv();
                },
                else => {
                    log.info("fd :{} handshake recv failed {}", .{ self.fd, err });
                    try self.close();
                },
            }
            return;
        };
        if (n == 0) {
            try self.close();
            return;
        }
        const input_buf = try self.input_buf.append(self.gpa, try self.io.getRecvBuffer(cqe));
        defer self.io.putRecvBuffer(cqe) catch {};

        const res = self.hs.run(input_buf, &self.output_buf) catch |err| {
            log.info("fd: {} tls handsake failed {}", .{ self.fd, err });
            try self.close();
            return;
        };

        try self.input_buf.set(self.gpa, res.unused_recv);
        if (res.send_pos > 0) {
            try self.io.send(completion.with(onSend), self.fd, res.send);
            return;
        }
        if (self.hs.cipher()) |cipher| {
            self.ktls = Ktls.init(cipher);
            try self.io.ktlsUgrade(completion.with(onUpgrade), self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
            return;
        }
        try self.io.recv(completion.with(onRecv), self.fd);
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.io.recv(completion.with(onRecv), self.fd);
    }

    fn onUpgrade(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        // TODO sto ako je nesto ostalo u input_buf
        assert(self.input_buf.buffer.len == 0);
        const conn = try self.gpa.create(Connection);
        conn.* = .{ .gpa = self.gpa, .io = self.io, .fd = self.fd };
        try conn.init();
        self.deinit();
    }

    fn onClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        self.deinit();
    }

    fn deinit(self: *Handshake) void {
        log.debug("handshake deinit", .{});
        self.input_buf.deinit(self.gpa);
        self.gpa.destroy(self);
    }
};

const Connection = struct {
    gpa: Allocator,
    io: *Io,
    fd: fd_t,
    completion: Io.Completion = .{},

    fn init(self: *Connection) !void {
        try self.io.recv(self.completion.with(onRecv), self.fd);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        // TODO retry on interrupt, no_buffs, close on all other
        _ = try Io.result(cqe);
        const bytes = try self.io.getRecvBuffer(cqe);
        defer self.io.putRecvBuffer(cqe) catch {};

        var hp: http.HeadParser = .{};
        const n = hp.feed(bytes);
        if (hp.state == .finished) {
            // TODO close on error
            const head = try http.Server.Request.Head.parse(bytes[0..n]);
            log.debug("head: {}", .{head});
        } else {
            log.debug("http header not found", .{});
        }

        try self.io.send(completion.with(onSend), self.fd, not_found);
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.close();
    }

    fn close(self: *Connection) !void {
        try self.io.close(self.completion.with(onClose), self.fd);
    }

    fn onClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        self.deinit();
    }

    fn deinit(self: *Connection) void {
        log.debug("connection deinit", .{});
        self.gpa.destroy(self);
    }
};

pub const UnusedDataBuffer = struct {
    const Self = @This();
    buffer: []u8 = &.{},

    pub fn append(self: *Self, allocator: Allocator, data: []const u8) ![]const u8 {
        if (self.buffer.len == 0) {
            // nothing to append to
            return data;
        }
        if (data.len == 0) {
            return self.buffer;
        }
        const old_len = self.buffer.len;
        self.buffer = try allocator.realloc(self.buffer, old_len + data.len);
        @memcpy(self.buffer[old_len..], data);
        return self.buffer;
    }

    pub fn set(self: *Self, allocator: Allocator, unused: []const u8) !void {
        if (unused.ptr == self.buffer.ptr and unused.len == self.buffer.len) {
            // nothing changed
            return;
        }
        // unused is part of the self.buffer so free after dupe
        const old_buffer = self.buffer;
        if (unused.len > 0) {
            self.buffer = try allocator.dupe(u8, unused);
        } else {
            self.buffer = &.{};
        }
        if (old_buffer.len > 0) {
            allocator.free(old_buffer);
        }
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.buffer);
        self.buffer = &.{};
    }
};

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
