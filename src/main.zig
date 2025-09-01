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
        try self.io.socket(self.completion.with(socket), &self.addr);
    }

    fn socket(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        self.fd = try Io.result(cqe);
        try self.io.listen(completion.with(listen), &self.addr, self.fd);
    }

    fn listen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        assert(0 == try Io.result(cqe));
        try self.io.accept(completion.with(accept), self.fd);
    }

    fn accept(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Listener = @alignCast(@fieldParentPtr("completion", completion));

        const fd: fd_t = Io.result(cqe) catch |err| switch (err) {
            error.OperationCanceled => return,
            else => return err,
        };

        try self.io.accept(completion.with(accept), self.fd);

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
        try self.io.recv(self.completion.with(recv), self.fd);
    }

    fn recv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        const n = Io.result(cqe) catch |err| {
            log.info("handshake recv failed {}", .{err});
            try self.io.close(completion.with(close), self.fd);
            return;
        };
        if (n == 0) {
            try self.io.close(completion.with(close), self.fd);
            return;
        }
        const input_buf = try self.input_buf.append(self.gpa, try self.io.getRecvBuffer(cqe));
        defer self.io.putRecvBuffer(cqe) catch {};

        const res = self.hs.run(input_buf, &self.output_buf) catch |err| {
            log.info("fd: {} tls handsake failed {}", .{ self.fd, err });
            try self.io.close(completion.with(close), self.fd);
            return;
        };

        try self.input_buf.set(self.gpa, res.unused_recv);
        if (res.send_pos > 0) {
            try self.io.send(completion.with(send), self.fd, res.send);
            return;
        }
        if (self.hs.cipher()) |cipher| {
            self.ktls = Ktls.init(cipher);
            try self.io.ktlsUgrade(completion.with(upgrade), self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
            return;
        }
        try self.io.recv(completion.with(recv), self.fd);
    }

    fn send(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.io.recv(completion.with(recv), self.fd);
    }

    fn upgrade(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        // TODO sto ako je nesto ostalo u input_buf
        assert(self.input_buf.buffer.len == 0);
        const conn = try self.gpa.create(Connection);
        conn.* = .{ .gpa = self.gpa, .io = self.io, .fd = self.fd };
        try conn.init();
        self.deinit();
    }

    fn close(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
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
        try self.io.recv(self.completion.with(recv), self.fd);
    }

    fn recv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
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

        try self.io.send(completion.with(send), self.fd, not_found);
    }

    fn send(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.io.close(completion.with(close), self.fd);
    }

    fn close(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
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

// Kernel structs and constants from: /usr/include/linux/tls.h or
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/tls.h
const Ktls = struct {
    const U = union(enum) {
        aes_gcm_128: AesGcm128,
        aes_gcm_256: AesGcm256,
        chacha20_poly1305: Chacha20Poly1305,
    };

    tx: U,
    rx: U,

    pub fn txBytes(k: *Ktls) []const u8 {
        return switch (k.tx) {
            inline else => |*v| mem.asBytes(v),
        };
    }

    pub fn rxBytes(k: *Ktls) []const u8 {
        return switch (k.rx) {
            inline else => |*v| mem.asBytes(v),
        };
    }

    pub const VERSION_1_2 = 0x0303;
    pub const VERSION_1_3 = 0x0304;
    pub const TX = 1;
    pub const RX = 2;

    pub const AES_GCM_128 = 51;
    pub const AES_GCM_256 = 52;
    pub const CHACHA20_POLY1305 = 54;

    pub const Info = extern struct {
        version: u16 = VERSION_1_3,
        cipher_type: u16 = mem.zeroes(u16),
    };
    pub const AesGcm128 = extern struct {
        info: Info = mem.zeroes(Info),
        iv: [8]u8 = mem.zeroes([8]u8),
        key: [16]u8 = mem.zeroes([16]u8),
        salt: [4]u8 = mem.zeroes([4]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };
    pub const AesGcm256 = extern struct {
        info: Info = mem.zeroes(Info),
        iv: [8]u8 = mem.zeroes([8]u8),
        key: [32]u8 = mem.zeroes([32]u8),
        salt: [4]u8 = mem.zeroes([4]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };
    pub const Chacha20Poly1305 = extern struct {
        info: Info = mem.zeroes(Info),
        iv: [12]u8 = mem.zeroes([12]u8),
        key: [32]u8 = mem.zeroes([32]u8),
        salt: [0]u8 = mem.zeroes([0]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };

    fn init(cipher: tls.Cipher) Ktls {
        switch (cipher) {
            .AES_128_GCM_SHA256 => |keys| {
                const k = makeKeys(AesGcm128, .{ .cipher_type = AES_GCM_128 }, keys);
                return .{
                    .tx = .{ .aes_gcm_128 = k.tx },
                    .rx = .{ .aes_gcm_128 = k.rx },
                };
            },
            .AES_256_GCM_SHA384 => |keys| {
                const k = makeKeys(AesGcm256, .{ .cipher_type = AES_GCM_256 }, keys);
                return .{
                    .tx = .{ .aes_gcm_256 = k.tx },
                    .rx = .{ .aes_gcm_256 = k.rx },
                };
            },
            .CHACHA20_POLY1305_SHA256 => |keys| {
                const k = makeKeys(Chacha20Poly1305, .{ .cipher_type = CHACHA20_POLY1305 }, keys);
                return .{
                    .tx = .{ .chacha20_poly1305 = k.tx },
                    .rx = .{ .chacha20_poly1305 = k.rx },
                };
            },
            else => unreachable,
        }
    }

    fn makeKeys(comptime T: type, info: Info, keys: anytype) struct { tx: T, rx: T } {
        return .{
            .tx = makeKey(T, info, keys.encrypt_iv, keys.encrypt_key, keys.encrypt_seq),
            .rx = makeKey(T, info, keys.decrypt_iv, keys.decrypt_key, keys.decrypt_seq),
        };
    }

    fn makeKey(comptime T: type, info: Info, iv: anytype, key: anytype, seq: u64) T {
        const salt_size = @sizeOf(@FieldType(T, "salt"));
        var t: T = .{
            .info = info,
            .salt = iv[0..salt_size].*,
            .iv = if (iv.len > salt_size) iv[salt_size..].* else @splat(0),
            .key = key,
        };
        std.mem.writeInt(u64, &t.rec_seq, seq, .big);
        return t;
    }
};

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
