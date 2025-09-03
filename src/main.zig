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

var server: struct {
    root: std.fs.Dir,
} = .{
    .root = undefined,
};

pub fn main() !void {
    signal.watch();

    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    server.root = std.fs.cwd();
    // Get real/absolute path string for cwd
    const path = try server.root.realpathAlloc(gpa, ".");
    std.debug.print("Current working directory: {s}\n", .{path});
    defer gpa.free(path);

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
                try conn.init(&.{});
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
    unused_recv: UnusedDataBuffer = .{},
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
        const recv_buf = try self.io.getRecvBuffer(cqe);
        defer self.io.putRecvBuffer(cqe) catch {};
        const input_buf = try self.unused_recv.append(self.gpa, recv_buf);

        const res = self.hs.run(input_buf, &self.output_buf) catch |err| {
            log.info("tls handsake failed {}", .{err});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
            try self.close();
            return;
        };

        try self.unused_recv.set(self.gpa, res.unused_recv);
        if (res.send_pos > 0) {
            try self.io.send(completion.with(onSend), self.fd, res.send, .{});
            return;
        }
        if (self.hs.cipher()) |cipher| {
            // handsake done
            const unused = self.unused_recv.buffer;
            if (unused.len > 0) {
                // Handshake done but there are unused recv ciphertext. We need
                // to decrypt that before passing to the connection. There are
                // chances that we don't have full tls record in unused!
                var input_rdr = std.Io.Reader.fixed(unused);
                var output_wrt = std.Io.Writer.fixed(&.{});
                var conn: tls.Connection = .{ .cipher = cipher, .output = &output_wrt, .input = &input_rdr };
                if (conn.next() catch |err| {
                    log.err("handshake unable to decrypt unused recv {} bytes {}", .{ unused.len, err });
                    try self.close();
                    return;
                }) |cleartext| {
                    log.debug("handsake unused cleartext {}", .{cleartext.len});
                    try self.unused_recv.set(self.gpa, cleartext);
                } else {
                    log.err("hadshake parital record in unused bytes {}", .{unused.len});
                    try self.close();
                    return;
                }

                self.ktls = Ktls.init(conn.cipher);
                try self.io.ktlsUgrade(completion.with(onUpgrade), self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
                return;
            }

            self.ktls = Ktls.init(cipher);
            try self.io.ktlsUgrade(completion.with(onUpgrade), self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
            return;
        }
        try self.recv();
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.io.recv(completion.with(onRecv), self.fd);
    }

    fn onUpgrade(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));
        // TODO handle errors
        _ = try Io.result(cqe);
        const conn = try self.gpa.create(Connection);
        conn.* = .{ .gpa = self.gpa, .io = self.io, .fd = self.fd };
        try conn.init(self.unused_recv.buffer);
        self.deinit();
    }

    fn onClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Handshake = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        self.deinit();
    }

    fn deinit(self: *Handshake) void {
        // log.debug("handshake deinit", .{});
        self.unused_recv.deinit(self.gpa);
        self.gpa.destroy(self);
    }
};

const Connection = struct {
    gpa: Allocator,
    io: *Io,
    fd: fd_t,
    completion: Io.Completion = .{},
    unused_recv: UnusedDataBuffer = .{},

    file: struct {
        fd: fd_t = -1,
        path: ?[:0]const u8 = null,
        stat: ?linux.Statx = null,
        header: ?[]u8 = null,
    } = .{},
    // Pipe file descriptors used in sendfile splices.
    // Created by sync system call on first use.
    pipe_fds: [2]linux.fd_t = .{ -1, -1 },

    fn init(self: *Connection, recv_buf: []const u8) !void {
        if (recv_buf.len > 0) {
            //log.debug("connection init with {}", .{recv_buf.len});
            try self.parseHeader(recv_buf);
            return;
        }
        try self.recv();
    }

    fn recv(self: *Connection) !void {
        try self.io.recv(self.completion.with(onRecv), self.fd);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        const n = Io.result(cqe) catch |err| {
            switch (err) {
                error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                    try self.recv();
                },
                else => {
                    log.info("connection recv failed {}", .{err});
                    try self.close();
                },
            }
            return;
        };
        if (n == 0) {
            try self.close();
            return;
        }
        const recv_buf = try self.io.getRecvBuffer(cqe);
        defer self.io.putRecvBuffer(cqe) catch {};

        try self.parseHeader(recv_buf);
    }

    fn parseHeader(self: *Connection, recv_buf: []const u8) !void {
        const input_buf = try self.unused_recv.append(self.gpa, recv_buf);
        var hp: http.HeadParser = .{};
        const head_tail = hp.feed(input_buf);
        if (hp.state != .finished) {
            try self.unused_recv.set(self.gpa, input_buf);
            //log.debug("short header {s}", .{input_buf});
            // Short read, read more
            try self.recv();
            return;
        }
        const head_buf = input_buf[0..head_tail];
        const head = http.Server.Request.Head.parse(head_buf) catch |err| {
            log.info("connection head parse {}", .{err});
            try self.close();
            return;
        };
        if (head.method == .GET and head.target.len > 0) {
            //log.debug("target: {s}", .{head.target});
            const path = try self.gpa.dupeZ(u8, head.target[1..]);
            self.file.path = path;
            try self.unused_recv.set(self.gpa, input_buf[head_tail..]);

            self.file.stat = mem.zeroes(linux.Statx);
            try self.io.statx(self.completion.with(onStat), server.root.fd, path, &self.file.stat.?);
            return;
        }
        try self.close();
    }

    fn onStat(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));
        const path = self.file.path.?;
        const stat = self.file.stat.?;

        _ = Io.result(cqe) catch |err| {
            switch (err) {
                error.NoSuchFileOrDirectory => try self.notFound(),
                else => {
                    log.info("stat '{s}' failed {}", .{ path, err });
                    try self.close();
                },
            }
            return;
        };
        // TODO ovdje je prilika da provjerim etag na osnovu mtime i odlucim da mogu odgovorti s not modified

        log.debug("statx: {}", .{stat});
        try self.io.openRead(self.completion.with(onOpen), server.root.fd, path);
    }

    fn onOpen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));
        const path = self.file.path.?;
        const stat = self.file.stat.?;

        const fd = Io.result(cqe) catch |err| {
            switch (err) {
                error.NoSuchFileOrDirectory => try self.notFound(),
                else => {
                    log.info("open '{s}' failed {}", .{ path, err });
                    try self.close();
                },
            }
            return;
        };
        self.file.fd = fd;

        const header_fmt = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n";
        self.file.header = try std.fmt.allocPrint(self.gpa, header_fmt, .{stat.size});
        try self.io.send(self.completion.with(onHeader), self.fd, self.file.header.?, .{ .more = true });

        log.debug("file opened {s} fd: {}", .{ path, fd });
    }

    fn onHeader(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));
        const stat = self.file.stat.?;

        _ = try Io.result(cqe);
        self.pipe_fds = try std.posix.pipe();
        try self.io.sendfile(self.completion.with(onBody), self.fd, self.file.fd, self.pipe_fds, 0, @intCast(stat.size));
    }

    fn onBody(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.io.close(self.completion.with(onFileClose), self.file.fd);
    }

    fn onFileClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.close();
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Connection = @alignCast(@fieldParentPtr("completion", completion));

        _ = try Io.result(cqe);
        try self.close();
    }

    fn notFound(self: *Connection) !void {
        try self.io.send(self.completion.with(onSend), self.fd, not_found, .{});
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
        if (self.file.path) |path| self.gpa.free(path);
        if (self.file.header) |header| self.gpa.free(header);

        // if (self.pipe_fds[0] != -1) {
        //     if (self.loop.closePipe(self.pipe_fds)) {
        //         self.pipe_fds = .{ -1, -1 };
        //     } else |err| {
        //         log.err("tcp close pipe {}", .{err});
        //     }
        // }

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
