pub fn main() !void {
    signal.watch();

    var dbga = std.heap.DebugAllocator(.{}){};
    const gpa = switch (builtin.mode) {
        .Debug => dbga.allocator(),
        else => std.heap.c_allocator,
    };
    defer switch (builtin.mode) {
        .Debug => _ = dbga.deinit(),
        else => {},
    };

    const args = try Args.parse(gpa);
    defer args.deinit(gpa);
    const root = if (args.root.len > 0)
        std.fs.cwd().openDir(args.root, .{}) catch |err| {
            fatal("cant't open root dir '{s}' {}", .{ args.root, err });
        }
    else
        std.fs.cwd();

    server = .{
        .root = root,
        .gpa = gpa,
        .pipes = .empty,
    };
    defer server.deinit();
    // // Get real/absolute path string for cwd
    // const path = try server.root.realpathAlloc(gpa, ".");
    // std.debug.print("Current working directory: {s}\n", .{path});
    // defer gpa.free(path);

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = 1024,
        .fd_nr = 1024,
        .recv_buffers = .{ .count = 256, .size = 4096 },
    });
    defer io.deinit(gpa);

    const cert_dir = try std.fs.cwd().openDir("../tls.zig/example/cert/localhost_ec", .{});
    var auth = try tls.config.CertKeyPair.fromFilePath(gpa, cert_dir, "cert.pem", "key.pem");
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
    log.info("time spend in tls handshake: {}ns {}ms", .{ tls_handshake_ns, tls_handshake_ns / std.time.ns_per_ms });
}

var tls_handshake_ns: u64 = 0;

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

    inline fn parent(completion: *Io.Completion) *Listener {
        return @alignCast(@fieldParentPtr("completion", completion));
    }

    fn init(self: *Listener) !void {
        try self.io.socket(self.completion.with(onSocket), &self.addr);
    }

    fn onSocket(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        self.fd = try Io.result(cqe);
        try self.io.listen(completion.with(onListen), &self.addr, self.fd, .{ .kernel_backlog = 1024 });
    }

    fn onListen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        assert(0 == try Io.result(cqe));
        try self.accept();
    }

    fn accept(self: *Listener) !void {
        try self.io.accept(self.completion.with(onAccept), self.fd);
    }

    fn onAccept(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);

        const fd: fd_t = Io.result(cqe) catch |err| switch (err) {
            error.SignalInterrupt => {
                try self.accept();
                return;
            },
            error.FileTableOverflow => {
                log.warn("listener accept {}", .{err});
                try self.accept();
                return;
            },
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
        try self.io.cancel(null, self.fd);
    }
};

const Handshake = struct {
    gpa: Allocator,
    io: *Io,
    /// tcp connection fd
    fd: fd_t,
    /// tls handsake algorithm
    hs: tls.nonblock.Server = undefined,
    /// buffer used for both read client messages and write server flight messages
    buffer: [tls.output_buffer_len]u8 = undefined,
    /// 0..pos part of the buffer read, written
    pos: usize = 0,
    /// pipe used in discard
    pipe: ?[2]fd_t = null,
    /// tls keys in kernel format
    ktls: Ktls = undefined,
    completion: Io.Completion = .{},
    /// pointer to the part of the buffer used in send, needed in the case of short send
    send_buf: []const u8 = &.{},
    /// ns spend in handshake algorithm
    ns: u64 = 0,

    inline fn parent(completion: *Io.Completion) *Handshake {
        return @alignCast(@fieldParentPtr("completion", completion));
    }

    fn init(self: *Handshake, config: tls.config.Server) !void {
        self.hs = .init(config);
        try self.recv();
    }

    fn recv(self: *Handshake) !void {
        if (self.hs.state == .init) {
            // Read client hello message in the buffer
            try self.io.recvInto(self.completion.with(onRecv), self.fd, self.buffer[self.pos..]);
            return;
        }
        // Peek client flight into buffer. We will later discard bytes consumed
        // in handshake leaving other bytes for connection to consume.
        self.pos = 0;
        try self.io.peek(self.completion.with(onRecv), self.fd, &self.buffer);
    }

    fn close(self: *Handshake) !void {
        try self.io.close(self.completion.with(onClose), self.fd);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const n = Io.result(cqe) catch |err| {
            switch (err) {
                error.SignalInterrupt => try self.recv(),
                error.OperationCanceled => try self.close(), // recv timeout
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
        self.ns += t.read();

        if (res.send_pos > 0) {
            // server flight
            self.send_buf = res.send;
            try self.io.send(completion.with(onSend), self.fd, self.send_buf, .{});
            return;
        }
        if (self.hs.done()) {
            // Hanshake done. Discard peeked bytes consumed in handshake leave
            // the rest in the tcp buffer to be decompressed by kernel and
            // consumed in connection.
            self.pipe = try server.getPipe();
            self.pos = res.recv_pos;
            try self.io.discard(completion.with(onDiscard), self.fd, self.pipe.?, @intCast(self.pos));
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
            try self.io.send(completion.with(onSend), self.fd, self.send_buf, .{});
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
            try self.io.discard(completion.with(onDiscard), self.fd, self.pipe.?, @intCast(self.pos));
            return;
        }
        // discard done
        // upgrade connection, push cipher to the kernel
        try server.putPipe(self.pipe.?);
        self.pipe = null;
        self.ktls = Ktls.init(self.hs.cipher().?);
        try self.io.ktlsUgrade(completion.with(onUpgrade), self.fd, self.ktls.txBytes(), self.ktls.rxBytes());
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
        const conn = try self.gpa.create(Connection);
        conn.* = .{ .gpa = self.gpa, .io = self.io, .fd = self.fd, .protocol = .https };
        try conn.init();
        self.deinit();
    }

    fn onClose(completion: *Io.Completion, _: linux.io_uring_cqe) !void {
        const self = parent(completion);
        self.deinit();
    }

    fn deinit(self: *Handshake) void {
        tls_handshake_ns += self.ns;
        if (self.pipe) |pipe| server.putPipe(pipe) catch {};
        self.gpa.destroy(self);
    }
};

const Connection = struct {
    const Protocol = enum { http, https };

    gpa: Allocator,
    io: *Io,
    fd: fd_t,
    completion: Io.Completion = .{},
    unused_recv: UnusedDataBuffer = .{},
    protocol: Protocol = .http,
    keep_alive: bool = true,

    file: struct {
        fd: fd_t = -1,
        path: ?[:0]const u8 = null,
        stat: linux.Statx = mem.zeroes(linux.Statx),
        header: ?[]u8 = null,
        header_pos: usize = 0,
        offset: usize = 0,
        pipe: [2]fd_t = .{ -1, -1 },
    } = .{},

    inline fn parent(completion: *Io.Completion) *Connection {
        return @alignCast(@fieldParentPtr("completion", completion));
    }

    fn init(self: *Connection) !void {
        try self.recv();
    }

    fn recv(self: *Connection) !void {
        try self.io.recv(self.completion.with(onRecv), self.fd);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const n = Io.result(cqe) catch |err| {
            switch (err) {
                error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                    log.info("connection recv retry on {}", .{err});
                    try self.recv();
                },
                else => {
                    log.info("connection recv failed {}", .{err});
                    try self.close();
                },
            }
            return;
        };
        if (n == 0) { // eof
            try self.close();
            return;
        }

        const recv_buf = try self.io.getRecvBuffer(cqe);
        try self.parseHeader(recv_buf);
        self.io.putRecvBuffer(cqe);
    }

    fn parseHeader(self: *Connection, recv_buf: []const u8) !void {
        const input_buf = try self.unused_recv.append(self.gpa, recv_buf);
        var hp: http.HeadParser = .{};
        const head_tail = hp.feed(input_buf);
        if (hp.state != .finished) {
            try self.unused_recv.set(self.gpa, input_buf);
            // short read, read more
            try self.recv();
            return;
        }
        const head_buf = input_buf[0..head_tail];
        const head = http.Server.Request.Head.parse(head_buf) catch |err| {
            log.info("connection head parse {}", .{err});
            try self.close();
            return;
        };
        const content_length: u64 = head.content_length orelse 0;
        self.keep_alive = head.keep_alive;
        if (head.method == .GET and content_length == 0) {
            // open target file
            const path = if (head.target.len <= 1)
                try self.gpa.dupeZ(u8, "index.html")
            else if (head.target[head.target.len - 1] == '/')
                try std.fmt.allocPrintSentinel(self.gpa, "{s}index.html", .{head.target[1..]}, 0)
            else
                try self.gpa.dupeZ(u8, head.target[1..]);
            self.file.path = path;
            try self.unused_recv.set(self.gpa, input_buf[head_tail..]);
            try self.io.openRead(self.completion.with(onOpen), server.root.fd, path, &self.file.stat);
            return;
        }
        // bad request
        try self.close();
    }

    fn onOpen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const file = &self.file;
        const fd = Io.result(cqe) catch |err| {
            switch (err) {
                error.NoSuchFileOrDirectory => {
                    log.info("not found '{s}'", .{file.path.?});
                    self.file.header = try Header.notFound(self.gpa, self.keep_alive);
                    try self.io.send(self.completion.with(onHeader), self.fd, self.file.header.?, .{ .more = true });
                },
                else => {
                    log.info("open '{s}' failed {}", .{ file.path.?, err });
                    try self.close();
                },
            }
            return;
        };
        file.fd = fd;

        const stat = std.fs.File.Stat.fromLinux(file.stat);
        if (stat.kind != .file) {
            log.err("not a file '{s}'", .{file.path.?});
            try self.fileClose();
            return;
        }
        //log.info("ok {d} '{s}' size: {d} keep-alive: {}", .{ self.fd, file.path.?, file.stat.size, self.keep_alive });
        self.file.header = try Header.ok(self.gpa, file.path.?, file.stat.size, self.keep_alive);
        try self.io.send(self.completion.with(onHeader), self.fd, self.file.header.?, .{ .more = true });
    }

    fn onHeader(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const file = &self.file;
        file.header_pos += @intCast(Io.result(cqe) catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.info("connection header send failed {}", .{err}),
            }
            try self.close();
            return;
        });
        if (file.header_pos < file.header.?.len) {
            // short send send more
            try self.io.send(completion.with(onHeader), self.fd, file.header.?[file.header_pos..], .{ .more = true });
            return;
        }
        // release header
        self.gpa.free(file.header.?);
        file.header = null;
        file.header_pos = 0;
        if (file.fd == -1) {
            // just header
            try self.close();
            return;
        }
        // send body
        const pipe = try server.getPipe();
        file.pipe = pipe;
        try self.io.sendfile(completion.with(onBody), self.fd, self.file.fd, pipe, 0, @intCast(file.stat.size));
    }

    fn onBody(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const file = &self.file;
        // handle result
        file.offset += @intCast(Io.result(cqe) catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.info("connection body send failed {}", .{err}),
            }
            try self.fileClose();
            return;
        });
        if (file.offset < file.stat.size) {
            // short send, send the rest of the file
            const len = file.stat.size - file.offset;
            try self.io.sendfile(completion.with(onBody), self.fd, file.fd, file.pipe, @intCast(file.offset), @intCast(len));
            return;
        }
        // cleanup
        try self.fileClose();
    }

    fn fileClose(self: *Connection) !void {
        const file = &self.file;
        if (file.path) |path| {
            self.gpa.free(path);
            file.path = null;
            try server.putPipe(file.pipe);
            file.pipe = .{ -1, -1 };
            file.offset = 0;
            file.stat = mem.zeroes(linux.Statx);
        }
        try self.io.close(self.completion.with(onFileClose), file.fd);
    }

    fn onFileClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        const file = &self.file;
        // handle result
        _ = Io.result(cqe) catch |err| switch (err) {
            error.SignalInterrupt => {
                try self.fileClose();
                return;
            },
            else => log.info("file close failed {}", .{err}),
        };
        // cleanup
        file.fd = -1;
        if (self.keep_alive) {
            // next request
            if (self.unused_recv.buffer.len > 0) {
                log.info("keep_alive unused_recv: {}", .{self.unused_recv.buffer.len});
                try self.parseHeader(&.{});
            } else {
                try self.recv();
            }
            return;
        }
        // close connection
        try self.close();
    }

    fn close(self: *Connection) !void {
        const completion = self.completion.with(onClose);
        if (self.protocol == .https) {
            try self.io.closeTls(completion, self.fd);
            return;
        }
        try self.io.close(completion, self.fd);
    }

    fn onClose(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self = parent(completion);
        _ = Io.result(cqe) catch |err| switch (err) {
            error.SignalInterrupt => {
                try self.close();
                return;
            },
            else => log.info("connection close failed {}", .{err}),
        };
        //log.info("{} close", .{self.fd});
        self.deinit();
    }

    fn deinit(self: *Connection) void {
        if (self.file.path) |path| self.gpa.free(path);
        if (self.file.header) |header| self.gpa.free(header);
        self.unused_recv.deinit(self.gpa);
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
        // log.warn("unused append {} {}", .{ self.buffer.len, data.len });
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

var server: Server = undefined;

const Server = struct {
    gpa: Allocator,
    root: std.fs.Dir,
    pipes: std.ArrayList([2]fd_t) = .empty,

    fn deinit(self: *Server) void {
        self.pipes.deinit(self.gpa);
    }

    fn getPipe(self: *Server) ![2]fd_t {
        if (self.pipes.pop()) |p| {
            return p;
        }
        const p = try posix.pipe();
        { // raise pipe size
            const F_SETPIPE_SZ = 1031;
            const rc = linux.fcntl(p[1], F_SETPIPE_SZ, set_pipe_size);
            switch (linux.E.init(rc)) {
                .SUCCESS => {},
                else => |errno| log.info("set pipe failed {}", .{@import("errno.zig").toError(errno)}),
            }
        }
        return p;
    }

    fn putPipe(self: *Server, p: [2]fd_t) !void {
        try self.pipes.append(self.gpa, p);
    }
};

// Limits sendfile chunk. default is 64K.
// 1M is Linux max: cat /proc/sys/fs/pipe-max-size
const set_pipe_size = 1048576;

const Header = struct {
    const connection_keep_alive = "Connection: keep-alive";
    const connection_close = "Connection: close";

    fn ok(gpa: Allocator, file: [:0]const u8, size: usize, keep_alive: bool) ![]u8 {
        const fmt = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "{s}\r\n\r\n";

        return try std.fmt.allocPrint(gpa, fmt, .{
            contentType(file),
            size,
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notFound(gpa: Allocator, keep_alive: bool) ![]u8 {
        const fmt = "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Length: 0\r\n" ++
            "{s}\r\n\r\n";

        return try std.fmt.allocPrint(gpa, fmt, .{
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn contentType(file_name: []const u8) []const u8 {
        const mime_types = [_][2][]const u8{
            .{ ".html", "text/html; charset=utf-8" },
            .{ ".htm", "text/html; charset=utf-8" },
            .{ ".css", "text/css; charset=utf-8" },
            .{ ".js", "application/javascript" },
            .{ ".json", "application/json" },
            .{ ".png", "image/png" },
            .{ ".jpg", "image/jpeg" },
            .{ ".jpeg", "image/jpeg" },
            .{ ".gif", "image/gif" },
            .{ ".svg", "image/svg+xml" },
            .{ ".txt", "text/plain" },
            .{ ".xml", "text/xml; charset=utf-8" },
            .{ ".csv", "text/csv; charset=utf-8" },
            .{ "gz", "application/gzip" },
            .{ ".ico", "image/vnd.microsoft.icon" },
            .{ ".otf", "font/otf" },
            .{ ".pdf", "application/pdf" },
            .{ ".tar", "application/x-tar" },
            .{ ".ttf", "font/ttf" },
            .{ ".wasm", "application/wasm" },
            .{ ".webp", "image/webp" },
            .{ ".woff", "font/woff" },
            .{ ".woff2", "font/woff2" },
        };
        for (mime_types) |pair| {
            if (std.mem.endsWith(u8, file_name, pair[0])) return pair[1];
        }
        return "application/octet-stream"; // Default MIME type
    }
};

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
const builtin = @import("builtin");

const Args = struct {
    root: []const u8 = &.{},
    http_port: u16 = 8080,
    https_port: u16 = 8443,

    fn deinit(self: Args, gpa: Allocator) void {
        gpa.free(self.root);
    }

    pub fn parse(gpa: Allocator) !Args {
        var iter = std.process.args();
        _ = iter.next();
        var args: Args = .{};

        while (iter.next()) |arg| {
            if (parseInt("http-port", arg, &iter)) |v| args.http_port = v;
            if (parseInt("https-port", arg, &iter)) |v| args.https_port = v;
            if (parseString("root", arg, &iter)) |v| args.root = try gpa.dupe(u8, v);
        }
        return args;
    }

    fn parseInt(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?u16 {
        const arg_name1 = "--" ++ name ++ "=";
        const arg_name2 = "--" ++ name;

        if (std.mem.startsWith(u8, arg, arg_name1)) {
            const suffix = arg[arg_name1.len..];
            return std.fmt.parseInt(u16, suffix, 10) catch |err| fatal(
                "bad {s} value '{s}': {s}",
                .{ arg_name1, arg, @errorName(err) },
            );
        } else if (std.mem.eql(u8, arg, arg_name2)) {
            if (iter.next()) |val| {
                return std.fmt.parseInt(u16, val, 10) catch |err| fatal(
                    "bad {s} value '{s}': {s}",
                    .{ arg_name2, arg, @errorName(err) },
                );
            } else fatal(
                "missing argument to '{s}'",
                .{arg_name2},
            );
        }
        return null;
    }

    fn parseString(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?[]const u8 {
        const arg_name1 = "--" ++ name ++ "=";
        const arg_name2 = "--" ++ name;

        if (std.mem.startsWith(u8, arg, arg_name1)) {
            const suffix = arg[arg_name1.len..];
            return suffix;
        } else if (std.mem.eql(u8, arg, arg_name2)) {
            if (iter.next()) |val| {
                return val;
            } else fatal(
                "missing argument to '{s}'",
                .{arg_name2},
            );
        }
        return null;
    }
};

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt, args);
    std.debug.print("\n", .{});
    std.process.exit(1);
}
