/// Static site root.
root: fs.Dir = undefined,
/// Linux pipes used in sendfile and discard io operations. Pool allows reusing
/// pipe without create/close for each operation.
pipes: PipePool = undefined,
/// Basic metric counters.
metric: Metric = .{},

gpa: Allocator,
io: *Io,
http_listener: Listener = undefined,
https_listener: Listener = undefined,
/// Tls certificate and private key pair. Null if cert argument is not provided.
/// If null https listener is not started.
tls_auth: ?tls.config.CertKeyPair = null,

// Ciphers supported by both tls handshake library and kernel
const cipher_suites = &[_]tls.config.CipherSuite{
    .AES_128_GCM_SHA256,
    .AES_256_GCM_SHA384,
    .CHACHA20_POLY1305_SHA256,
};

pub fn init(self: *Server) !void {
    const args = try Args.parse(self.gpa);
    defer args.deinit(self.gpa);
    self.root = if (args.root) |dir| dir else std.fs.cwd();
    if (args.cert) |cert_dir| {
        self.tls_auth = try tls.config.CertKeyPair.fromFilePath(self.gpa, cert_dir, "cert.pem", "key.pem");
    }

    self.pipes = .{ .gpa = self.gpa, .metric = &self.metric };
    try self.pipes.initPreheated(16);

    { // http
        const addr = try std.net.Address.resolveIp("127.0.0.1", args.http_port);
        self.http_listener = .{ .server = self, .io = self.io, .addr = addr };
        try self.http_listener.init();
    }
    if (self.tls_auth) |_| { // https
        const addr = try std.net.Address.resolveIp("127.0.0.1", args.https_port);
        self.https_listener = .{ .server = self, .io = self.io, .addr = addr, .protocol = .tls };
        try self.https_listener.init();
    }
}

pub fn deinit(self: *Server) void {
    self.pipes.deinit();
    if (self.tls_auth) |*a| a.deinit(self.gpa);
}

/// Listener has establish new connection
pub fn connect(self: *Server, protocol: Protocol, fd: fd_t) !void {
    try self.io.tcpNodelay(fd);
    switch (protocol) {
        .http, .https => {
            const conn = try self.gpa.create(Connection);
            conn.* = .{ .server = self, .gpa = self.gpa, .io = self.io, .fd = fd, .protocol = protocol };
            try conn.init();
            self.metric.conn.inc(protocol);
        },
        .tls => {
            const handshake = try self.gpa.create(Handshake);
            handshake.* = .{ .server = self, .io = self.io, .fd = fd };
            try handshake.init(.{
                .auth = if (self.tls_auth) |*a| a else null,
                .cipher_suites = cipher_suites,
            });
            self.metric.handshake.count +%= 1;
        },
    }
}

/// Destroy Connection or Handshake created in connect.
pub fn destroy(self: *Server, ptr: anytype) void {
    if (@TypeOf(ptr) == *Connection) {
        self.metric.conn.dec(ptr.protocol);
    }
    self.gpa.destroy(ptr);
}

pub fn stop(self: *Server) !void {
    try self.http_listener.close();
    if (self.tls_auth) |_| try self.https_listener.close();
}

pub const Pipe = struct {
    fds: [2]fd_t = .{ -1, -1 },
    large: bool = false,
};

const PipePool = struct {
    gpa: Allocator,
    large: std.ArrayList(Pipe) = .empty,
    small: std.ArrayList(Pipe) = .empty,
    metric: *Metric,

    fn initPreheated(self: *PipePool, count: usize) !void {
        for (0..count) |i| {
            const p = try self.create(i % 2 == 0);
            if (p.large)
                try self.large.append(self.gpa, p)
            else
                try self.small.append(self.gpa, p);
        }
    }

    pub fn deinit(self: *PipePool) void {
        for (self.large.items) |p| {
            posix.close(p.fds[0]);
            posix.close(p.fds[1]);
        }
        for (self.small.items) |p| {
            posix.close(p.fds[0]);
            posix.close(p.fds[1]);
        }
        self.large.deinit(self.gpa);
        self.small.deinit(self.gpa);
    }

    fn create(self: *PipePool, large: bool) !Pipe {
        const fds = try posix.pipe();
        var p: Pipe = .{ .fds = fds, .large = false };
        if (large) {
            // try to increase pipe size
            const F_SETPIPE_SZ = 1031;
            const rc = linux.fcntl(p.fds[1], F_SETPIPE_SZ, max_pipe_size);
            switch (linux.E.init(rc)) {
                .SUCCESS => p.large = true,
                else => |errno| log.debug("set pipe size failed {}", .{@import("errno.zig").toError(errno)}),
            }
        }
        if (p.large) {
            self.metric.pipe.large += 1;
        } else {
            self.metric.pipe.small += 1;
        }
        return p;
    }

    pub fn get(self: *PipePool, size: usize) !Pipe {
        const large = size > default_pipe_size;
        if (large) {
            if (self.large.pop()) |p| return p;
            if (self.small.pop()) |p| return p;
        } else {
            if (self.small.pop()) |p| return p;
            if (self.large.pop()) |p| return p;
        }
        return try self.create(large);
    }

    pub fn put(self: *PipePool, p: Pipe) !void {
        if (p.large) {
            try self.large.append(self.gpa, p);
            return;
        }
        try self.small.append(self.gpa, p);
    }

    const default_pipe_size = 64 * 1024;
    const max_pipe_size = 1024 * 1024;
};

pub const Protocol = enum {
    /// plain http
    http,
    /// during tls handshake
    tls,
    /// after tls handsake if finished
    https,
};

pub const Metric = struct {
    conn: struct {
        http: Gauge = .{},
        https: Gauge = .{},

        fn inc(self: *@This(), protocol: Protocol) void {
            switch (protocol) {
                .http => self.http.inc(),
                .https => self.https.inc(),
                .tls => {},
            }
        }

        fn dec(self: *@This(), protocol: Protocol) void {
            switch (protocol) {
                .http => self.http.dec(),
                .https => self.https.dec(),
                .tls => {},
            }
        }

        pub fn count(self: @This()) usize {
            return self.http.current + self.https.current;
        }
    } = .{},
    handshake: struct {
        count: usize = 0,
        duration: usize = 0,
    } = .{},
    files: struct {
        not_found: usize = 0,
        count: usize = 0,
        sendfile_more: usize = 0,
        bytes: usize = 0,
    } = .{},
    pipe: struct {
        large: usize = 0,
        small: usize = 0,
    } = .{},

    const Gauge = struct {
        current: usize = 0,
        total: usize = 0,
        max: usize = 0,

        fn inc(g: *Gauge) void {
            g.current += 1;
            g.total +%= 1;
            g.max = @max(g.max, g.current);
        }

        fn dec(g: *Gauge) void {
            g.current -= 1;
        }
    };
};

const Args = struct {
    root: ?fs.Dir = null,
    cert: ?fs.Dir = null,
    http_port: u16 = 8080,
    https_port: u16 = 8443,

    fn deinit(self: Args, gpa: Allocator) void {
        _ = self;
        _ = gpa;
    }

    pub fn parse(gpa: Allocator) !Args {
        _ = gpa;
        var iter = std.process.args();
        _ = iter.next();
        var args: Args = .{};

        while (iter.next()) |arg| {
            if (parseInt("http-port", arg, &iter)) |v| args.http_port = v;
            if (parseInt("https-port", arg, &iter)) |v| args.https_port = v;
            if (parseDir("root", arg, &iter)) |v| args.root = v;
            if (parseDir("cert", arg, &iter)) |v| args.cert = v;
        }
        return args;
    }

    fn parseDir(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?fs.Dir {
        if (parseString(name, arg, iter)) |v| {
            return std.fs.cwd().openDir(v, .{}) catch |err| {
                fatal("cant't open root dir '{s}' {}", .{ v, err });
            };
        }
        return null;
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

    fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
        std.debug.print(fmt, args);
        std.debug.print("\n", .{});
        std.process.exit(1);
    }
};

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const fd_t = linux.fd_t;
const net = std.net;
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;

const tls = @import("tls");
const Io = @import("Io.zig");
const Listener = @import("Listener.zig");
const Connection = @import("Connection.zig");
const Handshake = @import("Handshake.zig");
const log = std.log.scoped(.server);
const Server = @This();
