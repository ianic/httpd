const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const fd_t = linux.fd_t;
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

/// Static site root.
root: std.Io.Dir,
/// Where to find precompressed files.
cache: ?std.Io.Dir,
/// Basic metric counters.
metric: Metric = .{},

gpa: Allocator,
std_io: std.Io,
io: *Io,
listeners: std.AutoArrayHashMapUnmanaged(*Listener, void) = .empty,
connections: std.AutoArrayHashMapUnmanaged(*Connection, void) = .empty,
/// Tls config with certificate and private key pair.
/// If tls_config.auht is null https listener is not started.
tls_config: tls.config.Server,
timer: @import("Timer.zig"),

state: State = .active,
const State = enum {
    active,
    closing,
};

/// Ciphers supported by both tls handshake library and kernel
pub const cipher_suites = &[_]tls.config.CipherSuite{
    .AES_128_GCM_SHA256,
    .AES_256_GCM_SHA384,
    .CHACHA20_POLY1305_SHA256,
};

pub fn init(self: *Server, http_port: u16, https_port: u16) !void {
    try self.listeners.ensureUnusedCapacity(self.gpa, 2);
    // http
    {
        const addr = try std.Io.net.IpAddress.parse("0.0.0.0", http_port);
        const listener = try self.gpa.create(Listener);
        listener.* = .{ .server = self, .io = self.io, .addr = addr };
        try listener.init();
        self.listeners.putAssumeCapacity(listener, {});
    }
    // https
    if (self.tls_config.auth) |_| {
        const addr = try std.Io.net.IpAddress.parse("0.0.0.0", https_port);
        const listener = try self.gpa.create(Listener);
        listener.* = .{ .server = self, .io = self.io, .addr = addr, .protocol = .tls };
        try listener.init();
        self.listeners.putAssumeCapacity(listener, {});
    }
}

pub fn deinit(self: *Server) void {
    for (self.listeners.keys()) |listener| {
        self.gpa.destroy(listener);
    }
    self.listeners.deinit(self.gpa);
    for (self.connections.keys()) |conn| {
        self.gpa.destroy(conn);
    }
    self.connections.deinit(self.gpa);
}

/// Listener has accepted new connection
pub fn connect(self: *Server, protocol: Protocol, fd: fd_t) !void {
    if (self.state != .active) {
        try self.io.close(fd);
        return;
    }
    if (protocol != .https) { // already set
        try self.io.tcpNodelay(fd);
    }
    switch (protocol) {
        .http, .https => {
            try self.connections.ensureUnusedCapacity(self.gpa, 1);
            const conn = try self.gpa.create(Connection);
            conn.* = .{ .server = self, .gpa = self.gpa, .io = self.io, .fd = fd, .protocol = protocol };
            try conn.init();
            self.connections.putAssumeCapacity(conn, {});
            self.metric.conn.inc(protocol);
        },
        .tls => {
            const handshake = try self.gpa.create(Handshake);
            handshake.* = .{ .server = self, .io = self.io, .fd = fd, .timer = self.timer.clone() };
            try handshake.init(self.tls_config);
            self.metric.handshake.count +%= 1;
        },
    }
}

/// Destroy Connection, Handshake or Listener
pub fn destroy(self: *Server, ptr: anytype) void {
    if (@TypeOf(ptr) == *Connection) {
        self.metric.conn.dec(ptr.protocol);
        assert(self.connections.fetchSwapRemove(@ptrCast(ptr)) != null);
    }
    if (@TypeOf(ptr) == *Listener) {
        assert(self.listeners.fetchSwapRemove(@ptrCast(ptr)) != null);
    }
    self.gpa.destroy(ptr);
}

/// Close listeners switch state. Pending connections will be closed after
/// sending file. Keep-alive connections waiting for request will be closed on
/// read timeout.
pub fn close(self: *Server) !void {
    self.state = .closing;
    for (self.listeners.keys()) |listener| {
        try listener.close();
    }
    for (self.connections.keys()) |conn| {
        try conn.close();
    }
}

pub fn closing(self: *Server) bool {
    return self.state == .closing;
}

pub fn closed(self: *Server) bool {
    return self.listeners.count() == 0 and self.connections.count() == 0;
}

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
    files: Files = .{},

    pub const Files = struct {
        count: usize = 0,
        bytes: usize = 0,
        short_send_count: usize = 0,
        short_send_bytes: usize = 0,
    };

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
