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

pub fn main() !void {
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
    };
    const http_addr = try std.net.Address.resolveIp("127.0.0.1", 8080);
    const https_addr = try std.net.Address.resolveIp("127.0.0.1", 8443);

    var srv: Server = .{ .gpa = gpa, .io = &io, .tls_config = tls_config };
    try srv.newListener(http_addr, .http);
    try srv.newListener(https_addr, .https);

    while (true) {
        const cqe = try io.peek();
        // TODO: handle sqe exhaustion
        try srv.complete(cqe);
        io.advance();
    }
}

const Server = struct {
    gpa: Allocator,
    io: *Io,
    tls_config: tls.config.Server,
    pool: Pool = .{},

    // fn init(srv: *Server) !void {
    //     const io = srv.io;
    //     try io.socket(@bitCast(UserData{ .kind = .http_listener }), &srv.http_addr);
    //     try io.socket(@bitCast(UserData{ .kind = .https_listener }), &srv.https_addr);
    // }

    fn newListener(self: *Server, addr: net.Address, protocol: Listener.Protocol) !void {
        const listener = try self.gpa.create(Listener);
        errdefer self.gpa.destroy(listener);
        const id = try self.pool.put(self.gpa, @intFromPtr(listener));
        errdefer self.pool.remove(self.gpa, id) catch {};
        listener.* = .{
            .srv = self,
            .id = id,
            .fd = -1,
            .addr = addr,
            .protocol = protocol,
        };
        try listener.init();
    }

    fn newConnection(self: *Server, fd: fd_t) !void {
        const conn = try self.gpa.create(Connection);
        errdefer self.gpa.destroy(conn);
        const id = try self.pool.put(self.gpa, @intFromPtr(conn));
        errdefer self.pool.remove(self.gpa, id) catch {};
        conn.* = .{
            .srv = self,
            .id = id,
            .fd = fd,
        };
        try conn.init();
    }

    fn newHandshake(self: *Server, fd: fd_t) !void {
        const hs = try self.gpa.create(Handshake);
        errdefer self.gpa.destroy(hs);
        const id = try self.pool.put(self.gpa, @intFromPtr(hs));
        errdefer self.pool.remove(self.gpa, id) catch {};
        hs.* = .{
            .srv = self,
            .id = id,
            .fd = fd,
        };
        try hs.init();
    }

    fn complete(self: *Server, cqe: linux.io_uring_cqe) !void {
        const ud: UserData = @bitCast(cqe.user_data);
        const ptr = self.pool.get(ud.id);
        switch (ud.kind) {
            .listener => try Listener.complete(@ptrFromInt(ptr), cqe),
            .connection => try Connection.complete(@ptrFromInt(ptr), cqe),
            .handshake => try Handshake.complete(@ptrFromInt(ptr), cqe),

            // .https_listener => {
            //     switch (ud.operation) {
            //         .socket => {
            //             const fd = try Io.result(cqe);
            //             try io.listen(@bitCast(UserData{ .fd = fd, .kind = .https_listener }), &self.https_addr, fd);
            //         },
            //         .listen => {
            //             assert(0 == try Io.result(cqe));
            //             try io.accept(@bitCast(ud), ud.fd);
            //         },
            //         .accept => {
            //             try io.accept(@bitCast(ud), ud.fd);

            //             const fd: fd_t = try Io.result(cqe);
            //             const hs = try self.gpa.create(Handshake);
            //             const id = self.pool.put(hs);
            //             hs.* = .{
            //                 .id = id,
            //                 .srv = self,
            //                 .fd = fd,
            //             };
            //             try hs.init();

            //             log.debug("https connection {}", .{fd});
            //         },
            //         else => unreachable,
            //     }
            // },
            // .https_handshake => {
            //     switch (ud.operation) {
            //         .recv => {
            //             const bytes = try io.getRecvBuffer(cqe);
            //             std.debug.print("{s}", .{bytes});
            //             try io.putRecvBuffer(cqe);
            //         },
            //         else => unreachable,
            //     }
            // },
            // .connection => {
            //     switch (ud.operation) {
            //         .recv => {
            //             // TODO retry on interrupt, no_buffs
            //             _ = try Io.result(cqe);
            //             const bytes = try io.getRecvBuffer(cqe);

            //             var hp: http.HeadParser = .{};
            //             const n = hp.feed(bytes);
            //             if (hp.state == .finished) {
            //                 // TODO close on error
            //                 const head = try http.Server.Request.Head.parse(bytes[0..n]);
            //                 log.debug("head: {}", .{head});
            //             } else {
            //                 log.debug("http header not found", .{});
            //             }

            //             try io.send(@bitCast(ud), ud.fd, not_found);
            //             try io.putRecvBuffer(cqe);
            //         },
            //         .send => {
            //             try io.close(@bitCast(ud), ud.fd);
            //         },
            //         .close => {
            //             log.debug("connection closed", .{});
            //         },
            //         else => unreachable,
            //     }
            // },
        }
    }
};

const UserData = packed struct {
    const Kind = enum(u8) {
        listener,
        handshake,
        connection,
    };

    operation: Io.Operation = .nop, // 8
    _: u16 = 0, //  16 - unused
    kind: Kind, // 8
    id: u32, // 32
};

comptime {
    assert(@bitSizeOf(UserData) == 64);
}

test UserData {
    try testing.expectEqual(8, @sizeOf(UserData));
    try testing.expectEqual(64, @bitSizeOf(UserData));

    const user_data: UserData = .{ .operation = .send, .kind = .connection, .id = 0x0abbccdd };
    try testing.expectEqual(0x0a_bb_cc_dd_02_00_00_09, @as(u64, @bitCast(user_data)));
}

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

const Pool = struct {
    ptrs: std.ArrayList(usize) = .empty,
    free: std.ArrayList(u32) = .empty,

    pub fn put(self: *Pool, gpa: Allocator, ptr: usize) !u32 {
        if (self.free.pop()) |idx| {
            self.ptrs.items[idx] = @intCast(ptr);
            return idx;
        }
        try self.ptrs.append(gpa, ptr);
        return @intCast(self.ptrs.items.len - 1);
    }

    pub fn get(self: *Pool, idx: u32) usize {
        return self.ptrs.items[idx];
    }

    pub fn remove(self: *Pool, gpa: Allocator, idx: u32) !void {
        if (self.ptrs.items.len - 1 == idx) {
            _ = self.ptrs.pop();
            return;
        }
        try self.free.append(gpa, idx);
    }
};

const Listener = struct {
    srv: *Server,
    id: u32,
    fd: fd_t,
    addr: net.Address,
    protocol: Protocol = .http,

    const Protocol = enum { http, https };

    fn userData(self: *Listener) u64 {
        return @bitCast(UserData{ .id = self.id, .kind = .listener });
    }

    fn init(self: *Listener) !void {
        const io = self.srv.io;
        try io.socket(self.userData(), &self.addr);
    }

    fn complete(self: *Listener, cqe: linux.io_uring_cqe) !void {
        const io = self.srv.io;
        const ud: UserData = @bitCast(cqe.user_data);
        assert(ud.kind == .listener);

        switch (ud.operation) {
            .socket => {
                self.fd = try Io.result(cqe);
                try io.listen(self.userData(), &self.addr, self.fd);
            },
            .listen => {
                assert(0 == try Io.result(cqe));
                try io.accept(self.userData(), self.fd);
            },
            .accept => {
                try io.accept(@bitCast(ud), self.fd);
                const fd: fd_t = try Io.result(cqe);
                switch (self.protocol) {
                    .http => try self.srv.newConnection(fd),
                    .https => try self.srv.newHandshake(fd),
                }
            },
            else => unreachable,
        }
    }
};

const Handshake = struct {
    srv: *Server,
    id: u32,
    fd: fd_t,
    hs: tls.nonblock.Server = undefined,
    input_buf: UnusedDataBuffer = .{},
    output_buf: [tls.output_buffer_len]u8 = undefined,
    tx_opt_buf: []const u8 = &.{},
    rx_opt_buf: []const u8 = &.{},

    fn userData(self: *Handshake) u64 {
        return @bitCast(UserData{ .id = self.id, .kind = .handshake });
    }

    fn init(self: *Handshake) !void {
        const io = self.srv.io;
        self.hs = .init(self.srv.tls_config);
        try io.recv(self.userData(), self.fd);
    }

    fn complete(self: *Handshake, cqe: linux.io_uring_cqe) !void {
        const io = self.srv.io;
        const gpa = self.srv.gpa;
        const ud: UserData = @bitCast(cqe.user_data);
        assert(ud.kind == .handshake);

        switch (ud.operation) {
            .recv => {
                _ = try Io.result(cqe);

                const input_buf = try self.input_buf.append(gpa, try io.getRecvBuffer(cqe));
                defer io.putRecvBuffer(cqe) catch {};

                const res = try self.hs.run(input_buf, &self.output_buf);

                try self.input_buf.set(gpa, res.unused_recv);
                if (res.send_pos > 0) {
                    try io.send(self.userData(), self.fd, res.send);
                    return;
                }
                if (self.hs.cipher()) |cipher| {
                    self.tx_opt_buf, self.rx_opt_buf = try KTls.init(gpa, cipher);
                    try io.ktlsUgrade(self.userData(), self.fd, self.tx_opt_buf, self.rx_opt_buf);

                    //log.debug("tls connected {}", .{cipher});
                    //log.debug("tx_buf {x}", .{self.tx_opt_buf});
                    //try io.close(self.userData(), self.fd);
                    return;
                }
                try io.recv(self.userData(), self.fd);
            },
            .send => {
                try io.recv(self.userData(), self.fd);
            },
            .ktls_upgrade => {
                _ = try Io.result(cqe);
                log.debug("UPGRADED input_buffer_len: {}!!!", .{self.input_buf.buffer.len});
                //try io.close(self.userData(), self.fd);
                // TODO sto ako je nesto ostalo u input_buf
                try self.srv.newConnection(self.fd);
            },
            .close => {
                log.debug("tls closed", .{});
            },
            else => unreachable,
        }
    }
};

const Connection = struct {
    srv: *Server,
    id: u32,
    fd: fd_t,

    fn userData(self: *Connection) u64 {
        return @bitCast(UserData{ .id = self.id, .kind = .connection });
    }

    fn init(self: *Connection) !void {
        const io = self.srv.io;
        try io.recv(self.userData(), self.fd);
    }

    fn complete(self: *Connection, cqe: linux.io_uring_cqe) !void {
        const io = self.srv.io;
        const ud: UserData = @bitCast(cqe.user_data);
        assert(ud.kind == .connection);

        switch (ud.operation) {
            .recv => {
                // TODO retry on interrupt, no_buffs
                _ = try Io.result(cqe);
                const bytes = try io.getRecvBuffer(cqe);
                defer io.putRecvBuffer(cqe) catch {};

                var hp: http.HeadParser = .{};
                const n = hp.feed(bytes);
                if (hp.state == .finished) {
                    // TODO close on error
                    const head = try http.Server.Request.Head.parse(bytes[0..n]);
                    log.debug("head: {}", .{head});
                } else {
                    log.debug("http header not found", .{});
                }

                try io.send(self.userData(), self.fd, not_found);
            },
            .send => {
                _ = try Io.result(cqe);
                try io.close(self.userData(), self.fd);
            },
            .close => {
                // TODO notify server
                log.debug("connection closed", .{});
            },
            else => unreachable,
        }
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
//
// Generated by zig translate and than cleaned a little bit.
//$ zig translate-c -I/usr/include /usr/include/linux/tls.h
//
const KTls = struct {
    const U = union {
        aes_gcm_128: aes_gcm_128,
        aes_gcm_256: aes_gcm_256,
        chacha20_poly1305: chacha20_poly1305,
    };

    tx: U,
    rx: U,

    pub const VERSION_1_2 = 0x0303;
    pub const VERSION_1_3 = 0x0304;
    pub const TX = @as(c_int, 1);
    pub const RX = @as(c_int, 2);

    pub const AES_GCM_128 = @as(c_int, 51);
    pub const AES_GCM_256 = @as(c_int, 52);
    pub const CHACHA20_POLY1305 = @as(c_int, 54);

    pub const info = extern struct {
        version: u16 = mem.zeroes(u16),
        cipher_type: u16 = mem.zeroes(u16),
    };
    pub const aes_gcm_128 = extern struct {
        info: info = mem.zeroes(info),
        iv: [8]u8 = mem.zeroes([8]u8),
        key: [16]u8 = mem.zeroes([16]u8),
        salt: [4]u8 = mem.zeroes([4]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };
    pub const aes_gcm_256 = extern struct {
        info: info = mem.zeroes(info),
        iv: [8]u8 = mem.zeroes([8]u8),
        key: [32]u8 = mem.zeroes([32]u8),
        salt: [4]u8 = mem.zeroes([4]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };
    pub const chacha20_poly1305 = extern struct {
        info: info = mem.zeroes(info),
        iv: [12]u8 = mem.zeroes([12]u8),
        key: [32]u8 = mem.zeroes([32]u8),
        salt: [0]u8 = mem.zeroes([0]u8),
        rec_seq: [8]u8 = mem.zeroes([8]u8),
    };

    fn init(gpa: Allocator, cipher: tls.Cipher) !struct { []const u8, []const u8 } {
        switch (cipher) {
            .AES_256_GCM_SHA384 => |c| {
                const T = aes_gcm_256;
                const i: info = .{ .version = VERSION_1_3, .cipher_type = AES_GCM_256 };
                const tx = make(T, i, c.encrypt_iv, c.encrypt_key, c.encrypt_seq);
                const rx = make(T, i, c.decrypt_iv, c.decrypt_key, c.decrypt_seq);

                const tx_buf = try gpa.alignedAlloc(u8, mem.Alignment.of(T), @sizeOf(T));
                const rx_buf = try gpa.alignedAlloc(u8, mem.Alignment.of(T), @sizeOf(T));
                @memcpy(tx_buf, mem.asBytes(&tx));
                @memcpy(rx_buf, mem.asBytes(&rx));

                return .{ tx_buf, rx_buf };
            },
            else => unreachable,
        }
    }

    fn make(comptime T: type, i: info, iv: anytype, key: anytype, seq: u64) T {
        const salt_size = @sizeOf(@FieldType(T, "salt"));
        var t: T = .{
            .info = i,
            .salt = iv[0..salt_size].*,
            .iv = if (iv.len > salt_size) iv[salt_size..].* else @splat(0),
            .key = key,
        };
        std.mem.writeInt(u64, &t.rec_seq, seq, .big);
        return t;
    }
};

test "sizes" {
    std.debug.print("size 1: {} {}\n", .{ @sizeOf(KTls.aes_gcm_256), @alignOf(KTls.aes_gcm_256) });
    std.debug.print("size 2: {} {}\n", .{ @sizeOf(KTls.aes_gcm_128), @alignOf(KTls.aes_gcm_128) });
    std.debug.print("size 2: {} {}\n", .{ @sizeOf(KTls.chacha20_poly1305), @alignOf(KTls.chacha20_poly1305) });
}
