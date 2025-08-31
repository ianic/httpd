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

    const addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 8080);
    try io.socket(@bitCast(UserData{ .kind = .http_listener }), &addr);

    while (true) {
        const cqe = try io.peek();
        // TODO: handle sqe exhaustion
        try complete(gpa, &io, cqe, &addr);
        io.advance();
    }
}

fn complete(gpa: Allocator, io: *Io, cqe: linux.io_uring_cqe, addr: *const net.Address) !void {
    _ = gpa;

    const ud: UserData = @bitCast(cqe.user_data);
    switch (ud.kind) {
        .http_listener => {
            switch (ud.operation) {
                .socket => {
                    const fd = try Io.result(cqe);
                    try io.listen(@bitCast(UserData{ .fd = fd, .kind = .http_listener }), addr, fd);
                },
                .listen => {
                    assert(0 == try Io.result(cqe));
                    try io.accept(@bitCast(ud), ud.fd);
                },
                .accept => {
                    try io.accept(@bitCast(ud), ud.fd);
                    const fd: fd_t = try Io.result(cqe);
                    try io.recv(@bitCast(UserData{ .fd = fd, .kind = .connection }), fd);
                },
                else => unreachable,
            }
        },
        .connection => {
            switch (ud.operation) {
                .recv => {
                    // TODO retry on interrupt, no_buffs
                    _ = try Io.result(cqe);
                    const bytes = try io.getRecvBuffer(cqe);

                    var hp: http.HeadParser = .{};
                    const n = hp.feed(bytes);
                    if (hp.state == .finished) {
                        // TODO close on error
                        const head = try http.Server.Request.Head.parse(bytes[0..n]);
                        log.debug("head: {}", .{head});
                    } else {
                        log.debug("http header not found", .{});
                    }

                    try io.send(@bitCast(ud), ud.fd, not_found);
                    try io.putRecvBuffer(cqe);
                },
                .send => {
                    try io.close(@bitCast(ud), ud.fd);
                },
                .close => {
                    log.debug("connection closed", .{});
                },
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

const UserData = packed struct {
    const Kind = enum(u8) {
        http_listener,
        https_listener,
        https_handshake,
        connection,
    };

    operation: Io.Operation = .nop, // 8
    _: u16 = 0, //  16 - unused
    kind: Kind, // 8
    fd: fd_t = -1, // 32
};

comptime {
    assert(@bitSizeOf(UserData) == 64);
}

test UserData {
    try testing.expectEqual(8, @sizeOf(UserData));
    try testing.expectEqual(64, @bitSizeOf(UserData));

    const user_data: UserData = .{ .operation = .send, .kind = .connection, .fd = 0x0abbccdd };
    try testing.expectEqual(0x0a_bb_cc_dd_03_00_00_09, @as(u64, @bitCast(user_data)));
}

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
