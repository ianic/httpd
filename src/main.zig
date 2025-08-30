const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;
const http = std.http;
const assert = std.debug.assert;

const Loop = @import("Loop.zig");
const Operation = Loop.Operation;
const Completion = Loop.Completion;

const log = std.log.scoped(.main);

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const gpa = dbga.allocator();

    var loop: Loop = .{};
    try loop.init(gpa, .{
        .entries = 256,
        .fd_nr = 1024,
        .recv_buffers = .{ .count = 1, .size = 4096 },
    });
    defer loop.deinit(gpa);

    const addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 8080);
    var listener = Listener{ .addr = addr, .id = rsv_user_data.listener };
    _ = try listener.complete(&loop, .none);
    var conns: std.ArrayList(Connection) = .empty;
    defer conns.deinit(gpa);
    var free_conns: std.ArrayList(u32) = .empty;
    defer free_conns.deinit(gpa);

    while (true) {
        const completion = try loop.peek();
        if (completion.id == listener.id) {
            if (try listener.complete(&loop, completion)) |fd| {
                var conn: *Connection = if (free_conns.pop()) |id| brk: {
                    const conn = &conns.items[id];
                    conn.fd = fd;
                    break :brk conn;
                } else brk: {
                    try conns.append(gpa, .{ .fd = fd, .id = @intCast(conns.items.len) });
                    break :brk &conns.items[conns.items.len - 1];
                };
                _ = try conn.complete(&loop, .none);
            }
        } else {
            const conn = &conns.items[completion.id];
            if (try conn.complete(&loop, completion)) |id| {
                try free_conns.append(gpa, id);
            }
        }
        loop.advance();
    }
}
// TODO: handle Interrupt, NoBuffers errors in result
//
const Listener = struct {
    id: u32,
    fd: posix.fd_t = -1,
    addr: net.Address,

    // Returns accepted connection fd, or null.
    fn complete(self: *Listener, loop: *Loop, completion: Completion) !?posix.fd_t {
        switch (completion.operation) {
            .none => {
                try loop.socket(self.id, &self.addr);
            },
            .socket => {
                self.fd = try completion.result;
                try loop.listen(self.id, &self.addr, self.fd);
            },
            .listen => {
                assert(0 == try completion.result);
                try loop.accept(self.id, self.fd);
            },
            .accept => {
                const fd: posix.fd_t = try completion.result;
                log.debug("accept fd: {}", .{fd});
                try loop.accept(self.id, self.fd);
                return fd;
            },
            else => unreachable,
        }
        return null;
    }
};

const Connection = struct {
    id: u32,
    fd: posix.fd_t,

    fn complete(self: *Connection, loop: *Loop, completion: Completion) !?u32 {
        switch (completion.operation) {
            .none => {
                // TODO: add recv timer
                try loop.recv(self.id, self.fd);
            },
            .recv => {
                // TODO retry on interrupt, no_buffs
                _ = try completion.result;
                const bytes = try loop.getRecvBuffer(completion);

                log.debug("recv: {s}", .{bytes});

                var hp: http.HeadParser = .{};
                const n = hp.feed(bytes);
                if (hp.state == .finished) {

                    //TODO: look for Connection => keep-alive
                    // Accept-Encoding => gzip, deflate, br, zstd
                    log.debug("headers:", .{});
                    var iter: http.HeaderIterator = .init(bytes[0..n]);
                    while (iter.next()) |h| {
                        log.debug("    {s} => {s}", .{ h.name, h.value });
                    }
                } else {
                    log.debug("http header not found", .{});
                }

                try loop.putRecvBuffer(completion);
                try loop.close(self.id, self.fd);
            },
            .close => {
                return self.id;
            },
            else => unreachable,
        }
        return null;
    }
};

// Reserved values for user_data
const rsv_user_data = struct {
    const none: u32 = 0xff_ff_ff_ff;
    const listener: u32 = 0xff_ff_ff_fe;
};
