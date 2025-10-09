const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const linux = std.os.linux;
const fd_t = linux.fd_t;

const Io = @import("Io.zig");
const Server = @import("Server.zig");
const log = std.log.scoped(.listener);

const Listener = @This();

server: *Server,
io: *Io,
addr: net.Address,
protocol: Server.Protocol = .http,
fd: fd_t = -1,
op: Io.Op = .{},

fn parentPtr(res: Io.Result) *Listener {
    return @alignCast(@fieldParentPtr("op", res.ptr));
}

pub fn init(self: *Listener) !void {
    try self.io.socket(&self.op, onSocket, &self.addr);
}

fn onSocket(res: Io.Result) !void {
    const self = parentPtr(res);
    self.fd = try res.fd();
    try self.io.listen(&self.op, onListen, &self.addr, self.fd, .{ .kernel_backlog = 1024, .reuse_address = true });
}

fn onListen(res: Io.Result) !void {
    const self = parentPtr(res);
    try res.ok();
    try self.accept();
}

fn accept(self: *Listener) !void {
    try self.io.accept(&self.op, onAccept, self.fd);
}

fn onAccept(res: Io.Result) !void {
    const self = parentPtr(res);
    const fd = res.fd() catch |err| {
        switch (err) {
            error.SignalInterrupt => {
                try self.accept();
            },
            error.FileTableOverflow => {
                log.warn("listener accept {}", .{err});
                try self.accept();
            },
            error.OperationCanceled => {
                self.server.destroy(self);
            },
            else => return err,
        }
        return;
    };
    if (self.server.closing()) {
        try self.io.close(fd);
        return;
    }
    try self.accept();
    try self.server.connect(self.protocol, fd);
}

pub fn close(self: *Listener) !void {
    try self.io.cancel(self.fd);
    try self.io.close(self.fd);
}
