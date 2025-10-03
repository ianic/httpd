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
completion: Io.Completion = .{},

fn parentPtr(completion: *Io.Completion) *Listener {
    return @alignCast(@fieldParentPtr("completion", completion));
}

pub fn init(self: *Listener) !void {
    try self.io.socket(&self.completion, onSocket, &self.addr);
}

fn onSocket(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parentPtr(completion);
    self.fd = try Io.result(cqe);
    try self.io.listen(completion, onListen, &self.addr, self.fd, .{ .kernel_backlog = 1024, .reuse_address = true });
}

fn onListen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parentPtr(completion);
    assert(0 == try Io.result(cqe));
    try self.accept();
}

fn accept(self: *Listener) !void {
    try self.io.accept(&self.completion, onAccept, self.fd);
}

fn onAccept(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parentPtr(completion);
    const fd: fd_t = Io.result(cqe) catch |err| {
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
