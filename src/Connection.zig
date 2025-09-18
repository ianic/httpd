server: *Server,
gpa: Allocator,
io: *Io,
fd: fd_t,
completion: Io.Completion = .{},
unused_recv: UnusedDataBuffer = .{},
protocol: Server.Protocol = .http,
keep_alive: bool = true,
recv_timeout: linux.kernel_timespec = .{ .sec = keepalive_timeout, .nsec = 0 },

/// Fs file which is we are currently sending to the client. fd = -1 if there is
/// no file in processing.
file: struct {
    fd: fd_t = -1,
    path: ?[:0]const u8 = null,
    stat: linux.Statx = mem.zeroes(linux.Statx),
    header: ?[]u8 = null,
    header_pos: usize = 0,
    pipe: ?Server.Pipe = null,
    offset: usize = 0,
} = .{},

inline fn parent(completion: *Io.Completion) *Connection {
    return @alignCast(@fieldParentPtr("completion", completion));
}

pub fn init(self: *Connection) !void {
    try self.recv();
}

fn recv(self: *Connection) !void {
    if (self.server.state == .active) {
        try self.io.recvProvided(self.completion.with(onRecv), self.fd, &self.recv_timeout);
    } else {
        try self.close();
    }
}

fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const n = Io.result(cqe) catch |err| {
        switch (err) {
            error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                log.info("connection recv retry on {}", .{err}); // TODO remove logging
                try self.recv();
            },
            // recv timeout
            error.OperationCanceled => try self.close(),
            // connection closed
            error.IOError, error.ConnectionResetByPeer => try self.close(),
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

    const recv_buf = try self.io.getProvidedBuffer(cqe);
    try self.parseHeader(recv_buf);
    self.io.putProvidedBuffer(cqe);
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
        try self.io.openRead(self.completion.with(onOpen), self.server.root.fd, path, &self.file.stat);
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
                self.server.metric.files.not_found +%= 1;
                self.file.header = try Header.notFound(self.gpa, self.keep_alive);
                try self.io.send(self.completion.with(onHeader), self.fd, self.file.header.?, .{});
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
    const pipe = try self.server.pipes.get(file.stat.size);
    file.pipe = pipe;
    try self.io.sendfile(completion.with(onBody), self.fd, file.fd, pipe.fds, 0, @intCast(file.stat.size));
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
        try self.io.sendfile(completion.with(onBody), self.fd, file.fd, file.pipe.?.fds, @intCast(file.offset), @intCast(len));
        self.server.metric.files.sendfile_more +%= 1;
        return;
    }

    self.server.metric.files.count +%= 1;
    self.server.metric.files.bytes +%= file.stat.size;
    // cleanup
    try self.fileClose();
}

fn fileClose(self: *Connection) !void {
    const file = &self.file;
    if (file.path) |path| {
        self.gpa.free(path);
        file.path = null;
        if (file.pipe) |p| {
            try self.server.pipes.put(p);
            file.pipe = null;
        }
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

pub fn close(self: *Connection) !void {
    if (self.completion.active()) {
        // If called from server.
        // Cancel if receiving, else send file and than close.
        if (self.completion.callback == onRecv) {
            try self.io.cancel(null, self.fd);
        }
        return;
    }
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
    self.deinit();
}

fn deinit(self: *Connection) void {
    if (self.file.path) |path| self.gpa.free(path);
    if (self.file.header) |header| self.gpa.free(header);
    self.unused_recv.deinit(self.gpa);
    self.server.destroy(self);
}

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
const assert = std.debug.assert;
const net = std.net;
const linux = std.os.linux;
const fd_t = linux.fd_t;
const mem = std.mem;
const Allocator = mem.Allocator;
const http = std.http;

const Io = @import("Io.zig");
const Server = @import("Server.zig");
const log = std.log.scoped(.connection);
const Connection = @This();
const keepalive_timeout = 10;
