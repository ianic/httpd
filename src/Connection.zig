const Connection = @This();
const keepalive_timeout = 30;

server: *Server,
gpa: Allocator,
io: *Io,
fd: fd_t,
completion: Io.Completion = .{},
short_recv: ShortRecvBuffer = .{},
recv_timeout: linux.kernel_timespec = .{ .sec = keepalive_timeout, .nsec = 0 },
protocol: Server.Protocol = .http,
pipe: ?Server.Pipe = null, // for sendfile
offset: usize = 0, // header/body send offset
req: Request = .{},
rsp: Response = .{},

inline fn parent(completion: *Io.Completion) *Connection {
    return @alignCast(@fieldParentPtr("completion", completion));
}

pub fn init(self: *Connection) !void {
    try self.recv();
}

fn recv(self: *Connection) !void {
    if (self.server.closing()) {
        try self.close();
        return;
    }
    try self.io.recvProvided(&self.completion, onRecv, self.fd, &self.recv_timeout);
}

fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const n = Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                log.debug("connection recv retry on {}", .{err});
                try self.recv();
                return;
            },
            error.OperationCanceled => {}, // timeout or server close
            error.IOError, error.ConnectionResetByPeer => {}, // connection closed
            else => log.warn("connection recv failed {}", .{err}), // unexpected
        }
        break :brk 0;
    };
    if (n == 0) { // eof
        try self.close();
        return;
    }

    const recv_buf = try self.short_recv.append(self.gpa, try self.io.getProvidedBuffer(cqe));
    defer self.io.putProvidedBuffer(cqe);
    const req = Request.parse(self.gpa, recv_buf) catch |err| {
        log.debug("connection request parse {}", .{err});
        try self.close();
        return;
    };
    try self.short_recv.set(self.gpa, recv_buf[if (req) |r| r.size else 0..]);
    if (req) |r| {
        self.req = r;
        try self.open();
    } else {
        try self.recv();
    }
}

fn open(self: *Connection) !void {
    try self.io.openRead(&self.completion, onOpen, self.server.root.fd, self.req.path, &self.rsp.statx);
}

fn onOpen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const rsp = &self.rsp;
    const fd = Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.NoSuchFileOrDirectory => {
                break :brk -1;
            },
            error.SignalInterrupt => {
                try self.open();
            },
            error.FileTableOverflow => {
                log.warn("connection file open '{s}' retry on {}", .{ self.req.path, err });
                try self.open();
            },
            else => {
                log.warn("connection file open '{s}' failed {}", .{ self.req.path, err });
                try self.close();
            },
        }
        return;
    };
    try rsp.init(self.gpa, self.req, fd);
    try self.io.send(&self.completion, onHeader, self.fd, rsp.header, .{ .more = rsp.hasBody() });
    log.debug("{} {s} '{s}' {}", .{ self.fd, @tagName(rsp.status), self.req.path, self.rsp.statx.size });
}

fn onHeader(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const rsp = &self.rsp;
    self.offset += @intCast(Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.SignalInterrupt => break :brk 0,
            error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
            else => log.info("connection header send failed {}", .{err}),
        }
        try self.close();
        return;
    });
    if (self.offset < rsp.header.len) { // short send send more
        try self.io.send(completion, onHeader, self.fd, rsp.header[self.offset..], .{ .more = rsp.hasBody() });
        return;
    }
    if (rsp.status != .ok) { // no body
        try self.done();
        return;
    }
    // send file
    assert(self.pipe == null);
    self.offset = 0;
    self.pipe = try self.server.pipes.get(rsp.statx.size);
    try self.io.sendfile(completion, onBody, self.fd, rsp.fd, self.pipe.?.fds, 0, @intCast(rsp.statx.size));
}

fn onBody(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const rsp = &self.rsp;
    self.offset += @intCast(Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.SignalInterrupt => break :brk 0,
            error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
            else => log.info("connection body send failed {}", .{err}),
        }
        try self.close();
        return;
    });
    if (self.offset < rsp.statx.size) { // short send, send the rest of the file
        const len = self.rsp.statx.size - self.offset;
        try self.io.sendfile(completion, onBody, self.fd, rsp.fd, self.pipe.?.fds, @intCast(self.offset), @intCast(len));
        self.server.metric.files.sendfile_more +%= 1;
        return;
    }
    self.server.metric.files.count +%= 1;
    self.server.metric.files.bytes +%= rsp.statx.size;
    try self.done();
}

// Response sent
fn done(self: *Connection) !void {
    if (self.req.keep_alive) {
        try self.clear();
        try self.recv();
        return;
    }
    try self.close();
}

fn clear(self: *Connection) !void {
    if (self.pipe) |pipe| {
        try self.server.pipes.put(pipe);
        self.pipe = null;
    }
    self.offset = 0;
    if (self.rsp.fd >= 0) {
        try self.io.close(self.rsp.fd);
        self.rsp.fd = -1;
    }
    self.req.free(self.gpa);
    self.rsp.free(self.gpa);
}

pub fn close(self: *Connection) !void {
    if (self.completion.active()) {
        // If called from server.
        // Cancel if receiving, else send file and than close.
        if (self.completion.callback == onRecv) {
            try self.io.cancel(self.fd);
        }
        return;
    }
    try self.clear();
    if (self.protocol == .https) {
        try self.io.tlsCloseNotify(self.fd);
    }
    try self.io.close(self.fd);
    self.deinit();
}

fn deinit(self: *Connection) void {
    self.short_recv.deinit(self.gpa);
    self.server.destroy(self);
}

const Request = struct {
    path: [:0]const u8 = &.{},
    etag: struct {
        size: u64 = 0,
        mtime: i128 = 0,
    } = .{},
    keep_alive: bool = false,
    size: usize = 0, // size of the request in bytes, how much of recv_buf is used

    /// Returns null if recv_buf doesn't hold full http request
    fn parse(gpa: Allocator, recv_buf: []const u8) !?Request {
        var hp: http.HeadParser = .{};
        const size = hp.feed(recv_buf);
        if (hp.state != .finished) {
            return null;
        }
        const head = try Head.parse(recv_buf[0..size]);
        const content_length: u64 = head.content_length orelse 0;
        if (!(head.method == .GET and content_length == 0)) {
            return error.BadRequest;
        }

        var req: Request = .{
            .keep_alive = head.keep_alive,
            .size = size,
        };
        if (head.etag) |et| { // parse etag
            var it = mem.splitScalar(u8, et, '-');
            req.etag.mtime = std.fmt.parseInt(i128, it.first(), 16) catch 0;
            req.etag.size = std.fmt.parseInt(u64, it.rest(), 16) catch 0;
        }
        req.path = if (head.target.len <= 1)
            try gpa.dupeZ(u8, "index.html")
        else if (head.target[head.target.len - 1] == '/')
            try std.fmt.allocPrintSentinel(gpa, "{s}index.html", .{head.target[1..]}, 0)
        else
            try gpa.dupeZ(u8, head.target[1..]);

        return req;
    }

    fn free(req: *Request, gpa: Allocator) void {
        if (req.path.len > 0) {
            gpa.free(req.path);
        }
        req.* = .{};
    }
};

const Response = struct {
    statx: linux.Statx = mem.zeroes(linux.Statx),
    fd: fd_t = -1,
    status: http.Status = undefined, // TODO can I set this to 0
    header: []const u8 = &.{},

    fn free(rsp: *Response, gpa: Allocator) void {
        if (rsp.header.len > 0) {
            gpa.free(rsp.header);
        }
        rsp.* = .{};
    }

    fn init(rsp: *Response, gpa: Allocator, req: Request, fd: fd_t) !void {
        assert(rsp.fd == -1);
        if (fd == -1) {
            rsp.status = .not_found;
            rsp.header = try notFound(gpa, req.keep_alive);
            return;
        }
        rsp.fd = fd;
        const stat = fs.File.Stat.fromLinux(rsp.statx);
        if (stat.kind != .file) {
            rsp.status = .not_found;
            rsp.header = try notFound(gpa, req.keep_alive);
        } else if (etagMatch(stat, req)) {
            rsp.status = .not_modified;
            rsp.header = try notModified(gpa, stat, req.keep_alive);
        } else {
            rsp.status = .ok;
            rsp.header = try ok(gpa, stat, req.path, req.keep_alive);
        }
    }

    fn etagMatch(stat: fs.File.Stat, req: Request) bool {
        return stat.size == req.etag.size and stat.mtime == req.etag.mtime;
    }

    fn hasBody(rsp: Response) bool {
        return rsp.status == .ok;
    }

    const connection_keep_alive = "Connection: keep-alive";
    const connection_close = "Connection: close";

    fn ok(gpa: Allocator, stat: fs.File.Stat, file: [:0]const u8, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(gpa, fmt, .{
            contentType(file),
            stat.size,
            stat.mtime,
            stat.size,
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notModified(gpa: Allocator, stat: fs.File.Stat, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 304 Not Modified\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(gpa, fmt, .{
            stat.mtime,
            stat.size,
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notFound(gpa: Allocator, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Length: 0\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(gpa, fmt, .{
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn contentType(file_name: []const u8) []const u8 {
        const mime_types = [_][2][]const u8{
            .{ ".html", "text/html" },
            .{ ".htm", "text/html" },
            .{ ".css", "text/css" },
            .{ ".js", "application/javascript" },
            .{ ".json", "application/json" },
            .{ ".png", "image/png" },
            .{ ".jpg", "image/jpeg" },
            .{ ".jpeg", "image/jpeg" },
            .{ ".gif", "image/gif" },
            .{ ".svg", "image/svg+xml" },
            .{ ".txt", "text/plain" },
            .{ ".xml", "text/xml" },
            .{ ".csv", "text/csv" },
            .{ ".gz", "application/gzip" },
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

const ShortRecvBuffer = struct {
    buffer: []u8 = &.{},
    reset_buffer: []u8 = &.{},

    fn append(self: *ShortRecvBuffer, allocator: Allocator, recv_buf: []const u8) ![]const u8 {
        self.reset_buffer = self.buffer;
        if (self.buffer.len == 0) {
            // nothing to append to
            return recv_buf;
        }
        if (recv_buf.len == 0) {
            return self.buffer;
        }
        self.reset_buffer = self.buffer;
        self.buffer = try allocator.alloc(u8, self.reset_buffer.len + recv_buf.len);
        @memcpy(self.buffer[0..self.reset_buffer.len], self.reset_buffer);
        @memcpy(self.buffer[self.reset_buffer.len..], recv_buf);
        return self.buffer;
    }

    fn reset(self: *ShortRecvBuffer, allocator: Allocator) void {
        allocator.free(self.buffer);
        self.buffer = self.reset_buffer;
        self.reset_buffer = &.{};
    }

    fn set(self: *ShortRecvBuffer, allocator: Allocator, unused: []const u8) !void {
        if (self.reset_buffer.len > 0) {
            @branchHint(.unlikely);
            allocator.free(self.reset_buffer);
            self.reset_buffer = &.{};
        }
        if (unused.len == 0) {
            @branchHint(.likely);
            if (self.buffer.len > 0) {
                @branchHint(.unlikely);
                allocator.free(self.buffer);
                self.buffer = &.{};
            }
            return;
        }
        if (unused.ptr == self.buffer.ptr and unused.len == self.buffer.len) {
            return;
        }
        // unused is part of the self.buffer make copy before free
        const copy = try allocator.dupe(u8, unused);
        allocator.free(self.buffer);
        self.buffer = copy;
    }

    fn deinit(self: *ShortRecvBuffer, allocator: Allocator) void {
        allocator.free(self.buffer);
        allocator.free(self.reset_buffer);
    }
};

const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const fs = std.fs;
const linux = std.os.linux;
const fd_t = linux.fd_t;
const mem = std.mem;
const Allocator = mem.Allocator;
const http = std.http;

const Io = @import("Io.zig");
const Server = @import("Server.zig");
const Head = @import("Head.zig");
const log = std.log.scoped(.connection);
