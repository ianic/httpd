const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
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

const Connection = @This();
const keepalive_timeout = 30;
const max_header_size = 8192;

server: *Server,
gpa: Allocator,
io: *Io,
fd: fd_t, // tcp connection file descriptor
protocol: Server.Protocol = .http,
// per request arena allocator
arena: Allocator = undefined,
arena_instance: std.heap.ArenaAllocator = undefined,

// http request and respone
req: Request = .{},
rsp: Response = .{},

// io operations
recv_op: RequestRecv = undefined, // read http reqeust
send_op: SendBytes = undefined, // send http header
sendfile_op: Sendfile = undefined, // send file as http body
stat_ops: [4]FileStat = undefined, // file stat operation for each supported encoding
stat_join_count: usize = 0,

pub fn init(self: *Connection) !void {
    self.arena_instance = std.heap.ArenaAllocator.init(self.gpa);
    self.arena = self.arena_instance.allocator();
    self.recv_op = .{
        .gpa = self.gpa,
        .io = self.io,
        .vtable = .{
            .success = onRecv,
            .fail = onRecvError,
        },
        .fd = self.fd,
    };
    self.send_op = .{
        .io = self.io,
        .callback = onSend,
        .fd = self.fd,
    };
    self.sendfile_op = .{
        .io = self.io,
        .open_callback = onSendfileOpen,
        .send_callback = onSendfile,
        .conn_fd = self.fd,
        .metric = &self.server.metric.files,
    };

    try self.recv();
}

fn recv(self: *Connection) !void {
    if (self.server.closing()) {
        try self.shutdown(null);
        return;
    }
    try self.recv_op.prep();
}

/// Some bytes are recieved parse it into request
fn onRecv(op: *RequestRecv, bytes: []const u8) !usize {
    const self: *Connection = @alignCast(@fieldParentPtr("recv_op", op));
    self.server.metric.recv.count +%= 1;
    const n = try self.req.parse(self.arena, bytes) orelse {
        if (bytes.len >= max_header_size) {
            return error.RequestBufferOverflow;
        }
        try self.recv();
        self.server.metric.recv.short +%= 1;
        return 0;
    };
    self.server.metric.recv.bytes +%= bytes.len;
    if (self.server.cache == null)
        self.req.accept_encoding = self.req.accept_encoding[0..1]; // just .plain
    try self.fileStat();

    return n;
}

// Start FileStat operation for each encoding
fn fileStat(self: *Connection) !void {
    for (self.req.accept_encoding, 0..) |encoding, i| {
        var fs_op = &self.stat_ops[i];
        fs_op.* = .{
            .io = self.io,
            .cb = .{ .ptr = self, .fnc = onFileStatJoin },
            .dir = if (encoding == .plain) self.server.root else self.server.cache.?,
            .path = if (encoding == .plain)
                try self.arena.dupeZ(u8, self.req.path)
            else
                try mem.joinZ(self.arena, "", &.{ self.req.path, encoding.extension() }),
        };
        try fs_op.prep();
    }
    self.stat_join_count = self.req.accept_encoding.len;
}

fn onFileStatJoin(ptr: *anyopaque) !void {
    const self: *Connection = @ptrCast(@alignCast(ptr));
    // Wait for all operations to finish
    self.stat_join_count -= 1;
    if (self.stat_join_count != 0) return;

    const ops = self.stat_ops[0..self.req.accept_encoding.len];

    const plain = ops[0];
    if (plain.err) |err| return switch (err) {
        // Respond with not found
        error.NoSuchFileOrDirectory => try self.send(null),
        else => self.shutdown(err),
    };
    const plain_mtime = plain.statx.mtime;

    // Find best match, shortest one
    var idx: usize = 0;
    for (ops[1..], 1..) |stat, i| {
        if (stat.err != null) continue;
        // Plain and compressed mtime must match
        const mtime = stat.statx.mtime;
        if (!(mtime.sec == plain_mtime.sec and mtime.nsec == plain_mtime.nsec)) {
            continue;
        }
        if (stat.statx.size < ops[idx].statx.size) {
            idx = i;
        }
    }
    const match = &ops[idx];

    try self.send(.{
        .dir = match.dir,
        .path = match.path,
        .encoding = self.req.accept_encoding[idx],
        // TODO zasto convert use linux version
        .stat = try std.Io.Threaded.statFromLinux(&match.statx),
    });
}

/// File system file is found, or null if no such file, prepare repsonse header,
/// send header and body.
fn send(self: *Connection, fsr: ?FileStatResult) !void {
    // Prepare header
    self.rsp.fsr = fsr;
    try self.rsp.init(self.arena, self.req);

    // Start header send and sendfile prep operations in parallel. Sync is in
    // headerOpenJoin. If there is no body to send start only send header
    // operation, no sync is called from onSend then.
    try self.send_op.prep(self.rsp.header, self.hasBody());
    if (self.hasBody()) {
        try self.sendfile_op.prep(fsr.?.dir, fsr.?.path, fsr.?.stat.size);
    }
}

fn onRecvError(op: *RequestRecv, err: anyerror) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("recv_op", op));
    try self.shutdown(err);
}

/// Is there file to send as response body (by sendfile).
fn hasBody(self: Connection) bool {
    return !self.req.onlyHeader() and self.rsp.hasBody();
}

fn headerOpenJoin(self: *Connection) !void {
    if (self.sendfile_op.active() or self.send_op.active()) return;
    if (self.send_op.err) |err| return try self.shutdown(err);
    if (self.sendfile_op.err) |err| return try self.shutdown(err);
    try self.sendfile_op.send();
}

/// Header is sent, prepare sending body
fn onSend(op: *SendBytes) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("send_op", op));
    if (self.hasBody()) {
        return try self.headerOpenJoin();
    }
    if (op.err) |err| return try self.shutdown(err);
    try self.done();
}

fn onSendfileOpen(op: *Sendfile) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("sendfile_op", op));
    try self.headerOpenJoin();
}

/// Body is sent
fn onSendfile(op: *Sendfile) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("sendfile_op", op));
    if (op.err) |err| return try self.shutdown(err);
    try self.done();
}

/// Io operation failed
fn onError(ptr: *anyopaque, err: anyerror) !void {
    const self: *Connection = @ptrCast(@alignCast(ptr));
    try self.shutdown(err);
}

/// Done sending response
fn done(self: *Connection) !void {
    self.logAccess();
    if (self.req.keep_alive) {
        self.reset();
        try self.recv();
        return;
    }
    try self.shutdown(null);
}

/// Access log line
fn logAccess(self: Connection) void {
    const rsp = &self.rsp;
    log.debug(
        "{} {s} '{s}' {}/{} {s} {s}",
        .{
            self.fd,
            @tagName(rsp.status),
            self.req.path,
            rsp.header.len,
            rsp.bodySize(),
            @tagName(rsp.contentEncoding()),
            if (self.req.keep_alive) "keep-alive" else "close",
        },
    );
}

/// Prepare connection for next request
fn reset(self: *Connection) void {
    _ = self.arena_instance.reset(.free_all);
    self.req = .{};
    self.rsp = .{};
    self.sendfile_op.err = null;
    self.send_op.err = null;
}

/// Shutdown connection
fn shutdown(self: *Connection, maybe_err: ?anyerror) !void {
    if (maybe_err) |err| switch (err) {
        // timeout or server close
        error.OperationCanceled,
        // clean tcp connection close
        error.EndOfFile,
        error.EndOfStream,
        // broken tcp connection
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.IOError,
        => {},
        else => {
            // unexpected error
            log.warn("{} failed {}", .{ self.fd, err });
            // if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
        },
    };

    try self.sendfile_op.close();
    if (self.protocol == .https) {
        try self.io.tlsCloseNotify(self.fd);
    }
    try self.io.close(self.fd);

    self.arena_instance.deinit();
    self.recv_op.deinit();
    self.server.destroy(self);
}

/// External close request
pub fn close(self: *Connection) !void {
    // Cancel if receiving, else wait for pending response to finish
    if (self.recv_op.active()) {
        try self.io.cancel(self.fd);
    }
}

const Request = struct {
    path: [:0]const u8 = &.{},
    etag: struct {
        size: u64 = 0,
        mtime: i96 = 0,
    } = .{},
    keep_alive: bool = false,
    accept_encoding_buf: [4]ContentEncoding = @splat(.plain),
    accept_encoding: []ContentEncoding = &.{},
    size: usize = 0,
    method: http.Method = .GET,

    /// Returns null if recv_buf doesn't hold full http request
    fn parse(req: *Request, arena: Allocator, buf: []const u8) !?usize {
        var hp: http.HeadParser = .{};
        const n = hp.feed(buf);
        if (hp.state != .finished) {
            return null;
        }

        const head = try Head.parse(buf[0..n]);
        if (head.method != .GET and head.method != .HEAD) {
            return error.BadRequest;
        }
        if (head.content_length) |content_length| if (content_length != 0) {
            return error.BadRequest;
        };

        req.* = .{
            .keep_alive = head.keep_alive,
            .method = head.method,
        };
        if (head.etag) |et| { // parse etag
            var it = mem.splitScalar(u8, et, '-');
            req.etag.mtime = std.fmt.parseInt(i96, it.first(), 16) catch 0;
            req.etag.size = std.fmt.parseInt(u64, it.rest(), 16) catch 0;
        }
        req.path = if (head.target.len <= 1)
            try arena.dupeZ(u8, "index.html")
        else if (head.target[head.target.len - 1] == '/')
            try mem.joinZ(arena, "", &.{ head.target[1..], "index.html" })
        else
            try arena.dupeZ(u8, head.target[1..]);

        req.accept_encoding_buf[0] = .plain;
        req.accept_encoding = req.accept_encoding_buf[0..1];
        if (compressible(req.path)) {
            if (head.accept_encoding) |accept_encoding_str| {
                req.accept_encoding = try ContentEncoding.parse(&req.accept_encoding_buf, accept_encoding_str);
            }
        }

        return n;
    }

    fn onlyHeader(req: Request) bool {
        return req.method == .HEAD;
    }
};

const Response = struct {
    fsr: ?FileStatResult = null,
    status: http.Status = @enumFromInt(0),
    header: []const u8 = &.{},

    fn init(rsp: *Response, arena: Allocator, req: Request) !void {
        if (rsp.fsr == null) {
            rsp.status = .not_found;
            rsp.header = try notFound(arena, req.keep_alive);
            return;
        }
        const stat = rsp.fsr.?.stat;
        switch (stat.kind) {
            .file, .sym_link => {
                if (etagMatch(stat, req)) {
                    rsp.status = .not_modified;
                    rsp.header = try notModified(arena, stat, req.keep_alive);
                } else {
                    rsp.status = .ok;
                    rsp.header = try ok(arena, stat, req.path, rsp.fsr.?.encoding, req.keep_alive);
                }
            },
            .directory => {
                // Target path was without trailing '/' and points to directory; redirect
                rsp.status = .moved_permanently;
                rsp.header = try dirRedirect(arena, req.path, req.keep_alive);
            },
            else => {
                rsp.status = .not_found;
                rsp.header = try notFound(arena, req.keep_alive);
            },
        }
    }

    fn etagMatch(stat: std.Io.File.Stat, req: Request) bool {
        return stat.size == req.etag.size and stat.mtime.nanoseconds == req.etag.mtime;
    }

    fn hasBody(rsp: Response) bool {
        return rsp.status == .ok and rsp.bodySize() > 0;
    }

    fn bodySize(rsp: Response) usize {
        if (rsp.fsr) |f| return f.stat.size;
        return 0;
    }

    fn contentEncoding(rsp: Response) ContentEncoding {
        if (rsp.fsr) |f| return f.encoding;
        return .plain;
    }

    const connection_keep_alive = "Connection: keep-alive";
    const connection_close = "Connection: close";

    fn ok(
        arena: Allocator,
        stat: std.Io.File.Stat,
        file: [:0]const u8,
        encoding: ContentEncoding,
        keep_alive: bool,
    ) ![]const u8 {
        const last_modified: LastModified = .{ .sec = @intCast(@divTrunc(stat.mtime.nanoseconds, std.time.ns_per_s)) };
        const fmt = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n{s}" ++
            "Content-Length: {d}\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "Last-Modified: {f}\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(arena, fmt, .{
            contentType(file),
            encoding.header(),
            stat.size,
            stat.mtime,
            stat.size,
            last_modified,
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notModified(arena: Allocator, stat: std.Io.File.Stat, keep_alive: bool) ![]const u8 {
        const last_modified: LastModified = .{ .sec = @intCast(@divTrunc(stat.mtime.nanoseconds, std.time.ns_per_s)) };
        const fmt = "HTTP/1.1 304 Not Modified\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "Last-Modified: {f}\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(arena, fmt, .{
            stat.mtime,
            stat.size,
            last_modified,
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notFound(arena: Allocator, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Length: 0\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(arena, fmt, .{
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn dirRedirect(arena: Allocator, path: []const u8, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 301 Moved Permanently\r\n" ++
            "Content-Length: 0\r\n" ++
            "Location: \\{s}\\ \r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(arena, fmt, .{
            path,
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
            .{ ".md", "text/markdown" },
            .{ ".rss", "application/rss+xml" },
            .{ ".atom", "application/rss+xml" },
        };
        for (mime_types) |pair| {
            if (mem.endsWith(u8, file_name, pair[0])) return pair[1];
        }
        return "application/octet-stream"; // Default MIME type
    }

    test "header_buf size is big enough" {
        var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_instance.deinit();
        const arena = arena_instance.allocator();

        var req: Request = .{
            .path = "index.html",
            .keep_alive = true,
        };
        var rsp: Response = .{};
        { // not found
            try rsp.init(arena, req);
            try testing.expectEqual(.not_found, rsp.status);
            try testing.expectEqual(69, rsp.header.len);
            // std.debug.print("{s}\n", .{rsp.header});
        }
        { // ok
            rsp.fsr = .{
                .dir = undefined,
                .encoding = .plain,
                .stat = mem.zeroInit(std.Io.File.Stat, .{
                    .kind = .file,
                    .size = 1024 * 1024 * 1024,
                    .mtime = .{ .nanoseconds = std.time.ns_per_week * 1024 },
                }),
            };
            try rsp.init(arena, req);
            try testing.expectEqual(.ok, rsp.status);
            try testing.expectEqual(176, rsp.header.len);
            // std.debug.print("{s}\n", .{rsp.header});
        }
        { // not modified
            req.etag.mtime = rsp.fsr.?.stat.mtime.nanoseconds;
            req.etag.size = rsp.fsr.?.stat.size;
            try rsp.init(arena, req);
            try testing.expectEqual(.not_modified, rsp.status);
            try testing.expectEqual(133, rsp.header.len);
            // std.debug.print("{s}\n", .{rsp.header});
        }
    }
};

const ContentEncoding = enum {
    plain,
    gzip,
    brotli,
    zstd,

    fn extension(self: ContentEncoding) []const u8 {
        return switch (self) {
            .plain => "",
            .gzip => ".gz",
            .brotli => ".br",
            .zstd => ".zst",
        };
    }

    /// Parse Accept-Encoding http header into list of ContentEncoding values.
    /// Plain is always included at index 0.
    /// Returns null if no supported encodings are found in accept_encoding string.
    fn parse(list: []ContentEncoding, accept_encoding_str: []const u8) ![]ContentEncoding {
        list[0] = .plain;
        var i: usize = 1;
        var iter = mem.splitAny(u8, accept_encoding_str, ", ");
        while (iter.next()) |v| {
            if (v.len == 0) continue;
            const v1 = if (mem.indexOfScalar(u8, v, ';')) |j| v[0..j] else v;
            if (mem.eql(u8, v1, "gzip")) {
                list[i] = .gzip;
                i += 1;
            } else if (mem.eql(u8, v1, "br")) {
                list[i] = .brotli;
                i += 1;
            } else if (mem.eql(u8, v1, "zstd")) {
                list[i] = .zstd;
                i += 1;
            }
        }
        return list[0..i];
    }

    pub fn header(self: ContentEncoding) []const u8 {
        return switch (self) {
            .plain => "",
            .gzip => "Content-Encoding: gzip\r\n",
            .brotli => "Content-Encoding: br\r\n",
            .zstd => "Content-Encoding: zstd\r\n",
        };
    }

    test parse {
        var buf: [4]ContentEncoding = undefined;

        var ar = try parse(&buf, "gzip, deflate, zstd");
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.gzip, ar[1]);
        try testing.expectEqual(.zstd, ar[2]);

        ar = try parse(&buf, "br;q=1.0, gzip;q=0.8, *;q=0.1");
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.brotli, ar[1]);
        try testing.expectEqual(.gzip, ar[2]);

        ar = try parse(&buf, "one two");
        try testing.expectEqual(1, ar.len);
    }
};

pub fn compressible(file_name: []const u8) bool {
    const extensions = [_][]const u8{
        ".html",
        ".htm",
        ".css",
        ".js",
        ".json",
        ".svg",
        ".txt",
        ".xml",
        ".csv",
        ".md",
        ".rss",
        ".atom",
    };
    for (extensions) |ex| {
        if (mem.endsWith(u8, file_name, ex)) return true;
    }
    return false;
}

/// io.recv into provided buffer, parse bytes into http request, handle
/// interrupts, short reads, pipelining (multiple request in the buffer)
const RequestRecv = struct {
    const Self = @This();

    gpa: Allocator,
    io: *Io,
    op: Io.Op = .{},
    fd: fd_t,
    vtable: struct {
        // success callback returns number of bytes consumed
        success: *const fn (*Self, []const u8) anyerror!usize,
        fail: *const fn (*Self, anyerror) anyerror!void,
    },
    buffer: []u8 = &.{},
    recv_timeout: linux.kernel_timespec = .{ .sec = keepalive_timeout, .nsec = 0 },

    pub fn prep(self: *Self) !void {
        try self.io.recvProvided(&self.op, onComplete, self.fd, &self.recv_timeout);
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        self.onCompleteFallible(res) catch |err| {
            // log.warn("{} request recv {}", .{ self.fd, err });
            try self.vtable.fail(self, err);
        };
    }

    fn onCompleteFallible(self: *Self, res: Io.Result) !void {
        const n = res.bytes() catch |err| switch (err) {
            error.SignalInterrupt => return try self.prep(),
            else => return err,
        };
        if (n == 0) {
            return error.EndOfStream;
        }

        const recv_buf: []const u8 = brk: {
            const provided_buf = try self.io.getProvidedBuffer(res);
            if (self.buffer.len == 0) break :brk provided_buf;
            // there is saved part in the buffer append to it
            const prev_len = self.buffer.len;
            self.buffer = try self.gpa.realloc(self.buffer, prev_len + provided_buf.len);
            @memcpy(self.buffer[prev_len..], provided_buf);
            break :brk self.buffer;
        };
        defer self.io.putProvidedBuffer(res);

        const m = try self.vtable.success(self, recv_buf);
        if (m == 0) {
            if (self.buffer.len == 0) {
                // partial msg in provided recv_buf save that part
                self.buffer = try self.gpa.dupe(u8, recv_buf);
            }
            return;
        }
        {
            const unused = recv_buf[m..];
            const prev = self.buffer;
            if (unused.len > 0) {
                self.buffer = try self.gpa.dupe(u8, unused);
            }
            if (prev.len > 0) {
                self.gpa.free(prev);
                self.buffer = &.{};
            }
        }
    }

    pub fn active(self: *Self) bool {
        return self.op.active();
    }

    pub fn deinit(self: *Self) void {
        self.gpa.free(self.buffer);
    }
};

pub const SendBytes = struct {
    const Self = @This();

    io: *Io,
    op: Io.Op = .{},
    fd: fd_t,
    err: ?anyerror = null,
    callback: *const fn (*Self) anyerror!void,

    buffer: []const u8 = undefined,
    more: bool = false,
    offset: usize = 0,

    pub fn prep(self: *Self, buffer: []const u8, more: bool) !void {
        self.buffer = buffer;
        self.more = more;
        self.offset = 0;
        self.err = null;
        try self.send();
    }

    fn send(self: *Self) !void {
        try self.io.send(&self.op, onComplete, self.fd, self.buffer[self.offset..], .{ .more = self.more });
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        self.onCompleteFallible(res) catch |err| {
            self.err = err;
            try self.callback(self);
        };
    }

    fn onCompleteFallible(self: *Self, res: Io.Result) !void {
        self.offset += res.bytes() catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                else => return err,
            }
        };
        if (self.offset < self.buffer.len) {
            // short send
            return try self.send();
        }
        try self.callback(self);
    }

    pub fn active(self: *Self) bool {
        return self.op.active();
    }
};

const Sendfile = struct {
    const Self = @This();

    io: *Io,
    op1: Io.Op = .{},
    op2: Io.Op = .{},
    metric: *Server.Metric.Files,
    open_callback: *const fn (*Self) anyerror!void,
    send_callback: *const fn (*Self) anyerror!void,

    conn_fd: fd_t,
    file_fd: fd_t = -1,
    path: [:0]const u8 = undefined,
    dir: std.Io.Dir = undefined,
    pipe_fds: [2]fd_t = .{ -1, -1 },
    pipe_cap: usize = 0, // capacity of the pipe, unknown
    size: usize = 0, // size of the file to send
    sent: usize = 0, // number of bytes sent to the socket
    buffered: usize = 0, // number of bytes buffered in the pipe
    err: ?anyerror = null,

    pub fn prep(self: *Self, dir: std.Io.Dir, path: [:0]const u8, size: usize) !void {
        self.dir = dir;
        self.path = path;
        self.size = size;
        self.sent = 0;
        self.buffered = 0;
        self.err = null;

        if (self.pipe_fds[0] == -1) {
            try self.pipe();
        }
        try self.open();
    }

    fn pipe(self: *Self) !void {
        try self.io.pipe(&self.op1, Self.onPipe, &self.pipe_fds);
    }

    fn open(self: *Self) !void {
        try self.io.openRead(&self.op2, Self.onOpen, self.dir.handle, self.path, null);
    }

    fn onPipe(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op1", res.ptr));
        res.ok() catch |err| switch (err) {
            error.SignalInterrupt => return try self.pipe(),
            else => if (self.err == null) {
                self.err = err;
            },
        };
        try self.pipeOpenJoin();
    }

    fn onOpen(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op2", res.ptr));
        assert(self.file_fd == -1);
        self.file_fd = res.fd() catch |err| return switch (err) {
            error.SignalInterrupt => try self.open(),
            else => if (self.err == null) {
                self.err = err;
                try self.pipeOpenJoin();
            },
        };
        try self.pipeOpenJoin();
    }

    fn pipeOpenJoin(self: *Self) !void {
        if (self.op1.active() or self.op2.active()) {
            return;
        }
        try self.open_callback(self);
    }

    pub fn send(self: *Self) !void {
        assert(self.file_fd >= 0);
        assert(self.pipe_fds[0] >= 0);

        if (self.buffered > 0) {
            try self.io.pipeToSocket(
                &self.op2,
                onPipeToSocket,
                self.conn_fd,
                self.pipe_fds,
                @intCast(self.buffered),
            );
            return;
        }

        const len = @min(if (self.pipe_cap == 0) 1024 * 1024 else self.pipe_cap, self.size - self.sent);

        try self.io.fileToPipe(
            &self.op1,
            onFileToPipe,
            self.file_fd,
            self.pipe_fds,
            @intCast(self.sent),
            @intCast(len),
        );
        try self.io.pipeToSocket(
            &self.op2,
            onPipeToSocket,
            self.conn_fd,
            self.pipe_fds,
            @intCast(len),
        );
    }

    fn onFileToPipe(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op1", res.ptr));
        const bytes = res.bytes() catch |err| brk: {
            if (self.err == null) self.err = err;
            break :brk 0;
        };
        self.buffered += bytes;
        // Discover pipe capacity on the first short send, when pipe buffers
        // less than we asked for.
        if (self.pipe_cap == 0 and bytes > 0 and bytes < self.size and self.sent == 0) {
            self.metric.pipes +%= 1;
            self.metric.pipes_cap +%= bytes;
            self.pipe_cap = bytes;
        }
    }

    fn onPipeToSocket(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op2", res.ptr));
        self.onPipeToSocketFallible(res) catch |err| {
            if (self.err == null) self.err = err;
            try self.send_callback(self);
        };
    }

    fn onPipeToSocketFallible(self: *Self, res: Io.Result) !void {
        const bytes = res.bytes() catch |err| switch (err) {
            error.SignalInterrupt,
            error.TryAgain,
            error.OperationCanceled,
            => 0,
            else => return err,
        };
        self.buffered -= bytes;
        self.sent += bytes;

        // Short send, send other parts
        if (self.sent < self.size)
            return try self.send();

        // Success, do cleanup.
        {
            try self.io.close(self.file_fd);
            self.file_fd = -1;
        }
        self.metric.count +%= 1;
        self.metric.bytes +%= self.size;
        try self.send_callback(self);
    }

    pub fn close(self: *Self) !void {
        if (self.file_fd != -1) {
            try self.io.close(self.file_fd);
            self.file_fd = -1;
        }
        if (self.pipe_fds[0] != -1) {
            try self.io.close(self.pipe_fds[0]);
            try self.io.close(self.pipe_fds[1]);
            self.pipe_fds = .{ -1, -1 };
        }
    }

    pub fn active(self: *Self) bool {
        return self.op1.active() or self.op2.active();
    }
};

const LastModified = struct {
    sec: i64,

    pub fn format(self: LastModified, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(self.sec) };
        const day_secs = epoch_secs.getDaySeconds();
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const weekday = (epoch_day.day + 4) % 7;

        const day_names = [_][]const u8{
            "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
        };
        const month_names = [_][]const u8{
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        };

        try writer.print(
            "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT",
            .{
                day_names[weekday],
                month_day.day_index + 1, // 0-indexed → 1-indexed
                month_names[@intFromEnum(month_day.month) - 1],
                year_day.year,
                day_secs.getHoursIntoDay(),
                day_secs.getMinutesIntoHour(),
                day_secs.getSecondsIntoMinute(),
            },
        );
    }

    test LastModified {
        var buf: [30]u8 = undefined;
        const sec = 1777557784;

        const lm: LastModified = .{ .sec = sec };
        const res = try std.fmt.bufPrint(&buf, "{f}", .{lm});
        try std.testing.expectEqualStrings("Thu, 30 Apr 2026 14:03:04 GMT", res);
    }
};

test {
    _ = ContentEncoding;
    _ = Response;
    _ = LastModified;
    _ = FileStat;

    std.debug.print("sizes {} {} {} {}\n", .{
        @sizeOf(RequestRecv),
        @sizeOf(FileStat),
        @sizeOf(SendBytes),
        @sizeOf(Sendfile),
    });

    _ = Op;
    _ = FileStat;
}

const Op = union {
    recv: *RequestRecv,
    file_stat: *FileStat,
    send: *SendBytes,
    sendfile: *Sendfile,
};

const Callback = struct {
    ptr: *anyopaque,
    fnc: *const fn (*anyopaque) anyerror!void,

    fn call(self: *Callback) !void {
        try self.fnc(self.ptr);
    }
};

const FileStatResult = struct {
    dir: std.Io.Dir,
    path: [:0]const u8 = &.{},
    stat: std.Io.File.Stat,
    encoding: ContentEncoding,
};

const FileStat = struct {
    const Self = @This();

    io: *Io,
    op: Io.Op = .{},
    cb: Callback,
    err: ?anyerror = null,

    dir: std.Io.Dir,
    path: [:0]const u8,
    statx: linux.Statx = mem.zeroes(linux.Statx),

    fn prep(self: *Self) !void {
        try self.io.statx(&self.op, onComplete, self.dir.handle, self.path, &self.statx);
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        res.ok() catch |err| switch (err) {
            error.SignalInterrupt => return try self.prep(),
            else => self.err = err,
        };
        try self.cb.call();
    }

    fn status(self: *Self) OpStatus {
        if (self.op.active()) return .active;
        if (self.err != null) return .fail;
        if (@as(u2048, @bitCast(self.statx)) == 0) return .inactive;
        return .success;
    }

    test "status" {
        var op: FileStat = .{
            .io = undefined,
            .cb = undefined,
            .dir = undefined,
            .path = undefined,
        };
        try testing.expectEqual(.inactive, op.status());
        op.err = error.Fail;
        try testing.expectEqual(.fail, op.status());
    }

    test "size of" {
        try testing.expectEqual(256, @sizeOf(linux.Statx));
        try testing.expectEqual(312, @sizeOf(FileStat));
        try testing.expectEqual(96, @sizeOf(std.Io.File.Stat));
    }
};

const OpStatus = enum {
    inactive,
    active,
    success,
    fail,
};
