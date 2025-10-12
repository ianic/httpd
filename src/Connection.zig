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
const toLastModified = @import("time.zig").toLastModified;

const Connection = @This();
const keepalive_timeout = 30;
const max_header_size = 8192;
const max_retries = 1024;

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
file_stat_op: FileStat = undefined, // find file on the disk
send_op: SendBytes = undefined, // send http header
sendfile_op: Sendfile = undefined, // send file as http body

pub fn init(self: *Connection) !void {
    self.arena_instance = std.heap.ArenaAllocator.init(self.gpa);
    self.arena = self.arena_instance.allocator();

    self.recv_op = .{
        .allocator = self.gpa,
        .io = self.io,
        .fd = self.fd,
        .callback = onRequest,
    };
    self.file_stat_op = .{
        .io = self.io,
        .root = self.server.root,
        .cache = self.server.cache,
        .callback = onFileStat,
    };
    self.send_op = .{
        .io = self.io,
        .fd = self.fd,
        .callback = onHeader,
    };
    self.sendfile_op = .{
        .io = self.io,
        .conn_fd = self.fd,
        .callback = onSendfile,
    };

    try self.readRequest();
}

fn readRequest(self: *Connection) !void {
    if (self.server.closing()) {
        try self.shutdown(null);
        return;
    }
    try self.recv_op.prep();
}

/// res is http header bytes or error
fn onRequest(ptr: *RequestRecv, res: anyerror![]const u8) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("recv_op", ptr));
    const bytes = res catch |err| return try self.shutdown(err);
    self.req = Request.parse(self.arena, bytes) catch |err| return try self.shutdown(err);
    try self.file_stat_op.prep(
        self.arena,
        self.req.path,
        self.req.accept_encoding orelse &[_]ContentEncoding{.plain},
    );
}

fn onFileStat(ptr: *FileStat, res: anyerror!FileStat.Result) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("file_stat_op", ptr));
    const rsp = &self.rsp;
    rsp.fsr = res catch |err| brk: switch (err) {
        error.NoSuchFileOrDirectory => break :brk null,
        else => return try self.shutdown(err),
    };
    try rsp.init(self.arena, self.req);
    try self.send_op.prep(rsp.header, rsp.hasBody());
}

fn onHeader(ptr: *SendBytes, res: anyerror!void) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("send_op", ptr));
    res catch |err| return try self.shutdown(err);
    if (self.rsp.fsr) |fsr| {
        // there is file to send as body
        try self.sendfile_op.prep(fsr.dir, fsr.path, fsr.stat.size);
        return;
    }
    // no body
    try self.done();
}

fn onSendfile(ptr: *Sendfile, res: anyerror!void) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("sendfile_op", ptr));
    res catch |err| return try self.shutdown(err);
    self.server.metric.files.count +%= 1;
    self.server.metric.files.bytes +%= ptr.size;
    self.server.metric.files.sendfile_more +%= ptr.metric_short_send;
    try self.done();
}

/// Done sending response
fn done(self: *Connection) !void {
    self.logAccess();
    if (self.req.keep_alive) {
        try self.reset();
        try self.readRequest();
        return;
    }
    try self.shutdown(null);
}

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
fn reset(self: *Connection) !void {
    _ = self.arena_instance.reset(.free_all);
    self.req = .{};
    self.rsp = .{};
}

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
            if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace);
        },
    };
    try self.reset();
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
        mtime: i128 = 0,
    } = .{},
    keep_alive: bool = false,
    accept_encoding: ?[]ContentEncoding = null,

    /// Returns null if recv_buf doesn't hold full http request
    fn parse(allocator: Allocator, buf: []const u8) !Request {
        const head = try Head.parse(buf);
        const content_length: u64 = head.content_length orelse 0;
        if (!(head.method == .GET and content_length == 0)) {
            return error.BadRequest;
        }

        var req: Request = .{
            .keep_alive = head.keep_alive,
        };
        if (head.etag) |et| { // parse etag
            var it = mem.splitScalar(u8, et, '-');
            req.etag.mtime = std.fmt.parseInt(i128, it.first(), 16) catch 0;
            req.etag.size = std.fmt.parseInt(u64, it.rest(), 16) catch 0;
        }
        req.path = if (head.target.len <= 1)
            try allocator.dupeZ(u8, "index.html")
        else if (head.target[head.target.len - 1] == '/')
            try std.fmt.allocPrintSentinel(allocator, "{s}index.html", .{head.target[1..]}, 0)
        else
            try allocator.dupeZ(u8, head.target[1..]);

        if (compressible(req.path)) {
            if (head.accept_encoding) |accept_encoding| {
                if (try ContentEncoding.parse(allocator, accept_encoding)) |encodings| {
                    req.accept_encoding = encodings;
                }
            }
        }

        return req;
    }

    fn deinit(req: *Request, allocator: Allocator) void {
        if (req.path.len > 0) {
            allocator.free(req.path);
        }
        if (req.accept_encoding) |ae| {
            allocator.free(ae);
        }
        req.* = .{};
    }
};

const Response = struct {
    fd: fd_t = -1,
    fsr: ?FileStat.Result = null,
    status: http.Status = @enumFromInt(0),
    header: []const u8 = &.{},

    fn deinit(rsp: *Response, allocator: Allocator) void {
        if (rsp.header.len > 0) {
            allocator.free(rsp.header);
        }
        rsp.* = .{};
    }

    fn init(rsp: *Response, allocator: Allocator, req: Request) !void {
        if (rsp.fsr == null) {
            rsp.status = .not_found;
            rsp.header = try notFound(allocator, req.keep_alive);
            return;
        }
        const stat = rsp.fsr.?.stat;
        switch (stat.kind) {
            .file, .sym_link => {
                if (etagMatch(stat, req)) {
                    rsp.status = .not_modified;
                    rsp.header = try notModified(allocator, stat, req.keep_alive);
                } else {
                    rsp.status = .ok;
                    rsp.header = try ok(allocator, stat, req.path, rsp.fsr.?.encoding, req.keep_alive);
                }
            },
            .directory => {
                // Target path was without trailing '/' and points to directory; redirect
                rsp.status = .moved_permanently;
                rsp.header = try dirRedirect(allocator, req.path, req.keep_alive);
            },
            else => {
                rsp.status = .not_found;
                rsp.header = try notFound(allocator, req.keep_alive);
            },
        }
    }

    fn etagMatch(stat: fs.File.Stat, req: Request) bool {
        return stat.size == req.etag.size and stat.mtime == req.etag.mtime;
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
        allocator: Allocator,
        stat: fs.File.Stat,
        file: [:0]const u8,
        encoding: ContentEncoding,
        keep_alive: bool,
    ) ![]const u8 {
        var buf: [32]u8 = undefined;
        const fmt = "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: {s}\r\n{s}" ++
            "Content-Length: {d}\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(allocator, fmt, .{
            contentType(file),
            encoding.header(),
            stat.size,
            stat.mtime,
            stat.size,
            toLastModified(&buf, @intCast(@divTrunc(stat.mtime, std.time.ns_per_s))),
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notModified(allocator: Allocator, stat: fs.File.Stat, keep_alive: bool) ![]const u8 {
        var buf: [32]u8 = undefined;
        const fmt = "HTTP/1.1 304 Not Modified\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(allocator, fmt, .{
            stat.mtime,
            stat.size,
            toLastModified(&buf, @intCast(@divTrunc(stat.mtime, std.time.ns_per_s))),
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notFound(allocator: Allocator, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Length: 0\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(allocator, fmt, .{
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn dirRedirect(allocator: Allocator, path: []const u8, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 301 Moved Permanently\r\n" ++
            "Content-Length: 0\r\n" ++
            "Location: \\{s}\\ \r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(allocator, fmt, .{
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
    fn parse(allocator: Allocator, accept_encoding: []const u8) !?[]ContentEncoding {
        var list: std.ArrayList(ContentEncoding) = .empty;
        try list.append(allocator, .plain);

        var iter = mem.splitAny(u8, accept_encoding, ", ");
        while (iter.next()) |v| {
            if (v.len == 0) continue;
            const v1 = if (mem.indexOfScalar(u8, v, ';')) |i| v[0..i] else v;
            if (mem.eql(u8, v1, "gzip")) {
                try list.append(allocator, .gzip);
            } else if (mem.eql(u8, v1, "br")) {
                try list.append(allocator, .brotli);
            } else if (mem.eql(u8, v1, "zstd")) {
                try list.append(allocator, .zstd);
            }
        }

        if (list.items.len == 1) {
            list.deinit(allocator);
            return null;
        }
        return try list.toOwnedSlice(allocator);
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
        const testing = std.testing;

        var ar = (try parse(testing.allocator, "gzip, deflate, zstd")).?;
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.gzip, ar[1]);
        try testing.expectEqual(.zstd, ar[2]);
        testing.allocator.free(ar);

        ar = (try parse(testing.allocator, "br;q=1.0, gzip;q=0.8, *;q=0.1")).?;
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.brotli, ar[1]);
        try testing.expectEqual(.gzip, ar[2]);
        testing.allocator.free(ar);

        try testing.expectEqual(null, try parse(testing.allocator, "one two"));
    }
};

const FileStat = struct {
    const Self = @This();

    const Result = struct {
        dir: fs.Dir,
        path: [:0]const u8 = &.{},
        stat: fs.File.Stat,
        encoding: ContentEncoding,
    };

    io: *Io,
    callback: *const fn (*Self, anyerror!Result) anyerror!void,
    root: fs.Dir,
    cache: fs.Dir,

    ops: []StatOp = &.{},
    join_count: usize = 0,

    fn prep(self: *Self, allocator: Allocator, path: []const u8, encodings: []const ContentEncoding) !void {
        self.ops = try allocator.alloc(StatOp, encodings.len);
        self.join_count = encodings.len;

        for (encodings, 0..) |encoding, i| {
            self.ops[i] = .{
                .parent = self,
                .dir = if (encoding == .plain) self.root else self.cache,
                .encoding = encoding,
                .path = try mem.joinZ(allocator, "", &.{ path, encoding.extension() }),
            };
            try (&self.ops[i]).prep();
        }
    }

    fn join(self: *Self) !void {
        self.join_count -= 1;
        if (self.join_count > 0)
            return;

        const plain = self.ops[0];
        assert(plain.encoding == .plain);
        if (plain.err) |e| {
            try self.callback(self, e);
            return;
        }
        const plain_mtime = plain.statx.mtime;

        // find best match, shortest one
        var idx: usize = 0;
        for (self.ops, 0..) |stat, i| {
            if (stat.err != null) {
                continue;
            }
            // plain and compressed mtime must match
            const mtime = stat.statx.mtime;
            if (!(mtime.sec == plain_mtime.sec and mtime.nsec == mtime.nsec)) {
                continue;
            }
            if (stat.statx.size < self.ops[idx].statx.size) {
                idx = i;
            }
        }
        const match = &self.ops[idx];

        try self.callback(self, .{
            .dir = match.dir,
            .path = match.path,
            .encoding = match.encoding,
            .stat = fs.File.Stat.fromLinux(match.statx),
        });
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        if (self.ops.len == 0) return;
        for (self.ops) |f| {
            allocator.free(f.path);
        }
        allocator.free(self.ops);
        self.ops = &.{};
    }

    const StatOp = struct {
        parent: *FileStat,
        op: Io.Op = .{},
        dir: fs.Dir,
        path: [:0]const u8 = &.{},
        encoding: ContentEncoding,
        statx: linux.Statx = mem.zeroes(linux.Statx),
        err: ?anyerror = null,

        fn prep(op: *StatOp) !void {
            try op.parent.io.statx(&op.op, onComplete, op.dir.fd, op.path, &op.statx);
        }

        fn onComplete(res: Io.Result) !void {
            const op: *StatOp = @alignCast(@fieldParentPtr("op", res.ptr));
            res.ok() catch |err| switch (err) {
                error.SignalInterrupt => {
                    try op.prep();
                    return;
                },
                else => {
                    op.err = err;
                },
            };
            try op.parent.join();
        }
    };
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

    op: Io.Op = .{},
    recv_timeout: linux.kernel_timespec = .{ .sec = keepalive_timeout, .nsec = 0 },
    short_recv: ShortRecvBuffer = .{},
    allocator: Allocator,
    io: *Io,
    fd: fd_t,
    callback: *const fn (*Self, anyerror![]const u8) anyerror!void,
    no_buf_retries: usize = 0,

    pub fn prep(self: *Self) !void {
        try self.io.recvProvided(&self.op, onComplete, self.fd, &self.recv_timeout);
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        const n = res.bytes() catch |err| {
            switch (err) {
                error.SignalInterrupt => try self.prep(),
                error.NoBufferSpaceAvailable => {
                    self.no_buf_retries += 1;
                    if (self.no_buf_retries > max_retries) return try self.callback(self, err);
                    try self.prep();
                },
                else => try self.callback(self, err),
            }
            return;
        };
        if (n == 0) {
            try self.callback(self, error.EndOfStream);
            return;
        }

        const recv_buf = try self.short_recv.append(self.allocator, try self.io.getProvidedBuffer(res));
        defer self.io.putProvidedBuffer(res);

        var hp: http.HeadParser = .{};
        const header_len = hp.feed(recv_buf);
        if (hp.state != .finished) {
            if (recv_buf.len >= max_header_size) {
                try self.callback(self, error.RequestBufferOverflow);
                return;
            }
            try self.short_recv.set(self.allocator, recv_buf);
            try self.prep();
            return;
        }

        self.no_buf_retries = 0;
        try self.callback(self, recv_buf[0..header_len]);
        try self.short_recv.set(self.allocator, recv_buf[header_len..]);
    }

    pub fn active(self: *Self) bool {
        return self.op.active();
    }

    pub fn deinit(self: *Self) void {
        self.short_recv.deinit(self.allocator);
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

pub const SendBytes = struct {
    const Self = @This();

    io: *Io,
    callback: *const fn (*Self, anyerror!void) anyerror!void,
    op: Io.Op = .{},
    fd: fd_t,

    buffer: []const u8 = undefined,
    more: bool = false,
    offset: usize = 0,

    pub fn prep(self: *Self, buffer: []const u8, more: bool) !void {
        self.buffer = buffer;
        self.more = more;
        self.offset = 0;
        try self.prepIo();
    }

    fn prepIo(self: *Self) !void {
        try self.io.send(&self.op, onComplete, self.fd, self.buffer[self.offset..], .{ .more = self.more });
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        self.offset += res.bytes() catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                else => return try self.callback(self, err),
            }
        };
        // short send send more
        if (self.offset < self.buffer.len) return try self.prepIo();
        try self.callback(self, {});
    }

    pub fn active(self: *Self) bool {
        return self.op.active();
    }
};

const Sendfile = struct {
    const Self = @This();

    io: *Io,
    op: Io.Op = .{},
    callback: *const fn (*Self, anyerror!void) anyerror!void,

    conn_fd: fd_t,
    file_fd: fd_t = -1,
    pipe_fds: [2]fd_t = .{ -1, -1 },
    dir: fs.Dir = undefined,
    path: [:0]const u8 = undefined,
    size: usize = 0,

    offset: usize = 0,
    metric_short_send: usize = 0,

    pub fn prep(self: *Self, dir: fs.Dir, path: [:0]const u8, size: usize) !void {
        self.dir = dir;
        self.path = path;
        self.size = size;
        self.offset = 0;

        if (self.pipe_fds[0] == -1) {
            try self.pipe();
            return;
        }
        try self.open();
    }

    fn pipe(self: *Self) !void {
        try self.io.pipe(&self.op, Self.onPipe, &self.pipe_fds);
    }

    fn open(self: *Self) !void {
        try self.io.openRead(&self.op, Self.onOpen, self.dir.fd, self.path, null);
    }

    fn onPipe(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        res.ok() catch |err| {
            switch (err) {
                error.SignalInterrupt => try self.pipe(),
                else => try self.callback(self, err),
            }
            return;
        };
        try self.open();
    }

    fn onOpen(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        assert(self.file_fd == -1);
        self.file_fd = res.fd() catch |err| {
            switch (err) {
                error.SignalInterrupt => try self.open(),
                else => try self.callback(self, err),
            }
            return;
        };
        try self.sendfile();
    }

    pub fn sendfile(self: *Self) !void {
        try self.io.sendfile2(
            &self.op,
            onComplete,
            self.conn_fd,
            self.file_fd,
            self.pipe_fds,
            @intCast(self.offset),
            @intCast(self.size - self.offset),
        );
    }

    fn onComplete(res: Io.Result) !void {
        const self: *Self = @alignCast(@fieldParentPtr("op", res.ptr));
        self.offset += res.bytes() catch |err| brk: switch (err) {
            error.SignalInterrupt => break :brk 0,
            else => return try self.callback(self, err),
        };
        if (self.offset < self.size) { // short send, send the rest of the file
            self.metric_short_send += 1;
            try self.sendfile();
            return;
        }
        {
            try self.io.close(self.file_fd);
            self.file_fd = -1;
        }
        try self.callback(self, {});
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
        return self.op.active();
    }
};
