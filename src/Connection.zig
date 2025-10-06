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

server: *Server,
gpa: Allocator,
io: *Io,
fd: fd_t,
protocol: Server.Protocol = .http,
pipe: ?Server.Pipe = null, // for sendfile
arena_instance: std.heap.ArenaAllocator = undefined,
arena: Allocator = undefined,

// http request and respone
req: Request = .{},
rsp: Response = .{},

// io operations
recv_op: RequestRecv = undefined,
file_stat_op: FileStatPool = undefined,
file_open_op: FileOpen = undefined,
header_send_op: SendBytes = undefined,
sendfile_op: Sendfile = undefined,

pub fn init(self: *Connection) !void {
    self.arena_instance = std.heap.ArenaAllocator.init(self.gpa);
    self.arena = self.arena_instance.allocator();

    self.recv_op = .{
        .allocator = self.gpa,
        .io = self.io,
        .fd = self.fd,
        .callback = onRequest,
    };
    try self.recv();
}

fn recv(self: *Connection) !void {
    if (self.server.closing()) {
        try self.deinit();
        return;
    }
    try self.recv_op.recv();
}

/// res is http header bytes or error
fn onRequest(ptr: *RequestRecv, res: anyerror![]const u8) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("recv_op", ptr));
    const bytes = res catch {
        try self.deinit();
        return;
    };
    self.req = Request.parse(self.arena, bytes) catch |err| {
        log.debug("connection request parse {}", .{err});
        try self.deinit();
        return;
    };
    try self.file_stat_op.init(
        self.arena,
        self.io,
        self.server.root,
        self.server.cache,
        self.req.path,
        self.req.accept_encoding orelse &[_]ContentEncoding{.plain},
        onFileStat,
    );
}

fn onFileStat(ptr: *FileStatPool, res: anyerror!File) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("file_stat_op", ptr));

    const file = res catch |err| switch (err) {
        error.NoSuchFileOrDirectory => {
            try onOpen(&self.file_open_op, -1);
            return;
        },
        else => {
            try self.deinit();
            return;
        },
    };
    self.rsp.file = file;
    self.file_open_op = .{
        .io = self.io,
        .dir = file.dir,
        .path = file.path,
        .callback = onOpen,
    };
    try self.file_open_op.open();
}

fn onOpen(ptr: *FileOpen, res: anyerror!fd_t) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("file_open_op", ptr));
    const fd = res catch |err| {
        log.warn("connection file open '{s}' failed {}", .{ ptr.path, err });
        try self.deinit();
        return;
    };
    const rsp = &self.rsp;
    try rsp.init(self.arena, self.req, fd);

    self.header_send_op = .{
        .io = self.io,
        .fd = self.fd,
        .buffer = rsp.header,
        .more = rsp.hasBody(),
        .callback = onHeader,
    };
    try self.header_send_op.send();
    log.debug(
        "{} {s} '{s}' {}/{} {s}",
        .{
            self.fd,
            @tagName(rsp.status),
            self.req.path,
            rsp.header.len,
            rsp.bodySize(),
            @tagName(rsp.contentEncoding()),
        },
    );
}

fn onHeader(ptr: *SendBytes, res: anyerror!void) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("header_send_op", ptr));
    res catch {
        try self.deinit();
        return;
    };
    const rsp = &self.rsp;
    if (!rsp.hasBody()) {
        try self.done();
        return;
    }
    // send file
    assert(self.pipe == null);
    self.pipe = try self.server.pipes.get(rsp.bodySize());
    self.sendfile_op = .{
        .io = self.io,
        .conn_fd = self.fd,
        .file_fd = rsp.fd,
        .pipe = self.pipe.?,
        .size = rsp.bodySize(),
        .callback = onSendfile,
    };
    try self.sendfile_op.send();
}

fn onSendfile(ptr: *Sendfile, res: anyerror!void) !void {
    const self: *Connection = @alignCast(@fieldParentPtr("sendfile_op", ptr));
    res catch {
        if (self.pipe) |pipe| {
            // pipe can be unusable after broken pipe
            // don't reuse it
            self.server.pipes.broken(pipe);
            self.pipe = null;
        }
        try self.deinit();
        return;
    };
    self.server.metric.files.count +%= 1;
    self.server.metric.files.bytes +%= ptr.size;
    self.server.metric.files.sendfile_more +%= ptr.metric_short_send;
    try self.done();
}

// Response sent
fn done(self: *Connection) !void {
    if (self.req.keep_alive) {
        try self.clear();
        try self.recv();
        return;
    }
    try self.deinit();
}

fn clear(self: *Connection) !void {
    if (self.pipe) |pipe| {
        try self.server.pipes.put(pipe);
        self.pipe = null;
    }
    if (self.rsp.fd >= 0) {
        try self.io.close(self.rsp.fd);
        self.rsp.fd = -1;
    }
    _ = self.arena_instance.reset(.free_all);
    self.req = .{};
    self.rsp = .{};
    self.file_stat_op = undefined;
}

pub fn close(self: *Connection) !void {
    // Cancel if receiving, else wait for pending operations
    if (self.recv_op.active()) {
        try self.io.cancel(self.fd);
    }
}

fn deinit(self: *Connection) !void {
    try self.clear();

    if (self.protocol == .https) {
        try self.io.tlsCloseNotify(self.fd);
    }
    try self.io.close(self.fd);
    self.arena_instance.deinit();
    self.recv_op.deinit();
    self.server.destroy(self);
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
    file: ?File = null,
    status: http.Status = @enumFromInt(0),
    header: []const u8 = &.{},

    fn deinit(rsp: *Response, allocator: Allocator) void {
        if (rsp.header.len > 0) {
            allocator.free(rsp.header);
        }
        rsp.* = .{};
    }

    fn init(rsp: *Response, allocator: Allocator, req: Request, fd: fd_t) !void {
        assert(rsp.fd == -1);
        if (fd == -1) {
            rsp.status = .not_found;
            rsp.header = try notFound(allocator, req.keep_alive);
            return;
        }
        rsp.fd = fd;
        const stat = rsp.file.?.stat;

        switch (stat.kind) {
            .file, .sym_link => {
                if (etagMatch(stat, req)) {
                    rsp.status = .not_modified;
                    rsp.header = try notModified(allocator, stat, req.keep_alive);
                } else {
                    rsp.status = .ok;
                    rsp.header = try ok(allocator, stat, req.path, rsp.file.?.encoding, req.keep_alive);
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
        if (rsp.file) |f| return f.stat.size;
        return 0;
    }

    fn contentEncoding(rsp: Response) ContentEncoding {
        if (rsp.file) |f| return f.encoding;
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

const File = struct {
    dir: fs.Dir,
    path: [:0]const u8 = &.{},
    stat: fs.File.Stat,
    encoding: ContentEncoding,
};

const FileStatPool = struct {
    const Self = @This();

    files: []FileStat = &.{},
    join_count: usize = 0,
    callback: *const fn (*Self, anyerror!File) anyerror!void,

    fn init(
        self: *Self,
        allocator: Allocator,
        io: *Io,
        root: fs.Dir,
        cache: fs.Dir,
        path: []const u8,
        encodings: []const ContentEncoding,
        callback: *const fn (*Self, anyerror!File) anyerror!void,
    ) !void {
        self.* = .{
            .callback = callback,
            .files = try allocator.alloc(FileStat, encodings.len),
            .join_count = encodings.len,
        };

        for (encodings, 0..) |encoding, i| {
            self.files[i] = .{
                .io = io,
                .dir = if (encoding == .plain) root else cache,
                .encoding = encoding,
                .ptr = self,
                .callback = join,
                .path = try mem.joinZ(allocator, "", &.{ path, encoding.extension() }),
            };
            try (&self.files[i]).stat();
        }
    }

    fn join(ptr: *anyopaque) !void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.join_count -= 1;
        if (self.join_count > 0)
            return;

        const plain = self.files[0];
        assert(plain.encoding == .plain);
        if (plain.err) |e| {
            try self.callback(self, e);
            return;
        }
        const plain_mtime = plain.statx.mtime;

        // find best match, shortest one
        var idx: usize = 0;
        for (self.files, 0..) |stat, i| {
            if (stat.err != null) {
                continue;
            }
            // plain and compressed mtime must match
            const mtime = stat.statx.mtime;
            if (!(mtime.sec == plain_mtime.sec and mtime.nsec == mtime.nsec)) {
                continue;
            }
            if (stat.statx.size < self.files[idx].statx.size) {
                idx = i;
            }
        }
        const match = &self.files[idx];

        const res: File = .{
            .dir = match.dir,
            .path = match.path,
            .encoding = match.encoding,
            .stat = fs.File.Stat.fromLinux(match.statx),
        };
        try self.callback(self, res);
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        if (self.files.len == 0) return;
        for (self.files) |f| {
            allocator.free(f.path);
        }
        allocator.free(self.files);
        self.files = &.{};
    }
};

const FileStat = struct {
    const Self = @This();

    io: *Io,
    dir: fs.Dir,
    path: [:0]const u8 = &.{},
    statx: linux.Statx = mem.zeroes(linux.Statx),
    completion: Io.Completion = .{},
    err: ?anyerror = null,
    encoding: ContentEncoding,
    ptr: *anyopaque,
    callback: *const fn (*anyopaque) anyerror!void,

    fn stat(self: *Self) !void {
        try self.io.statx(&self.completion, onStat, self.dir.fd, self.path, &self.statx);
    }

    fn onStat(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Self = @alignCast(@fieldParentPtr("completion", completion));
        _ = Io.result(cqe) catch |err| switch (err) {
            error.SignalInterrupt => {
                try self.stat();
                return;
            },
            else => {
                self.err = err;
            },
        };
        try self.callback(self.ptr);
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

    completion: Io.Completion = .{},
    recv_timeout: linux.kernel_timespec = .{ .sec = keepalive_timeout, .nsec = 0 },
    short_recv: ShortRecvBuffer = .{},
    allocator: Allocator,
    io: *Io,
    fd: fd_t,
    callback: *const fn (*Self, anyerror![]const u8) anyerror!void,

    fn recv(self: *Self) !void {
        try self.io.recvProvided(&self.completion, Self.onRecv, self.fd, &self.recv_timeout);
    }

    fn onRecv(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Self = @alignCast(@fieldParentPtr("completion", completion));
        const n = Io.result(cqe) catch |err| {
            switch (err) {
                error.SignalInterrupt, error.NoBufferSpaceAvailable => {
                    log.debug("connection recv retry on {}", .{err});
                    try self.recv();
                    return;
                },
                error.OperationCanceled, // timeout or server close
                error.IOError,
                error.ConnectionResetByPeer, // connection closed
                => {},
                else => log.warn("connection recv failed {}", .{err}), // unexpected
            }
            try self.callback(self, err);
            return;
        };
        if (n == 0) {
            try self.callback(self, error.EndOfStream);
            return;
        }

        const recv_buf = try self.short_recv.append(self.allocator, try self.io.getProvidedBuffer(cqe));
        defer self.io.putProvidedBuffer(cqe);

        var hp: http.HeadParser = .{};
        const header_len = hp.feed(recv_buf);
        if (hp.state != .finished) {
            if (recv_buf.len >= max_header_size) {
                try self.callback(self, error.RequestBufferOverflow);
                return;
            }
            try self.short_recv.set(self.allocator, recv_buf);
            try self.recv();
            return;
        }
        try self.short_recv.set(self.allocator, recv_buf[header_len..]);
        try self.callback(self, recv_buf[0..header_len]);
    }

    fn active(self: *Self) bool {
        return self.completion.active();
    }

    fn deinit(self: *Self) void {
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

const FileOpen = struct {
    const Self = @This();

    completion: Io.Completion = .{},
    io: *Io,
    dir: fs.Dir,
    path: [:0]const u8,
    callback: *const fn (*Self, anyerror!fd_t) anyerror!void,

    fn open(self: *Self) !void {
        try self.io.openRead(&self.completion, Self.onOpen, self.dir.fd, self.path, null);
    }

    fn onOpen(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Self = @alignCast(@fieldParentPtr("completion", completion));

        const fd = Io.result(cqe) catch |err| brk: {
            switch (err) {
                error.NoSuchFileOrDirectory => {
                    break :brk -1;
                },
                error.SignalInterrupt => {
                    try self.open();
                },
                error.FileTableOverflow => {
                    log.warn("connection file open '{s}' retry on {}", .{ self.path, err });
                    try self.open();
                },
                else => {
                    try self.callback(self, err);
                },
            }
            return;
        };

        try self.callback(self, fd);
    }
};

const SendBytes = struct {
    const Self = @This();

    io: *Io,
    completion: Io.Completion = .{},
    fd: fd_t,
    buffer: []const u8,
    offset: usize = 0,
    more: bool,
    callback: *const fn (*Self, anyerror!void) anyerror!void,

    fn send(self: *Self) !void {
        try self.io.send(&self.completion, Self.onSend, self.fd, self.buffer[self.offset..], .{ .more = self.more });
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Self = @alignCast(@fieldParentPtr("completion", completion));
        self.offset += @intCast(Io.result(cqe) catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.info("connection header send failed {}", .{err}),
            }
            try self.callback(self, err);
            return;
        });
        if (self.offset < self.buffer.len) {
            // short send send more
            try self.send();
            return;
        }

        try self.callback(self, {});
    }
};

const Sendfile = struct {
    const Self = @This();

    io: *Io,
    completion: Io.Completion = .{},
    conn_fd: fd_t,
    file_fd: fd_t,
    pipe: Server.Pipe,
    size: usize,
    offset: usize = 0,
    callback: *const fn (*Self, anyerror!void) anyerror!void,
    metric_short_send: usize = 0,

    fn send(self: *Self) !void {
        try self.io.sendfile(
            &self.completion,
            Self.onSend,
            self.conn_fd,
            self.file_fd,
            self.pipe.fds,
            @intCast(self.offset),
            @intCast(self.size - self.offset),
        );
    }

    fn onSend(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
        const self: *Self = @alignCast(@fieldParentPtr("completion", completion));
        self.offset += @intCast(Io.result(cqe) catch |err| brk: {
            switch (err) {
                error.SignalInterrupt => break :brk 0,
                error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.warn("sendfile failed {}", .{err}),
            }
            try self.callback(self, err);
            return;
        });
        if (self.offset < self.size) {
            // short send, send the rest of the file
            self.metric_short_send += 1;
            try self.send();
            return;
        }
        try self.callback(self, {});
    }
};
