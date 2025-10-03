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
fs_pool: FileStatPool = undefined,
arena_instance: std.heap.ArenaAllocator = undefined,
arena: Allocator = undefined,

inline fn parent(completion: *Io.Completion) *Connection {
    return @alignCast(@fieldParentPtr("completion", completion));
}

pub fn init(self: *Connection) !void {
    self.arena_instance = std.heap.ArenaAllocator.init(self.gpa);
    self.arena = self.arena_instance.allocator();
    try self.recv();
}

fn recv(self: *Connection) !void {
    if (self.server.closing()) {
        try self.deinit();
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
        try self.deinit();
        return;
    }

    const recv_buf = try self.short_recv.append(self.gpa, try self.io.getProvidedBuffer(cqe));
    const mreq = Request.parse(self.arena, recv_buf) catch |err| {
        log.debug("connection request parse {}", .{err});
        self.io.putProvidedBuffer(cqe);
        try self.deinit();
        return;
    };
    self.io.putProvidedBuffer(cqe);
    try self.short_recv.set(self.gpa, recv_buf[if (mreq) |r| r.size else 0..]);

    if (mreq) |req| {
        self.req = req;
        try self.fs_pool.init(
            self,
            onFile,
            self.arena,
            self.io,
            self.server.root,
            self.server.cache,
            req.path,
            req.accept_encoding orelse &[_]ContentEncoding{.plain},
        );
        return;
    }

    try self.recv();
}

fn onFile(ptr: *anyopaque, res: anyerror!File) !void {
    const self: *Connection = @ptrCast(@alignCast(ptr));
    const rsp = &self.rsp;
    rsp.file = res catch |err| switch (err) {
        error.NoSuchFileOrDirectory => {
            //TODO: rethinkg
            try rsp.init(self.arena, self.req, -1);
            try self.io.send(&self.completion, onHeader, self.fd, rsp.header, .{ .more = rsp.hasBody() });
            return;
        },
        else => {
            try self.deinit();
            return;
        },
    };
    try self.open();
}

fn open(self: *Connection) !void {
    const file = self.rsp.file.?;
    try self.io.openRead(&self.completion, onOpen, file.dir.fd, file.path, null);
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
                try self.deinit();
            },
        }
        return;
    };
    try rsp.init(self.arena, self.req, fd);
    try self.io.send(&self.completion, onHeader, self.fd, rsp.header, .{ .more = rsp.hasBody() });
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

fn onHeader(completion: *Io.Completion, cqe: linux.io_uring_cqe) !void {
    const self = parent(completion);
    const rsp = &self.rsp;
    self.offset += @intCast(Io.result(cqe) catch |err| brk: {
        switch (err) {
            error.SignalInterrupt => break :brk 0,
            error.EndOfFile, error.BrokenPipe, error.ConnectionResetByPeer => {},
            else => log.info("connection header send failed {}", .{err}),
        }
        try self.deinit();
        return;
    });
    if (self.offset < rsp.header.len) { // short send send more
        try self.io.send(completion, onHeader, self.fd, rsp.header[self.offset..], .{ .more = rsp.hasBody() });
        return;
    }
    self.offset = 0;
    if (!rsp.hasBody()) {
        try self.done();
        return;
    }
    // send file
    assert(self.pipe == null);
    self.pipe = try self.server.pipes.get(rsp.file.?.stat.size);
    try self.io.sendfile(completion, onBody, self.fd, rsp.fd, self.pipe.?.fds, 0, @intCast(rsp.file.?.stat.size));
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
        if (self.pipe) |pipe| { // pipe can be unusable after broken pipe
            self.server.pipes.broken(pipe);
            self.pipe = null;
        }
        try self.deinit();
        return;
    });
    if (self.offset < rsp.file.?.stat.size) { // short send, send the rest of the file
        const len = self.rsp.file.?.stat.size - self.offset;
        try self.io.sendfile(completion, onBody, self.fd, rsp.fd, self.pipe.?.fds, @intCast(self.offset), @intCast(len));
        self.server.metric.files.sendfile_more +%= 1;
        return;
    }
    self.server.metric.files.count +%= 1;
    self.server.metric.files.bytes +%= rsp.file.?.stat.size;
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
    self.offset = 0;
    if (self.rsp.fd >= 0) {
        try self.io.close(self.rsp.fd);
        self.rsp.fd = -1;
    }
    _ = self.arena_instance.reset(.free_all);
    self.req = .{};
    self.rsp = .{};
    self.fs_pool = undefined;
}

pub fn close(self: *Connection) !void {
    // Cancel if receiving, else wait for send to finish
    if (self.completion.active() and self.completion.callback == onRecv) {
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
    accept_encoding: ?[]ContentEncoding = null,

    /// Returns null if recv_buf doesn't hold full http request
    fn parse(allocator: Allocator, recv_buf: []const u8) !?Request {
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
            try allocator.dupeZ(u8, "index.html")
        else if (head.target[head.target.len - 1] == '/')
            try std.fmt.allocPrintSentinel(allocator, "{s}index.html", .{head.target[1..]}, 0)
        else
            try allocator.dupeZ(u8, head.target[1..]);

        if (compressible(req.path)) {
            if (head.accept_encoding) |ae| {
                const encodings = ContentEncoding.parse(ae);
                if (encodings.len > 1) {
                    req.accept_encoding = try allocator.dupe(ContentEncoding, encodings);
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
    // statx: linux.Statx = mem.zeroes(linux.Statx),
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
            toLastModified(@intCast(@divTrunc(stat.mtime, std.time.ns_per_s))) catch "",
            if (keep_alive) connection_keep_alive else connection_close,
        });
    }

    fn notModified(allocator: Allocator, stat: fs.File.Stat, keep_alive: bool) ![]const u8 {
        const fmt = "HTTP/1.1 304 Not Modified\r\n" ++
            "ETag: \"{x}-{x}\"\r\n" ++
            "Last-Modified: {s}\r\n" ++
            "{s}\r\n\r\n";
        return try std.fmt.allocPrint(allocator, fmt, .{
            stat.mtime,
            stat.size,
            toLastModified(@intCast(@divTrunc(stat.mtime, std.time.ns_per_s))) catch "",
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

test "file open" {
    const gpa = testing.allocator;

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = 16,
        .fd_nr = 16,
        .recv_buffers = .{ .count = 1, .size = 4096 },
    });
    defer io.deinit(gpa);
    const dir = try fs.cwd().openDir("site/www.ziglang.org/zig-out/", .{});
    const path = "index.html";

    var conn: struct {
        done: bool = false,
        fn onFile(ptr: *anyopaque, stat: anyerror!File) !void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (stat) |s| {
                std.debug.print("stat: {} {} {s}\n", .{ s.stat.size, s.encoding, s.path });
            } else |err| {
                std.debug.print("err: {}\n", .{err});
            }
            self.done = true;
        }
    } = .{};

    var pool: FileStatPool = .{ .ptr = &conn, .callback = @TypeOf(conn).onFile };
    try pool.init(gpa, &io, dir, path, ContentEncoding.parse("zstd gzip br pero zdero jozo bozo"));
    defer pool.deinit(gpa);

    while (!conn.done) {
        try io.tick();
    }
}

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

    /// Parse Accept-Encoding http header into list.
    /// Plain is always included.
    inline fn parse(accept_encoding: []const u8) []ContentEncoding {
        var list: [4]ContentEncoding = undefined;
        list[0] = .plain;
        var idx: usize = 1;

        var iter = mem.splitAny(u8, accept_encoding, ", ");
        while (iter.next()) |v| {
            if (v.len == 0) continue;
            const v1 = if (mem.indexOfScalar(u8, v, ';')) |i| v[0..i] else v;
            if (mem.eql(u8, v1, "gzip")) {
                list[idx] = .gzip;
                idx += 1;
            } else if (mem.eql(u8, v1, "br")) {
                list[idx] = .brotli;
                idx += 1;
            } else if (mem.eql(u8, v1, "zstd")) {
                list[idx] = .zstd;
                idx += 1;
            }
        }
        return list[0..idx];
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
        var ar = parse("gzip, deflate, zstd");
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.gzip, ar[1]);
        try testing.expectEqual(.zstd, ar[2]);

        ar = parse("br;q=1.0, gzip;q=0.8, *;q=0.1");
        try testing.expectEqual(3, ar.len);
        try testing.expectEqual(.plain, ar[0]);
        try testing.expectEqual(.brotli, ar[1]);
        try testing.expectEqual(.gzip, ar[2]);
    }
};

const testing = std.testing;

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
    ptr: *anyopaque,
    callback: *const fn (*anyopaque, anyerror!File) anyerror!void,

    fn init(
        self: *Self,
        ptr: *anyopaque,
        callback: *const fn (*anyopaque, anyerror!File) anyerror!void,
        allocator: Allocator,
        io: *Io,
        root: fs.Dir,
        cache: fs.Dir,
        path: []const u8,
        encodings: []const ContentEncoding,
    ) !void {
        self.* = .{
            .ptr = ptr,
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
                .path = try std.mem.joinZ(allocator, "", &.{ path, encoding.extension() }),
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
            try self.callback(self.ptr, e);
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
        try self.callback(self.ptr, res);
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
        if (std.mem.endsWith(u8, file_name, ex)) return true;
    }
    return false;
}

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
