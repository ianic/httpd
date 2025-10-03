const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;

const tls = @import("tls");
const Io = @import("Io.zig");
const Server = @import("Server.zig");
const signal = @import("signal.zig");
const compressible = @import("Connection.zig").compressible;
const log = std.log.scoped(.main);

pub fn main() !void {
    signal.watch();

    var dbga = std.heap.DebugAllocator(.{}){};
    const gpa = switch (builtin.mode) {
        .Debug => dbga.allocator(),
        else => std.heap.c_allocator,
    };
    defer switch (builtin.mode) {
        .Debug => _ = dbga.deinit(),
        else => {},
    };

    const args = try Args.parse();
    const root = args.root.?;

    if (args.command == .compress) {
        try compress(gpa, root, args.cache.?);
        return;
    }

    var io: Io = .{};
    try io.init(gpa, .{
        .entries = args.sqes,
        .fd_nr = args.fds,
        .recv_buffers = .{ .count = args.buf_count, .size = args.buf_size },
    });
    defer io.deinit(gpa);

    var server: Server = .{
        .gpa = gpa,
        .io = &io,
        .root = root,
        .cache = args.cache orelse root,
        .tls_auth = if (args.cert) |dir| try tls.config.CertKeyPair.fromFilePath(gpa, dir, "cert.pem", "key.pem") else null,
    };
    try server.init(args.http_port, args.https_port);
    defer server.deinit();

    while (true) {
        try io.tick();
        if (signal.get()) |sig| switch (sig) {
            posix.SIG.TERM, posix.SIG.INT => break,
            posix.SIG.USR1 => {
                log.info("metric: {}", .{server.metric});
                log.info("io metric: {}", .{server.io.metric});
            },
            else => {
                log.info("ignoring signal {}", .{sig});
            },
        };
    }
    signal.reset();

    // Stop listening for new connections.
    try server.close();
    // Wait for existing connections to finish.
    while (!server.closed()) {
        try io.tick();
    }
}

const Args = struct {
    root: ?fs.Dir = null,
    cache: ?fs.Dir = null,
    cert: ?fs.Dir = null,
    http_port: u16 = 8080,
    https_port: u16 = 8443,
    buf_count: u16 = 2,
    buf_size: u32 = 4096 * 16,
    fds: u16 = 1024,
    sqes: u16 = 1024,
    command: Command = .start,

    const Command = enum {
        start,
        compress,
    };

    pub fn parse() !Args {
        var iter = std.process.args();
        _ = iter.next();
        var args: Args = .{};

        var idx: usize = 0;
        while (iter.next()) |arg| : (idx += 1) {
            if (idx == 0) {
                if (mem.eql(u8, "start", arg)) {
                    args.command = .start;
                    continue;
                } else if (mem.eql(u8, "compress", arg)) {
                    args.command = .compress;
                    continue;
                }
            }
            switch (args.command) {
                .start => {
                    if (parseInt(u16, "http-port", arg, &iter)) |v| {
                        args.http_port = v;
                    } else if (parseInt(u16, "https-port", arg, &iter)) |v| {
                        args.https_port = v;
                    } else if (parseInt(u16, "sqes", arg, &iter)) |v| {
                        args.sqes = v;
                    } else if (parseInt(u16, "fds", arg, &iter)) |v| {
                        args.fds = v;
                    } else if (parseInt(u16, "buf-count", arg, &iter)) |v| {
                        args.buf_count = v;
                    } else if (parseInt(u32, "buf-size", arg, &iter)) |v| {
                        args.buf_size = v;
                    } else if (parseDir("root", arg, &iter, false)) |v| {
                        args.root = v;
                    } else if (parseDir("cache", arg, &iter, true)) |v| {
                        args.cache = v;
                    } else if (parseDir("cert", arg, &iter, false)) |v| {
                        args.cert = v;
                    } else if (mem.eql(u8, "-h", arg) or mem.eql(u8, "--help", arg)) {
                        help(0);
                    } else {
                        std.debug.print("unknown argument '{s}'\n", .{arg});
                        help(1);
                    }
                },
                .compress => {
                    if (parseDir("root", arg, &iter, false)) |v| {
                        args.root = v;
                    } else if (parseDir("cache", arg, &iter, true)) |v| {
                        args.cache = v;
                    } else if (mem.eql(u8, "-h", arg) or mem.eql(u8, "--help", arg)) {
                        help(0);
                    } else {
                        std.debug.print("unknown argument '{s}'\n", .{arg});
                        help(1);
                    }
                },
            }
        }

        if (args.root == null) {
            std.debug.print("missing required '--root' argument\n", .{});
            help(1);
        }
        if (args.command == .compress and args.cache == null) {
            std.debug.print("missing required '--cache' argument\n", .{});
            help(1);
        }

        return args;
    }

    fn parseDir(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator, mk_if_not_found: bool) ?fs.Dir {
        if (parseString(name, arg, iter)) |v| {
            return fs.cwd().openDir(v, .{}) catch |err| {
                if (mk_if_not_found and err == error.FileNotFound) {
                    if (mkDir(v)) |d| return d;
                }
                fatal("cant't open dir '{s}' {}", .{ v, err });
            };
        }
        return null;
    }

    fn mkDir(path: []const u8) ?fs.Dir {
        fs.cwd().makePath(path) catch return null;
        return fs.cwd().openDir(path, .{}) catch return null;
    }

    fn parseInt(T: type, comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?T {
        const arg_name1 = "--" ++ name ++ "=";
        const arg_name2 = "--" ++ name;

        if (mem.startsWith(u8, arg, arg_name1)) {
            const suffix = arg[arg_name1.len..];
            return std.fmt.parseInt(T, suffix, 10) catch |err| fatal(
                "bad {s} value '{s}': {s}",
                .{ arg_name1, arg, @errorName(err) },
            );
        } else if (mem.eql(u8, arg, arg_name2)) {
            if (iter.next()) |val| {
                return std.fmt.parseInt(T, val, 10) catch |err| fatal(
                    "bad {s} value '{s}': {s}",
                    .{ arg_name2, arg, @errorName(err) },
                );
            } else fatal(
                "missing argument to '{s}'",
                .{arg_name2},
            );
        }
        return null;
    }

    fn parseString(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?[]const u8 {
        const arg_name1 = "--" ++ name ++ "=";
        const arg_name2 = "--" ++ name;

        if (mem.startsWith(u8, arg, arg_name1)) {
            const suffix = arg[arg_name1.len..];
            return suffix;
        } else if (mem.eql(u8, arg, arg_name2)) {
            if (iter.next()) |val| {
                return val;
            } else fatal(
                "missing argument to '{s}'",
                .{arg_name2},
            );
        }
        return null;
    }

    fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
        std.debug.print(fmt, args);
        std.debug.print("\n", .{});
        std.process.exit(1);
    }

    pub fn help(status: u8) noreturn {
        std.debug.print(
            \\Usage: httpd [COMMAND] [OPTIONS]
            \\
            \\Commands:
            \\  (no command)|start  Start server
            \\  compress            Compress (gzip, brotli, zstd) files in the site root
            \\
            \\Start command options:
            \\  --root              Root folder of the static site to serve
            \\  --cache             Cache folder with precompressed site files
            \\  --cert              Certificate folder. Two files are expected there:
            \\                        cert.pem - site tls certificate
            \\                        key.pem  - certificate private key
            \\  --http-port         Port for HTTP listener  (default 8080)
            \\  --https-port        Port for HTTPS listener (default 8443)
            \\io_uring options:
            \\  --sqes              Number of submission queue entries (default 1024, max 32768, must be power of 2)
            \\  --fds               Number of fixed file descriptors   (default 1024)
            \\  --buf-count         Number of receive provided buffers (default 2)
            \\  --buf-size          Size of each provided buffer       (defalut 4096 * 16)
            \\
            \\Compress command options:
            \\  --root              Root folder of the static site
            \\  --cache             Compress desination
            \\
            \\General options:
            \\  --help, -h          Print this help
            \\
            \\
        , .{});
        std.process.exit(status);
    }
};

fn compress(allocator: Allocator, root: fs.Dir, cache_dir: fs.Dir) !void {
    var dir = try root.openDir(".", .{ .iterate = true });
    defer dir.close();

    var pool: Thread.Pool = undefined;
    try Thread.Pool.init(&pool, Thread.Pool.Options{
        .allocator = allocator,
        .n_jobs = try Thread.getCpuCount(),
    });
    defer pool.deinit();

    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind == .file and compressible(entry.path)) {
            if (fs.path.dirname(entry.path)) |dir_name| {
                try cache_dir.makePath(dir_name);
            }
            const path = try allocator.dupe(u8, entry.path);
            try pool.spawn(compressFile, .{ allocator, dir, path, cache_dir });
        }
    }
}

fn compressFile(allocator: Allocator, dir: fs.Dir, path: []const u8, cache_dir: fs.Dir) void {
    compressFileFallible(allocator, dir, path, cache_dir) catch |err| {
        log.err("compress '{s}' failed {}", .{ path, err });
    };
}

fn compressFileFallible(allocator: Allocator, dir: fs.Dir, path: []const u8, cache_dir: fs.Dir) !void {
    defer allocator.free(path);
    const stat = try dir.statFile(path);
    if (stat.size < 512) {
        return;
    }

    const cmds: [3]struct {
        cmd: []const u8,
        flags: []const u8,
        ext: []const u8,
    } = .{
        .{ .cmd = "gzip", .flags = "-kfq", .ext = ".gz" },
        .{ .cmd = "brotli", .flags = "-kf", .ext = ".br" },
        .{ .cmd = "zstd", .flags = "-kfq", .ext = ".zst" },
    };
    for (cmds) |c| {
        const c_path = try mem.join(allocator, "", &.{ path, c.ext });
        defer allocator.free(c_path);
        if (cache_dir.statFile(c_path)) |c_stat| {
            if (c_stat.mtime == stat.mtime) {
                continue;
            }
        } else |_| {}

        var child = std.process.Child.init(&[_][]const u8{ c.cmd, c.flags, path }, allocator);
        child.cwd_dir = dir;
        const term = try child.spawnAndWait();
        if (term.Exited == 0) {
            try posix.renameat(dir.fd, c_path, cache_dir.fd, c_path);
            const c_stat = try cache_dir.statFile(c_path);
            log.info("{s:<6} {d:5.2}% {}->{} {s}", .{
                c.cmd,
                @as(f64, @floatFromInt(c_stat.size * 100)) / @as(f64, @floatFromInt(stat.size)),
                stat.size,
                c_stat.size,
                path,
            });
        } else {
            log.err("{s} {s} exit: {}", .{ c.cmd, path, term.Exited });
        }
    }
}

test {
    _ = @import("Connection.zig");
}
