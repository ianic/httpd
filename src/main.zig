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
        try compress(gpa, root);
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
                    } else if (parseDir("root", arg, &iter)) |v| {
                        args.root = v;
                    } else if (parseDir("cert", arg, &iter)) |v| {
                        args.cert = v;
                    } else if (mem.eql(u8, "-h", arg) or mem.eql(u8, "--help", arg)) {
                        help(0);
                    } else {
                        std.debug.print("unknown argument '{s}'\n", .{arg});
                        help(1);
                    }
                },
                .compress => {
                    if (parseDir("root", arg, &iter)) |v| {
                        args.root = v;
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

        return args;
    }

    fn parseDir(comptime name: []const u8, arg: [:0]const u8, iter: *std.process.ArgIterator) ?fs.Dir {
        if (parseString(name, arg, iter)) |v| {
            return std.fs.cwd().openDir(v, .{}) catch |err| {
                fatal("cant't open root dir '{s}' {}", .{ v, err });
            };
        }
        return null;
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
            \\
            \\General options:
            \\  --help, -h          Print this help
            \\
            \\
        , .{});
        std.process.exit(status);
    }
};

fn compress(allocator: Allocator, root: fs.Dir) !void {
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
            const stat = try dir.statFile(entry.path);
            if (stat.size > 512) {
                const file_path = try allocator.dupe(u8, entry.path);
                try pool.spawn(compressFile, .{ allocator, dir, file_path });
            }
        }
    }
}

fn compressFile(allocator: Allocator, dir: fs.Dir, file_path: []const u8) void {
    defer allocator.free(file_path);

    const cmds = &[_][3][]const u8{
        .{ "gzip", "-kfq", ".gz" },
        .{ "brotli", "-kf", ".br" },
        .{ "zstd", "-kfq", ".zst" },
    };
    for (cmds) |pair| {
        const cmd = pair[0];
        const flags = pair[1];
        var child = std.process.Child.init(&[_][]const u8{ cmd, flags, file_path }, allocator);
        child.cwd_dir = dir;
        const term = child.spawnAndWait() catch |err| {
            log.err("{s} spawn {} ", .{ cmd, err });
            continue;
        };
        if (term.Exited == 0) {
            const stat = dir.statFile(file_path) catch return;
            const compressed_path = std.mem.join(allocator, "", &.{ file_path, pair[2] }) catch return;
            defer allocator.free(compressed_path);
            const c_stat = dir.statFile(compressed_path) catch return;

            log.info("{s:<6} {d:5.2}% {}->{} {s}", .{
                cmd,
                @as(f64, @floatFromInt(c_stat.size * 100)) / @as(f64, @floatFromInt(stat.size)),
                stat.size,
                c_stat.size,
                file_path,
            });
        } else {
            log.err("{s} {s} exit: {}", .{ cmd, file_path, term.Exited });
        }
    }
}

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

test {
    _ = @import("Connection.zig");
}
