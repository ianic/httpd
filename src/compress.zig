const std = @import("std");
const posix = std.posix;
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;

const compressible = @import("Connection.zig").compressible;
const log = std.log.scoped(.compress);

const compress_min_file_size = 512;

const commands: [3]struct {
    bin: []const u8,
    flags: []const u8,
    ext: []const u8,
} = .{
    .{ .bin = "gzip", .flags = "-kfq", .ext = ".gz" },
    .{ .bin = "brotli", .flags = "-kf", .ext = ".br" },
    .{ .bin = "zstd", .flags = "-kfq", .ext = ".zst" },
};

pub fn compress(allocator: Allocator, root: fs.Dir, cache_dir: fs.Dir) !void {
    try ensureBin(allocator);

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
    defer allocator.free(path);
    compressFileFallible(allocator, dir, path, cache_dir) catch |err| {
        log.err("compress '{s}' failed {}", .{ path, err });
    };
}

fn ensureBin(allocator: Allocator) !void {
    for (commands) |cmd| {
        var child = std.process.Child.init(&[_][]const u8{ cmd.bin, "--version" }, allocator);
        child.stdout_behavior = .Ignore;
        const term = child.spawnAndWait() catch |err| {
            switch (err) {
                error.FileNotFound => log.err("{s} not found in PATH", .{cmd.bin}),
                else => {},
            }
            return err;
        };
        if (term.Exited != 0) {
            log.err("{s} exit: {}", .{ cmd.bin, term.Exited });
        }
    }
}

fn compressFileFallible(allocator: Allocator, dir: fs.Dir, path: []const u8, cache_dir: fs.Dir) !void {
    const stat = try dir.statFile(path);
    if (stat.size < compress_min_file_size) {
        return;
    }

    for (commands) |cmd| {
        const c_path = try mem.join(allocator, "", &.{ path, cmd.ext });
        defer allocator.free(c_path);
        if (cache_dir.statFile(c_path)) |c_stat| {
            if (c_stat.mtime == stat.mtime) {
                continue;
            }
        } else |_| {}

        var child = std.process.Child.init(&[_][]const u8{ cmd.bin, cmd.flags, path }, allocator);
        child.cwd_dir = dir;
        const term = try child.spawnAndWait();
        if (term.Exited == 0) {
            try posix.renameat(dir.fd, c_path, cache_dir.fd, c_path);
            const c_stat = try cache_dir.statFile(c_path);
            log.info("{s:<6} {d:5.2}% {}->{} {s}", .{
                cmd.bin,
                @as(f64, @floatFromInt(c_stat.size * 100)) / @as(f64, @floatFromInt(stat.size)),
                stat.size,
                c_stat.size,
                path,
            });
        } else {
            log.err("{s} {s} exit: {}", .{ cmd.bin, path, term.Exited });
        }
    }
}
