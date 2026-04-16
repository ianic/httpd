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

pub fn compress(init: std.process.Init, gpa: Allocator, root: std.Io.Dir, cache_dir: std.Io.Dir) !void {
    var threaded: std.Io.Threaded = .init(gpa, .{
        .environ = init.minimal.environ,
        .async_limit = std.Io.Limit.limited(try std.Thread.getCpuCount()),
    });
    defer threaded.deinit();
    const io = threaded.io();

    try ensureBin(io);

    var dir = try root.openDir(io, ".", .{ .iterate = true });
    defer dir.close(io);

    var group: std.Io.Group = .init;
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind == .file and compressible(entry.path)) {
            if (fs.path.dirname(entry.path)) |dir_name| {
                try cache_dir.createDirPath(io, dir_name);
            }
            const path = try gpa.dupe(u8, entry.path);
            group.async(io, compressFile, .{ io, gpa, dir, path, cache_dir });
        }
    }
    try group.await(io);
}

fn compressFile(io: std.Io, gpa: Allocator, dir: std.Io.Dir, path: []const u8, cache_dir: std.Io.Dir) void {
    defer gpa.free(path);
    compressFileFallible(io, gpa, dir, path, cache_dir) catch |err| {
        log.err("compress '{s}' failed {}", .{ path, err });
    };
}

fn ensureBin(io: std.Io) !void {
    for (commands) |cmd| {
        const argv = &[_][]const u8{ cmd.bin, "--version" };
        var child = std.process.spawn(io, .{
            .argv = argv,
            .stdout = .ignore,
        }) catch |err| {
            switch (err) {
                error.FileNotFound => log.err("{s} not found in PATH", .{cmd.bin}),
                else => {},
            }
            return err;
        };
        const term = try child.wait(io);
        if (term.exited != 0) {
            log.err("{s} exit: {}", .{ cmd.bin, term.exited });
        }
    }
}

fn compressFileFallible(io: std.Io, gpa: Allocator, dir: std.Io.Dir, path: []const u8, cache_dir: std.Io.Dir) !void {
    const stat = try dir.statFile(io, path, .{});
    if (stat.size < compress_min_file_size) {
        return;
    }

    for (commands) |cmd| {
        const c_path = try mem.joinZ(gpa, "", &.{ path, cmd.ext });
        defer gpa.free(c_path);
        if (cache_dir.statFile(io, c_path, .{})) |c_stat| {
            if (c_stat.mtime.nanoseconds == stat.mtime.nanoseconds) {
                continue;
            }
        } else |_| {}

        const argv = &[_][]const u8{ cmd.bin, cmd.flags, path };
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .cwd = .{ .dir = dir },
        });

        const term = try child.wait(io);
        if (term.exited == 0) {
            switch (posix.system.errno(posix.system.renameat(dir.handle, c_path, cache_dir.handle, c_path))) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
            const c_stat = try cache_dir.statFile(io, c_path, .{});
            log.info("{s:<6} {d:5.2}% {}->{} {s}", .{
                cmd.bin,
                @as(f64, @floatFromInt(c_stat.size * 100)) / @as(f64, @floatFromInt(stat.size)),
                stat.size,
                c_stat.size,
                path,
            });
        } else {
            log.err("{s} {s} exit: {}", .{ cmd.bin, path, term.exited });
        }
    }
}
