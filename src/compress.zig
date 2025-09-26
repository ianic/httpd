pub fn main() !void {
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
    const root = args.root orelse return;
    var dir = try root.openDir(".", .{ .iterate = true });
    defer dir.close();

    var pool: Thread.Pool = undefined;
    try Thread.Pool.init(&pool, Thread.Pool.Options{
        .allocator = gpa,
        .n_jobs = try Thread.getCpuCount(),
    });
    defer pool.deinit();

    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind == .file and compressible(entry.path)) {
            const stat = try dir.statFile(entry.path);
            if (stat.size > 512) {
                const file_path = try gpa.dupe(u8, entry.path);
                try pool.spawn(workerFunc, .{ gpa, dir, file_path });
            }
        }
    }
}

fn workerFunc(gpa: Allocator, dir: fs.Dir, file_path: []const u8) void {
    defer gpa.free(file_path);

    const cmds = &[_][2][]const u8{
        .{ "gzip", "-kfq" },
        .{ "brotli", "-kf" },
        //.{ "zstd", "-kfq" },
    };
    for (cmds) |pair| {
        const cmd = pair[0];
        const flags = pair[1];
        var child = std.process.Child.init(&[_][]const u8{ cmd, flags, file_path }, gpa);
        child.cwd_dir = dir;
        const term = child.spawnAndWait() catch |err| {
            log.err("{s} spawn {} ", .{ cmd, err });
            continue;
        };
        if (term.Exited == 0) {
            log.debug("{s} {s}", .{ cmd, file_path });
        } else {
            log.err("{s} {s} exit: {}", .{ cmd, file_path, term.Exited });
        }
    }
}

fn compressible(file_name: []const u8) bool {
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
        //".png",
        //".jpg",
        //".jpeg",
        //".gif",
        //".gz",
        //".ico",
        //".otf",
        //".pdf",
        //".tar",
        //".ttf",
        //".wasm",
        //".webp",
        //".woff",
        //".woff2",
    };
    for (extensions) |ex| {
        if (std.mem.endsWith(u8, file_name, ex)) return true;
    }
    return false;
}

const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Args = @import("main.zig").Args;
const log = std.log.scoped(.compress);
