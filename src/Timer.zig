const std = @import("std");

io: std.Io,
started: std.Io.Timestamp = .zero,

const Self = @This();

pub fn start(self: *Self) void {
    self.started = std.Io.Timestamp.now(self.io, .real);
}

pub fn read(self: *Self) usize {
    const now_ts = std.Io.Timestamp.now(self.io, .real);
    const duration = self.started.durationTo(now_ts);
    self.started = now_ts;
    return @intCast(duration.toNanoseconds());
}

pub fn clone(self: *Self) Self {
    return .{ .io = self.io };
}
