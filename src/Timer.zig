const std = @import("std");
const linux = std.os.linux;

started: std.Io.Timestamp = .zero,

const Self = @This();

pub fn start(self: *Self) void {
    self.started = now();
}

pub fn read(self: *Self) usize {
    const now_ts = now();
    const duration = self.started.durationTo(now_ts);
    self.started = now_ts;
    return @intCast(duration.toNanoseconds());
}

pub fn now() std.Io.Timestamp {
    var ts = std.mem.zeroes(linux.timespec);
    _ = linux.clock_gettime(.REALTIME, &ts);
    return .{ .nanoseconds = std.Io.Threaded.nanosecondsFromPosix(&ts) };
}
