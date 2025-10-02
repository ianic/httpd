const std = @import("std");

pub fn main() !void {
    const now: i64 = std.time.timestamp();
    std.debug.print("{s}\n", .{try toLastModified(now)});
}

pub extern "c" fn gmtime(timep: *const i64) *tm;
pub extern "c" fn strftime(
    s: [*c]u8,
    maxsize: usize,
    format: [*c]const u8,
    timeptr: *tm,
) usize;

const tm = extern struct {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
};

pub inline fn toLastModified(sec: i64) ![]const u8 {
    var buffer: [32]u8 = undefined;
    const format = "%a, %d %b %Y %H:%M:%S GMT";
    const tm_ptr = gmtime(&sec);
    const res = strftime(&buffer, buffer.len, format, tm_ptr);
    if (res == 0) {
        return error.BufferTooSmall;
    }
    return buffer[0..res];
}
