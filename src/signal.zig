const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.signal);

var signal = std.atomic.Value(c_int).init(posix.SIG.UNUSED);

pub fn get() ?c_int {
    const sig = signal.load(.monotonic);
    if (sig == posix.SIG.UNUSED)
        return null;
    signal.store(posix.SIG.UNUSED, .release);
    return sig;
}

pub fn watch() void {
    var act = posix.Sigaction{
        .handler = .{
            .handler = struct {
                fn wrapper(sig: c_int) callconv(.c) void {
                    signal.store(sig, .release);
                    //log.debug("signal received {}", .{sig});
                }
            }.wrapper,
        },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.USR1, &act, null);
    posix.sigaction(posix.SIG.USR2, &act, null);
    posix.sigaction(posix.SIG.PIPE, &act, null);
}
