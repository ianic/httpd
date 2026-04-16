const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.signal);

const empty = posix.SIG.SYS;

var signal = std.atomic.Value(posix.SIG).init(empty);

pub fn get() ?posix.SIG {
    const sig = signal.load(.monotonic);
    if (sig == empty)
        return null;
    signal.store(empty, .release);
    return sig;
}

pub fn watch() void {
    var act = posix.Sigaction{
        .handler = .{
            .handler = struct {
                fn wrapper(sig: posix.SIG) callconv(.c) void {
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

pub fn reset() void {
    var act = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.DFL },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.USR1, &act, null);
    posix.sigaction(posix.SIG.USR2, &act, null);
    posix.sigaction(posix.SIG.PIPE, &act, null);
}
