const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,

    read_buffers: struct {
        size: u32 = 0,
        count: u16 = 0,
    } = .{},
};

const Loop = @This();

ring: linux.IoUring,
read_buffer_group: ?linux.IoUring.BufferGroup,

pub fn init(allocator: Allocator, opt: Options) !Loop {
    var ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer ring.deinit();
    try ring.register_files_sparse(opt.fd_nr);

    const read_buffer_group: ?linux.IoUring.BufferGroup = if (opt.read_buffers.size > 0 and opt.read_buffers.count > 0)
        try linux.IoUring.BufferGroup.init(
            &ring,
            allocator,
            0,
            opt.read_buffers.size,
            opt.read_buffers.count,
        )
    else
        null;

    return .{
        .ring = ring,
        .read_buffer_group = read_buffer_group,
    };
}

pub fn deinit(self: *Loop, allocator: Allocator) void {
    if (self.read_buffer_group) |*bg| bg.deinit(allocator);
    self.ring.deinit();
}
