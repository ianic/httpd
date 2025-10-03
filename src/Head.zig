/// Copy of std.http.Server.Request.Head
/// https://github.com/ziglang/zig/blob/7b92d5f4052be651e9bc5cd4ad78a69ccbee865d/lib/std/http/Server.zig#L70
/// with added etag and accept encoding
const std = @import("std");
const mem = std.mem;
const http = std.http;
const testing = std.testing;

const Head = @This();

method: http.Method,
target: []const u8,
version: http.Version,
expect: ?[]const u8,
content_type: ?[]const u8,
content_length: ?u64,
transfer_encoding: http.TransferEncoding,
transfer_compression: http.ContentEncoding,
etag: ?[]const u8,
keep_alive: bool,
accept_encoding: ?[]const u8,

pub const ParseError = error{
    UnknownHttpMethod,
    HttpHeadersInvalid,
    HttpHeaderContinuationsUnsupported,
    HttpTransferEncodingUnsupported,
    HttpConnectionHeaderUnsupported,
    InvalidContentLength,
    CompressionUnsupported,
    MissingFinalNewline,
};

pub fn parse(bytes: []const u8) ParseError!Head {
    var it = mem.splitSequence(u8, bytes, "\r\n");

    const first_line = it.next().?;
    if (first_line.len < 10)
        return error.HttpHeadersInvalid;

    const method_end = mem.indexOfScalar(u8, first_line, ' ') orelse
        return error.HttpHeadersInvalid;

    const method = std.meta.stringToEnum(http.Method, first_line[0..method_end]) orelse
        return error.UnknownHttpMethod;

    const version_start = mem.lastIndexOfScalar(u8, first_line, ' ') orelse
        return error.HttpHeadersInvalid;
    if (version_start == method_end) return error.HttpHeadersInvalid;

    const version_str = first_line[version_start + 1 ..];
    if (version_str.len != 8) return error.HttpHeadersInvalid;
    const version: http.Version = switch (int64(version_str[0..8])) {
        int64("HTTP/1.0") => .@"HTTP/1.0",
        int64("HTTP/1.1") => .@"HTTP/1.1",
        else => return error.HttpHeadersInvalid,
    };

    const target = first_line[method_end + 1 .. version_start];

    var head: Head = .{
        .method = method,
        .target = target,
        .version = version,
        .expect = null,
        .content_type = null,
        .content_length = null,
        .transfer_encoding = .none,
        .transfer_compression = .identity,
        .etag = null,
        .keep_alive = switch (version) {
            .@"HTTP/1.0" => false,
            .@"HTTP/1.1" => true,
        },
        .accept_encoding = null,
    };

    while (it.next()) |line| {
        if (line.len == 0) return head;
        switch (line[0]) {
            ' ', '\t' => return error.HttpHeaderContinuationsUnsupported,
            else => {},
        }

        var line_it = mem.splitScalar(u8, line, ':');
        const header_name = line_it.next().?;
        const header_value = mem.trim(u8, line_it.rest(), " \t");
        if (header_name.len == 0) return error.HttpHeadersInvalid;

        if (std.ascii.eqlIgnoreCase(header_name, "connection")) {
            head.keep_alive = !std.ascii.eqlIgnoreCase(header_value, "close");
        } else if (std.ascii.eqlIgnoreCase(header_name, "expect")) {
            head.expect = header_value;
        } else if (std.ascii.eqlIgnoreCase(header_name, "content-type")) {
            head.content_type = header_value;
        } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
            if (head.content_length != null) return error.HttpHeadersInvalid;
            head.content_length = std.fmt.parseInt(u64, header_value, 10) catch
                return error.InvalidContentLength;
        } else if (std.ascii.eqlIgnoreCase(header_name, "content-encoding")) {
            if (head.transfer_compression != .identity) return error.HttpHeadersInvalid;

            const trimmed = mem.trim(u8, header_value, " ");

            if (http.ContentEncoding.fromString(trimmed)) |ce| {
                head.transfer_compression = ce;
            } else {
                return error.HttpTransferEncodingUnsupported;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "transfer-encoding")) {
            // Transfer-Encoding: second, first
            // Transfer-Encoding: deflate, chunked
            var iter = mem.splitBackwardsScalar(u8, header_value, ',');

            const first = iter.first();
            const trimmed_first = mem.trim(u8, first, " ");

            var next: ?[]const u8 = first;
            if (std.meta.stringToEnum(http.TransferEncoding, trimmed_first)) |transfer| {
                if (head.transfer_encoding != .none)
                    return error.HttpHeadersInvalid; // we already have a transfer encoding
                head.transfer_encoding = transfer;

                next = iter.next();
            }

            if (next) |second| {
                const trimmed_second = mem.trim(u8, second, " ");

                if (http.ContentEncoding.fromString(trimmed_second)) |transfer| {
                    if (head.transfer_compression != .identity)
                        return error.HttpHeadersInvalid; // double compression is not supported
                    head.transfer_compression = transfer;
                } else {
                    return error.HttpTransferEncodingUnsupported;
                }
            }

            if (iter.next()) |_| return error.HttpTransferEncodingUnsupported;
        } else if (std.ascii.eqlIgnoreCase(header_name, "if-none-match")) {
            const trimmed = mem.trim(u8, header_value, "\"");
            head.etag = trimmed;
        } else if (std.ascii.eqlIgnoreCase(header_name, "accept-encoding")) {
            head.accept_encoding = header_value;
        }
    }
    return error.MissingFinalNewline;
}

test parse {
    const request_bytes = "GET /hi HTTP/1.0\r\n" ++
        "content-tYpe: text/plain\r\n" ++
        "content-Length:10\r\n" ++
        "expeCt:   100-continue \r\n" ++
        "TRansfer-encoding:\tdeflate, chunked \r\n" ++
        "Accept-Encoding: gzip, deflate, br, zstd\r\n" ++
        "connectioN:\t keep-alive \r\n\r\n";

    const req = try parse(request_bytes);

    try testing.expectEqual(.GET, req.method);
    try testing.expectEqual(.@"HTTP/1.0", req.version);
    try testing.expectEqualStrings("/hi", req.target);

    try testing.expectEqualStrings("text/plain", req.content_type.?);
    try testing.expectEqualStrings("100-continue", req.expect.?);

    try testing.expectEqual(true, req.keep_alive);
    try testing.expectEqual(10, req.content_length.?);
    try testing.expectEqual(.chunked, req.transfer_encoding);
    try testing.expectEqual(.deflate, req.transfer_compression);
}

inline fn int64(array: *const [8]u8) u64 {
    return @bitCast(array.*);
}

/// Help the programmer avoid bugs by calling this when the string
/// memory of `Head` becomes invalidated.
fn invalidateStrings(h: *Head) void {
    h.target = undefined;
    if (h.expect) |*s| s.* = undefined;
    if (h.content_type) |*s| s.* = undefined;
}
