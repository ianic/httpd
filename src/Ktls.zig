//! Kernel structs and constants from: /usr/include/linux/tls.h or
//! https://github.com/torvalds/linux/blob/master/include/uapi/linux/tls.h

const std = @import("std");
const mem = std.mem;
const tls = @import("tls");

const Ktls = @This();

const U = union(enum) {
    aes_gcm_128: AesGcm128,
    aes_gcm_256: AesGcm256,
    chacha20_poly1305: Chacha20Poly1305,
};

tx: U,
rx: U,

pub fn txBytes(k: *Ktls) []const u8 {
    return switch (k.tx) {
        inline else => |*v| mem.asBytes(v),
    };
}

pub fn rxBytes(k: *Ktls) []const u8 {
    return switch (k.rx) {
        inline else => |*v| mem.asBytes(v),
    };
}

pub const VERSION_1_2 = 0x0303;
pub const VERSION_1_3 = 0x0304;
pub const TX = 1;
pub const RX = 2;

pub const AES_GCM_128 = 51;
pub const AES_GCM_256 = 52;
pub const CHACHA20_POLY1305 = 54;

pub const Info = extern struct {
    version: u16 = VERSION_1_3,
    cipher_type: u16 = mem.zeroes(u16),
};
pub const AesGcm128 = extern struct {
    info: Info = mem.zeroes(Info),
    iv: [8]u8 = mem.zeroes([8]u8),
    key: [16]u8 = mem.zeroes([16]u8),
    salt: [4]u8 = mem.zeroes([4]u8),
    rec_seq: [8]u8 = mem.zeroes([8]u8),
};
pub const AesGcm256 = extern struct {
    info: Info = mem.zeroes(Info),
    iv: [8]u8 = mem.zeroes([8]u8),
    key: [32]u8 = mem.zeroes([32]u8),
    salt: [4]u8 = mem.zeroes([4]u8),
    rec_seq: [8]u8 = mem.zeroes([8]u8),
};
pub const Chacha20Poly1305 = extern struct {
    info: Info = mem.zeroes(Info),
    iv: [12]u8 = mem.zeroes([12]u8),
    key: [32]u8 = mem.zeroes([32]u8),
    salt: [0]u8 = mem.zeroes([0]u8),
    rec_seq: [8]u8 = mem.zeroes([8]u8),
};

pub fn init(cipher: tls.Cipher) Ktls {
    switch (cipher) {
        .AES_128_GCM_SHA256 => |keys| {
            const k = makeKeys(AesGcm128, .{ .cipher_type = AES_GCM_128 }, keys);
            return .{
                .tx = .{ .aes_gcm_128 = k.tx },
                .rx = .{ .aes_gcm_128 = k.rx },
            };
        },
        .AES_256_GCM_SHA384 => |keys| {
            const k = makeKeys(AesGcm256, .{ .cipher_type = AES_GCM_256 }, keys);
            return .{
                .tx = .{ .aes_gcm_256 = k.tx },
                .rx = .{ .aes_gcm_256 = k.rx },
            };
        },
        .CHACHA20_POLY1305_SHA256 => |keys| {
            const k = makeKeys(Chacha20Poly1305, .{ .cipher_type = CHACHA20_POLY1305 }, keys);
            return .{
                .tx = .{ .chacha20_poly1305 = k.tx },
                .rx = .{ .chacha20_poly1305 = k.rx },
            };
        },
        else => unreachable,
    }
}

fn makeKeys(comptime T: type, info: Info, keys: anytype) struct { tx: T, rx: T } {
    return .{
        .tx = makeKey(T, info, keys.encrypt_iv, keys.encrypt_key, keys.encrypt_seq),
        .rx = makeKey(T, info, keys.decrypt_iv, keys.decrypt_key, keys.decrypt_seq),
    };
}

fn makeKey(comptime T: type, info: Info, iv: anytype, key: anytype, seq: u64) T {
    const salt_size = @sizeOf(@FieldType(T, "salt"));
    var t: T = .{
        .info = info,
        .salt = iv[0..salt_size].*,
        .iv = if (iv.len > salt_size) iv[salt_size..].* else @splat(0),
        .key = key,
    };
    mem.writeInt(u64, &t.rec_seq, seq, .big);
    return t;
}
