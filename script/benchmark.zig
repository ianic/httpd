const std = @import("std");
const mem = std.mem;
const time = std.time;
const Timer = time.Timer;

// Testing that private key to key pair should be done once and not for each
// signature. It is important for server where there are many connections.

// if private key to key pair is out of loop
// zig run benchmark.zig -OReleaseFast
// 1.590234547s       6288 signatures/s

// if private key to key pair is in the loop
// zig run benchmark.zig -OReleaseFast
// 2.879966179s       3472 signatures/s

// compare with openssl
// $ openssl speed --secnods 1 ecdsa
//                                      sign    verify    sign/s verify/s
// 256 bits ecdsa (brainpoolP256r1)   0.0002s   0.0002s   5575.0   5713.0
// 256 bits ecdsa (brainpoolP256t1)   0.0002s   0.0002s   5565.0   5943.4

pub fn main() !void {
    const signatures_count = 10000;
    var timer = try Timer.start();
    const start = timer.lap();
    var i: usize = 0;
    while (i < signatures_count) : (i += 1) {

        // private key to key pair
        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const key_len = Ecdsa.SecretKey.encoded_length;
        if (key.len < key_len) return error.InvalidEncoding;
        const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
        const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);

        // signature
        var signer = try key_pair.signer(null);
        signer.update(&verify_bytes);
        const signature = try signer.finalize();
        mem.doNotOptimizeAway(signature);
        // to der - not importat, fast
        // var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        // const der = signature.toDer(&buf);
        // mem.doNotOptimizeAway(&der);
    }

    const end = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(u64, @intFromFloat(signatures_count / elapsed_s));

    std.debug.print("{}s {:10} signatures/s\n", .{ elapsed_s, throughput });
}

const key = hexToBytes("a7209ad906913563ec7434f6cd92280785b76de16d758480f0c5c873f923f135");
const verify_bytes = hexToBytes("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c2073657276");

pub fn hexToBytes(comptime hex: []const u8) [removeNonHex(hex).len / 2]u8 {
    @setEvalBranchQuota(1000 * 100);
    const hex2 = comptime removeNonHex(hex);
    comptime var res: [hex2.len / 2]u8 = undefined;
    _ = comptime std.fmt.hexToBytes(&res, hex2) catch unreachable;
    return res;
}
fn removeNonHex(comptime hex: []const u8) []const u8 {
    @setEvalBranchQuota(1000 * 100);
    var res: [hex.len]u8 = undefined;
    var i: usize = 0;
    for (hex) |c| {
        if (std.ascii.isHex(c)) {
            res[i] = c;
            i += 1;
        }
    }
    return res[0..i];
}
