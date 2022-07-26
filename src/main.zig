const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Managed = std.math.big.int.Managed;
const Allocator = std.mem.Allocator;
const test_allocator = std.testing.allocator;
const ArrayList = std.ArrayList;
const w = std.os.windows;
// 256 bytes -> 2048 -> ~4096
const RSA_SIZE = 128;

// Inner struct of RSA. This is used to seperate the allocator from the internal RSA parameters.
// This can be later utilized for creating PKCS1
const Inner = struct {
    p: Managed,
    q: Managed,
    pq: Managed,
    d: Managed,
    phi: Managed,
    e: Managed,
};

//Windows Only
// Using the bcrypt header to generate cryptographically secure random numbers.
pub extern "bcrypt" fn BCryptGenRandom(
    //*void / BCRYPT_ALG_HANDLE
    hAlgorithm: ?*anyopaque,
    //PUCHAR
    pbBuffer: *w.UCHAR,
    //ULONG
    cbBuffer: w.ULONG,
    //ULONG
    dwFlags: w.ULONG,
) callconv(w.WINAPI) w.NTSTATUS;

pub const RSA = struct {
    allocator: Allocator,
    inner: *Inner,

    pub fn init(alloc: Allocator) !RSA {
        var inner = try alloc.create(Inner);
        inner.* = Inner{
            .p = try generatePrimeThreaded(alloc),
            .q = try generatePrimeThreaded(alloc),
            .pq = try Managed.initSet(alloc, 1),
            .d = undefined,
            .phi = try Managed.initSet(alloc, 1),
            .e = try Managed.initSet(alloc, 65537),
        };
        try Managed.mul(&inner.pq, &inner.q, &inner.pq);
        var p1 = try Managed.initSet(alloc, 1);
        defer p1.deinit();
        var q1 = try Managed.initSet(alloc, 1);
        defer q1.deinit();
        try Managed.sub(&p1, &inner.p, &p1);
        try Managed.sub(&q1, &inner.q, &q1);
        try Managed.mul(&inner.phi, &p1, &q1);
        inner.d = try modinv(inner.e, inner.phi);

        return RSA{
            .inner = inner,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *RSA) void {
        self.inner.phi.deinit();
        self.inner.p.deinit();
        self.inner.q.deinit();
        self.inner.e.deinit();
        self.inner.d.deinit();
        self.inner.pq.deinit();
        self.allocator.destroy(self.inner);
        self.inner = undefined;
    }
};

fn toggle(r: *Managed, bit: u16) !void {
    var one = try Managed.initSet(r.allocator, 1);
    try one.shiftLeft(&one, bit);
    try Managed.bitXor(r, r, &one);
    one.deinit();
}

fn toggleRandomBit(r: *Managed) !void {
    var seed = std.time.nanoTimestamp();
    if (seed < 0) {
        std.log.warn("Bad seed, using constant seed", .{});
        seed = 42;
    }
    var rand = std.rand.DefaultPrng.init(@intCast(u64, seed));
    var num = rand.random().uintAtMost(u16, RSA_SIZE);
    std.log.warn("{}", .{num});
    try toggle(r, num);
}

//Will toggle n random bits on the passed variable.
//This function is definately NOT cryptographically secure and
//should not be used to generate real values used for RSA
fn toggleRandomBits(r: *Managed, iterations: u16) !void {
    var seed = std.time.nanoTimestamp();
    if (seed < 0) {
        std.log.warn("Bad seed, using constant seed", .{});
        seed = 42;
    }
    var rand = std.rand.DefaultPrng.init(@intCast(u64, seed));
    var i: u16 = 0;
    while (i <= iterations) : (i += 1) {
        var num = rand.random().uintAtMost(u16, RSA_SIZE);
        //std.log.warn("{}\n", .{num});
        try toggle(r, num);
    }
}

// Generates random number by toggling random bits of the provided r.
// this function acts similarly to toggleRandomBits. However, it will assert that the number outputted is > start and < end.
fn toggleRandomBitsRanged(r: *Managed, iterations: u16, start: Managed, end: Managed) !void {
    var seed = std.time.nanoTimestamp();
    if (seed < 0) {
        std.log.warn("Bad seed, using constant seed", .{});
        seed = 42;
    }
    var rand = std.rand.DefaultPrng.init(@intCast(u64, seed));
    var i: u16 = 0;
    while (i <= iterations) : (i += 1) {
        var num = rand.random().uintAtMost(u16, RSA_SIZE);
        //std.log.warn("{}\n",.{num});
        try toggle(r, num);
    }
    var temp = try Managed.initSet(r.allocator, 1);
    defer temp.deinit();
    try Managed.add(&temp, &start, &temp);
    try Managed.sub(&temp, &end, &temp);
    try Managed.divFloor(&temp, r, r, &temp);
    try Managed.add(r, r, &start);
}

fn truncate(r: *Managed, bits: u16) !void {
    var one = try Managed.initSet(r.allocator, 1);
    defer one.deinit();
    try one.shiftLeft(&one, bits);
    var one_again = try Managed.initSet(r.allocator, 1);
    defer one_again.deinit();
    try one.sub(&one, &one_again);
    try r.bitAnd(r, &one);
}

fn generateDevRandomRanged(alloc: Allocator, fd: *?std.fs.File, start: Managed, end: Managed) !Managed {
    if (builtin.os.tag == .windows) {
        var pbData: [RSA_SIZE]w.BYTE = undefined;
        const ptr = @ptrCast(*w.BYTE, &pbData);
        _ = BCryptGenRandom(null, ptr, RSA_SIZE, 0x00000002);
        var ret = try numbify(&pbData, alloc);
        var temp = try Managed.init(alloc);
        defer temp.deinit();
        try Managed.add(&temp, &start, &temp);
        try Managed.sub(&temp, &end, &temp);
        try Managed.divFloor(&temp, &ret, &ret, &temp);
        try Managed.add(&ret, &ret, &start);
        return ret;
    } else {
        // Open Dev random then close it once done if no file was open.
        // helps with keeping the file open for multiple generations.
        if (fd.* == null) {
            var file = try std.fs.cwd().openFile("/dev/urandom", .{});
            defer file.close();
            var buf_reader = std.io.bufferedReader(file.reader());
            var in_stream = buf_reader.reader();
            var preret = try in_stream.readBytesNoEof(RSA_SIZE);
            var ret = try numbify(&preret, alloc);
            var temp = try Managed.init(alloc);
            defer temp.deinit();
            try Managed.add(&temp, &start, &temp);
            try Managed.sub(&temp, &end, &temp);
            try Managed.divFloor(&temp, &ret, &ret, &temp);
            try Managed.add(&ret, &ret, &start);
            return ret;
        }
        var buf_reader = std.io.bufferedReader(fd.*.?.reader());
        var in_stream = buf_reader.reader();
        var preret = try in_stream.readBytesNoEof(RSA_SIZE);
        var ret = try numbify(&preret, alloc);
        var temp = try Managed.init(alloc);
        defer temp.deinit();
        try Managed.add(&temp, &start, &temp);
        try Managed.sub(&temp, &end, &temp);
        try Managed.divFloor(&temp, &ret, &ret, &temp);
        try Managed.add(&ret, &ret, &start);
        return ret;
    }
}

fn generateDevRandom(alloc: Allocator, fd: *?std.fs.File) !Managed {
    if (builtin.os.tag == .windows) {
        var pbData: [RSA_SIZE]w.BYTE = undefined;
        const ptr = @ptrCast(*w.BYTE, &pbData);
        _ = BCryptGenRandom(null, ptr, RSA_SIZE, 0x00000002);
        return try numbify(&pbData, alloc);
    } else {
        // Open Dev random then close it once done if no file was open.
        // helps with keeping the file open for multiple generations.
        if (fd.* == null) {
            var file = try std.fs.cwd().openFile("/dev/urandom", .{});
            defer file.close();
            var buf_reader = std.io.bufferedReader(file.reader());
            var in_stream = buf_reader.reader();
            var ret = try in_stream.readBytesNoEof(RSA_SIZE);
            return try numbify(&ret, alloc);
        }
        var buf_reader = std.io.bufferedReader(fd.*.?.reader());
        var in_stream = buf_reader.reader();
        var ret = try in_stream.readBytesNoEof(RSA_SIZE);
        return try numbify(&ret, alloc);
    }
}

// String Tools

// Makes an arbitrary number out of a string.
// Takes the string, converts it to a lower hex slice without 0x, then uses Managed to set it from
// a "string".
pub fn numbify(string: []const u8, alloc: Allocator) !Managed {
    var ret = try Managed.init(alloc);
    const hexed = try std.fmt.allocPrint(
        alloc,
        "{x}",
        .{std.fmt.fmtSliceHexLower(string)},
    );
    defer alloc.free(hexed);
    try ret.setString(16, hexed);
    return ret;
}

// Oposite of numbify. Takes in a string of a big int, converts it back to hex
// then converts that hex to bytes to construct the original string.
pub fn denumbify(input: []const u8, alloc: Allocator) ![]u8 {
    var ret = try Managed.initSet(alloc, 1);
    try ret.setString(10, input);
    defer ret.deinit();
    const t = ret.toConst();
    var tt = try t.toStringAlloc(alloc, 16, std.fmt.Case.lower);
    defer alloc.free(tt);
    var val = try alloc.alloc(u8, input.len * 2);
    var decoded = try std.fmt.hexToBytes(val, tt);
    return decoded;
}
// Calculates Modular Multiplicative Inverse.
// This function will use the same allocator as a0 for internal allocations
pub fn modinv(a0: Managed, m0: Managed) !Managed {
    var one = try Managed.initSet(a0.allocator, 1);
    if (m0.toConst().order(one.toConst()) == std.math.Order.eq) {
        return one;
    }
    defer one.deinit();
    var a = try a0.clone();
    defer a.deinit();
    var m = try m0.clone();
    defer m.deinit();
    var x0 = try Managed.initSet(a0.allocator, 0);
    defer x0.deinit();
    var inv = try Managed.initSet(a0.allocator, 1);
    while (a.toConst().order(one.toConst()) == std.math.Order.gt) {
        var temp = try Managed.initSet(a0.allocator, 0);
        defer temp.deinit();
        var rem = try Managed.initSet(a0.allocator, 0);
        defer rem.deinit();
        try Managed.divFloor(&temp, &rem, &a, &m);
        //std.log.warn("{}", .{rem});
        try Managed.mul(&temp, &temp, &x0);
        try Managed.sub(&inv, &inv, &temp);
        std.mem.swap(Managed, &rem, &a);
        std.mem.swap(Managed, &a, &m);
        std.mem.swap(Managed, &x0, &inv);
    }

    var zero = try Managed.initSet(a0.allocator, 0);
    defer zero.deinit();
    if (inv.toConst().order(zero.toConst()) == std.math.Order.lt) {
        try inv.add(&inv, &m0);
    }
    return inv;
}

// Low to high power mod function.
// Similar to the modinv, this will take three managed much like pow(b,e,m) in python.
// This function should produce the equivlent of c = b^e mod m
// The allocator for this function internal use is taken from the b value's allocator.
pub fn powMod(b: Managed, e: Managed, m: Managed) !Managed {
    var accum = try Managed.initSet(b.allocator, 1);
    var one = try Managed.initSet(b.allocator, 0x1);
    defer one.deinit();
    var temp = try Managed.initSet(b.allocator, 0);
    defer temp.deinit();
    var x = try e.clone();
    defer x.deinit();
    var apow = try b.clone();
    defer apow.deinit();
    while (!x.eqZero()) {
        if (x.isOdd()) {
            try Managed.mul(&accum, &accum, &apow);
            try Managed.divFloor(&temp, &accum, &accum, &m);
        }
        try x.shiftRight(&x, 1);
        var temp1 = try Managed.initSet(b.allocator, 0);
        defer temp1.deinit();
        try Managed.mul(&temp1, &apow, &apow);
        try Managed.divFloor(&temp, &apow, &temp1, &m);
    }
    return accum;
}

// Miller Rabin primality test where iterations is the number of rounds.
// true => number is probably prime
// false => number is definately not a prime
fn millerRabin(num: Managed, iterations: u16) !bool {
    var iters = iterations;
    if (num.eqZero()) {
        return false;
    }
    // used to compare the num, and see if it's <= 5.
    var six = try Managed.initSet(num.allocator, 6);
    defer six.deinit();
    if (num.toConst().order(six.toConst()) == std.math.Order.lt) {
        return true;
    }
    if (num.isEven()) {
        return false;
    }

    //:outer random num constants
    var lower = try Managed.initSet(num.allocator, 1);
    defer lower.deinit();
    var higher = try num.clone();
    defer higher.deinit();
    try Managed.sub(&higher, &higher, &lower);
    // rand constants end
    //
    var two = try Managed.initSet(num.allocator, 2);
    defer two.deinit();
    var r: u64 = 0;
    var s = try Managed.initSet(num.allocator, 1);
    defer s.deinit();
    try Managed.sub(&s, &num, &s);
    while (s.isEven()) {
        r += 1;
        try s.shiftRight(&s, 1);
    }
    outer: while (iters > 0) : (iters -= 1) {
        var a = try Managed.initSet(num.allocator, 0);
        defer a.deinit();
        try toggleRandomBitsRanged(&a, 100, lower, higher);
        var x = try powMod(a, s, num);
        defer x.deinit();

        if (x.toConst().order(lower.toConst()) == std.math.Order.eq or
            x.toConst().order(higher.toConst()) == std.math.Order.eq)
        {
            continue :outer;
        }
        var z: u64 = 1;
        inner: while (z < r) : (z += 1) {
            var temp00 = x;
            defer temp00.deinit();
            x = try powMod(temp00, two, num);
            if (x.toConst().order(lower.toConst()) == std.math.Order.eq) {
                return false;
            } else if (x.toConst().order(higher.toConst()) == std.math.Order.eq) {
                break :inner;
            }
        }
        if (z == r) {
            return false;
        }
    }
    return true;
}

// Primes less than 5000. This is to help speed up the process for finding odd numbers that aren't primes.
const LowerPrimes = [_]u32{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999 };

// Miller Rabin primality test. This functions returns a void instead of a bool.
// However, it takes in the bool as a supplied argument. This is helpful for the usage of threads.
// ret.* = true => Probably Prime
// ret.* = false => definately not a prime
fn millerRabinThreadHelped(ret: *bool, num: Managed, iterations: u16) !void {
    var iters = iterations;
    if (num.eqZero()) {
        ret.* = false;
        return;
    }
    // used to compare the num, and see if it's <= 5.
    if (num.isEven()) {
        ret.* = false;
        return;
    }
    for (LowerPrimes) |lp| {
        var allocatedLp = try Managed.initSet(num.allocator, lp);
        defer allocatedLp.deinit();
        var temp = try Managed.init(num.allocator);
        defer temp.deinit();
        try Managed.divFloor(&allocatedLp, &temp, &num, &allocatedLp);
        if (temp.toConst().eqZero()) {
            ret.* = false;
            return;
        }
    }
    //:outer random num constants
    var lower = try Managed.initSet(num.allocator, 1);
    defer lower.deinit();
    var higher = try num.clone();
    defer higher.deinit();
    try Managed.sub(&higher, &higher, &lower);
    // rand constants end
    var two = try Managed.initSet(num.allocator, 2);
    defer two.deinit();
    var r: u64 = 0;
    var s = try Managed.initSet(num.allocator, 1);
    defer s.deinit();
    try Managed.sub(&s, &num, &s);
    while (s.isEven()) {
        r += 1;
        try s.shiftRight(&s, 1);
    }
    var file = std.fs.cwd().openFile("/dev/urandom", .{}) catch null;
    defer {
        if (file != null) {
            file.?.close();
        }
    }
    outer: while (iters > 0) : (iters -= 1) {
        var a = try generateDevRandomRanged(num.allocator, &file, lower, higher);
        defer a.deinit();
        var x = try powMod(a, s, num);
        defer x.deinit();

        if (x.toConst().order(lower.toConst()) == std.math.Order.eq or
            x.toConst().order(higher.toConst()) == std.math.Order.eq)
        {
            continue :outer;
        }
        var z: u64 = 1;
        inner: while (z < r) : (z += 1) {
            var temp00 = x;
            defer temp00.deinit();
            x = try powMod(temp00, two, num);
            if (x.toConst().order(lower.toConst()) == std.math.Order.eq) {
                ret.* = false;
                return;
            } else if (x.toConst().order(higher.toConst()) == std.math.Order.eq) {
                break :inner;
            }
        }
        if (z == r) {
            ret.* = false;
            return;
        }
    }
    ret.* = true;
    return;
}

// single threaded prime generation function. takes in the allocator for the prime generated.
// It will continueously run generateDevRandom until the result of millerRabin is true.
fn generate_prime(alloc: Allocator) !Managed {
    var candy = try generateDevRandom(alloc, null);
    var exit = try millerRabin(candy, 40);
    while (exit != true) {
        candy.deinit();
        candy = try generateDevRandom(alloc, null);
        // toggle 1 more random bit and see it that makes it a prime
        exit = try millerRabin(candy, 40);
        //std.debug.print("\nCandy {}\n", .{candy});
    }
    return candy;
}

// Similar to generate_prime. However, this function is threaded for optimization.
// takes in the allocator which will be used to allocate the prime candidate and the thread pool.
const ThreadCount: usize = 100;
pub fn generatePrimeThreaded(alloc: Allocator) !Managed {
    var ret: Managed = undefined;
    var exit = true;
    var file = std.fs.cwd().openFile("/dev/urandom", .{}) catch null;
    while (exit) {
        var candies = ArrayList(Managed).init(alloc);
        defer candies.deinit();
        var bools = [_]bool{undefined} ** ThreadCount;
        //defer threads.deinit();
        var iterations: usize = 0;
        //initialize the array with random values
        while (iterations < ThreadCount) : (iterations += 1) {
            try candies.append(try generateDevRandom(alloc, &file));
        }
        var threads = ArrayList(std.Thread).init(alloc);
        defer threads.deinit();
        iterations = 0;
        while (iterations < ThreadCount) : (iterations += 1) {
            const thread = try std.Thread.spawn(.{}, millerRabinThreadHelped, .{ &bools[iterations], candies.items[iterations], 40 });
            try threads.append(thread);
        }

        for (threads.items) |th| {
            th.join();
        }
        for (bools) |val, idx| {
            if (val and exit) {
                ret = try candies.items[idx].clone();
                exit = false;
            }
            candies.items[idx].deinit();
        }
    }
    if (file != null) {
        file.?.close();
    }
    return ret;
}

test "Test Threaded Generation" {
    var prime = try generatePrimeThreaded(test_allocator);
    std.debug.print("GOT PRIME: {}\n", .{prime});
    defer prime.deinit();
}

//test "Test Prime Generation" {
//    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
//    defer arena.deinit();
//    const allocator = arena.allocator();
//    var prime = try generate_prime(allocator);
//    defer prime.deinit();
//    std.debug.print("\nRandom Prime {}\n", .{prime});
//}

test "Miller Rabin Test Test" {
    var prime = try Managed.initSet(test_allocator, 0);
    try prime.setString(10, "190924658555315858151119591629547667189398663156457464802722656138791473781208916582860638604319810040699438425180594060124689945423307189481337028373");
    defer prime.deinit();
    var result = try millerRabin(prime, 40);
    try testing.expectEqual(result, true);
}

test "Miller Rabin Test Test 1" {
    var prime = try Managed.initSet(test_allocator, 0);
    try prime.setString(10, "23");
    defer prime.deinit();
    var result = try millerRabin(prime, 40);
    try testing.expectEqual(result, true);
}

test "Miller Rabin Test Test 2" {
    var prime = try Managed.initSet(test_allocator, 0);
    try prime.setString(10, "420");
    defer prime.deinit();
    var result = try millerRabin(prime, 40);
    try testing.expectEqual(result, false);
}

test "Pow Mod" {
    var b = try Managed.initSet(test_allocator, 1555123);
    defer b.deinit();
    var e = try Managed.initSet(test_allocator, 1441);
    defer e.deinit();
    var m = try Managed.initSet(test_allocator, 15);
    defer m.deinit();
    var ret = try powMod(b, e, m);
    defer ret.deinit();
    var expected = try Managed.initSet(test_allocator, 13);
    defer expected.deinit();
    try testing.expectEqual(ret.toConst().order(expected.toConst()), std.math.Order.eq);
}

test "Mod Inverse test" {
    var a = try Managed.initSet(test_allocator, 38);
    defer a.deinit();
    var b = try Managed.initSet(test_allocator, 97);
    defer b.deinit();
    var res = try modinv(a, b);
    var expected = try Managed.initSet(test_allocator, 23);
    defer res.deinit();
    defer expected.deinit();
    try testing.expectEqual(res.toConst().order(expected.toConst()), std.math.Order.eq);
}

test "Numbify test" {
    var val = try numbify("HELLO WORLD", test_allocator);
    defer val.deinit();
    var expected = try Managed.initSet(test_allocator, 87369909750770137432214596);
    defer expected.deinit();
    try testing.expectEqual(expected.toConst().order(val.toConst()), std.math.Order.eq);
}

test "Denumbify test" {
    var val = try denumbify("87369909750770137432214596", test_allocator);
    defer test_allocator.free(val);
    var t = "HELLO WORLD";
    try testing.expect(std.mem.eql(u8, t, val));
    //std.log.warn("{s}",.{val});

}

test "Verifying random bit toggle" {
    var toggle_me = try Managed.initSet(test_allocator, 15);
    defer toggle_me.deinit();
    try toggleRandomBits(&toggle_me, 100);
    std.debug.print("\nRandom Number: {}\n", .{toggle_me});
}

test "Bit Shit" {
    var toggle_me = try Managed.initSet(test_allocator, 15);
    defer toggle_me.deinit();
    try toggle(&toggle_me, 4);
    var expected = try Managed.initSet(test_allocator, 31);
    defer expected.deinit();
    try testing.expectEqual(toggle_me.toConst().order(expected.toConst()), std.math.Order.eq);
}

test "Encrypt then Decrypt with RSA" {
    var rsa = try RSA.init(test_allocator);
    defer rsa.deinit();
    var hello = try numbify("HELLO WORLD", test_allocator);
    defer hello.deinit();
    // encypt
    var result = try powMod(hello, rsa.inner.e, rsa.inner.pq);
    defer result.deinit();
    std.debug.print("ENCRYPTED: {}\n", .{result});
    // decrypt
    var decrypted = try powMod(result, rsa.inner.d, rsa.inner.pq);
    defer decrypted.deinit();
    var decrypted_to_text = try decrypted.toConst().toStringAlloc(test_allocator, 10, std.fmt.Case.lower);
    defer test_allocator.free(decrypted_to_text);
    var decrypted_text = try denumbify(decrypted_to_text, test_allocator);
    defer test_allocator.free(decrypted_text);
    try testing.expect(std.mem.eql(u8, "HELLO WORLD", decrypted_text));
}

test "Generate Random Number With dev/random" {
    var file: ?std.fs.File = null;
    var rand = try generateDevRandom(test_allocator, &file);
    defer rand.deinit();
    std.debug.print("{}\n", .{rand});
}
