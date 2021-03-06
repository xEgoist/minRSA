const std = @import("std");
const testing = std.testing;
const Managed = std.math.big.int.Managed;
const Allocator = std.mem.Allocator;
const test_allocator = std.testing.allocator;

// 2048 -> ~4096
const RSA_SIZE = 2048;

const Inner = struct {
    p: Managed,
    q: Managed,
    pq: Managed,
    d: Managed,
    phi: Managed,
};

pub const RSA = struct {
    e: u32 = 65537,
    allocator: Allocator,
    inner: *Inner,

    fn init(alloc: Allocator) !RSA {
        var inner = try alloc.create(Inner);
        inner.* = Inner{
            .p = try Managed.initSet(alloc, 1),
            .q = try Managed.initSet(alloc, 1),
            .pq = try Managed.initSet(alloc, 1),
            .d = try Managed.initSet(alloc, 1),
            .phi = try Managed.initSet(alloc, 1),
        };

        return RSA{
            .inner = inner,
            .allocator = alloc,
        };
    }

    fn deinit(self: *RSA) void {
        self.inner.phi.deinit();
        self.inner.p.deinit();
        self.inner.q.deinit();
        self.inner.d.deinit();
        self.inner.pq.deinit();
        self.allocator.destroy(self.inner);
        self.inner = undefined;
    }
};

fn toggle(r: *Managed, bit: u16) !void {
    var one = try Managed.initSet(r.allocator, 1);
    defer one.deinit();
    try one.shiftLeft(&one, bit);
    try r.bitXor(r, &one);
}

fn toggleRandomBit(r: *Managed) !void {
    var seed = std.time.milliTimestamp();
    if (seed < 0) {
        std.log.warn("Bad seed, using constant seed", .{});
        seed = 42;
    }
    var rand = std.rand.DefaultPrng.init(@intCast(u64, seed));
    var num = rand.random().uintAtMost(u16, RSA_SIZE);
    std.log.warn("{}", .{num});
    try toggle(r, num);
}

fn toggleRandomBits(r: *Managed, iterations: u16) !void {
    var seed = std.time.milliTimestamp();
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
    var seed = std.time.milliTimestamp();
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

// String Tools

// Makes an arbitrary number out of a string.
// Takes the string, converts it to a lower hex slice without 0x, then uses Managed to set it from
// a "string".
fn numbify(string: []const u8, alloc: Allocator) !Managed {
    var ret = try Managed.initSet(alloc, 1);
    const hexed = try std.fmt.allocPrint(
        alloc,
        "{x}",
        .{std.fmt.fmtSliceHexLower(string)},
    );
    defer alloc.free(hexed);
    try ret.setString(16, hexed);
    return ret;
}

fn denumbify(input: []const u8, alloc: Allocator) ![]u8 {
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

fn modinv(a0: Managed, m0: Managed) !Managed {
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

fn generate_prime(alloc: Allocator) !Managed {
    var candy = try Managed.initSet(alloc, 1);
    try toggleRandomBits(&candy, 100);
    var exit = try millerRabin(candy, 40);
    while (exit != true) {
        std.log.warn("\nCandy {}\n", .{candy});
        candy.deinit();
        candy = try Managed.initSet(alloc, 0);
        // toggle 1 more random bit and see it that makes it a prime
        try toggleRandomBits(&candy, 100);
        exit = try millerRabin(candy, 40);
        //std.debug.print("\nCandy {}\n", .{candy});
    }
    return candy;
}

test "Test Prime Generation" {
    var prime = try generate_prime(test_allocator);
    defer prime.deinit();
    std.debug.print("\nRandom Prime {}\n", .{prime});
}

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

test "initialization of RSA struct" {
    var rs = try RSA.init(test_allocator);
    defer rs.deinit();
    var expected = try Managed.initSet(test_allocator, 1);
    defer expected.deinit();
    try testing.expectEqual(expected.toConst().order(rs.inner.p.toConst()), std.math.Order.eq);
}

test "Bit Shit" {
    var toggle_me = try Managed.initSet(test_allocator, 15);
    defer toggle_me.deinit();
    try toggle(&toggle_me, 4);
    var expected = try Managed.initSet(test_allocator, 31);
    defer expected.deinit();
    try testing.expectEqual(toggle_me.toConst().order(expected.toConst()), std.math.Order.eq);
}
