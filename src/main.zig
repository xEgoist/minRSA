const std = @import("std");
const testing = std.testing;
const Managed = std.math.big.int.Managed;
const Allocator = std.mem.Allocator;
const test_allocator = std.testing.allocator;

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
    var num = rand.random().int(u16);
    if (num > RSA_SIZE) {
        num %= RSA_SIZE;
    }
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
        var num = rand.random().int(u16);
        if (num > RSA_SIZE) {
            num %= RSA_SIZE;
        }
        //std.log.warn("{}\n",.{num});
        try toggle(r, num);
    }
}

fn truncate(r: *Managed, bits: u16) !void {
    var one = try Managed.initSet(r.allocator, 1);
    try one.shiftLeft(&one, bits);
    var one_again = try Managed.initSet(r.allocator, 1);
    defer one_again.deinit();
    try one.sub(&one, &one_again);
    try r.bitAnd(r, &one);
}

// String Tools
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
    std.log.warn("{}", .{toggle_me});
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
