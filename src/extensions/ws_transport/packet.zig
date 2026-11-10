const std = @import("std");
pub const max_packet = 4 * 1024 * 1024;

/// Observe plaintext lengths before AES-CTR; retain only headers, not plaintext.
/// Completed ciphertext is consumed independently, without advancing AES twice.
pub const Splitter = struct {
    tag: u32,
    header: [4]u8 = undefined,
    used: usize = 0,
    remaining: usize = 0,
    sizes: std.ArrayList(usize) = .empty,
    head: usize = 0,

    pub fn deinit(self: *Splitter, a: std.mem.Allocator) void {
        self.sizes.deinit(a);
    }
    pub fn observe(self: *Splitter, a: std.mem.Allocator, data: []const u8) !void {
        var pos: usize = 0;
        while (pos < data.len) {
            if (self.remaining > 0) {
                const n = @min(self.remaining, data.len - pos);
                self.remaining -= n;
                pos += n;
                continue;
            }
            self.header[self.used] = data[pos];
            self.used += 1;
            pos += 1;
            const abridged = self.tag == 0xefefefef;
            const need: usize = if (abridged and self.header[0] & 0x7f != 0x7f) 1 else 4;
            if (self.used < need) continue;
            const body: usize = if (abridged)
                (if (need == 1) @as(usize, self.header[0] & 0x7f) else @as(usize, std.mem.readInt(u24, self.header[1..4], .little))) * 4
            else
                std.mem.readInt(u32, &self.header, .little) & 0x7fffffff;
            if (body == 0 or body > max_packet) return error.InvalidMtprotoPacketLength;
            if (self.sizes.items.len - self.head >= 32768) return error.WsPacketQueueFull;
            try self.sizes.append(a, need + body);
            self.remaining = body;
            self.used = 0;
        }
    }
    pub fn next(self: *const Splitter) ?usize {
        return if (self.head < self.sizes.items.len) self.sizes.items[self.head] else null;
    }
    pub fn consume(self: *Splitter) void {
        self.head += 1;
        if (self.head == self.sizes.items.len) {
            self.sizes.clearRetainingCapacity();
            self.head = 0;
        } else if (self.head >= 1024 and self.head >= self.sizes.items.len / 2) {
            std.mem.copyForwards(usize, self.sizes.items, self.sizes.items[self.head..]);
            self.sizes.items.len -= self.head;
            self.head = 0;
        }
    }
};

test "packet observer preserves boundaries across every TCP split and quick ack bit" {
    const data = [_]u8{ 0x84, 0, 0, 0, 1, 2, 3, 4, 4, 0, 0, 0, 5, 6, 7, 8 };
    // Intermediate's quick ack bit is in the most significant byte.
    var bytes = data;
    bytes[0] = 4;
    bytes[3] = 0x80;
    for (0..bytes.len + 1) |split| {
        var s = Splitter{ .tag = 0xeeeeeeee };
        defer s.deinit(std.testing.allocator);
        try s.observe(std.testing.allocator, bytes[0..split]);
        try s.observe(std.testing.allocator, bytes[split..]);
        try std.testing.expectEqual(@as(usize, 8), s.next().?);
        s.consume();
        try std.testing.expectEqual(@as(usize, 8), s.next().?);
        s.consume();
        try std.testing.expect(s.next() == null);
    }
}
