const std = @import("std");
pub const max_message = @import("packet.zig").max_packet + 4;
pub const Frame = struct { opcode: u4, fin: bool, payload: []const u8, end: usize };

/// Server frames must be unmasked; extensions are not negotiated.
pub fn parse(bytes: []const u8) !?Frame {
    if (bytes.len < 2) return null;
    if (bytes[0] & 0x70 != 0 or bytes[1] & 0x80 != 0) return error.InvalidWsFrame;
    const op: u4 = @truncate(bytes[0]);
    if (op != 0 and op != 2 and op != 8 and op != 9 and op != 10) return error.InvalidWsOpcode;
    const fin = bytes[0] & 0x80 != 0;
    var len: u64 = bytes[1] & 0x7f;
    var start: usize = 2;
    if (len == 126) {
        if (bytes.len < 4) return null;
        len = std.mem.readInt(u16, bytes[2..4], .big);
        start = 4;
        if (len < 126) return error.InvalidWsFrame;
    } else if (len == 127) {
        if (bytes.len < 10) return null;
        len = std.mem.readInt(u64, bytes[2..10], .big);
        start = 10;
        if (len < 65536) return error.InvalidWsFrame;
    }
    if (op >= 8 and (!fin or len > 125 or (op == 8 and len == 1))) return error.InvalidWsControl;
    if (len > max_message) return error.WsMessageTooLarge;
    const end = start + @as(usize, @intCast(len));
    if (bytes.len < end) return null;
    return .{ .opcode = op, .fin = fin, .payload = bytes[start..end], .end = end };
}

/// Caller owns the returned masked client frame.
pub fn encode(a: std.mem.Allocator, opcode: u4, payload: []const u8) ![]u8 {
    if (payload.len > max_message) return error.WsMessageTooLarge;
    const header: usize = if (payload.len < 126) 2 else if (payload.len <= 65535) 4 else 10;
    const out = try a.alloc(u8, header + 4 + payload.len);
    out[0] = 0x80 | @as(u8, opcode);
    out[1] = 0x80 | @as(u8, if (header == 2) @intCast(payload.len) else if (header == 4) 126 else 127);
    if (header == 4) std.mem.writeInt(u16, out[2..4], @intCast(payload.len), .big);
    if (header == 10) std.mem.writeInt(u64, out[2..10], payload.len, .big);
    const mask = out[header..][0..4];
    @import("../../crypto/crypto.zig").randomBytes(mask);
    for (payload, 0..) |b, i| out[header + 4 + i] = b ^ mask[i % 4];
    return out;
}

test "server parser waits for arbitrary splits and rejects masked/control frames" {
    const bytes = [_]u8{ 0x82, 3, 1, 2, 3 };
    for (0..bytes.len) |n| try std.testing.expect((try parse(bytes[0..n])) == null);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try parse(&bytes)).?.payload);
    try std.testing.expectError(error.InvalidWsFrame, parse(&.{ 0x82, 0x80 }));
    try std.testing.expectError(error.InvalidWsControl, parse(&.{ 0x09, 0 }));
}

test "client masking round trip at all header widths" {
    const a = std.testing.allocator;
    for ([_]usize{ 0, 125, 126, 65535, 65536 }) |size| {
        const payload = try a.alloc(u8, size);
        defer a.free(payload);
        @memset(payload, 0x5a);
        const out = try encode(a, 2, payload);
        defer a.free(out);
        const h: usize = if (size < 126) 2 else if (size <= 65535) 4 else 10;
        try std.testing.expect(out[1] & 0x80 != 0);
        for (out[h + 4 ..], 0..) |b, i| try std.testing.expectEqual(@as(u8, 0x5a), b ^ out[h + i % 4]);
    }
}
