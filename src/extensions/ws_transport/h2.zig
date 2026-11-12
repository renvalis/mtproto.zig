//! MTProto HTTP /api transcoder, following Flowseal's cf_h2.py packet mapping.
//! nghttp2 owns HTTP/2 framing, HPACK, flow control and stream multiplexing.
const std = @import("std");
const crypto = @import("../../crypto/crypto.zig");
const tls = @import("tls.zig");
const enabled = @import("build_options").telegram_ws;
const Ptr = *anyopaque;
extern fn cf_h2_new([*:0]const u8) ?Ptr;
extern fn cf_h2_free(Ptr) void;
extern fn cf_h2_ready(Ptr) c_int;
extern fn cf_h2_post(Ptr, [*:0]const u8, [*]const u8, usize) c_int;
extern fn cf_h2_feed(Ptr, [*]const u8, usize) isize;
extern fn cf_h2_drain(Ptr, *?[*]const u8) isize;
extern fn cf_h2_reply(Ptr, *?[*]const u8, *usize) c_int;
extern fn cf_h2_pop(Ptr) void;

pub const H2 = struct {
    handle: Ptr,
    host: [254:0]u8,
    decode: ?crypto.AesCtr = null,
    encode: ?crypto.AesCtr = null,

    pub fn init(host: []const u8) !H2 {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        var name: [254:0]u8 = @splat(0);
        @memcpy(name[0..host.len], host);
        return .{ .handle = cf_h2_new(&name) orelse return error.H2InitFailed, .host = name };
    }
    pub fn deinit(self: *H2) void {
        if (comptime !enabled) return;
        cf_h2_free(self.handle);
        if (self.decode) |*cipher| cipher.wipe();
        if (self.encode) |*cipher| cipher.wipe();
    }
    pub fn ready(self: *H2) bool {
        if (comptime !enabled) return false;
        return cf_h2_ready(self.handle) == 1;
    }
    pub fn nonce(self: *H2, bytes: []const u8) !void {
        if (bytes.len != 64) return error.InvalidWsNonce;
        // The parent's outbound nonce exposes the raw relay keys in bytes 8..56.
        // Transcode its encrypted packet stream into HTTP bodies, without ever
        // advancing the parent's AES state twice.
        self.decode = crypto.AesCtr.init(bytes[8..40], std.mem.readInt(u128, bytes[40..56], .big));
        self.decode.?.ctr +%= 4;
        var reverse: [48]u8 = undefined;
        defer std.crypto.secureZero(u8, &reverse);
        for (0..48) |i| reverse[i] = bytes[55 - i];
        self.encode = crypto.AesCtr.init(reverse[0..32], std.mem.readInt(u128, reverse[32..48], .big));
    }
    pub fn feed(self: *H2, bytes: []const u8) !void {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        const n = cf_h2_feed(self.handle, bytes.ptr, bytes.len);
        if (n < 0 or n != bytes.len) return error.H2ProtocolError;
    }
    pub fn drain(self: *H2, client: *tls.Client) !void {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        while (true) {
            var bytes: ?[*]const u8 = null;
            const n = cf_h2_drain(self.handle, &bytes);
            if (n < 0) return error.H2ProtocolError;
            if (n == 0) return;
            var off: usize = 0;
            while (off < n) {
                const end = @min(off + 16384, @as(usize, @intCast(n)));
                try client.write(bytes.?[off..end]);
                off = end;
            }
        }
    }
    /// False means HTTP concurrency/memory capacity is exhausted; retain this
    /// ciphertext packet in the caller and retry after processing a response.
    pub fn post(self: *H2, a: std.mem.Allocator, ciphertext: []const u8, tag: u32) !bool {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        const plain = try a.dupe(u8, ciphertext);
        defer a.free(plain);
        var decoder = self.decode orelse return error.InvalidWsNonce;
        decoder.apply(plain);
        const body = try packetBody(plain, tag);
        const result = cf_h2_post(self.handle, &self.host, body.ptr, body.len);
        if (result < 0) return error.H2RequestFailed;
        if (result != 0) return false;
        self.decode = decoder;
        return true;
    }
    pub fn collect(self: *H2, a: std.mem.Allocator, application: *std.ArrayList(u8), tag: u32, limit: usize) !void {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        while (true) {
            var bytes: ?[*]const u8 = null;
            var len: usize = 0;
            const result = cf_h2_reply(self.handle, &bytes, &len);
            if (result < 0) return error.H2ResponseFailed;
            if (result == 0) return;
            defer cf_h2_pop(self.handle);
            if (len == 0) continue; // HEAD preflight or an empty HTTP reply.
            if (self.encode == null) return error.UnexpectedH2Payload;
            if (len > limit -| application.items.len -| 7) return error.WsBufferFull;
            const start = application.items.len;
            var prefix: [4]u8 = undefined;
            var padding: [3]u8 = undefined;
            crypto.randomBytes(&padding);
            const pad: usize = if (tag == 0xdddddddd) padding[0] % 4 else 0;
            const prefix_len: usize = if (tag == 0xefefefef) blk: {
                const words = len / 4;
                if (words < 0x7f) {
                    prefix[0] = @intCast(words);
                    break :blk 1;
                }
                prefix[0] = 0x7f;
                std.mem.writeInt(u24, prefix[1..4], @intCast(words), .little);
                break :blk 4;
            } else blk: {
                std.mem.writeInt(u32, &prefix, @intCast(len + pad), .little);
                break :blk 4;
            };
            try application.appendSlice(a, prefix[0..prefix_len]);
            try application.appendSlice(a, bytes.?[0..len]);
            try application.appendSlice(a, padding[0..pad]);
            self.encode.?.apply(application.items[start..]);
        }
    }
};

pub fn packetBody(plain: []const u8, tag: u32) ![]const u8 {
    if (plain.len < 1) return error.InvalidMtprotoPacketLength;
    const header: usize = if (tag == 0xefefefef and plain[0] & 0x7f != 0x7f) 1 else 4;
    if (plain.len < header) return error.InvalidMtprotoPacketLength;
    var body = plain[header..];
    if (tag == 0xdddddddd) {
        if (body.len < 24) return error.InvalidMtprotoPacketLength;
        const packet_len: usize = if (std.mem.allEqual(u8, body[0..8], 0))
            20 + @as(usize, std.mem.readInt(u32, body[16..20], .little))
        else
            24 + ((body.len - 24) / 16) * 16;
        const max_padding: usize = if (std.mem.allEqual(u8, body[0..8], 0)) 256 else 15;
        if (packet_len < 24 or packet_len > body.len or body.len - packet_len > max_padding) return error.InvalidMtprotoPacketLength;
        body = body[0..packet_len];
    }
    if (body.len < 24 or body.len > 4 * 1024 * 1024 or body.len % 4 != 0) return error.InvalidMtprotoPacketLength;
    return body;
}

test "HTTP MTProto removes transport padding without changing encrypted body" {
    var frame: [47]u8 = @splat(0);
    std.mem.writeInt(u32, frame[0..4], 43 | 0x80000000, .little);
    std.mem.writeInt(u32, frame[20..24], 20, .little);
    try std.testing.expectEqual(@as(usize, 40), (try packetBody(&frame, 0xdddddddd)).len);
    frame[20] = 255;
    try std.testing.expectError(error.InvalidMtprotoPacketLength, packetBody(&frame, 0xdddddddd));
}
