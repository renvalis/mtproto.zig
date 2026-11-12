const std = @import("std");
const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const Upgrade = struct {
    key: [24]u8,
    accept: [28]u8,
    pub fn init() Upgrade {
        var entropy: [16]u8 = undefined;
        @import("../../crypto/crypto.zig").randomBytes(&entropy);
        var out: Upgrade = undefined;
        _ = std.base64.standard.Encoder.encode(&out.key, &entropy);
        var sha = std.crypto.hash.Sha1.init(.{});
        sha.update(&out.key);
        sha.update(guid);
        var digest: [20]u8 = undefined;
        sha.final(&digest);
        _ = std.base64.standard.Encoder.encode(&out.accept, &digest);
        return out;
    }
    pub fn request(self: *const Upgrade, buf: []u8, host: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "GET /apiws HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n", .{ host, self.key });
    }
    /// Return end of HTTP headers, leaving any pipelined WS bytes untouched.
    pub fn validate(self: *const Upgrade, data: []const u8) !?usize {
        const end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse {
            if (data.len > 8192) return error.WsHttpHeadersTooLarge;
            return null;
        };
        if (end > 8192) return error.WsHttpHeadersTooLarge;
        var lines = std.mem.splitSequence(u8, data[0..end], "\r\n");
        const status = lines.next() orelse return error.InvalidWsUpgrade;
        if (!std.mem.startsWith(u8, status, "HTTP/1.1 101 ")) return error.WsUpgradeRejected;
        var accept = false;
        var upgrade = false;
        var connection = false;
        var protocol = false;
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidWsUpgrade;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Accept")) {
                if (accept or !std.mem.eql(u8, value, &self.accept)) return error.InvalidWsAccept;
                accept = true;
            } else if (std.ascii.eqlIgnoreCase(name, "Upgrade")) {
                if (upgrade or !std.ascii.eqlIgnoreCase(value, "websocket")) return error.InvalidWsUpgrade;
                upgrade = true;
            } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
                var tokens = std.mem.splitScalar(u8, value, ',');
                while (tokens.next()) |t| if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), "upgrade")) {
                    connection = true;
                };
            } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Protocol")) {
                if (protocol or !std.mem.eql(u8, value, "binary")) return error.InvalidWsProtocol;
                protocol = true;
            } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Extensions")) return error.UnsupportedWsExtension;
        }
        if (!accept or !upgrade or !connection or !protocol) return error.InvalidWsUpgrade;
        return end + 4;
    }
};

test "upgrade validates accept and preserves pipelined bytes" {
    const u = Upgrade.init();
    var buf: [512]u8 = undefined;
    const response = try std.fmt.bufPrint(&buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: binary\r\n\r\nTAIL", .{u.accept});
    const end = (try u.validate(response)).?;
    try std.testing.expectEqualStrings("TAIL", response[end..]);
    try std.testing.expectError(error.WsUpgradeRejected, u.validate("HTTP/1.1 302 Found\r\n\r\n"));
}
