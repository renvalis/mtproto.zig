const std = @import("std");
const cf = @import("cf_domains.zig");

/// Fixed-size values avoid allocator ownership changes in the parent Config.
pub const Config = struct {
    dc_ips: [6][4]u8 = .{
        .{ 149, 154, 175, 50 },  .{ 149, 154, 167, 220 },
        .{ 149, 154, 175, 100 }, .{ 149, 154, 167, 220 },
        .{ 149, 154, 171, 5 },   .{ 91, 105, 192, 100 },
    },
    fronting: bool = true,
    cf_fallback: bool = true,
    cf_first: bool = false,
    cf_h2_media: bool = true,
    cf_domains: [4096]u8 = blk: {
        var buf = [_]u8{0} ** 4096;
        @memcpy(buf[0..cf.default_domains.len], cf.default_domains);
        break :blk buf;
    },
    cf_domains_len: usize = cf.default_domains.len,
    fronting_sni: [253]u8 = blk: {
        var buf = [_]u8{0} ** 253;
        @memcpy(buf[0..13], "sprinthost.ru");
        break :blk buf;
    },
    fronting_sni_len: usize = 13,
    /// Explicit opt-in to the source project's chain-only fronting policy.
    fronting_verify_hostname: bool = true,
    handshake_timeout_sec: u32 = 8,
    pool_size: u8 = 1, // per DC/media bucket per worker; 0 disables prewarming

    pub fn sni(self: *const Config) []const u8 {
        return self.fronting_sni[0..self.fronting_sni_len];
    }

    pub fn cfDomains(self: *const Config) []const u8 {
        return self.cf_domains[0..self.cf_domains_len];
    }

    pub fn parse(self: *Config, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "cf_h2_media")) {
            self.cf_h2_media = try boolean(value);
        } else if (std.mem.eql(u8, key, "cf_fallback")) {
            self.cf_fallback = try boolean(value);
        } else if (std.mem.eql(u8, key, "cf_first")) {
            self.cf_first = try boolean(value);
        } else if (std.mem.eql(u8, key, "cf_domains")) {
            _ = try cf.validateDomains(value);
            if (value.len > self.cf_domains.len) return error.InvalidWsCfDomain;
            @memcpy(self.cf_domains[0..value.len], value);
            self.cf_domains_len = value.len;
        } else if (std.mem.eql(u8, key, "fronting")) {
            self.fronting = try boolean(value);
        } else if (std.mem.eql(u8, key, "fronting_verify_hostname")) {
            self.fronting_verify_hostname = try boolean(value);
        } else if (std.mem.eql(u8, key, "fronting_sni")) {
            if (value.len == 0 or value.len > self.fronting_sni.len) return error.InvalidWsSni;
            for (value) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-')) return error.InvalidWsSni;
            @memcpy(self.fronting_sni[0..value.len], value);
            self.fronting_sni_len = value.len;
        } else if (std.mem.eql(u8, key, "pool_size")) {
            self.pool_size = try std.fmt.parseInt(u8, value, 10);
            if (self.pool_size > 4) return error.InvalidWsPoolSize;
        } else if (std.mem.eql(u8, key, "handshake_timeout_sec")) {
            self.handshake_timeout_sec = try std.fmt.parseInt(u32, value, 10);
            if (self.handshake_timeout_sec == 0 or self.handshake_timeout_sec > 60) return error.InvalidWsTimeout;
        } else if (std.mem.startsWith(u8, key, "dc") and std.mem.endsWith(u8, key, "_ip")) {
            const dc = try std.fmt.parseInt(u16, key[2 .. key.len - 3], 10);
            const i = index(dc) orelse return error.InvalidWsDc;
            const ip = try std.Io.net.IpAddress.parseIp4(value, 443);
            self.dc_ips[i] = ip.ip4.bytes;
        } else return error.UnknownWsConfigKey;
    }
};

pub fn index(dc: usize) ?usize {
    return if (dc >= 1 and dc <= 5) dc - 1 else if (dc == 203) 5 else null;
}

fn boolean(v: []const u8) !bool {
    if (std.mem.eql(u8, v, "true")) return true;
    if (std.mem.eql(u8, v, "false")) return false;
    return error.InvalidWsBoolean;
}

test "WS config rejects malformed endpoint and SNI" {
    var cfg = Config{};
    try std.testing.expectEqualStrings("sprinthost.ru", cfg.sni());
    try cfg.parse("dc2_ip", "192.0.2.1");
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &cfg.dc_ips[1]);
    try std.testing.expectError(error.InvalidWsSni, cfg.parse("fronting_sni", "x\r\ny"));
    try std.testing.expectError(error.InvalidWsDc, cfg.parse("dc6_ip", "192.0.2.1"));
}
