const std = @import("std");
const config = @import("config.zig");
const Cloudflare = @import("cloudflare.zig").Registry;

pub const Route = struct {
    address: std.Io.net.IpAddress,
    host_buf: [253]u8,
    host_len: usize,
    fronted: bool,
    cf_domain: ?usize = null,
    h2: bool = false,
    attempt: usize = 0,

    pub fn host(self: *const Route) []const u8 {
        return self.host_buf[0..self.host_len];
    }
};

pub fn directAttempts(cfg: *const config.Config, media: bool) usize {
    return @as(usize, if (cfg.fronting) 2 else 1) * @as(usize, if (media) 2 else 1);
}

pub fn attemptCount(cfg: *const config.Config, cf: ?*Cloudflare, media: bool) usize {
    return directAttempts(cfg, media) + if (cf) |registry| registry.count * 2 * @as(usize, if (media and cfg.cf_h2_media) 2 else 1) else @as(usize, 0);
}

/// Resolve only from background DNS snapshots; never block an epoll worker.
/// Pin the returned route through TCP/TLS so concurrent preference/DNS changes
/// cannot change the Host or SNI for an already-started connection.
pub fn next(cfg: *const config.Config, cf: ?*Cloudflare, dc: usize, media: bool, start: usize) !?Route {
    const dc_index = config.index(dc) orelse return error.UnsupportedWsDc;
    const direct_count = directAttempts(cfg, media);
    const h2_media = media and cfg.cf_h2_media;
    const cf_count = if (cf) |registry| registry.count * 2 * @as(usize, if (h2_media) 2 else 1) else @as(usize, 0);
    var attempt = start;
    while (attempt < direct_count + cf_count) : (attempt += 1) {
        const is_cf = if (cfg.cf_first) attempt < cf_count else attempt >= direct_count;
        if (!is_cf) {
            const direct_index = if (cfg.cf_first) attempt - cf_count else attempt;
            var out = (try route(cfg, dc, media, direct_index)).?;
            out.attempt = attempt;
            return out;
        }
        const registry = cf.?;
        const cf_index = if (cfg.cf_first) attempt else attempt - direct_count;
        const preferred = registry.preferred[dc_index].load(.monotonic);
        const domain = (preferred + cf_index / 2) % registry.count;
        const address = registry.address(dc_index, domain, cf_index % 2) orelse continue;
        var out = Route{ .address = address, .host_buf = undefined, .host_len = 0, .fronted = false, .cf_domain = domain, .attempt = attempt };
        // As in Flowseal, try HTTP/2 /api for media before CF WSS /apiws.
        out.h2 = h2_media and cf_index < registry.count * 2;
        out.host_len = (try registry.host(&out.host_buf, dc, domain)).len;
        return out;
    }
    return null;
}

/// Try normal and alternate SNI for each media-specific/domain candidate.
pub fn route(cfg: *const config.Config, dc: usize, media: bool, attempt: usize) !?Route {
    const i = config.index(dc) orelse return error.UnsupportedWsDc;
    const modes: usize = if (cfg.fronting) 2 else 1;
    if (attempt >= modes * @as(usize, if (media) 2 else 1)) return null;
    var out = Route{ .address = .{ .ip4 = .{ .bytes = cfg.dc_ips[i], .port = 443 } }, .host_buf = undefined, .host_len = 0, .fronted = attempt % modes == 1 };
    const domain_dc = if (dc == 203) 2 else dc;
    const h = try std.fmt.bufPrint(&out.host_buf, "kws{d}{s}.web.telegram.org", .{ domain_dc, if (media and attempt / modes == 0) "-1" else "" });
    out.host_len = h.len;
    return out;
}

test "DC203 and media use source domain mapping without changing destination IP" {
    const cfg = config.Config{};
    const a = (try route(&cfg, 203, true, 0)).?;
    const b = (try route(&cfg, 203, true, 1)).?;
    const c = (try route(&cfg, 203, true, 2)).?;
    try std.testing.expectEqualStrings("kws2-1.web.telegram.org", a.host());
    try std.testing.expect(b.fronted);
    try std.testing.expectEqualStrings("kws2.web.telegram.org", c.host());
    try std.testing.expect((try route(&cfg, 203, true, 4)) == null);
}

test "Cloudflare routes pin DNS addresses and media prefers H2 before WSS" {
    const Cache = @import("../../proxy/dns_cache.zig").Cache;
    const cache = try Cache.create(std.testing.allocator);
    defer cache.destroy();
    const id = try cache.add("kws2.cf.test", 443, .init(&.{.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 443 } }}));
    var cf = Cloudflare{ .dns = cache, .count = 1 };
    @memcpy(cf.domains[0][0..7], "cf.test");
    cf.lengths[0] = 7;
    for (&cf.ids) |*ids| ids[0] = id;
    const cfg = config.Config{ .cf_first = true };
    const normal = (try next(&cfg, &cf, 2, false, 0)).?;
    try std.testing.expectEqualStrings("kws2.cf.test", normal.host());
    try std.testing.expect(!normal.h2 and !normal.fronted);
    const media_h2 = (try next(&cfg, &cf, 2, true, 0)).?;
    try std.testing.expect(media_h2.h2);
    const media_wss = (try next(&cfg, &cf, 2, true, 1)).?;
    try std.testing.expectEqual(@as(usize, 2), media_wss.attempt);
    try std.testing.expect(!media_wss.h2);
    const direct = (try next(&cfg, &cf, 2, true, 4)).?;
    try std.testing.expect(direct.cf_domain == null);
}
