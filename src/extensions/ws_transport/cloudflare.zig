//! Cloudflare WSS routes from Flowseal/tg-ws-proxy (MIT, pinned reference commit).
//! DNS is registered at startup and refreshed by the parent's background cache.
const std = @import("std");
const Cache = @import("../../proxy/dns_cache.zig").Cache;
const net = @import("../../proxy/net_helpers.zig");

const domains_config = @import("cf_domains.zig");
const max_domains = domains_config.max_domains;

pub const Registry = struct {
    dns: *Cache,
    count: usize = 0,
    domains: [max_domains][241]u8 = undefined,
    lengths: [max_domains]usize = undefined,
    ids: [6][max_domains]usize = undefined,
    preferred: [6]std.atomic.Value(usize) = .{ .init(0), .init(0), .init(0), .init(0), .init(0), .init(0) },

    pub fn create(a: std.mem.Allocator, dns: *Cache, domains: []const u8) !*Registry {
        _ = try domains_config.validateDomains(domains);
        const self = try a.create(Registry);
        errdefer a.destroy(self);
        self.* = .{ .dns = dns };
        var tokens = std.mem.tokenizeAny(u8, domains, ", \t");
        while (tokens.next()) |domain| {
            @memcpy(self.domains[self.count][0..domain.len], domain);
            self.lengths[self.count] = domain.len;
            self.count += 1;
        }
        for (0..6) |dc_index| {
            // Spread initial traffic across the reference's domain pool.
            self.preferred[dc_index].store(dc_index % self.count, .monotonic);
            for (0..self.count) |domain_index| {
                var host_buf: [253]u8 = undefined;
                const dc = if (dc_index == 5) 203 else dc_index + 1;
                const hostname = try self.host(&host_buf, dc, domain_index);
                var initial: net.AddressCandidates = .{};
                if (net.getAddressList(a, hostname, 443)) |addresses| {
                    defer addresses.deinit();
                    initial = .init(addresses.addrs);
                } else |_| {}
                self.ids[dc_index][domain_index] = try dns.add(hostname, 443, initial);
            }
        }
        return self;
    }

    pub fn host(self: *const Registry, buf: []u8, dc: usize, domain: usize) ![]const u8 {
        return std.fmt.bufPrint(buf, "kws{d}.{s}", .{ dc, self.domains[domain][0..self.lengths[domain]] });
    }

    pub fn address(self: *Registry, dc_index: usize, domain: usize, candidate: usize) ?net.Address {
        const addresses = self.dns.snapshot(self.ids[dc_index][domain]);
        // Prefer IPv4 consistently. Keep two addresses per domain for endpoint failover.
        var seen: usize = 0;
        for (addresses.slice()) |candidate_address| {
            if (net.isIpv6(candidate_address)) continue;
            if (seen == candidate) return candidate_address;
            seen += 1;
        }
        return null;
    }
};
