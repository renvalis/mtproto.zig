const std = @import("std");

pub const max_domains = 20;
pub const default_domains = "pclead.co.uk,offshor.co.uk,cakeisalie.co.uk,noskomnadzor.co.uk,lovetrue.co.uk,sorokdva.co.uk,pyatdesyatdva.co.uk,kartoshka.co.uk,sorokodin.co.uk,pyatdesyatodin.co.uk,notelega.co.uk,ebally.co.uk,havegreatday.co.uk,pomogite.co.uk,fixtelega.co.uk,sadnews.co.uk,onedaychamp.co.uk,stopblocking.co.uk,nothingthere.co.uk";

pub fn validDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 240 or std.mem.indexOfScalar(u8, domain, '.') == null) return false;
    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

pub fn validateDomains(value: []const u8) !usize {
    var tokens = std.mem.tokenizeAny(u8, value, ", \t");
    var count: usize = 0;
    while (tokens.next()) |domain| {
        if (!validDomain(domain)) return error.InvalidWsCfDomain;
        count += 1;
        if (count > max_domains) return error.TooManyWsCfDomains;
    }
    if (count == 0) return error.InvalidWsCfDomain;
    return count;
}

test "Cloudflare domains reject injection and empty pools" {
    try std.testing.expectEqual(@as(usize, 2), try validateDomains("one.example, two.example"));
    try std.testing.expectError(error.InvalidWsCfDomain, validateDomains("one.example\r\nHost: evil"));
    try std.testing.expectError(error.InvalidWsCfDomain, validateDomains(""));
    try std.testing.expectError(error.InvalidWsCfDomain, validateDomains("bad..example"));
}
