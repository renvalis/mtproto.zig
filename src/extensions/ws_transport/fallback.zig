const std = @import("std");
pub const Backoff = struct {
    failures: u8 = 0,
    retry_after_ms: i64 = 0,
    pub fn fail(self: *Backoff, now: i64) void {
        self.failures = @min(self.failures +| 1, 13);
        const delay: i64 = @min(@as(i64, 1000) << @as(u6, @intCast(self.failures - 1)), 3_600_000);
        self.retry_after_ms = now + delay;
    }
    pub fn success(self: *Backoff) void {
        self.* = .{};
    }
};
test "backoff is bounded and resets on success" {
    var b = Backoff{};
    for (0..20) |_| b.fail(100);
    try std.testing.expectEqual(@as(i64, 3_600_100), b.retry_after_ms);
    b.success();
    try std.testing.expectEqual(@as(i64, 0), b.retry_after_ms);
}
