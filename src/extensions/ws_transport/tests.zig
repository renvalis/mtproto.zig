//! Protocol regressions; process-level TLS/WS tests live in test/ws_transport_e2e.py.
test {
    _ = @import("config.zig");
    _ = @import("dc_router.zig");
    _ = @import("client.zig");
    _ = @import("frame.zig");
    _ = @import("packet.zig");
    _ = @import("fallback.zig");
    _ = @import("tls.zig");
    _ = @import("cf_domains.zig");
    _ = @import("h2.zig");
}
