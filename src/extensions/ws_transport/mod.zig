//! Telegram DC WSS transport, based on Flowseal/tg-ws-proxy (MIT).
//! Protocol reference: commit 6690b788432fd0f59b0f38e228494bcd6bede1ca.
pub const Config = @import("config.zig").Config;
pub const Context = @import("tls.zig").Context;
pub const Session = @import("session.zig").Session;
pub const Pool = @import("pool.zig").Pool;
pub const router = @import("dc_router.zig");
pub const Cloudflare = @import("cloudflare.zig").Registry;
pub const enabled = @import("build_options").telegram_ws;

test {
    _ = @import("tests.zig");
}
