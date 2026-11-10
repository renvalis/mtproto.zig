//! Narrow adapter to the parent queue/cipher pipeline. No EventLoop dependency.
const std = @import("std");
const queue_io = @import("../../proxy/queue_io.zig");
var ignored = std.atomic.Value(u64).init(0);

pub fn flushWire(slot: anytype) !bool {
    const s = slot.ws_session orelse return true;
    if (s.wire.items.len == 0) return true;
    if (slot.upstream_queue.total_len + s.wire.items.len > @import("session.zig").Session.max_buffer) return error.WsBufferFull;
    const done = try queue_io.queueOrWriteMsg(slot.upstream_fd, &slot.upstream_queue, s.wire.items, slot.traffic_client_to_upstream_counter orelse &ignored, if (slot.user_metrics) |entry| &entry.client_to_upstream_bytes_total else null);
    s.wire.clearRetainingCapacity();
    return done;
}

pub fn observePlain(slot: anytype, bytes: []const u8) !void {
    // relay_steps also has small test harnesses without extension fields.
    if (comptime @hasField(@TypeOf(slot.*), "ws_session")) {
        if (slot.ws_session) |s| try s.observePlain(bytes);
    }
}

const ws_transport = @import("mod.zig");
const constants = @import("../../protocol/constants.zig");
const nowMs = @import("../../proxy/socket_utils.zig").nowMs;
const posix = std.posix;
const log = std.log.scoped(.proxy);

pub fn startHandshake(self: anytype, slot: anytype, comptime hooks: anytype) void {
    const cfg = &self.state.config.telegram_ws;
    const route = slot.ws_route orelse {
        hooks.close(self, slot, "WS route exhausted");
        return;
    };
    log.debug("[{d}] WS connect dc={d} media={} route={s} host={s} attempt={d}", .{ slot.conn_id, slot.dc_abs, slot.dc_idx < 0, if (route.h2) @as([]const u8, "cf_h2") else if (route.cf_domain != null) "cf" else "direct", route.host(), slot.ws_attempt });
    slot.ws_session = ws_transport.Session.create(self.state.allocator, self.state.ws_context.?, cfg, route, @intFromEnum(slot.proto_tag)) catch |err| {
        fail(self, slot, err, hooks);
        return;
    };
    slot.phase = .ws_handshake;
    slot.upstream_connect_started_ms = nowMs();
    slot.ws_session.?.advance(&.{}) catch |err| {
        fail(self, slot, err, hooks);
        return;
    };
    _ = flushWire(slot) catch |err| {
        fail(self, slot, err, hooks);
        return;
    };
}

pub fn fail(self: anytype, slot: anytype, err: anyerror, comptime hooks: anytype) void {
    log.debug("[{d}] Telegram WS attempt {d} failed: {any}", .{ slot.conn_id, slot.ws_attempt, err });
    if (!retry(self, slot, hooks)) hooks.close(self, slot, "Telegram WS upstream failed");
}

pub fn retry(self: anytype, slot: anytype, comptime hooks: anytype) bool {
    // No replay after the obfuscation init/application stream has started.
    if (slot.ws_direct_fallback or (if (slot.ws_session) |s| s.nonce_sent else false)) return false;
    hooks.cleanup(self, slot);
    if (slot.ws_session) |session| session.destroy();
    slot.ws_session = null;
    slot.upstream_queue.clear();
    while (true) {
        slot.ws_attempt += 1;
        const route = (ws_transport.router.next(&self.state.config.telegram_ws, self.state.ws_routes, slot.dc_abs, slot.dc_idx < 0, slot.ws_attempt) catch null) orelse break;
        slot.ws_route = route;
        slot.ws_attempt = route.attempt;
        hooks.connect(self, slot, route.address, .dc) catch continue;
        return true;
    }
    if (self.state.config.allow_direct_fallback) {
        slot.ws_direct_fallback = true;
        const address = constants.getDcAddressV4(slot.dc_abs) orelse return false;
        hooks.connect(self, slot, address, .dc) catch return false;
        return true;
    }
    return false;
}

pub fn readable(self: anytype, slot: anytype, comptime hooks: anytype) void {
    const n = posix.read(slot.upstream_fd, self.shared_read_buf[0..]) catch |err| {
        if (err == error.WouldBlock) return;
        fail(self, slot, err, hooks);
        return;
    };
    if (n == 0) {
        if (slot.phase == .relaying) hooks.half_close(self, slot, slot.upstream_fd) else fail(self, slot, error.EndOfStream, hooks);
        return;
    }
    const session = slot.ws_session.?;
    session.advance(self.shared_read_buf[0..n]) catch |err| {
        fail(self, slot, err, hooks);
        return;
    };
    _ = flushWire(slot) catch |err| blk: {
        // A peer may close immediately after its final reply. Failure to send
        // the Close acknowledgement must not discard authenticated payload.
        if (!session.closed) {
            fail(self, slot, err, hooks);
            return;
        }
        slot.upstream_queue.clear();
        break :blk false;
    };
    if (slot.phase == .ws_handshake and session.phase == .ready) {
        if (session.route.cf_domain) |domain| {
            if (self.state.ws_routes) |routes| routes.preferred[@import("config.zig").index(slot.dc_abs).?].store(domain, .monotonic);
        }
        log.info("[{d}] WS ready dc={d} media={} route={s} host={s}", .{ slot.conn_id, slot.dc_abs, slot.dc_idx < 0, if (session.route.h2) @as([]const u8, "cf_h2") else if (session.route.cf_domain != null) "cf" else "direct", session.route.host() });
        hooks.nonce(self, slot);
        if (slot.phase == .idle) return;
        if (slot.upstream_queue.isEmpty()) hooks.nonce_writable(self, slot);
        if (slot.phase == .idle) return;
    }
    if (session.application.items.len > 0) {
        if (slot.phase != .relaying and slot.phase != .writing_dc_nonce) {
            hooks.close(self, slot, "unexpected WS payload");
            return;
        }
        var off: usize = 0;
        while (off < session.application.items.len) {
            const size = @min(session.application.items.len - off, self.shared_read_buf.len);
            const payload = session.application.items[off..][0..size];
            if (slot.tg_decryptor) |*dec| dec.apply(payload);
            if (slot.client_encryptor) |*enc| enc.apply(payload);
            if (slot.client_queue.total_len + size > ws_transport.Session.max_buffer) {
                hooks.close(self, slot, "WS client queue full");
                return;
            }
            if (slot.client_transport == .direct_obfuscated) {
                _ = hooks.queue_client(slot, self.state.allocator, payload) catch {
                    hooks.close(self, slot, "WS client write failed");
                    return;
                };
            } else {
                hooks.queue_tls(slot, self.state.allocator, payload) catch {
                    hooks.close(self, slot, "WS client write failed");
                    return;
                };
            }
            slot.s2c_bytes += size;
            off += size;
        }
        session.application.clearRetainingCapacity();
        slot.last_server_byte_ms = nowMs();
    }
    if (session.closed) hooks.half_close(self, slot, slot.upstream_fd);
}
