//! Worker-owned pool of unused WSS sessions, driven by the same epoll fd.
//! Retire fds until batch end so stale events cannot hit a recycled descriptor.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Session = @import("session.zig").Session;
const Context = @import("tls.zig").Context;
const Config = @import("config.zig").Config;
const router = @import("dc_router.zig");
const Backoff = @import("fallback.zig").Backoff;
const sockets = @import("../../proxy/socket_utils.zig");
const Upstream = @import("../../proxy/upstream.zig").Upstream;
const Queue = @import("../../proxy/message_queue.zig").MessageQueue;
const queue_io = @import("../../proxy/queue_io.zig");

const Entry = struct {
    fd: posix.fd_t,
    session: *Session,
    queue: Queue,
    connecting: bool,
    created: i64,
};
const Bucket = struct {
    entries: std.ArrayList(*Entry) = .empty,
    backoff: Backoff = .{},
    attempt: usize = 0,
};
pub const Taken = struct { fd: posix.fd_t, session: *Session, attempt: usize };
pub const Pool = struct {
    allocator: std.mem.Allocator,
    epoll_fd: posix.fd_t,
    context: *Context,
    config: Config,
    cf: ?*@import("cloudflare.zig").Registry = null,
    buckets: [12]Bucket = @splat(.{}),
    retired: [256]posix.fd_t = undefined,
    retired_len: usize = 0,
    counter: std.atomic.Value(u64) = .init(0),

    pub fn create(a: std.mem.Allocator, epoll_fd: posix.fd_t, ctx: *Context, cfg: Config, cf: ?*@import("cloudflare.zig").Registry) !*Pool {
        const out = try a.create(Pool);
        out.* = .{ .allocator = a, .epoll_fd = epoll_fd, .context = ctx, .config = cfg, .cf = cf };
        return out;
    }
    pub fn destroy(self: *Pool) void {
        for (&self.buckets) |*b| {
            for (b.entries.items) |e| {
                sockets.closeFd(e.fd);
                e.session.destroy();
                e.queue.deinit();
                self.allocator.destroy(e);
            }
            b.entries.deinit(self.allocator);
        }
        self.drainRetired();
        self.allocator.destroy(self);
    }
    pub fn drainRetired(self: *Pool) void {
        for (self.retired[0..self.retired_len]) |fd| sockets.closeFd(fd);
        self.retired_len = 0;
    }
    fn ctl(self: *Pool, op: u32, e: *Entry) !void {
        var ev = linux.epoll_event{ .events = linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.ERR | linux.EPOLL.HUP, .data = .{ .fd = e.fd } };
        if (e.connecting or !e.queue.isEmpty()) ev.events |= linux.EPOLL.OUT;
        const rc = linux.epoll_ctl(self.epoll_fd, op, e.fd, &ev);
        if (linux.errno(rc) != .SUCCESS) return error.WsPoolEpollError;
    }
    fn discard(self: *Pool, b: *Bucket, i: usize, now: i64, failure: bool) void {
        const e = b.entries.swapRemove(i);
        _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, e.fd, null);
        std.debug.assert(self.retired_len < self.retired.len);
        self.retired[self.retired_len] = e.fd;
        self.retired_len += 1;
        e.session.destroy();
        e.queue.deinit();
        self.allocator.destroy(e);
        if (failure) {
            b.backoff.fail(now);
            b.attempt += 1;
        }
    }
    fn flush(self: *Pool, e: *Entry) !void {
        const s = e.session;
        if (e.queue.total_len + s.wire.items.len > Session.max_buffer) return error.WsBufferFull;
        if (s.wire.items.len > 0) {
            _ = try queue_io.queueOrWriteMsg(e.fd, &e.queue, s.wire.items, &self.counter, null);
            s.wire.clearRetainingCapacity();
        }
        _ = try queue_io.flushQueue(e.fd, &e.queue, &self.counter, null);
    }
    fn advance(self: *Pool, e: *Entry, events: u32) !void {
        if (e.connecting) {
            if (events & (linux.EPOLL.OUT | linux.EPOLL.ERR | linux.EPOLL.HUP) == 0) return;
            try sockets.checkSocketConnectError(e.fd);
            e.connecting = false;
            try e.session.advance(&.{});
        }
        if (events & linux.EPOLL.IN != 0) {
            var buf: [32768]u8 = undefined;
            const n = posix.read(e.fd, &buf) catch |err| {
                if (err == error.WouldBlock) {
                    try self.flush(e);
                    try self.ctl(linux.EPOLL.CTL_MOD, e);
                    return;
                }
                return err;
            };
            if (n == 0) return error.WsPoolClosed;
            try e.session.advance(buf[0..n]);
            // No obfuscation init has been sent: unsolicited data cannot be adopted.
            if (e.session.application.items.len > 0) return error.WsPoolUnexpectedPayload;
            if (e.session.closed) return error.WsPoolClosed;
        }
        if (events & (linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP) != 0) return error.WsPoolClosed;
        try self.flush(e);
        try self.ctl(linux.EPOLL.CTL_MOD, e);
    }
    pub fn handle(self: *Pool, fd: posix.fd_t, events: u32, now: i64) bool {
        for (&self.buckets) |*b| {
            for (b.entries.items, 0..) |e, i| {
                if (e.fd != fd) continue;
                self.advance(e, events) catch {
                    self.discard(b, i, now, true);
                    return true;
                };
                if (e.session.phase == .ready) b.backoff.success();
                return true;
            }
        }
        return false;
    }
    pub fn tick(self: *Pool, now: i64) void {
        for (&self.buckets, 0..) |*b, k| {
            var i: usize = 0;
            while (i < b.entries.items.len) {
                const e = b.entries.items[i];
                const ready = e.session.phase == .ready;
                const max_age: i64 = if (ready) 120_000 else @as(i64, self.config.handshake_timeout_sec) * 1000;
                if (now - e.created > max_age) {
                    self.discard(b, i, now, !ready);
                } else {
                    i += 1;
                }
            }
            if (b.entries.items.len >= self.config.pool_size or now < b.backoff.retry_after_ms) continue;
            const dc: usize = if (k / 2 == 5) 203 else k / 2 + 1;
            const media = k % 2 == 1;
            const attempts = router.attemptCount(&self.config, self.cf, media);
            b.attempt %= attempts;
            const route = (router.next(&self.config, self.cf, dc, media, b.attempt) catch null) orelse {
                b.attempt = 0;
                continue;
            };
            b.attempt = route.attempt;
            self.spawn(b, route, now) catch {
                b.backoff.fail(now);
                b.attempt += 1;
            };
        }
    }
    fn spawn(self: *Pool, b: *Bucket, route: router.Route, now: i64) !void {
        const e = try self.allocator.create(Entry);
        errdefer self.allocator.destroy(e);
        const s = try Session.create(self.allocator, self.context, &self.config, route, 0xeeeeeeee);
        errdefer s.destroy();
        const connector = Upstream.initDirect();
        const connection = try connector.connect(route.address);
        errdefer sockets.closeFd(connection.fd);
        e.* = .{ .fd = connection.fd, .session = s, .queue = .{ .allocator = self.allocator }, .connecting = true, .created = now };
        try self.ctl(linux.EPOLL.CTL_ADD, e);
        errdefer _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, e.fd, null);
        try b.entries.append(self.allocator, e);
    }
    pub fn take(self: *Pool, dc: usize, media: bool, tag: u32, now: i64) ?Taken {
        const index = @import("config.zig").index(dc) orelse return null;
        const b = &self.buckets[index * 2 + @as(usize, @intFromBool(media))];
        for (b.entries.items, 0..) |e, i| {
            if (e.session.phase != .ready or !e.queue.isEmpty() or now - e.created >= 120_000) continue;
            _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, e.fd, null);
            _ = b.entries.swapRemove(i);
            e.session.splitter.tag = tag;
            const out = Taken{ .fd = e.fd, .session = e.session, .attempt = e.session.route.attempt };
            e.queue.deinit();
            self.allocator.destroy(e);
            return out;
        }
        return null;
    }
};
