const std = @import("std");
const tls = @import("tls.zig");
const frame = @import("frame.zig");
const Upgrade = @import("client.zig").Upgrade;
const Splitter = @import("packet.zig").Splitter;
const Config = @import("config.zig").Config;
const Route = @import("dc_router.zig").Route;
const H2 = @import("h2.zig").H2;

pub const Session = struct {
    allocator: std.mem.Allocator,
    client: tls.Client,
    route: Route,
    upgrade: Upgrade,
    phase: enum { tls, upgrade, ready } = .tls,
    splitter: Splitter,
    nonce_sent: bool = false,
    closed: bool = false,
    fragmented: bool = false,
    fragment_bytes: usize = 0,
    incoming: std.ArrayList(u8) = .empty,
    ciphertext: std.ArrayList(u8) = .empty,
    application: std.ArrayList(u8) = .empty,
    wire: std.ArrayList(u8) = .empty,
    http2: ?H2 = null,
    pub const max_buffer = 8 * 1024 * 1024;

    pub fn create(a: std.mem.Allocator, ctx: *tls.Context, cfg: *const Config, route: Route, tag: u32) !*Session {
        const s = try a.create(Session);
        errdefer a.destroy(s);
        s.* = .{ .allocator = a, .client = try tls.Client.init(ctx, if (route.fronted) cfg.sni() else route.host(), !route.fronted or cfg.fronting_verify_hostname), .route = route, .upgrade = Upgrade.init(), .splitter = .{ .tag = tag } };
        errdefer s.client.deinit();
        if (route.h2) try s.client.enableH2();
        return s;
    }
    pub fn destroy(self: *Session) void {
        self.client.deinit();
        if (self.http2) |*h2| h2.deinit();
        self.splitter.deinit(self.allocator);
        self.incoming.deinit(self.allocator);
        self.ciphertext.deinit(self.allocator);
        self.application.deinit(self.allocator);
        self.wire.deinit(self.allocator);
        self.allocator.destroy(self);
    }
    fn append(self: *Session, buf: *std.ArrayList(u8), bytes: []const u8) !void {
        if (bytes.len > max_buffer -| buf.items.len) return error.WsBufferFull;
        try buf.appendSlice(self.allocator, bytes);
    }
    pub fn observePlain(self: *Session, bytes: []const u8) !void {
        try self.splitter.observe(self.allocator, bytes);
    }
    pub fn send(self: *Session, bytes: []const u8) !void {
        if (self.phase != .ready or self.closed) return error.WsNotReady;
        if (!self.nonce_sent) {
            if (bytes.len != 64) return error.InvalidWsNonce;
            if (self.http2) |*h2| try h2.nonce(bytes) else try self.sendFrame(2, bytes);
            self.nonce_sent = true;
        } else {
            try self.append(&self.ciphertext, bytes);
            try self.flushPackets();
        }
        try self.drain();
    }
    fn flushPackets(self: *Session) !void {
        var used: usize = 0;
        while (self.splitter.next()) |size| {
            if (self.ciphertext.items.len - used < size) break;
            const packet = self.ciphertext.items[used..][0..size];
            if (self.http2) |*h2| {
                if (!try h2.post(self.allocator, packet, self.splitter.tag)) break;
            } else try self.sendFrame(2, packet);
            used += size;
            self.splitter.consume();
        }
        if (used > 0) {
            std.mem.copyForwards(u8, self.ciphertext.items, self.ciphertext.items[used..]);
            self.ciphertext.items.len -= used;
        }
        if (self.http2) |*h2| try h2.drain(&self.client);
    }
    fn sendFrame(self: *Session, opcode: u4, bytes: []const u8) !void {
        const encoded = try frame.encode(self.allocator, opcode, bytes);
        defer self.allocator.free(encoded);
        var offset: usize = 0;
        while (offset < encoded.len) {
            const end = @min(offset + 16384, encoded.len);
            try self.client.write(encoded[offset..end]);
            try self.drain();
            offset = end;
        }
    }
    fn drain(self: *Session) !void {
        var buf: [32768]u8 = undefined;
        while (true) {
            const n = self.client.drain(&buf);
            if (n == 0) break;
            try self.append(&self.wire, buf[0..n]);
        }
    }
    pub fn advance(self: *Session, raw: []const u8) !void {
        if (raw.len > 0) try self.client.feed(raw);
        if (self.phase == .tls) {
            const ready = try self.client.handshake();
            try self.drain();
            if (!ready) return;
            if (self.route.h2) {
                self.http2 = try H2.init(self.route.host());
                try self.http2.?.drain(&self.client);
            } else {
                var request_buf: [1024]u8 = undefined;
                try self.client.write(try self.upgrade.request(&request_buf, self.route.host()));
            }
            try self.drain();
            self.phase = .upgrade;
        }
        var buf: [32768]u8 = undefined;
        while (true) {
            const n = self.client.read(&buf) catch |err| {
                if (err == error.TlsClosed and self.phase == .ready) {
                    self.closed = true;
                    return;
                }
                return err;
            };
            try self.drain();
            if (n == 0) break;
            if (self.http2) |*h2| {
                try h2.feed(buf[0..n]);
                if (h2.ready()) self.phase = .ready;
                try h2.collect(self.allocator, &self.application, self.splitter.tag, max_buffer);
                if (self.nonce_sent) try self.flushPackets();
                try h2.drain(&self.client);
                try self.drain();
                continue;
            }
            try self.append(&self.incoming, buf[0..n]);
            if (self.phase == .upgrade) {
                const end = (try self.upgrade.validate(self.incoming.items)) orelse continue;
                std.mem.copyForwards(u8, self.incoming.items, self.incoming.items[end..]);
                self.incoming.items.len -= end;
                self.phase = .ready;
            }
            try self.consumeFrames();
            if (self.closed) return;
        }
    }
    fn consumeFrames(self: *Session) !void {
        var pos: usize = 0;
        while (try frame.parse(self.incoming.items[pos..])) |f| {
            switch (f.opcode) {
                8 => {
                    if (f.payload.len >= 2) {
                        const code = std.mem.readInt(u16, f.payload[0..2], .big);
                        if (code < 1000 or code >= 5000 or code == 1004 or code == 1005 or code == 1006 or code == 1015) return error.InvalidWsClose;
                        if (!std.unicode.utf8ValidateSlice(f.payload[2..])) return error.InvalidWsClose;
                    }
                    try self.sendFrame(8, f.payload);
                    self.closed = true;
                    return;
                },
                9 => try self.sendFrame(10, f.payload),
                10 => {},
                0, 2 => {
                    if ((f.opcode == 0) != self.fragmented) return error.InvalidWsContinuation;
                    self.fragment_bytes += f.payload.len;
                    if (self.fragment_bytes > frame.max_message) return error.WsMessageTooLarge;
                    try self.append(&self.application, f.payload);
                    self.fragmented = !f.fin;
                    if (f.fin) self.fragment_bytes = 0;
                },
                else => unreachable,
            }
            pos += f.end;
        }
        if (pos > 0) {
            std.mem.copyForwards(u8, self.incoming.items, self.incoming.items[pos..]);
            self.incoming.items.len -= pos;
        }
    }
};
