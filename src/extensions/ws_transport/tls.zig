//! Statically linked OpenSSL memory BIO adapter with embedded Mozilla CA roots.
//! All socket I/O stays in the parent's epoll loop; trust is loaded at startup.
const std = @import("std");
const enabled = @import("build_options").telegram_ws;
const Ptr = *anyopaque;

const Api = struct {
    OPENSSL_init_ssl: *const fn (u64, ?Ptr) callconv(.c) c_int,
    TLS_client_method: *const fn () callconv(.c) ?Ptr,
    SSL_CTX_new: *const fn (Ptr) callconv(.c) ?Ptr,
    SSL_CTX_free: *const fn (Ptr) callconv(.c) void,
    SSL_CTX_get_cert_store: *const fn (Ptr) callconv(.c) Ptr,
    SSL_CTX_load_verify_locations: *const fn (Ptr, [*:0]const u8, ?[*:0]const u8) callconv(.c) c_int,
    BIO_new_mem_buf: *const fn ([*]const u8, c_int) callconv(.c) ?Ptr,
    PEM_read_bio_X509: *const fn (Ptr, ?Ptr, ?Ptr, ?Ptr) callconv(.c) ?Ptr,
    X509_STORE_add_cert: *const fn (Ptr, Ptr) callconv(.c) c_int,
    X509_free: *const fn (Ptr) callconv(.c) void,
    SSL_CTX_set_verify: *const fn (Ptr, c_int, ?Ptr) callconv(.c) void,
    SSL_CTX_ctrl: *const fn (Ptr, c_int, c_long, ?Ptr) callconv(.c) c_long,
    SSL_new: *const fn (Ptr) callconv(.c) ?Ptr,
    SSL_free: *const fn (Ptr) callconv(.c) void,
    SSL_ctrl: *const fn (Ptr, c_int, c_long, ?Ptr) callconv(.c) c_long,
    SSL_set1_host: *const fn (Ptr, [*:0]const u8) callconv(.c) c_int,
    SSL_set_alpn_protos: *const fn (Ptr, [*]const u8, c_uint) callconv(.c) c_int,
    SSL_get0_alpn_selected: *const fn (Ptr, *?[*]const u8, *c_uint) callconv(.c) void,
    SSL_set_bio: *const fn (Ptr, Ptr, Ptr) callconv(.c) void,
    SSL_set_connect_state: *const fn (Ptr) callconv(.c) void,
    SSL_do_handshake: *const fn (Ptr) callconv(.c) c_int,
    SSL_get_error: *const fn (Ptr, c_int) callconv(.c) c_int,
    SSL_read: *const fn (Ptr, [*]u8, c_int) callconv(.c) c_int,
    SSL_write: *const fn (Ptr, [*]const u8, c_int) callconv(.c) c_int,
    BIO_s_mem: *const fn () callconv(.c) Ptr,
    BIO_new: *const fn (Ptr) callconv(.c) ?Ptr,
    BIO_free: *const fn (Ptr) callconv(.c) c_int,
    BIO_read: *const fn (Ptr, [*]u8, c_int) callconv(.c) c_int,
    BIO_write: *const fn (Ptr, [*]const u8, c_int) callconv(.c) c_int,
    ERR_clear_error: *const fn () callconv(.c) void,
};

const linked = struct {
    extern fn OPENSSL_init_ssl(options: u64, settings: ?Ptr) callconv(.c) c_int;
    extern fn TLS_client_method() callconv(.c) ?Ptr;
    extern fn SSL_CTX_new(arg0: Ptr) callconv(.c) ?Ptr;
    extern fn SSL_CTX_free(arg0: Ptr) callconv(.c) void;
    extern fn SSL_CTX_get_cert_store(arg0: Ptr) callconv(.c) Ptr;
    extern fn SSL_CTX_load_verify_locations(arg0: Ptr, arg1: [*:0]const u8, arg2: ?[*:0]const u8) callconv(.c) c_int;
    extern fn BIO_new_mem_buf(arg0: [*]const u8, arg1: c_int) callconv(.c) ?Ptr;
    extern fn PEM_read_bio_X509(arg0: Ptr, arg1: ?Ptr, arg2: ?Ptr, arg3: ?Ptr) callconv(.c) ?Ptr;
    extern fn X509_STORE_add_cert(arg0: Ptr, arg1: Ptr) callconv(.c) c_int;
    extern fn X509_free(arg0: Ptr) callconv(.c) void;
    extern fn SSL_CTX_set_verify(arg0: Ptr, arg1: c_int, arg2: ?Ptr) callconv(.c) void;
    extern fn SSL_CTX_ctrl(arg0: Ptr, arg1: c_int, arg2: c_long, arg3: ?Ptr) callconv(.c) c_long;
    extern fn SSL_new(arg0: Ptr) callconv(.c) ?Ptr;
    extern fn SSL_free(arg0: Ptr) callconv(.c) void;
    extern fn SSL_ctrl(arg0: Ptr, arg1: c_int, arg2: c_long, arg3: ?Ptr) callconv(.c) c_long;
    extern fn SSL_set1_host(arg0: Ptr, arg1: [*:0]const u8) callconv(.c) c_int;
    extern fn SSL_set_alpn_protos(arg0: Ptr, arg1: [*]const u8, arg2: c_uint) callconv(.c) c_int;
    extern fn SSL_get0_alpn_selected(arg0: Ptr, arg1: *?[*]const u8, arg2: *c_uint) callconv(.c) void;
    extern fn SSL_set_bio(arg0: Ptr, arg1: Ptr, arg2: Ptr) callconv(.c) void;
    extern fn SSL_set_connect_state(arg0: Ptr) callconv(.c) void;
    extern fn SSL_do_handshake(arg0: Ptr) callconv(.c) c_int;
    extern fn SSL_get_error(arg0: Ptr, arg1: c_int) callconv(.c) c_int;
    extern fn SSL_read(arg0: Ptr, arg1: [*]u8, arg2: c_int) callconv(.c) c_int;
    extern fn SSL_write(arg0: Ptr, arg1: [*]const u8, arg2: c_int) callconv(.c) c_int;
    extern fn BIO_s_mem() callconv(.c) Ptr;
    extern fn BIO_new(arg0: Ptr) callconv(.c) ?Ptr;
    extern fn BIO_free(arg0: Ptr) callconv(.c) c_int;
    extern fn BIO_read(arg0: Ptr, arg1: [*]u8, arg2: c_int) callconv(.c) c_int;
    extern fn BIO_write(arg0: Ptr, arg1: [*]const u8, arg2: c_int) callconv(.c) c_int;
    extern fn ERR_clear_error() callconv(.c) void;
};

pub const Context = struct {
    api: Api,
    ctx: Ptr,

    pub fn create(a: std.mem.Allocator) !*Context {
        if (comptime !enabled) return error.TelegramWsBuildDisabled;
        var api: Api = undefined;
        inline for (std.meta.fields(Api)) |f| @field(api, f.name) = &@field(linked, f.name);
        // Do not read openssl.cnf or load externally configured providers.
        if (api.OPENSSL_init_ssl(0x80, null) != 1) return error.TlsInitFailed;
        const ctx = api.SSL_CTX_new(api.TLS_client_method() orelse return error.TlsInitFailed) orelse return error.TlsInitFailed;
        errdefer api.SSL_CTX_free(ctx);
        if (std.c.getenv("SSL_CERT_FILE")) |path| {
            // An explicit trust-file override replaces the embedded roots, fail closed.
            if (api.SSL_CTX_load_verify_locations(ctx, path, null) != 1) return error.TlsCaLoadFailed;
        } else {
            const pem = @embedFile("ws_ca");
            const bio = api.BIO_new_mem_buf(pem, @intCast(pem.len)) orelse return error.TlsCaLoadFailed;
            defer _ = api.BIO_free(bio);
            const store = api.SSL_CTX_get_cert_store(ctx);
            var count: usize = 0;
            while (api.PEM_read_bio_X509(bio, null, null, null)) |cert| {
                defer api.X509_free(cert);
                if (api.X509_STORE_add_cert(store, cert) != 1) return error.TlsCaLoadFailed;
                count += 1;
            }
            api.ERR_clear_error(); // PEM EOF is expected.
            if (count == 0) return error.TlsCaLoadFailed;
        }
        api.SSL_CTX_set_verify(ctx, 1, null); // SSL_VERIFY_PEER: never disable CA verification.
        if (api.SSL_CTX_ctrl(ctx, 123, 0x0303, null) != 1) return error.TlsInitFailed; // TLS >= 1.2
        const out = try a.create(Context);
        out.* = .{ .api = api, .ctx = ctx };
        return out;
    }
    pub fn destroy(self: *Context, a: std.mem.Allocator) void {
        self.api.SSL_CTX_free(self.ctx);
        a.destroy(self);
    }
};

pub const Client = struct {
    context: *Context,
    ssl: Ptr,
    input: Ptr,
    output: Ptr,
    h2: bool = false,

    pub fn enableH2(self: *Client) !void {
        if (self.context.api.SSL_set_alpn_protos(self.ssl, "\x02h2", 3) != 0) return error.TlsInitFailed;
        self.h2 = true;
    }

    pub fn init(ctx: *Context, sni: []const u8, verify_name: bool) !Client {
        const api = &ctx.api;
        const ssl = api.SSL_new(ctx.ctx) orelse return error.TlsInitFailed;
        errdefer api.SSL_free(ssl);
        var name: [254:0]u8 = undefined;
        if (sni.len == 0 or sni.len > 253) return error.InvalidWsSni;
        @memcpy(name[0..sni.len], sni);
        name[sni.len] = 0;
        if (api.SSL_ctrl(ssl, 55, 0, @ptrCast(&name)) != 1) return error.TlsInitFailed;
        if (verify_name and api.SSL_set1_host(ssl, @ptrCast(&name)) != 1) return error.TlsInitFailed;
        const input = api.BIO_new(api.BIO_s_mem()) orelse return error.TlsInitFailed;
        const output = api.BIO_new(api.BIO_s_mem()) orelse {
            _ = api.BIO_free(input);
            return error.TlsInitFailed;
        };
        api.SSL_set_bio(ssl, input, output); // Ownership transfers to SSL.
        api.SSL_set_connect_state(ssl);
        return .{ .context = ctx, .ssl = ssl, .input = input, .output = output };
    }
    pub fn deinit(self: *Client) void {
        self.context.api.SSL_free(self.ssl);
    }
    pub fn feed(self: *Client, bytes: []const u8) !void {
        if (self.context.api.BIO_write(self.input, bytes.ptr, @intCast(bytes.len)) != bytes.len) return error.TlsInputFailed;
    }
    pub fn handshake(self: *Client) !bool {
        self.context.api.ERR_clear_error();
        const rc = self.context.api.SSL_do_handshake(self.ssl);
        if (rc == 1) {
            if (self.h2) {
                var selected: ?[*]const u8 = null;
                var len: c_uint = 0;
                self.context.api.SSL_get0_alpn_selected(self.ssl, &selected, &len);
                if (len != 2 or selected == null or !std.mem.eql(u8, selected.?[0..len], "h2")) return error.H2AlpnRequired;
            }
            return true;
        }
        _ = try self.result(rc);
        return false;
    }
    fn result(self: *Client, rc: c_int) !usize {
        if (rc > 0) return @intCast(rc);
        return switch (self.context.api.SSL_get_error(self.ssl, rc)) {
            2, 3 => 0, // WANT_READ / WANT_WRITE, resume on next epoll event.
            6 => error.TlsClosed,
            else => error.TlsProtocolError,
        };
    }
    pub fn read(self: *Client, buf: []u8) !usize {
        self.context.api.ERR_clear_error();
        return self.result(self.context.api.SSL_read(self.ssl, buf.ptr, @intCast(buf.len)));
    }
    pub fn write(self: *Client, bytes: []const u8) !void {
        self.context.api.ERR_clear_error();
        // Memory BIO cannot backpressure; retrying a TLS write on new data is forbidden.
        const rc = try self.result(self.context.api.SSL_write(self.ssl, bytes.ptr, @intCast(bytes.len)));
        if (rc != bytes.len) return error.TlsWriteIncomplete;
    }
    pub fn drain(self: *Client, buf: []u8) usize {
        const n = self.context.api.BIO_read(self.output, buf.ptr, @intCast(buf.len));
        return if (n > 0) @intCast(n) else 0;
    }
};

test "bundled TLS context loads trusted roots without a system trust directory" {
    if (comptime !enabled) return error.SkipZigTest;
    const context = try Context.create(std.testing.allocator);
    defer context.destroy(std.testing.allocator);
}
