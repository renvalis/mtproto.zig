//! Bundled TLS and HTTP/2 dependencies for the Telegram transport.
const std = @import("std");

pub const Dependencies = struct {
    archives: std.Build.LazyPath,
    ca: std.Build.LazyPath,
    h2: std.Build.LazyPath,

    pub fn attach(self: Dependencies, module: *std.Build.Module) void {
        module.link_libc = true;
        module.addObjectFile(self.archives.path(module.owner, "libssl.a"));
        module.addObjectFile(self.archives.path(module.owner, "libcrypto.a"));
        module.addObjectFile(self.h2.path(module.owner, "cf_h2.o"));
        module.addObjectFile(self.h2.path(module.owner, "lib/.libs/libnghttp2.a"));
        module.addAnonymousImport("ws_ca", .{ .root_source_file = self.ca });
    }
};

pub fn dependencies(b: *std.Build, target: std.Build.ResolvedTarget) ?Dependencies {
    if (target.result.os.tag != .linux or (target.result.cpu.arch != .x86_64 and target.result.cpu.arch != .aarch64))
        @panic("Telegram WS currently supports Linux x86_64 and aarch64 targets");
    // Request all lazy packages on the first configure pass.
    const openssl = b.lazyDependency("ws_openssl", .{});
    const certifi = b.lazyDependency("ws_certifi", .{});
    const nghttp2 = b.lazyDependency("ws_nghttp2", .{});
    if (openssl == null or certifi == null or nghttp2 == null) return null;
    const jobs = b.option(u16, "ws_tls_jobs", "Parallel C compiler jobs for bundled TLS (default: 4)") orelse 4;
    if (jobs == 0) @panic("ws_tls_jobs must be positive");
    const build = b.addSystemCommand(&.{"sh"});
    build.addFileArg(b.path("src/extensions/ws_transport/build_openssl.sh"));
    build.addArg(b.graph.zig_exe);
    build.addDirectoryArg(openssl.?.path(""));
    build.addArg(target.query.zigTriple(b.allocator) catch @panic("OOM"));
    build.addArg(b.fmt("{d}", .{jobs}));
    const archives = build.addOutputDirectoryArg("openssl");
    build.step.name = "build bundled OpenSSL";
    // Preserve upstream Perl diagnostics without presenting successful builds as failures.
    // std.Build reports the captured stderr automatically if the command fails.
    _ = build.captureStdErr(.{ .basename = "openssl-build.stderr" });
    const h2 = b.addSystemCommand(&.{"sh"});
    h2.addFileArg(b.path("src/extensions/ws_transport/build_nghttp2.sh"));
    h2.addArg(b.graph.zig_exe);
    h2.addDirectoryArg(nghttp2.?.path(""));
    h2.addArg(target.query.zigTriple(b.allocator) catch @panic("OOM"));
    h2.addArg(b.fmt("{d}", .{jobs}));
    h2.addFileArg(b.path("src/extensions/ws_transport/cf_h2.c"));
    const h2_output = h2.addOutputDirectoryArg("nghttp2");
    _ = h2.captureStdOut(.{ .basename = "nghttp2-build.stdout" });
    _ = h2.captureStdErr(.{ .basename = "nghttp2-build.stderr" });
    h2.step.name = "build bundled nghttp2";
    return .{ .archives = archives, .ca = certifi.?.path("certifi/cacert.pem"), .h2 = h2_output };
}
