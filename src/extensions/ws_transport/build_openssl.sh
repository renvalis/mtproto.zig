#!/bin/sh
# Build pinned OpenSSL sources out-of-tree using the same Zig toolchain/target.
# Inputs/outputs are owned by std.Build's cache; nothing is installed on the host.
set -eu
export WS_ZIG_EXE="$1" WS_ZIG_TARGET="$3"
ws_source="$2"
ws_jobs="$4"
mkdir -p "$5"
cd "$5"
ws_output="$PWD"
case "$WS_ZIG_TARGET" in
    x86_64-linux*) ws_platform=linux-x86_64 ;;
    aarch64-linux*) ws_platform=linux-aarch64 ;;
    *) echo "Unsupported Telegram WS static TLS target: $WS_ZIG_TARGET" >&2; exit 1 ;;
esac
cat > zig-cc <<'WRAPPER'
#!/bin/sh
exec "$WS_ZIG_EXE" cc -target "$WS_ZIG_TARGET" "$@"
WRAPPER
cat > zig-ar <<'WRAPPER'
#!/bin/sh
exec "$WS_ZIG_EXE" ar "$@"
WRAPPER
cat > zig-ranlib <<'WRAPPER'
#!/bin/sh
exec "$WS_ZIG_EXE" ranlib "$@"
WRAPPER
chmod +x zig-cc zig-ar zig-ranlib
export CC="$ws_output/zig-cc" AR="$ws_output/zig-ar" RANLIB="$ws_output/zig-ranlib"
# Memory BIO only: no socket/DNS code, loadable providers, engines or DSO loader.
# Default provider and TLS algorithms are compiled into the static archives.
perl "$ws_source/Configure" "$ws_platform" -fPIC \
    --prefix=/openssl --openssldir=/openssl/ssl --libdir=lib \
    no-shared no-tests no-apps no-docs no-legacy no-engine no-dso no-module \
    no-sock no-http no-quic
make -j "$ws_jobs" build_libs
