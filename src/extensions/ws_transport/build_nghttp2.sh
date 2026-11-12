#!/bin/sh
set -eu
export WS_ZIG_EXE="$1" WS_ZIG_TARGET="$3"
ws_source="$2"
ws_jobs="$4"
ws_adapter="$5"
mkdir -p "$6"
cd "$6"
ws_output="$PWD"
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
cat > zig-ld <<'WRAPPER'
#!/bin/sh
exec "$WS_ZIG_EXE" ld.lld "$@"
WRAPPER
chmod +x zig-cc zig-ar zig-ranlib zig-ld
export CC="$ws_output/zig-cc" AR="$ws_output/zig-ar" RANLIB="$ws_output/zig-ranlib" LD="$ws_output/zig-ld"
"$ws_source/configure" --host="$WS_ZIG_TARGET" --enable-lib-only \
    --enable-static --disable-shared --disable-dependency-tracking \
    --without-libxml2 CFLAGS="-O2 -fPIC"
# Zig's package extraction normalizes timestamps. Use the release's generated
# configure/Makefile inputs, never try to regenerate them with host autotools.
make -C lib -j "$ws_jobs" ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
"$CC" -O2 -fPIC -I"$ws_source/lib/includes" -I"$ws_output/lib/includes" \
    -c "$ws_adapter" -o cf_h2.o
