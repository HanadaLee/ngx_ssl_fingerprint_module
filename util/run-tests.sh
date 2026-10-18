#!/usr/bin/env bash

set -euo pipefail

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
nginx_source="$module_root/.ci/nginx"
test_output="$module_root/.ci/test-output"
build_jobs="${TEST_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
mkdir -p "$test_output"
exec > >(tee "$test_output/run.log") 2>&1

bash "$module_root/util/run-unit-tests.sh"

configure_args=(
    --prefix="$nginx_source/test-prefix"
    --with-debug
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_v3_module
    --with-http_realip_module
    --with-http_sub_module
    --with-http_json_module
    --with-stream
    --with-stream_ssl_module
    --with-stream_realip_module
)

openssl_source="$module_root/.ci/openssl"
patch -d "$nginx_source" -p1 --forward < "$module_root/patches/nginx-1.29.3+.patch"
configure_args+=(--with-openssl="$openssl_source" --with-openssl-opt=no-tests)

# Match OpenResty's asynchronous Lua ClientHello callback support.
nginx_version="$(sed -n 's/^#define NGINX_VERSION[[:space:]]*"\([^"]*\)"/\1/p' "$nginx_source/src/core/nginx.h")"
for callback in ssl_cert ssl_sess ssl_client_hello; do
    callback_patch="$module_root/.ci/openresty/patches/nginx/$nginx_version/nginx-$nginx_version-${callback}_cb_yield.patch"
    patch -d "$nginx_source" -p1 --forward --fuzz=1 < "$callback_patch"
done

luajit_prefix="$module_root/.ci/luajit-install"
make -C "$module_root/.ci/luajit" -j"$build_jobs" PREFIX="$luajit_prefix"
make -C "$module_root/.ci/luajit" install PREFIX="$luajit_prefix"
export LUAJIT_LIB="$luajit_prefix/lib"
export LUAJIT_INC="$luajit_prefix/include/luajit-2.1"
configure_args+=(
    --with-ld-opt="-Wl,-rpath,$LUAJIT_LIB"
    --add-module="$module_root/.ci/lua-nginx-module"
)
export TEST_FINGERPRINT_LUA_PATH="$module_root/.ci/lua-resty-core/lib/?.lua;$module_root/.ci/lua-resty-lrucache/lib/?.lua;;"
export LUA_PATH="$TEST_FINGERPRINT_LUA_PATH"

configure_args+=(--add-module="$module_root")

cd "$nginx_source"
sh ./configure "${configure_args[@]}"
make -j"$build_jobs"

export TEST_NGINX_BINARY="$nginx_source/objs/nginx"
export PERL5LIB="$module_root/.ci/nginx-tests/lib"
export TMPDIR="$(mktemp -d /tmp/nginx-module-test.XXXXXX)"
export TEST_NGINX_LEAVE=1
export TEST_NGINX_SERVROOT="$TMPDIR/servroot"
collect_logs() {
    find "$TMPDIR" -type f -name '*.log' -exec cp --parents {} "$test_output/" \;
}
trap collect_logs EXIT
if [[ "$(id -u)" == 0 ]]; then
    export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-user root;}"
fi
"$TEST_NGINX_BINARY" -V

cd "$module_root"
shopt -s nullglob
tests=()
for test_file in t/*.t; do
    tests+=("$test_file")
done
if (( ${#tests[@]} == 0 )); then
    echo "No tests selected" >&2
    exit 1
fi
prove -v "${tests[@]}"
