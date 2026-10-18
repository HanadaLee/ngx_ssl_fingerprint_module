#!/usr/bin/env bash
set -euo pipefail
module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
flags=(-O1 -g -Wall -Wextra -Werror -Wno-unused-parameter
       -Wno-deprecated-declarations -fno-omit-frame-pointer)
if [[ "${TEST_SANITIZE:-1}" == 1 ]]; then
    flags+=(-fsanitize=address,undefined -fno-pie -no-pie)
fi
"${CC:-cc}" "${flags[@]}" -I"$module_root/t/unit/stubs" -I"$module_root/src" \
    "$module_root/t/unit/ngx_ssl_fingerprint_test.c" \
    -lssl -lcrypto -o "$test_root/probe"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}" \
    python3 "$module_root/t/unit/fingerprints.py" "$test_root/probe"
