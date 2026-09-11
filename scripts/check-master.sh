#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Override if validating against the repository's nightly toolchain.
toolchain="${MASTER_RUST_TOOLCHAIN:-stable}"
cargo "+$toolchain" fmt -p iso-master -- --check
cargo "+$toolchain" clippy -p iso-master --all-targets -- -D warnings
cargo "+$toolchain" test -p iso-master -p iso-client
cargo "+$toolchain" build -p iso-master
cd contrib/master
npm run lint
npm run format:check
npm run typecheck
npm test
npm run build
npm run test:rpc
if [[ "${RUN_BROWSER_TESTS:-0}" == 1 ]]; then
  npm run test:browser
fi
