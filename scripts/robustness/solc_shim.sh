#!/bin/sh
# solc launcher for forge on Linux and WSL (forge test --use <this file>): runs the solc-js shim.
# PQID_NODE may name the node binary (for example the absolute nvm path of D-034); otherwise node from PATH.
here=$(cd "$(dirname "$0")" && pwd)
exec "${PQID_NODE:-node}" "$here/solcjs_shim.cjs" "$@"
