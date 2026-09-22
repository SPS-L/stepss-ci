#!/usr/bin/env bash
# Developer ID signing and notarization for the STEPSS platform.
#
# Every command is a separate entry point so that the composite action can
# order them and so that each is testable in isolation. Nothing here reads a
# workflow context: credentials arrive as environment variables, which is what
# lets the whole file be exercised on Linux against fake Apple tools.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: sign.sh <command> [args]
  preflight                 refuse to continue without credentials
  keychain-open             create a temporary keychain and import the identity
  keychain-close            delete it
  cert-expiry               fail past the certificate's notAfter, warn within a year
  identity                  print the SHA-1 of the one signing identity
  sign <file>...            codesign with hardened runtime and entitlements
  verify <file>...          codesign --verify --strict
  notarize <file>...        submit to notarytool and wait for Accepted
  staple <bundle>           staple a ticket to a .dmg or .app and validate it
  assess <file>             spctl assessment
EOF
}

main() {
  local cmd="${1:-}"
  [ -n "$cmd" ] || { usage; exit 2; }
  shift
  case "$cmd" in
    *) echo "sign.sh: unknown command: $cmd" >&2; usage; exit 2 ;;
  esac
}

main "$@"
