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

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "sign.sh: $name is empty." >&2
    echo "Signing cannot proceed. This step does not skip, because a skipped" >&2
    echo "signing step publishes unsigned binaries under a green run." >&2
    exit 1
  fi
}

cmd_preflight() {
  require_var APPLE_SIGNING_P12
  require_var APPLE_SIGNING_P12_PASSWORD
  if [ "${SIGN_NOTARIZE:-true}" != "false" ]; then
    require_var APPLE_NOTARY_KEY_P8
    require_var APPLE_NOTARY_KEY_ID
    require_var APPLE_NOTARY_ISSUER_ID
  fi
  echo "Credentials present."
}

main() {
  local cmd="${1:-}"
  [ -n "$cmd" ] || { usage; exit 2; }
  shift
  case "$cmd" in
    preflight) cmd_preflight "$@" ;;
    *) echo "sign.sh: unknown command: $cmd" >&2; usage; exit 2 ;;
  esac
}

main "$@"
