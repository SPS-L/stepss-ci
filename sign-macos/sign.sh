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

# GNU date on the Linux test runner, BSD date on the macOS runner. The format
# is OpenSSL's notAfter, e.g. "Sep 12 06:46:04 2031 GMT".
days_until() {
  local when="$1" target now
  if date --version >/dev/null 2>&1; then
    target="$(date -u -d "$when" +%s)"
  else
    target="$(date -u -j -f "%b %d %T %Y %Z" "$when" +%s)"
  fi
  now="$(date -u +%s)"
  echo $(( (target - now) / 86400 ))
}

cmd_cert_expiry() {
  local when="${1:?sign.sh cert-expiry needs a notAfter string}"
  local days; days="$(days_until "$when")"
  if [ "$days" -lt 0 ]; then
    echo "sign.sh: the signing certificate expired on $when." >&2
    echo "Every macOS release fails until it is replaced. See the rotation" >&2
    echo "notes in the stepss umbrella CLAUDE.md." >&2
    exit 1
  fi
  if [ "$days" -lt 365 ]; then
    echo "sign.sh: WARNING, the signing certificate expires in $days days, on $when." >&2
  fi
  echo "Certificate valid for $days more days."
}

keychain_path() { echo "${RUNNER_TEMP:?RUNNER_TEMP is unset}/stepss-signing.keychain-db"; }

cmd_keychain_open() {
  require_var APPLE_SIGNING_P12
  require_var APPLE_SIGNING_P12_PASSWORD
  local kc; kc="$(keychain_path)"
  local kcpass; kcpass="$(openssl rand -base64 24)"
  local p12="${RUNNER_TEMP}/identity.p12"

  printf '%s' "$APPLE_SIGNING_P12" | base64 --decode > "$p12"
  security create-keychain -p "$kcpass" "$kc"
  security set-keychain-settings -lut 21600 "$kc"
  security unlock-keychain -p "$kcpass" "$kc"
  # -A is deliberately not used: the partition list below grants access to
  # codesign alone rather than to every application on the runner.
  security import "$p12" -k "$kc" -P "$APPLE_SIGNING_P12_PASSWORD" \
           -T /usr/bin/codesign -T /usr/bin/productsign
  security set-key-partition-list -S apple-tool:,apple:,codesign: \
           -s -k "$kcpass" "$kc"
  # Unquoted deliberately: word splitting turns each pre-existing keychain
  # path into its own argv item. Quoting this would collapse N keychains into
  # one argument joined by embedded newlines instead of N separate paths.
  security list-keychains -d user -s "$kc" $(security list-keychains -d user | tr -d ' "')
  rm -f "$p12"
  echo "Keychain ready at $kc"
}

cmd_keychain_close() {
  local kc; kc="$(keychain_path)"
  security delete-keychain "$kc" || true
  echo "Keychain removed."
}

cmd_identity() {
  local listing count hash
  listing="$(security find-identity -v -p codesigning "$(keychain_path)")"
  count="$(printf '%s\n' "$listing" | grep -c -E '^[[:space:]]*[0-9]+\) [0-9A-F]{40} ' || true)"
  if [ "$count" -ne 1 ]; then
    echo "sign.sh: expected exactly one code signing identity, found $count." >&2
    printf '%s\n' "$listing" >&2
    exit 1
  fi
  hash="$(printf '%s\n' "$listing" | grep -o -E '[0-9A-F]{40}' | head -n1)"
  printf '%s\n' "$hash"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cmd_sign() {
  [ "$#" -gt 0 ] || { echo "sign.sh: sign needs at least one file" >&2; exit 2; }
  local ents="${SIGN_ENTITLEMENTS:-$SCRIPT_DIR/entitlements.plist}"
  local hash; hash="$(cmd_identity)"
  local f
  for f in "$@"; do
    [ -f "$f" ] || { echo "sign.sh: no such file: $f" >&2; exit 1; }
  done
  for f in "$@"; do
    echo "Signing $f"
    codesign --force --timestamp --options runtime \
             --entitlements "$ents" --sign "$hash" "$f"
  done
}

cmd_verify() {
  [ "$#" -gt 0 ] || { echo "sign.sh: verify needs at least one file" >&2; exit 2; }
  local f
  for f in "$@"; do
    codesign --verify --strict --verbose=2 "$f"
  done
}

# notarytool's --output-format json is emitted by Swift's JSONEncoder, which
# pretty-prints with a space either side of the colon ("status" : "Accepted")
# and across multiple lines. A sed/substring match tuned to compact JSON
# silently returns empty against that shape, so this parses for real.
# python3 ships on every macOS runner.
#
# Exits 3 (rather than letting an unhandled JSONDecodeError abort the whole
# script under `set -e`) when stdin is not the JSON object notarytool
# promises, e.g. an error string it printed to stdout instead. The caller
# must check for that exit code rather than trust an empty result: an empty
# string is also what a present-but-unparseable field would look like.
json_field() {
  local field="$1"
  python3 -c 'import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get(sys.argv[1], ""))
except Exception:
    sys.exit(3)' "$field"
}

cmd_notarize() {
  [ "$#" -gt 0 ] || { echo "sign.sh: notarize needs at least one file" >&2; exit 2; }
  require_var APPLE_NOTARY_KEY_P8
  require_var APPLE_NOTARY_KEY_ID
  require_var APPLE_NOTARY_ISSUER_ID

  local work="${RUNNER_TEMP:?RUNNER_TEMP is unset}/notary"
  mkdir -p "$work"
  local p8="$work/key.p8"
  printf '%s' "$APPLE_NOTARY_KEY_P8" | base64 --decode > "$p8"

  # A .dmg or .app is submitted as itself; bare executables are zipped,
  # because notarytool accepts only .zip, .pkg and .dmg.
  local payload
  if [ "$#" -eq 1 ] && case "$1" in *.dmg|*.pkg|*.app) true ;; *) false ;; esac; then
    payload="$1"
  else
    # ditto's archive mode (-c) accepts exactly one source, so every input
    # file is staged flat into one directory first and that single directory
    # is what gets archived. --keepParent is deliberately not used: it would
    # wrap the contents in an entry named for the staging directory under
    # $RUNNER_TEMP, and Apple issues a notarization ticket per Mach-O found
    # in the archive, so a flat layout of the binaries is what is wanted.
    local stage="$work/payload"
    rm -rf "$stage"
    mkdir -p "$stage"
    local f base
    for f in "$@"; do
      base="$(basename "$f")"
      if [ -e "$stage/$base" ]; then
        echo "sign.sh: notarize: two inputs are both named $base; the archive would lose one." >&2
        exit 1
      fi
      cp "$f" "$stage/$base"
    done
    payload="$work/payload.zip"
    ditto -c -k "$stage" "$payload"
  fi

  local json status parse_rc=0
  json="$(xcrun notarytool submit "$payload" \
            --key "$p8" --key-id "$APPLE_NOTARY_KEY_ID" \
            --issuer "$APPLE_NOTARY_ISSUER_ID" \
            --wait --output-format json)"
  rm -f "$p8"
  # `|| parse_rc=$?` rather than a bare command substitution: under `set -e`
  # a failing `status="$(...)"` would otherwise abort the script right here,
  # on a raw Python traceback, before the message below or the log fetch
  # ever run.
  status="$(printf '%s' "$json" | json_field status)" || parse_rc=$?
  if [ "$parse_rc" -ne 0 ]; then
    echo "sign.sh: could not parse notarytool's output as JSON." >&2
    echo "notarytool said:" >&2
    printf '%s\n' "$json" >&2
    local id; id="$(printf '%s' "$json" | json_field id)" || id=""
    if [ -n "$id" ]; then
      xcrun notarytool log "$id" --key-id "$APPLE_NOTARY_KEY_ID" \
            --issuer "$APPLE_NOTARY_ISSUER_ID" >&2 || true
    fi
    exit 1
  fi
  echo "notarytool status: $status"
  if [ "$status" != "Accepted" ]; then
    local id; id="$(printf '%s' "$json" | json_field id)"
    echo "sign.sh: notarization was not accepted (status: $status)." >&2
    # Apple's reason is the only actionable part and lives behind a second
    # call, so it is fetched here rather than left for someone to run by hand.
    xcrun notarytool log "$id" --key-id "$APPLE_NOTARY_KEY_ID" \
          --issuer "$APPLE_NOTARY_ISSUER_ID" >&2 || true
    exit 1
  fi
}

cmd_staple() {
  local bundle="${1:?sign.sh staple needs a .dmg, .pkg or .app}"
  xcrun stapler staple "$bundle"
  xcrun stapler validate "$bundle"
}

cmd_assess() {
  local target="${1:?sign.sh assess needs a path}"
  case "$target" in
    *.dmg|*.pkg) spctl --assess --type install --verbose=4 "$target" ;;
    *)           spctl --assess --type execute --verbose=4 "$target" ;;
  esac
}

main() {
  local cmd="${1:-}"
  [ -n "$cmd" ] || { usage; exit 2; }
  shift
  case "$cmd" in
    preflight) cmd_preflight "$@" ;;
    cert-expiry) cmd_cert_expiry "$@" ;;
    keychain-open)  cmd_keychain_open "$@" ;;
    keychain-close) cmd_keychain_close "$@" ;;
    identity)       cmd_identity "$@" ;;
    sign)   cmd_sign "$@" ;;
    verify) cmd_verify "$@" ;;
    notarize) cmd_notarize "$@" ;;
    staple)   cmd_staple "$@" ;;
    assess)   cmd_assess "$@" ;;
    *) echo "sign.sh: unknown command: $cmd" >&2; usage; exit 2 ;;
  esac
}

main "$@"
