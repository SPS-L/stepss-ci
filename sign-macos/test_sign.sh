#!/usr/bin/env bash
# Unit tests for sign-macos/sign.sh. Runs on Linux with no credentials and no
# Apple tooling: every macOS binary the script calls is replaced by a fake on
# PATH that logs its argv to $ARGV_LOG and exits with $FAKE_EXIT.
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$ROOT/sign.sh"
FAILURES=0
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }
ok()   { echo "ok: $*"; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
FAKEBIN="$TMPD/fakebin"; mkdir -p "$FAKEBIN"
ARGV_LOG="$TMPD/argv.log"

# One fake per Apple tool. Each appends its own name and arguments to the log
# so that a test can assert on what the script actually invoked, and honours
# FAKE_<TOOL>_EXIT so that a test can force a failure.
for tool in security codesign xcrun ditto spctl; do
  cat > "$FAKEBIN/$tool" <<EOF
#!/usr/bin/env bash
echo "$tool \$*" >> "$ARGV_LOG"
var="FAKE_\$(echo "$tool" | tr '[:lower:]' '[:upper:]')_EXIT"
out_var="FAKE_\$(echo "$tool" | tr '[:lower:]' '[:upper:]')_OUT"
[ -n "\${!out_var:-}" ] && printf '%s\n' "\${!out_var}"
exit "\${!var:-0}"
EOF
  chmod +x "$FAKEBIN/$tool"
done
export PATH="$FAKEBIN:$PATH"

run_sign() { : > "$ARGV_LOG"; bash "$SCRIPT" "$@" 2>&1; }

# ---- dispatcher ----------------------------------------------------------
out="$(run_sign no-such-command)"; rc=$?
[ "$rc" = 2 ] && ok "unknown command exits 2" || fail "unknown command exited $rc, expected 2"
case "$out" in *no-such-command*) ok "unknown command is named in the error" ;;
               *) fail "error did not name the command: $out" ;; esac

# ---- preflight -----------------------------------------------------------
export APPLE_SIGNING_P12="Zm9v" APPLE_SIGNING_P12_PASSWORD="pw" \
       APPLE_NOTARY_KEY_P8="YmFy" APPLE_NOTARY_KEY_ID="8A4L5VF84Z" \
       APPLE_NOTARY_ISSUER_ID="69a6de82-68c9-47e3-e053-5b8c7c11a4d1"

out="$(run_sign preflight)"; rc=$?
[ "$rc" = 0 ] && ok "preflight passes with every credential set" \
               || fail "preflight failed with a full environment: $out"

out="$(APPLE_SIGNING_P12= run_sign preflight)"; rc=$?
[ "$rc" = 1 ] && ok "preflight fails without the certificate" \
               || fail "preflight exited $rc without the certificate, expected 1"
case "$out" in *APPLE_SIGNING_P12*) ok "preflight names the missing variable" ;;
               *) fail "preflight did not name APPLE_SIGNING_P12: $out" ;; esac

out="$(APPLE_NOTARY_ISSUER_ID= run_sign preflight)"; rc=$?
[ "$rc" = 1 ] && ok "preflight fails without the issuer id" \
               || fail "preflight exited $rc without the issuer id, expected 1"

out="$(APPLE_NOTARY_ISSUER_ID= SIGN_NOTARIZE=false run_sign preflight)"; rc=$?
[ "$rc" = 0 ] && ok "preflight ignores notary credentials when not notarizing" \
               || fail "preflight exited $rc in sign-only mode: $out"

echo
[ "$FAILURES" = 0 ] && { echo "all tests passed"; exit 0; }
echo "$FAILURES test(s) failed"; exit 1
