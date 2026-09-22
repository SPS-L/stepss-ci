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

# ---- cert-expiry ---------------------------------------------------------
out="$(run_sign cert-expiry "Sep 12 06:46:04 2031 GMT")"; rc=$?
[ "$rc" = 0 ] && ok "a certificate valid for years passes" \
               || fail "cert-expiry rejected a 2031 date: $out"

out="$(run_sign cert-expiry "Jan 01 00:00:00 2020 GMT")"; rc=$?
[ "$rc" = 1 ] && ok "an expired certificate fails" \
               || fail "cert-expiry exited $rc on a 2020 date, expected 1"
case "$out" in *expired*) ok "the failure says expired" ;;
               *) fail "the failure did not say expired: $out" ;; esac

soon="$(date -u -d '+90 days' '+%b %d %H:%M:%S %Y GMT' 2>/dev/null \
        || date -u -v+90d '+%b %d %H:%M:%S %Y GMT')"
out="$(run_sign cert-expiry "$soon")"; rc=$?
[ "$rc" = 0 ] && ok "a certificate expiring in 90 days still passes" \
               || fail "cert-expiry exited $rc on a near date: $out"
case "$out" in *90\ days*|*89\ days*|*91\ days*) ok "the warning counts the days" ;;
               *) fail "no day count in the warning: $out" ;; esac

# ---- identity ------------------------------------------------------------
# RUNNER_TEMP must be exported before these: cmd_identity resolves the
# keychain path the same way keychain-open/keychain-close do, so it needs
# RUNNER_TEMP set even though it does not touch the keychain lifecycle.
export RUNNER_TEMP="$TMPD"
one_identity='  1) A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "Developer ID Application: Cyprus University of Technology (SWZD63F3C7)"
     1 valid identities found'
out="$(FAKE_SECURITY_OUT="$one_identity" run_sign identity)"; rc=$?
[ "$rc" = 0 ] && ok "identity succeeds with exactly one" \
               || fail "identity exited $rc with one identity: $out"
[ "$out" = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" ] \
  && ok "identity prints the bare hash" || fail "identity printed: $out"

none='     0 valid identities found'
out="$(FAKE_SECURITY_OUT="$none" run_sign identity)"; rc=$?
[ "$rc" = 1 ] && ok "identity fails when the keychain holds none" \
               || fail "identity exited $rc with no identity"

two="$one_identity
  2) FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \"Developer ID Application: Other (XXXX)\""
out="$(FAKE_SECURITY_OUT="$two" run_sign identity)"; rc=$?
[ "$rc" = 1 ] && ok "identity fails when the keychain holds two" \
               || fail "identity exited $rc with two identities"

# ---- keychain lifecycle --------------------------------------------------
out="$(run_sign keychain-open)"; rc=$?
[ "$rc" = 0 ] && ok "keychain-open succeeds" || fail "keychain-open: $out"
grep -q 'security create-keychain' "$ARGV_LOG" \
  && ok "keychain-open creates a keychain" || fail "no create-keychain in: $(cat "$ARGV_LOG")"
grep -q 'security import' "$ARGV_LOG" \
  && ok "keychain-open imports the identity" || fail "no import in: $(cat "$ARGV_LOG")"
grep -q 'security set-key-partition-list' "$ARGV_LOG" \
  && ok "keychain-open sets the partition list" || fail "no partition list in: $(cat "$ARGV_LOG")"

# Regression test: the final `security list-keychains -s ...` line used to
# quote the inner command substitution, collapsing N pre-existing keychains
# into one argv item joined by embedded newlines instead of N separate path
# arguments. A single pre-existing keychain hid this (there was nothing to
# join), so this test stages two.
two_keychains='    "/Users/runner/Library/Keychains/login.keychain-db"
    "/Users/runner/Library/Keychains/other.keychain-db"'
out="$(FAKE_SECURITY_OUT="$two_keychains" run_sign keychain-open)"; rc=$?
[ "$rc" = 0 ] && ok "keychain-open succeeds with two pre-existing keychains" \
               || fail "keychain-open with two pre-existing keychains: $out"
grep -q 'security list-keychains -d user -s .*login.keychain-db .*other.keychain-db' "$ARGV_LOG" \
  && ok "keychain-open passes pre-existing keychains as separate arguments" \
  || fail "pre-existing keychains not passed as separate arguments: $(cat "$ARGV_LOG")"
grep -qx '/Users/runner/Library/Keychains/other.keychain-db' "$ARGV_LOG" \
  && fail "a keychain path leaked onto its own line (embedded newline): $(cat "$ARGV_LOG")" \
  || ok "no keychain path is split across an embedded newline"

out="$(run_sign keychain-close)"; rc=$?
[ "$rc" = 0 ] && ok "keychain-close succeeds" || fail "keychain-close: $out"
grep -q 'security delete-keychain' "$ARGV_LOG" \
  && ok "keychain-close deletes the keychain" || fail "no delete in: $(cat "$ARGV_LOG")"

# ---- sign and verify -----------------------------------------------------
: > "$TMPD/ramses"; : > "$TMPD/ramses.so"
out="$(FAKE_SECURITY_OUT="$one_identity" run_sign sign "$TMPD/ramses" "$TMPD/ramses.so")"; rc=$?
[ "$rc" = 0 ] && ok "sign succeeds over two files" || fail "sign: $out"
[ "$(grep -c '^codesign ' "$ARGV_LOG")" = 2 ] \
  && ok "sign invokes codesign once per file" || fail "codesign calls: $(grep -c '^codesign ' "$ARGV_LOG")"
grep -q -- '--options runtime' "$ARGV_LOG" \
  && ok "sign enables the hardened runtime" || fail "no --options runtime: $(cat "$ARGV_LOG")"
grep -q -- '--timestamp' "$ARGV_LOG" \
  && ok "sign requests a secure timestamp" || fail "no --timestamp"
grep -q -- '--entitlements' "$ARGV_LOG" \
  && ok "sign passes entitlements" || fail "no --entitlements"
grep -q 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678' "$ARGV_LOG" \
  && ok "sign uses the resolved hash" || fail "hash not used: $(cat "$ARGV_LOG")"

out="$(FAKE_SECURITY_OUT="$one_identity" FAKE_CODESIGN_EXIT=1 run_sign sign "$TMPD/ramses")"; rc=$?
[ "$rc" != 0 ] && ok "a codesign failure fails the step" || fail "sign swallowed a codesign failure"

out="$(run_sign sign "$TMPD/does-not-exist")"; rc=$?
[ "$rc" = 1 ] && ok "sign fails on a missing file" || fail "sign exited $rc on a missing file"

out="$(run_sign verify "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "verify succeeds" || fail "verify: $out"
grep -q -- '--verify --strict' "$ARGV_LOG" \
  && ok "verify is strict" || fail "verify not strict: $(cat "$ARGV_LOG")"

# ---- notarize ------------------------------------------------------------
# notarytool's --output-format json is Swift's JSONEncoder: it pretty-prints
# with a space either side of the colon ("status" : "Accepted") across
# several lines. These fixtures use that real shape, so a status/id
# extraction that regresses to a compact "status":"..." substring or sed
# match fails here (it did: see the fix-round report for the reproduction).
accepted='{
  "id" : "abc-123",
  "status" : "Accepted"
}'
out="$(FAKE_XCRUN_OUT="$accepted" run_sign notarize "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "notarize succeeds on Accepted (pretty-printed JSON)" || fail "notarize: $out"
grep -q 'xcrun notarytool submit' "$ARGV_LOG" \
  && ok "notarize submits" || fail "no submit: $(cat "$ARGV_LOG")"
grep -q -- '--wait' "$ARGV_LOG" \
  && ok "notarize waits for the verdict" || fail "no --wait"
grep -q '69a6de82-68c9-47e3-e053-5b8c7c11a4d1' "$ARGV_LOG" \
  && ok "notarize passes the issuer id" || fail "no issuer id: $(cat "$ARGV_LOG")"
grep -q 'ditto ' "$ARGV_LOG" \
  && ok "notarize builds a zip with ditto" || fail "no ditto call"

# Compact JSON never comes from notarytool itself, but the parser must not
# be tied to either shape.
accepted_compact='{"id":"abc-123","status":"Accepted"}'
out="$(FAKE_XCRUN_OUT="$accepted_compact" run_sign notarize "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "notarize succeeds on Accepted (compact JSON)" || fail "notarize compact: $out"

invalid='{
  "id" : "abc-123",
  "status" : "Invalid"
}'
out="$(FAKE_XCRUN_OUT="$invalid" run_sign notarize "$TMPD/ramses")"; rc=$?
[ "$rc" = 1 ] && ok "notarize fails on Invalid" || fail "notarize exited $rc on Invalid"
case "$out" in *Invalid*) ok "the failure reports the status" ;;
               *) fail "status not reported: $out" ;; esac
grep -q 'notarytool log' "$ARGV_LOG" \
  && ok "a rejection fetches Apple's log" || fail "no log fetch: $(cat "$ARGV_LOG")"

# notarytool's --output-format json can still land a raw error string on
# stdout (an auth failure, a network error), which is not JSON at all. This
# used to raise an unhandled JSONDecodeError inside json_field; under `set
# -e` the enclosing `status="$(...)"` assignment then aborted sign.sh on a
# Python traceback, before the "not accepted" message printed and before the
# log fetch ever ran (see the fix-round report for the before/after
# transcripts).
badjson='error: could not connect to notarization service'
out="$(FAKE_XCRUN_OUT="$badjson" run_sign notarize "$TMPD/ramses")"; rc=$?
[ "$rc" != 0 ] && ok "notarize fails on unparseable notarytool output" \
               || fail "notarize exited 0 on unparseable output"
case "$out" in *"could not parse notarytool's output as JSON"*) ok "the failure is named, not a raw traceback" ;;
               *) fail "no named failure: $out" ;; esac
case "$out" in *"$badjson"*) ok "the received (non-JSON) text is echoed" ;;
               *) fail "received text not echoed: $out" ;; esac
case "$out" in *Traceback*) fail "a Python traceback leaked to the caller: $out" ;;
               *) ok "no raw Python traceback leaks to the caller" ;; esac

# ---- empty file list (the action.yml side of the same fix round) ---------
# action.yml now checks ${#files[@]} before ever expanding "${files[@]}" (or
# indexing "${files[0]}"), so an empty paths input calls sign.sh with zero
# file arguments instead of letting the shell expand an empty array — which
# raises "unbound variable" under bash 3.2's `set -u` (fixed in bash 4.4;
# the macOS runner's stock /bin/bash predates that fix and this sandbox's
# bash postdates it, so the crash itself cannot be reproduced here — see the
# fix-round report). This pins the sign.sh side of that fix: the contract
# action.yml's empty branch relies on is that sign.sh's own message, not a
# shell error, is what a caller sees.
out="$(run_sign sign)"; rc=$?
[ "$rc" = 2 ] && ok "sign with zero files exits 2" || fail "sign with zero files exited $rc"
case "$out" in *"sign needs at least one file"*) ok "sign's own message reports the empty input" ;;
               *) fail "sign did not name the empty input: $out" ;; esac
case "$out" in *"unbound variable"*|*"bad substitution"*) fail "a shell error leaked instead of sign.sh's message: $out" ;;
               *) ok "no shell-level error text leaks from a zero-argument sign" ;; esac

out="$(run_sign notarize)"; rc=$?
[ "$rc" = 2 ] && ok "notarize with zero files exits 2" || fail "notarize with zero files exited $rc"
case "$out" in *"notarize needs at least one file"*) ok "notarize's own message reports the empty input" ;;
               *) fail "notarize did not name the empty input: $out" ;; esac

# ---- staple and assess ---------------------------------------------------
out="$(run_sign staple "$TMPD/STEPSS.dmg")"; rc=$?
[ "$rc" = 0 ] && ok "staple succeeds" || fail "staple: $out"
grep -q 'xcrun stapler staple' "$ARGV_LOG" && ok "staple staples" || fail "no staple call"
grep -q 'xcrun stapler validate' "$ARGV_LOG" && ok "staple validates" || fail "no validate call"

out="$(run_sign assess "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "assess succeeds" || fail "assess: $out"
grep -q '^spctl ' "$ARGV_LOG" && ok "assess calls spctl" || fail "no spctl call"

echo
[ "$FAILURES" = 0 ] && { echo "all tests passed"; exit 0; }
echo "$FAILURES test(s) failed"; exit 1
