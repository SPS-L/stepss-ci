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
export ARGV_LOG
for tool in xcrun; do
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

# ditto gets a dedicated fake rather than the generic template above: it is
# the one tool sign.sh calls in a mode (-c, archive creation) where the real
# tool enforces a contract on argument count ("ditto: Can't archive multiple
# sources"). The generic fake exits 0 whatever it is handed, which is
# exactly how the multi-source ditto bug shipped past every assertion in
# this suite: the fake accepted the invalid call sign.sh made. This one
# rejects more than one source the same way real ditto does.
cat > "$FAKEBIN/ditto" <<EOF
#!/usr/bin/env bash
echo "ditto \$*" >> "$ARGV_LOG"
create=false
args=()
for a in "\$@"; do
  case "\$a" in
    -c) create=true ;;
    -k|-V|--keepParent|--norsrc|--rsrc|--sequesterRsrc) : ;;
    -*) : ;;
    *) args+=("\$a") ;;
  esac
done
if \$create && [ "\${#args[@]}" -gt 2 ]; then
  echo "ditto: Can't archive multiple sources" >&2
  echo "Usage: ditto [ <options> ] src [ ... src ] dst" >&2
  exit 1
fi
[ -n "\${FAKE_DITTO_OUT:-}" ] && printf '%s\n' "\$FAKE_DITTO_OUT"
exit "\${FAKE_DITTO_EXIT:-0}"
EOF
chmod +x "$FAKEBIN/ditto"

# security gets a dedicated fake because the generic "log argv, exit 0"
# template made `keychain-close` untestable: it exited 0 whether or not there
# was a keychain, so `security delete-keychain || true` looked safe without
# anything proving it. That `|| true` is what lets a caller close a keychain
# under `if: always()` after a failure that happened before one existed, so
# it needs a fake that can actually reject the call. This one tracks the
# keychain file: create-keychain creates it, delete-keychain removes it and
# fails the way the real tool does when it is not there.
cat > "$FAKEBIN/security" <<'EOF'
#!/usr/bin/env bash
echo "security $*" >> "$ARGV_LOG"
sub="${1:-}"
kc=""
for a in "$@"; do case "$a" in *.keychain-db) kc="$a" ;; esac; done
case "$sub" in
  create-keychain) [ -n "$kc" ] && : > "$kc" ;;
  delete-keychain)
    if [ -n "$kc" ] && [ ! -e "$kc" ]; then
      echo "security: SecKeychainDelete: The specified keychain could not be found." >&2
      exit 1
    fi
    [ -n "$kc" ] && rm -f "$kc"
    ;;
esac
[ -n "${FAKE_SECURITY_OUT:-}" ] && printf '%s\n' "$FAKE_SECURITY_OUT"
exit "${FAKE_SECURITY_EXIT:-0}"
EOF
chmod +x "$FAKEBIN/security"

# codesign gets a dedicated fake rather than the generic "log argv, exit 0"
# template, so that a test can fail one named file and not the others:
# FAKE_CODESIGN_EXIT fails every call, FAKE_CODESIGN_FAIL_TARGET fails only
# the file whose path ends with the value given. A single global knob cannot
# express "this binary verifies and the next one does not", and a suite that
# cannot express that cannot tell "every file was assessed" from "the first
# file was assessed", which is the bug round 5 fixed.
cat > "$FAKEBIN/codesign" <<'EOF'
#!/usr/bin/env bash
echo "codesign $*" >> "$ARGV_LOG"
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --entitlements|--sign|--identifier|--prefix|--requirements) shift ;;
    -*) : ;;
    *) target="$1" ;;
  esac
  shift
done
rc="${FAKE_CODESIGN_EXIT:-0}"
if [ -n "${FAKE_CODESIGN_FAIL_TARGET:-}" ]; then
  case "$target" in
    *"$FAKE_CODESIGN_FAIL_TARGET") rc=1 ;;
    *) rc=0 ;;
  esac
fi
if [ "$rc" != 0 ]; then
  echo "$target: code object is not signed at all" >&2
  exit "$rc"
fi
[ -n "${FAKE_CODESIGN_OUT:-}" ] && printf '%s\n' "$FAKE_CODESIGN_OUT"
exit 0
EOF
chmod +x "$FAKEBIN/codesign"

# spctl gets a dedicated fake for the same reason ditto did: the generic one
# exited 0 whatever it was handed, so `spctl --assess --type execute` on a
# bare command-line executable passed every assertion in this suite while
# failing on the runner. Real spctl assesses application bundles and declines
# anything else with the message below and exit 3. Note that it says the
# code is valid, because it is; spctl is refusing the question, not the
# binary.
cat > "$FAKEBIN/spctl" <<'EOF'
#!/usr/bin/env bash
echo "spctl $*" >> "$ARGV_LOG"
type=""; target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --type) type="${2:-}"; shift ;;
    --type=*) type="${1#--type=}" ;;
    -*) : ;;
    *) target="$1" ;;
  esac
  shift
done
[ -n "${FAKE_SPCTL_OUT:-}" ] && printf '%s\n' "$FAKE_SPCTL_OUT"
[ -n "${FAKE_SPCTL_EXIT:-}" ] && exit "$FAKE_SPCTL_EXIT"
accept() { echo "$target: accepted"; echo "source=Notarized Developer ID"; exit 0; }
case "$type" in
  execute)
    case "$target" in
      *.app|*.app/) accept ;;
      *) echo "$target: rejected (the code is valid but does not seem to be an app)" >&2
         exit 3 ;;
    esac ;;
  install)
    case "$target" in
      *.dmg|*.pkg) accept ;;
      *) echo "$target: rejected" >&2; exit 3 ;;
    esac ;;
  *) echo "$target: rejected" >&2; exit 3 ;;
esac
EOF
chmod +x "$FAKEBIN/spctl"

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

# The keychain's lifetime, which is the whole of the keep-keychain story.
# `Close the keychain` is an ordinary step of a composite action, not a post
# step (composite actions have no `runs.post`), so it runs when the call
# returns rather than when the job ends. A caller that needs the keychain
# afterwards, as stepss-java-ui does when it passes keychain-path to
# jpackage's --mac-signing-keychain, sets keep-keychain: true and closes it
# itself later with mode: close.
KC="$TMPD/stepss-signing.keychain-db"
rm -f "$KC"
out="$(run_sign keychain-open)"; rc=$?
[ -e "$KC" ] && ok "keychain-open creates the keychain file" \
             || fail "keychain-open left no keychain at $KC: $out"
out="$(run_sign keychain-close)"; rc=$?
[ ! -e "$KC" ] && ok "keychain-close removes the keychain file" \
               || fail "keychain-close left $KC behind: $out"

# mode: close runs under `if: always()`, so it is called after failures that
# happened before a keychain existed. sign.sh keychain-close swallows the
# delete failure with `|| true` and that is confirmed here rather than
# assumed: the assertion below is only worth anything because the fake
# security really does reject the call, which this checks first.
rm -f "$KC"
if security delete-keychain "$KC" >/dev/null 2>&1; then
  fail "the fake security accepted deleting a keychain that does not exist"
else
  ok "the fake security rejects deleting a keychain that does not exist"
fi
out="$(run_sign keychain-close)"; rc=$?
[ "$rc" = 0 ] && ok "keychain-close succeeds when there is no keychain" \
               || fail "keychain-close exited $rc with no keychain present: $out"
case "$out" in *"Keychain removed"*) ok "keychain-close reports removal even when there was nothing to remove" ;;
               *) fail "keychain-close said nothing: $out" ;; esac

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
# --wait alone is unbounded: a stall at Apple's end would run to GitHub's
# 360-minute job ceiling before anyone found out.
grep -q -- '--timeout' "$ARGV_LOG" \
  && ok "notarize bounds the wait with a timeout" || fail "no --timeout: $(cat "$ARGV_LOG")"
grep -q '69a6de82-68c9-47e3-e053-5b8c7c11a4d1' "$ARGV_LOG" \
  && ok "notarize passes the issuer id" || fail "no issuer id: $(cat "$ARGV_LOG")"
grep -q 'ditto ' "$ARGV_LOG" \
  && ok "notarize builds a zip with ditto" || fail "no ditto call"

# ---- notarize: archiving one file and more than one -----------------------
# ditto's archive mode (-c) accepts exactly one source. Before this fix,
# `ditto -c -k --keepParent "$@" "$payload"` handed it every input file plus
# the destination, which is invalid the moment there is more than one file.
# This is exactly the failure stepss-helios hit on its first real run
# (`ditto: Can't archive multiple sources`), and the old fake ditto accepted
# the invalid call anyway (see the fix-round report for the red-then-green
# transcript proving that against the pre-fix code).
rm -rf "$TMPD/notary"
out="$(FAKE_XCRUN_OUT="$accepted" run_sign notarize "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "notarize archives a single file" || fail "single-file notarize: $out"
# Anchored so this matches only "ditto -c -k <one arg> <one arg>" exactly:
# an extra --keepParent token, or a third path before the destination, fails
# the match just as it would fail real ditto's argument count.
grep -qE '^ditto -c -k [^ ]+ [^ ]+$' "$ARGV_LOG" \
  && ok "ditto is given exactly one source (the staging directory)" \
  || fail "ditto call: $(cat "$ARGV_LOG")"
[ -e "$TMPD/notary/payload/ramses" ] \
  && ok "the single file is staged for archiving" \
  || fail "not staged: $(ls "$TMPD/notary/payload" 2>&1)"

rm -rf "$TMPD/notary"
out="$(FAKE_XCRUN_OUT="$accepted" run_sign notarize "$TMPD/ramses" "$TMPD/ramses.so")"; rc=$?
[ "$rc" = 0 ] && ok "notarize archives two files" || fail "two-file notarize: $out"
grep -qE '^ditto -c -k [^ ]+ [^ ]+$' "$ARGV_LOG" \
  && ok "ditto is still given exactly one source with two inputs" \
  || fail "ditto call: $(cat "$ARGV_LOG")"
[ -e "$TMPD/notary/payload/ramses" ] && [ -e "$TMPD/notary/payload/ramses.so" ] \
  && ok "both input files are present in the staged archive directory" \
  || fail "staged files: $(ls "$TMPD/notary/payload" 2>&1)"
staged_count="$(find "$TMPD/notary/payload" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
[ "$staged_count" = 2 ] \
  && ok "the staged layout is flat, not nested under a runner-specific path" \
  || fail "staged directory has $staged_count top-level entries"

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

# assess: a bare executable. `spctl --assess --type execute` used to be asked
# here and answered "rejected (the code is valid but does not seem to be an
# app)" with exit 3, because a plain Mach-O tool is not an application bundle
# and spctl assesses application bundles. helios, ramses, CODEGEN and dyngraph
# all ship bare executables, so that was four of the five callers failing on a
# correctly signed, Apple-notarized binary. The fake spctl above now answers
# exactly that way, so a regression to spctl for this artefact kind fails here
# rather than on the runner.
#
# What replaced it was a signature check plus a codesign "=notarized"
# requirement test, and the requirement test is gone again: on a real runner
# it reported no ticket for a binary notarytool had returned Accepted for
# twenty seconds earlier. There are no assertions here about notarization,
# deliberately. cmd_notarize is where that is established, and its assertions
# are in the notarize block above.
out="$(run_sign assess "$TMPD/ramses")"; rc=$?
[ "$rc" = 0 ] && ok "assess passes a validly signed bare executable" \
               || fail "assess on a bare executable exited $rc: $out"
grep -q '^spctl ' "$ARGV_LOG" \
  && fail "assess still asks spctl about a bare executable: $(cat "$ARGV_LOG")" \
  || ok "assess does not ask spctl about a bare executable"
grep -q -- 'codesign --verify --strict' "$ARGV_LOG" \
  && ok "assess checks the signature itself" || fail "no signature check: $(cat "$ARGV_LOG")"
case "$out" in *"signature valid"*) ok "assess reports the signature as valid" ;;
               *) fail "assess did not report the signature: $out" ;; esac

out="$(FAKE_CODESIGN_EXIT=1 run_sign assess "$TMPD/ramses")"; rc=$?
[ "$rc" = 1 ] && ok "assess fails when the signature is not valid" \
               || fail "assess exited $rc on an invalid signature"
case "$out" in *"signature on"*"is not valid"*) ok "an invalid signature is named as such" ;;
               *) fail "the signature failure was not named: $out" ;; esac

# assess: a .dmg keeps its existing treatment. A stapled ticket travels inside
# it, so spctl can answer offline and answers the whole Gatekeeper question.
out="$(run_sign assess "$TMPD/STEPSS.dmg")"; rc=$?
[ "$rc" = 0 ] && ok "assess passes a stapled .dmg" || fail "assess on a .dmg: $out"
grep -q -- 'spctl --assess --type install' "$ARGV_LOG" \
  && ok "a .dmg is assessed by spctl as an install" || fail "no install assessment: $(cat "$ARGV_LOG")"
grep -q '^codesign ' "$ARGV_LOG" \
  && fail "a .dmg was sent down the bare-executable path: $(cat "$ARGV_LOG")" \
  || ok "a .dmg is not sent down the bare-executable path"

# assess: every file, not just the first. The action used to close with
# `assess "${files[0]}"`, so helios's libhelios_api.dylib and ramses's
# ramses.so were signed and notarized but never checked. A problem confined
# to the second artefact passed the step.
: > "$ARGV_LOG"
out="$(run_sign assess "$TMPD/ramses" "$TMPD/ramses.so")"; rc=$?
[ "$rc" = 0 ] && ok "assess passes two validly signed executables" \
               || fail "assess over two files exited $rc: $out"
[ "$(printf '%s\n' "$out" | grep -c '^Assessing ')" = 2 ] \
  && ok "assess names each file it checks" \
  || fail "assess named $(printf '%s\n' "$out" | grep -c '^Assessing ') files, expected 2: $out"
grep -qE '^codesign --verify --strict --verbose=2 .*/ramses\.so$' "$ARGV_LOG" \
  && ok "the second file gets its own signature check" \
  || fail "no signature check for the second file: $(cat "$ARGV_LOG")"

# The second file fails and the first does not. This is the case the old
# single-file assess could not see at all.
out="$(FAKE_CODESIGN_FAIL_TARGET=ramses.so run_sign assess "$TMPD/ramses" "$TMPD/ramses.so")"; rc=$?
[ "$rc" = 1 ] && ok "a failure on the second file fails the step" \
               || fail "assess exited $rc when the second file failed: $out"
case "$out" in *"signature on "*"/ramses.so is not valid"*)
                 ok "the failing file is named, not just any file" ;;
               *) fail "the failing file was not named: $out" ;; esac
[ "$(printf '%s\n' "$out" | grep -c '^Assessing ')" = 2 ] \
  && ok "the run reached the second file before failing" \
  || fail "assess did not reach the second file: $out"

# The same zero-argument contract sign and notarize already keep, so that
# action.yml's count guard has something to hand an empty list to.
out="$(run_sign assess)"; rc=$?
[ "$rc" = 2 ] && ok "assess with zero files exits 2" || fail "assess with zero files exited $rc: $out"
case "$out" in *"assess needs at least one file"*) ok "assess's own message reports the empty input" ;;
               *) fail "assess did not name the empty input: $out" ;; esac
case "$out" in *"unbound variable"*|*"bad substitution"*|*"parameter null"*)
                 fail "a shell error leaked instead of sign.sh's message: $out" ;;
               *) ok "no shell-level error text leaks from a zero-argument assess" ;; esac

# An .app is an application bundle, which is the one thing
# `spctl --assess --type execute` is for.
out="$(run_sign assess "$TMPD/STEPSS.app")"; rc=$?
[ "$rc" = 0 ] && ok "assess passes an .app" || fail "assess on an .app: $out"
grep -q -- 'spctl --assess --type execute' "$ARGV_LOG" \
  && ok "an .app is assessed by spctl as executable code" \
  || fail "no execute assessment for an .app: $(cat "$ARGV_LOG")"

# ---- action.yml ----------------------------------------------------------
# The composite action's own behaviour cannot be executed here: nothing in
# this suite invokes GitHub Actions, and its `if:` conditions are evaluated
# by the runner, not by bash. What follows checks the text of action.yml
# instead. That proves the gates are written, not that GitHub reads them the
# way intended, and it is here because the alternative is no check at all on
# the file where every defect so far has been found by a real run.
ACTION="$ROOT/action.yml"

grep -qE '^  keep-keychain:' "$ACTION" \
  && ok "the action declares a keep-keychain input" || fail "no keep-keychain input"
grep -qE '^    default: "false"' "$ACTION" \
  && ok "keep-keychain defaults to false, so the four engine callers are unaffected" \
  || fail "keep-keychain does not default to false"

close_if="$(grep -E "^[[:space:]]*if: always\(\)" "$ACTION" || true)"
case "$close_if" in *"inputs.keep-keychain != 'true'"*)
       ok "the closing step is skipped when the caller keeps the keychain" ;;
     *) fail "the closing step is not gated on keep-keychain: $close_if" ;; esac
case "$close_if" in *"inputs.mode == 'close'"*)
       ok "mode: close closes the keychain whatever keep-keychain says" ;;
     *) fail "mode: close does not force the close: $close_if" ;; esac

# Preflight, Open, Sign and Notarize must all stand down in close mode, or
# `mode: close` would demand credentials and try to notarize nothing.
[ "$(grep -c "inputs.mode != 'close'" "$ACTION")" = 4 ] \
  && ok "every other step is gated off close mode" \
  || fail "$(grep -c "inputs.mode != 'close'" "$ACTION") steps gated off close mode, expected 4"

# Composite actions have no runs.post. The closing step is an ordinary step
# and must stay one; a post: key here would be silently ignored.
grep -qE '^[[:space:]]*post:' "$ACTION" \
  && fail "action.yml declares a post step, which a composite action cannot have" \
  || ok "the closing step is not declared as a post step"

# The rule from the note at the top of stepss-java-ui's release.yml: no
# ${{ }} expression is interpolated into the text of a run: script, because
# that substitution happens before bash sees the line. Every remaining
# occurrence must be an env: assignment, an if:, a value: or a default:.
interp="$(grep -n '\${{' "$ACTION" \
          | grep -vE '^[0-9]+:[[:space:]]*#' \
          | grep -vE '^[0-9]+:[[:space:]]*(if|value|default):' \
          | grep -vE '^[0-9]+:[[:space:]]+[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*\$\{\{' || true)"
[ -z "$interp" ] \
  && ok "no expression is interpolated into a run: body" \
  || fail "an expression is interpolated into a run: body: $interp"

echo
[ "$FAILURES" = 0 ] && { echo "all tests passed"; exit 0; }
echo "$FAILURES test(s) failed"; exit 1
