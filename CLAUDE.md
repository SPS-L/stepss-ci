# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

One composite action, `sign-macos`, called by the five STEPSS repositories that build a macOS artefact: ramses, Codegen, helios, dyngraph and java-ui. All of its logic is in `sign-macos/sign.sh`, a command dispatcher, and `sign-macos/action.yml` orders those commands and passes credentials through. `sign-macos/test_sign.sh` exercises the script on Linux against fakes for every Apple tool, and `.github/workflows/test.yml` runs that on every push.

The repository is public, and that is load-bearing rather than incidental. GitHub resolves every action a job references before running any step, so while this was private, `stepss-java-ui` failed all three of its bundle legs at `Set up job`, including Linux and Windows, which would have skipped the signing step entirely. Making it public was the fix. Do not make it private again without first arranging for every caller to check it out with a token and reference it by local path.

## The one thing to know before changing anything

**A green test run is evidence about the fakes, not about Apple's tools.** Every fake in `test_sign.sh` has, at some point, accepted an invocation the real tool rejects, and each time the suite passed while the code could not work. This has happened five times:

- `ditto` was called with more than one source. The real tool takes exactly one and aborts with "Can't archive multiple sources", which only helios triggered, because it is the only caller passing two files.
- `security` exited zero for every call, so six assertions about the keychain were untestable rather than passing.
- `codesign` and `spctl` accepted argument shapes the real tools do not.
- `xcrun` accepted `notarytool log` without `--key`, so the one diagnostic that matters on a rejection could never run.

The rule that follows: when you add or change a call to an Apple tool, make the fake enforce that tool's real contract first, and prove the new assertion goes red against the current head before you fix the code. A fake that always succeeds is worse than no test, because it produces confidence rather than silence.

The corollary is that `action.yml` is the least verified file here. Nothing on Ubuntu can execute a composite action's runtime behaviour, so the assertions covering it read it as text and prove only that a gate is written, not that GitHub evaluates it as intended. Most defects that reached a real runner came from that file or from a fake.

## Facts learned from real runners

These cost failed releases to discover. None is visible from the test suite.

**The macOS runner's `bash` is 3.2.57.** `shell: bash` resolves to Apple's stock build, which predates `mapfile` and `readarray` by two major versions, and treats `"${arr[@]}"` on a zero-element array under `set -u` as an unbound variable, which bash 4.4 changed. Both traps are live in this repository: build arrays with a `while IFS= read -r` loop, and guard on `${#arr[@]}` before expanding. CI here runs bash 5 on Ubuntu and cannot see either.

**`notarytool --output-format json` pretty-prints.** It is a Swift program and emits `"status" : "Accepted"` with spaces around the colon. A `sed` expression matching `"status":"` returns nothing, and an empty status compares unequal to `Accepted`, so every submission reads as failed. The parse goes through `python3`, which is present on every macOS runner, and the fixtures carry both the spaced and compact shapes.

**`codesign --test-requirement="=notarized"` does not work for unstapled code.** On a real runner, `notarytool` returned `Accepted` and the requirement test reported no ticket for the same unmodified binary twenty seconds later. A ticket attaches only to a `.dmg`, `.pkg` or `.app`, and a bare Mach-O file cannot carry one. The evidence of notarization is `cmd_notarize`'s own gated verdict. Do not reintroduce the requirement test, and do not add a retry loop around it in the belief that propagation is slow.

**`spctl` answers a different question for each artefact kind, and three of this repository's assessments were wrong before they were right.** `--type execute` assesses application bundles and rejects a command-line tool with "the code is valid but does not seem to be an app", which is `spctl` confirming the signature while declining to judge it. `--type install` assesses installer packages and rejects a disk image with "no usable signature", because `jpackage` signs the app inside the image and leaves the container unsigned; `--type open` fails identically for the same reason, so a `.dmg` is checked by validating its stapled ticket instead. Only `.pkg` and `.app` get an `spctl` call today.

**A composite action cannot declare post steps.** `runs.post` is available to JavaScript and Docker actions alone, and a `post:` key here is ignored silently. Every step of this action runs inline inside the caller's single step, which is why `Close the keychain` would otherwise destroy the keychain before the caller could use it, and why `keep-keychain` and `mode: close` exist.

**Apple's notary service opens jar files.** It found FlatLaf's unsigned native dylibs inside `stepss.jar` and rejected the whole disk image. It does not open `.tar.gz`, which is why the engines travelling that way inside the same jar were never flagged. The fix lives in `stepss-java-ui`, which signs Mach-O entries inside its jars before `jpackage` packages them, but the reason belongs here too, because anyone extending this action to a new artefact kind should expect the notary to look deeper than they do.

## Conventions

`sign.sh` is a dispatcher: one `case` arm per command, new arms above the catch-all, and `set -euo pipefail` throughout. Commands are small enough to test individually, and the credential-shaped ones refuse rather than skip when a secret is missing, because a skipped signing step publishes unsigned binaries under a green run.

Never interpolate a `${{ }}` expression into a `run:` body. Pass it through `env:` and read it as a shell variable. This is not style: `${{ inputs.paths }}` was interpolated directly in five places, in the step that holds the signing identity and the notary key, and a path shaped like `a";id;"` would have executed. An assertion now enforces it, by shape rather than by parsing YAML, so a contrived line shaped like an env assignment could still slip past.

The private key written for `notarytool` is removed by an `EXIT` trap over a file-scope variable, not by an `rm` on the happy path. It must survive until the rejection log has been fetched and must not survive the process, and the trap fires after a function's locals are gone, which is why the variable is not `local`.

## The `v1` tag

Callers reference `SPS-L/stepss-ci/sign-macos@v1`, a moving major tag, matching the platform-wide rule of pinning majors so that fixes arrive without a commit in every caller. Moving it is routine and is done by force-push after CI passes on the new head. Confirm afterwards with `git ls-remote --tags origin v1` rather than trusting the local tag, because a local `git tag -f` that was never pushed looks identical to a successful move.

Anything that changes what a caller must pass is a breaking change and needs a `v2` rather than a move. Nothing has needed one yet; `keep-keychain` and `mode: close` were added with defaults that leave existing callers untouched.

## Deliberately not done

The `.dmg` container is not signed. `jpackage` signs the app and its bundled runtime and leaves the image unsigned, and Gatekeeper accepts a notarized, stapled image regardless, so users are unaffected. The cost is that the image's own Gatekeeper behaviour cannot be verified by this pipeline. Signing it belongs in `stepss-java-ui`'s build, before notarization; if that is done, the `spctl` call for a `.dmg` can be restored, and in that order.
