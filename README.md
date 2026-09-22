# stepss-ci

Shared GitHub Actions for the STEPSS platform. One action lives here today, `sign-macos`, which signs macOS binaries with the Cyprus University of Technology Developer ID certificate and submits them to Apple for notarization.

The repository is public. It contains a shell script, an entitlements property list and a composite action definition, and no credentials of any kind: the certificate and the notary key live in the SPS-L organization's secret store and are handed to the action at run time. It is public because GitHub resolves every action referenced by a job before running any step, and a private action that a caller cannot resolve fails every platform of that job, including the ones that would have skipped the step.

## What the action does

macOS refuses to run downloaded software that carries no recognised signature. Two separate things are needed to satisfy it. The binary must be **signed** with a Developer ID certificate, which identifies who built it, and it must be **notarized**, which means Apple has scanned it and recorded a ticket saying so. The action does both, in that order, and verifies the result.

Signing happens on the runner. The action creates a throwaway keychain, imports the identity into it, resolves that identity by its SHA-1 hash rather than by name, and runs `codesign` with a secure timestamp, the hardened runtime and an entitlements file. Notarization happens at Apple. The action packages what it signed, submits it with `notarytool`, waits for a verdict, and fails the step on anything other than `Accepted`.

## Calling it

Add the action to the job that builds the macOS artefacts, immediately after the build and before any step that runs the binary. Put it before the tests rather than after, so that the existing test gates exercise the signed artefact. A signature that prevents a binary from starting then fails the build where the build is already looking, instead of on a user's machine.

The four engine repositories need one call:

```yaml
- name: Sign and notarize
  uses: SPS-L/stepss-ci/sign-macos@v1
  with:
    paths: |
      build/Release_gnu_m/ramses
      build/Release_gnu_m/ramses.so
  env:
    APPLE_SIGNING_P12: ${{ secrets.APPLE_SIGNING_P12 }}
    APPLE_SIGNING_P12_PASSWORD: ${{ secrets.APPLE_SIGNING_P12_PASSWORD }}
    APPLE_NOTARY_KEY_P8: ${{ secrets.APPLE_NOTARY_KEY_P8 }}
    APPLE_NOTARY_KEY_ID: ${{ vars.APPLE_NOTARY_KEY_ID }}
    APPLE_NOTARY_ISSUER_ID: ${{ vars.APPLE_NOTARY_ISSUER_ID }}
```

Note that the two notary identifiers come from `vars`, not `secrets`. A `vars` value read through the `secrets` context yields an empty string rather than an error, and the failure then appears on the runner as a missing credential.

The desktop bundle in `stepss-java-ui` is the harder case, because `jpackage` does the signing itself and needs a keychain that outlives the call. It opens the keychain with one invocation, lets `jpackage` use it, notarizes the finished disk image with a second, and closes the keychain with a third:

```yaml
- name: Open the signing keychain
  id: signing
  uses: SPS-L/stepss-ci/sign-macos@v1
  with:
    mode: sign
    paths: ""
    keep-keychain: true
  env:
    APPLE_SIGNING_P12: ${{ secrets.APPLE_SIGNING_P12 }}
    APPLE_SIGNING_P12_PASSWORD: ${{ secrets.APPLE_SIGNING_P12_PASSWORD }}

# ... jpackage runs here, pointed at steps.signing.outputs.keychain-path ...

- name: Notarize and staple
  uses: SPS-L/stepss-ci/sign-macos@v1
  with:
    mode: notarize
    bundle: bundle/STEPSS-3.82.dmg
  env:
    # all five, as above

- name: Close the signing keychain
  if: always()
  uses: SPS-L/stepss-ci/sign-macos@v1
  with:
    mode: close
```

The closing call is not optional when `keep-keychain` is used. A composite action cannot declare a post step, so nothing runs it on the caller's behalf.

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `sign-and-notarize` | Also `sign`, `notarize` or `close`. |
| `paths` | empty | Newline-separated Mach-O files to sign. Empty leaves signing to the caller. |
| `bundle` | empty | A `.dmg`, `.pkg` or `.app` to staple after notarization. |
| `entitlements` | empty | Override the shipped entitlements file. |
| `keep-keychain` | `"false"` | Leave the keychain open for later steps. The caller must then close it. |

| Output | Meaning |
|---|---|
| `keychain-path` | The temporary keychain, for a tool that must be told where to look. |
| `identity` | SHA-1 of the resolved signing identity. |

## Credentials

Three organization secrets and two organization variables, scoped to the five repositories that sign something: `stepss-ramses`, `stepss-Codegen`, `stepss-helios`, `stepss-dyngraph` and `stepss-java-ui`. `stepss-python-ui` and `stepss-cg-studio` are deliberately not among them; their wheels bundle binaries that were already signed upstream, so neither needs a credential of its own.

| Name | Kind | Contents |
|---|---|---|
| `APPLE_SIGNING_P12` | secret | base64 of a PKCS#12 holding the certificate and its private key |
| `APPLE_SIGNING_P12_PASSWORD` | secret | the export password for that bundle |
| `APPLE_NOTARY_KEY_P8` | secret | base64 of the App Store Connect API key |
| `APPLE_NOTARY_KEY_ID` | variable | the key's identifier |
| `APPLE_NOTARY_ISSUER_ID` | variable | the issuing account's identifier |

The certificate is `Developer ID Application: Cyprus University of Technology (SWZD63F3C7)` and expires on **2031-09-12**. The action checks that date on every run and warns within a year of it. The Apple Developer Program membership renews annually on **2026-11-20**, and a lapse revokes the certificate regardless of its own expiry date; nothing guards that one.

## What the action can and cannot promise

Signing and notarization both happen for every artefact it is given. Stapling does not, and cannot. A notarization ticket attaches only to a `.dmg`, a `.pkg` or an `.app`, so the desktop disk image carries its ticket locally while the command-line engines, which ship loose inside `.tar.gz` archives, do not. Those are notarized but unstapled: Gatekeeper confirms them against Apple's servers on first run, which needs network access once, on a machine that has never seen the binary before.

There is also no local check that proves an unstapled binary was notarized. `codesign --test-requirement="=notarized"` looks like one and is not: on a real runner it reported no ticket for a binary Apple had accepted twenty seconds earlier. The evidence of notarization is therefore `notarytool`'s own verdict, which the action gates on during the build, and the closing check verifies the signature rather than re-asking a question that cannot be answered.

## Tests

```sh
bash sign-macos/test_sign.sh
```

110 assertions, on Linux, with no credentials and no Mac. Every Apple tool is replaced by a fake on `PATH` that records how it was called and can be made to fail. The repository's own CI runs this on every push and pull request.

Read `CLAUDE.md` before changing anything here. It records what a passing test run does and does not prove, which is the single most important thing to know about this repository.
