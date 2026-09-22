# stepss-ci

Shared GitHub Actions for the STEPSS platform.

## `sign-macos`

Signs Mach-O files with the Cyprus University of Technology Developer ID
certificate and submits them to Apple's notary service. Used by
stepss-ramses, stepss-Codegen, stepss-helios, stepss-dyngraph and
stepss-java-ui.

Credentials come from organization secrets and variables scoped to those
five repositories. See
`docs/superpowers/specs/2026-09-22-macos-code-signing-design.md` in the
stepss umbrella repository for the design and for why the
`disable-library-validation` entitlement is mandatory.

All logic lives in `sign-macos/sign.sh` and is unit-tested on Linux by
`sign-macos/test_sign.sh`, which needs neither credentials nor a Mac.
