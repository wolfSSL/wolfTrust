# C Coding Standard

wolfTrust adheres to the wolfSSL coding standards and targets ISO C99, with
project-specific no-`goto` and no-standalone-scope rules. The aim is to keep
the code straightforward to assess in a future MISRA C:2023 or DO-178 process.
These checks improve readiness; they are not a claim of MISRA compliance or
certification evidence.

## Required rules

- Compile project C as ISO C99. Variable-length arrays are prohibited.
- Do not use `goto`. Use structured control flow and status-gated fallthrough
  cleanup.
- Do not use standalone brace blocks solely to shorten a variable's lifetime.
- Use C comments (`/* ... */`), spaces in core source, and no trailing
  whitespace. Preserve existing section-banner style when editing nearby code.
- Explicitly erase sensitive buffers that must be cleared. Existing secure-
  erasure routines use volatile byte writes; record that approach as a
  deviation in any formal MISRA compliance plan.
- Use `WT_STATIC_ASSERT()` for file-scope compile-time checks; `_Static_assert`
  is C11 and is not permitted.

Runnable tests follow the no-`goto` and no-standalone-scope rules. Vendored
submodules keep their upstream coding standards. The pinned wolfHSM callback
ABI requires anonymous aggregate support in dependency headers; formal
qualification must record that boundary as a dependency deviation. The strict
C99 host gate does not compile ARM-only source; target inline assembly and
compiler intrinsics require separate platform qualification.

## Automated checks

- `sh scripts/check_house_style.sh`
- `python3 scripts/check-empty-brace-scopes.py`
- `make c99-check CC=clang` or `make c99-check CC=gcc`

The C99 check first compiles a valid C99 probe and verifies that the compiler
rejects C11-only syntax and variable-length arrays. It then builds and runs
the existing host suites with strict C99 flags.

The matching GitHub Actions workflows run these gates on every pull request.
