# Crypto operation profiles

`WT_ENGINE=native|hsm` selects the crypto engine independently of the application
API. `WT_CRYPTO_PROFILE=default|full` selects the exported operations. Native is
the default engine. Neither TPM nor PKCS#11 requires wolfHSM.

The default profile covers RNG, SHA-256 and P-256 key generation, signing and
verification. It also includes the key, session and token management needed to
use those operations. PKCS#11 retains PIN setup, login, attempt limits and
recovery. `config/crypto-profiles.json` is the explicit default operation list.
The full profile retains the broader operations supported by the pinned
libraries and this platform's algorithm and memory configuration.

## Select operations

Use the same settings for the application and its provider:

```sh
make secure-image CONFIG_PKCS11=y WT_ENGINE=native WT_CRYPTO_PROFILE=default
make secure-image CONFIG_TPM=y WT_ENGINE=hsm WT_CRYPTO_PROFILE=full

WT_CRYPTO_ENABLE='pkcs11:C_GetObjectSize tpm:PCR_Read' \
WT_CRYPTO_DISABLE='psa:psa_sign_hash' \
  make secure-image CONFIG_PKCS11=y
```

Enable and disable lists contain whitespace-separated `api:operation` names.
Overrides apply after the selected profile; disable wins if both lists name the
same operation. They select entry points, not automatic dependencies between
application calls. An application that removes initialization or a required key
lifecycle call must use an appropriate lifecycle of its own.

A JSON file can replace individual lists. Unspecified lists retain the selected
profile's defaults:

```json
{
  "psa": ["psa_crypto_init", "psa_generate_random", "psa_hash_compute"],
  "mechanisms": ["CKM_SHA256"]
}
```

Pass its absolute path with `WT_CRYPTO_CONFIG`. The accepted fields are `psa`,
`pkcs11`, `tpm`, and `mechanisms`, each a JSON array of names. An empty mechanism
list exports no crypto mechanisms. Unknown fields and operation names fail the
build. The TPM provider requires at least one selected command; disable the
interface with `CONFIG_TPM=n` when no TPM commands are needed.

Inspect known dependency entry points or generate a selection directly:

```sh
python3 tools/crypto_profile.py --list
python3 tools/crypto_profile.py --output build/crypto-profile \
  --profile default --enable pkcs11:C_GetObjectSize --disable psa:psa_sign_hash
```

The command catalog includes dependency commands whose algorithm or feature
family can be disabled by platform settings. Selection does not override those
settings or provide missing NV storage. A default-derived TPM selection checks
that every requested command survived those guards. The full profile retains
the dependency guards; `TPM_CAP_COMMANDS` reports the commands actually built.

## What is removed

PSA public entry points forward to private implementations only when selected.
A disabled public entry point returns `PSA_ERROR_NOT_SUPPORTED`. Internal calls
retain private names so, for example, disabling multipart hashing does not break
a selected one-shot hash operation. Unreferenced private functions are removed
by section garbage collection and LTO.

PKCS#11 keeps the standard function-list ABI. Disabled entries are typed stubs
returning `CKR_FUNCTION_NOT_SUPPORTED` without a transport call. The provider
also rejects a forged disabled wire operation before decoding its arguments or
calling the backend. Removed mechanisms return `CKR_MECHANISM_INVALID`.
Mechanism enumeration and action flags reflect the allowed operations.

TPM generation filters the pinned fwTPM dispatch table in the build directory.
It preserves the original handlers and authorization metadata. Disabled commands
return `TPM_RC_COMMAND_CODE`, disappear from `TPM_CAP_COMMANDS`, and no longer
retain their handlers through the table. Dependency source and pins are not
modified.

Removing an operation does not remove primitives needed internally. PKCS#11
PIN protection still needs PBKDF2/HMAC, and fwTPM can need hashing and symmetric
crypto for object protection even when related public mechanisms are absent.
TPM and PKCS#11 images link no wolfPSA Crypto implementation. Their `psa_call`
functions are the FF-M IPC boundary.

## Reference builds and verification

FreeRTOS guest builds use `WT_LTO=1` by default; `WT_LTO=0` disables it.
RTOS, startup, libc and cross-world transport objects keep their compilation
boundaries. The default FreeRTOS TPM application uses the TPM for crypto and
links no application-side wolfCrypt/HSM engine. Set `WT_TPM_CLIENT_WOLFCRYPT=1`
when a custom application needs local cryptography for HMAC/parameter-encrypted
sessions or host-side key preparation. Full reference builds retain that support.
The TPM provider still selects native/HSM normally.
TPM/PKCS#11 HSM providers omit unused software ECC fallback by default.
`WT_PROVIDER_ECC_FALLBACK=1` restores it; native builds always retain software
ECC, and the HSM server keeps its own implementation. PSA retains the software
ECC path required for deterministic ECDSA; that dependency is not removed.

The `profile` PKCS#11 reference suite exercises the default operations, capability
filtering, disabled entry points, forged wire requests and PIN recovery. The
`all` suite retains the 40-case broader regression. CI tests both profiles across
both engines and both Cortex-M OS clients, plus the Cortex-A interfaces and
partition isolation. The PSA default tests run RNG, SHA-256 and P-256 from
FreeRTOS and check disabled API behavior on both OS clients.

Run `make test` for the host regressions. Use `WT_CRYPTO_PROFILE=default` or
`full` with the existing target scenario runners. The runners default to `full`
to preserve existing conformance and broad test workloads; product builds default
to `default`. Applications must match the selected operation list.

[Footprint measurements](Interface-Footprint.md) include a reproducible script
and distinguish the common crypto workload from full protocol coverage.

TPM selections containing `ZGen_2Phase` retain software ECC point arithmetic
because its full-point operation is outside the HSM ECDH callback. Adding that
command restores the dependency automatically; it is absent from the small
default profile.
