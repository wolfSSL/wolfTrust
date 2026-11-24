# Arm PSA FF conformance adapter

This adapter compiles selected upstream Arm PSA Firmware Framework tests
without modifying their source. The exact repository revision is stored in
`tests/upstream/psa-arch-tests.rev`.

Run the current conformance gate from the repository root:

```sh
make test-conformance
```

The current host gate executes upstream tests `i001` through `i008`, `i010`,
`i011`, `i012`, `i024`, `i025`, `i026`, `i027`, `i063`, `i067`, `i071`, `i088`,
and `i090`. These cover framework and service versions, the connection
lifecycle (busy/reject, accept/close, allowed version policies and types,
status-code echo, caller identity, the connect limit, and block/poll refusal),
the connection drop and signal-mask refusal paths, the invec/outvec data
plane (`psa_read`/`psa_skip`/`psa_write`/`psa_set_rhandle`), invalid service
IDs, strict, relaxed, and unspecified version policies, Secure-only access
policy, a successful Secure connection lifecycle, closing and calling with an
invalid or null handle, calling with more than `PSA_MAX_IOVEC` vectors, calling
with a negative message type, memory manipulation, and RoT lifecycle state.
`i067` reports SKIP: it requires SP heap allocation support, which wolfTrust
does not advertise.

`i003` and `i027` need a real server, not the generic reply-success dispatch,
so `main.c` carries a per-test dispatch: a `g_active_test` selector routes
`test_dispatch()` to the matching per-test server. Every per-test server
behavior is derived independently from two published sources only: the
compiled client test sources (whose data values and assertions define the
observable contract) and the pinned FF-M specification. The upstream suite's
partition-side (`test_supp_*`) sources are not consulted; where a client only
requires a nonnegative reply (`i003` check 3), the server runs wolfTrust's own
`psa_read`/`psa_skip` exercise sequence over the client's documented input
bytes rather than any upstream sequence. `i027` replies `PROGRAMMER_ERROR`
to the call to drop the connection; that also required a wolfTrust fix so a
client may `psa_close` a dropped (`WT_SLOT_ERROR`) connection, not
only an idle one. The harness `val` vtable gained `ipc_connect`/`ipc_close`.

The unspecified-version-policy tests (`i010`, `i011`, `i026`) model an
`UNSPECIFIED` manifest service the way FF-M resolves its defaults: version 1 and
`STRICT` policy. `i026` and `i090` also required wolfTrust conformance fixes to
`psa_call`, both in the PROGRAMMER-ERROR family: `in_len + out_len >
PSA_MAX_IOVEC` and a negative message type now return
`PSA_ERROR_PROGRAMMER_ERROR` per FF-M, not `PSA_ERROR_INVALID_ARGUMENT`.

Every remaining `ff/ipc` test in the pinned suite needs target hardware, not
more host dispatch: real multi-partition memory isolation (`i048`-`i053`, which
need the SPM to reject a caller vector pointing into another partition's MMIO —
M33MU only) or a client that itself runs as a Secure Partition (`i058` doorbell,
compiled out under `-DNONSECURE_TEST_BUILD`). The server-side halves of
`i063` (signal-mask filtering) and `i002`'s block/poll checks are likewise
deferred to the M33MU slice. See task-list.md Phase 3 item 10.

This focused host gate is not the complete Arm architecture suite. The full
suite requires its Non-secure application and three Secure test partitions to
run through wolfTrust's production Armv8-M SPM and isolation path. Phase 3 is
not conformant until those binaries execute under M33MU and every applicable
test result is recorded.

wolfTrust's independent implementation tests live in `tests/host/spm_core`.
They cover properties outside the selected upstream cases, including forged
and stale handles, caller ownership, bounded pools, message scrubbing, vector
limits, and output-pointer revalidation.
