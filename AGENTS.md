# wolfTrust for agents

wolfTrust is a TrustZone-M Secure Partition Manager (Arm FF-M) with a shared
core and per-SoC ports. The rules every change follows are in
[docs/Coding-Standard.md](docs/Coding-Standard.md); how the code is laid out
is in [docs/Project-Structure.md](docs/Project-Structure.md).

- Bringing up a new SoC: follow [tools/new-port/PLAYBOOK.md](tools/new-port/PLAYBOOK.md)
  (inputs, forbidden paths, the scaffold, gates G0 to G7, what to stop and
  ask about). The human guide is [docs/Porting.md](docs/Porting.md); the
  registered ports are in [docs/Ports.md](docs/Ports.md), generated from
  `port/<soc>/port.json`.
- A port change touches only the port's own files; `tools/check-port-only-diff.sh
  --thin <soc> <base-ref>` proves it. Shared code (`src/`, `include/`, `port/common/`,
  `mk/common.mk`, `mk/arch-*.mk`, `tests/target/lib/`, the runners, the
  workflows) is changed only by a core change with its own review.
- Tests: `make test` (host suites, the registry and scenario self-tests, the
  assertion mutation test, the provisioning gates), `make test-target
  TARGET=<soc>` (M33MU), `make test-hardware TARGET=<soc>` (a board). A skip
  is never a pass; emulator evidence is never hardware evidence.
- Never run `lock`, set `WT_PRODUCTION_LOCK` or `WT_FIXTURE_BOUND`, burn a
  fuse, or write an option byte. Provisioning writes need a person.
