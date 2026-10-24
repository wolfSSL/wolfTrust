# Provisioning

`provisioning_ctrl.sh` takes a wolfTrust part from development to a production
lock with the same commands on every port. `TARGET` selects the port:

```sh
TARGET=stm32h563 tests/target/provisioning/provisioning_ctrl.sh help
TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh help
```

The flow is the same everywhere: `advance` a state as a reversible mock,
check the part in it, `regress`, then `lock` that state for real. Each `lock`
is one manual, previewed step that ends in an "are you sure" prompt and a typed
`I ACCEPT <state>`.

How to provision a device, generically and per port, is in
[docs/Provisioning.md](../../../docs/Provisioning.md).

| File | Role |
| --- | --- |
| `provisioning_ctrl.sh` | the only script you run: commands, rehearsal records, and every lock gate |
| `provisioning_ctrl_<target>.sh` | a port: the device's states and how to read, mock, and write them |
| `test_provisioning_gates.sh` | offline tests of every gate against stub tools (`make test-provisioning`) |

To add a port, copy a port file and implement its `port_*` functions; the
main script and its gates stay unchanged.
