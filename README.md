# doublezero-xdp-rx

Standalone userspace AF_XDP receiver and latency benchmark tooling for DoubleZero GRE-encapsulated shred traffic.

## Contents

- `doublezero_rx`: attach the DoubleZero Aya XDP program, arm AF_XDP on a queue, and log redirected packets.
- `doublezero_kernel_rx`: receive the same multicast feed through the normal UDP socket path for comparison.
- `run_doublezero_rx.sh`: launch the XDP receiver and install the FDIR rule after AF_XDP is armed.
- `run_doublezero_rx_bench.sh`: run the UDP and AF_XDP receivers back-to-back and print a latency table.

## Requirements

- Linux with AF_XDP / XDP support
- `ethtool`
- A built DoubleZero Aya eBPF object from a sibling `doublezero-xdp` repo or `DOUBLEZERO_XDP_BPF_OBJECT`
- Root privileges to attach XDP and manage Flow Director rules

## Build

```bash
cargo build --bin doublezero_rx --bin doublezero_kernel_rx
```

## Run

```bash
./run_doublezero_rx.sh
```

If the eBPF object is not in the default location, override it:

```bash
DOUBLEZERO_XDP_BPF_OBJECT=/path/to/doublezero-xdp-ebpf ./run_doublezero_rx.sh
```
