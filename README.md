# doublezero-xdp-rx

Standalone userspace AF_XDP receiver and latency benchmark tooling for Doublezero GRE-encapsulated shred traffic.

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).

## Contents

This is a Cargo workspace with two crates:

- `doublezero-xdp-rx` (root): userspace AF_XDP receivers and benchmark tooling.
  - `doublezero_xdp_rx`: attach the Doublezero Aya XDP program, arm AF_XDP on a queue, and log redirected packets.
  - `doublezero_kernel_rx`: receive the same multicast feed through the normal UDP socket path for comparison.
  - `run_doublezero_rx.sh`: launch the XDP receiver and install the FDIR rule after AF_XDP is armed.
  - `run_doublezero_rx_bench.sh`: run the UDP and AF_XDP receivers back-to-back and print a latency table.
- `doublezero-xdp-ebpf`: the Aya-based XDP/eBPF program (`#![no_std]/#![no_main]`) decapsulates GRE and redirects Doublezero shred multicast UDP into the `xsks_map` AF_XDP socket map. The userspace `doublezero_xdp_rx` binary loads the compiled object via `aya::Ebpf::load_file` and attaches the `doublezero_xdp_redirect` XDP program to the configured NIC. See [`doublezero-xdp-ebpf/SPEC.md`](doublezero-xdp-ebpf/SPEC.md) for the full classifier policy, header layout, and constants.

## Requirements

- Linux with AF_XDP / XDP support
- `ethtool`
- Rust nightly (the eBPF crate needs `-Z build-std=core` for the `bpfel-unknown-none` target)
- Root privileges to attach XDP and manage Flow Director rules

## Tested NIC / XDP Setup

These are the host details used for the Doublezero kernel-vs-XDP RX testing on this machine:

- Physical NIC: `enp1s0f0`
- PCI device: `0000:01:00.0`
- Adapter: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection, rev `01`
- Driver: `ixgbe`
- Driver version: `6.8.0-60-generic`
- Firmware version: `0x800006d1, 1.1876.0`
- Link: `10000Mb/s`, full duplex, auto-negotiation off
- Channels: `24` combined, with AF_XDP bound to queue `3`
- Ring settings during capture: RX `512`, TX `512`; hardware maximum RX/TX `8192`
- XDP attach mode: `drv`, via `--attach-mode drv` / `ATTACH_MODE=drv`
- AF_XDP bind: zero-copy, via `--zero-copy true` / `ZERO_COPY=true` (the default; pass `false` for NICs or modes without zero-copy support, e.g. veth or `skb`)
- Kernel comparison interface: `doublezero1`
- Doublezero shred UDP port: `7733`
- Flow Director steering: outer IPv4 `<your-src-ip> -> <your-dst-ip>` to queue `3`, rule loc `2043`

Relevant feature state during capture:

- `ntuple-filters`: on
- `receive-hashing`: on
- `generic-receive-offload`: on
- `large-receive-offload`: off
- `rx-vlan-offload`: on

## Doublezero Edge / Seat-Specific Values

This repository documents the Doublezero packet shape and the local setup used for testing, but the exact underlay and multicast values are not universal. They depend on the Doublezero edge/seat allocated to the machine or device.

At minimum, expect these values to be seat-specific:

- Outer GRE source IP: the remote Doublezero edge endpoint.
- Outer GRE destination IP: the local public IP for this host/seat.
- Inner shred multicast destination: the multicast group assigned for the Doublezero feed.
- Kernel multicast interface/group used by `doublezero_kernel_rx`, for example `doublezero1` and `233.84.178.12` on the tested setup.

The current eBPF classifier has the accepted inner multicast destinations hardcoded in [`doublezero-xdp-ebpf/src/main.rs`](doublezero-xdp-ebpf/src/main.rs):

| Group | Feed |
|-------|------|
| `233.84.178.1` | leader shreds (`edge-solana-shreds`) |
| `233.84.178.12` | retransmit EU |
| `233.84.178.13` | retransmit APAC |
| `233.84.178.14` | retransmit Americas |
| `233.84.178.16` | root shreds |

This covers every Doublezero Edge shred group currently published (check with `doublezero multicast group list`). If Doublezero adds a group, add a constant next to `INNER_SHRED_MCAST_*` and rebuild the eBPF object:

```bash
cargo +nightly build --release \
  --target bpfel-unknown-none \
  -Z build-std=core \
  -p doublezero-xdp-ebpf
```

The same seat-specific addresses must also be reflected in the launcher/benchmark environment, especially `FDIR_SRC_IP`, `FDIR_DST_IP`, `KERNEL_GROUP`, and `DZ_CLIENT_IP`. A more portable future version should move the multicast allowlist into a BPF map populated by userspace instead of requiring an eBPF rebuild.

## Build

Build the userspace binaries (host target):

```bash
cargo build --release --bin doublezero_xdp_rx --bin doublezero_kernel_rx
```

Build the eBPF program (cross-compiled to `bpfel-unknown-none`, requires nightly with `rust-src`):

```bash
cargo +nightly build --release \
  --target bpfel-unknown-none \
  -Z build-std=core \
  -p doublezero-xdp-ebpf
```

The resulting object is written to:

```
target/bpfel-unknown-none/release/doublezero-xdp-ebpf
```

This is the default path the `doublezero_xdp_rx` binary searches when neither `--bpf-object` nor `DOUBLEZERO_XDP_BPF_OBJECT` is set, and is the path `run_doublezero_rx.sh` uses for `BPF_OBJECT`. The userspace loader calls `aya::Ebpf::load_file(<path>)` and then attaches the `doublezero_xdp_redirect` XDP program to the configured NIC.

## Run

> **Important:** Before running, set the Doublezero edge/seat-specific values for your allocation. At minimum, edit `run_doublezero_rx.sh` and `run_doublezero_rx_bench.sh`, or export env vars, for `FDIR_SRC_IP`, `FDIR_DST_IP`, `KERNEL_GROUP`, and `DZ_CLIENT_IP`. If your assigned shred multicast destination is not one of the hardcoded eBPF groups, add it next to the `INNER_SHRED_MCAST_*` constants in `doublezero-xdp-ebpf/src/main.rs` and rebuild the eBPF object before launching.

```bash
./run_doublezero_rx.sh
```

To override the eBPF object location (e.g. if you built it elsewhere):

```bash
DOUBLEZERO_XDP_BPF_OBJECT=/path/to/doublezero-xdp-ebpf ./run_doublezero_rx.sh
```
