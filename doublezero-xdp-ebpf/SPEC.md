# `doublezero-xdp-ebpf` — XDP Program Spec

This crate is the kernel-side XDP/eBPF program loaded by `doublezero_xdp_rx`. It is `#![no_std]/#![no_main]` and is cross-compiled to `bpfel-unknown-none`.

Source: [`src/main.rs`](src/main.rs).

## Purpose

Identify DoubleZero shred traffic — GRE-encapsulated IPv4 carrying multicast UDP shreds — and redirect it from the NIC RX path into an AF_XDP socket via the pinned `xsks_map`. All other traffic (including DoubleZero control plane such as BGP-over-TCP and heartbeats on UDP 5765) is left on the kernel networking stack with `XDP_PASS`.

This is RX-only. The program never modifies, drops, or forwards packets.

## Entry point

```rust
#[xdp]
pub fn doublezero_xdp_redirect(ctx: XdpContext) -> u32
```

`doublezero_xdp_rx` looks up this program by name when attaching to a NIC.

## Map

```rust
#[map(name = "xsks_map")]
static SOCKS: XskMap = XskMap::pinned(64, 0);
```

- Type: `XskMap` (AF_XDP socket map), pinned in bpffs so userspace can register XSKs into it.
- Max entries: 64 (indexed by NIC RX queue).
- Userspace `doublezero_xdp_rx` inserts its AF_XDP socket file descriptor into the slot corresponding to the queue it bound to.

## Classifier policy (in order)

For every packet, the program walks fixed offsets and falls through to `XDP_PASS` on any mismatch or bounds-check failure.

| Step | Check                                                        | Mismatch → action |
|----- |--------------------------------------------------------------|-------------------|
| 1    | Outer Ethernet ethertype == `0x0800` (IPv4)                  | `XDP_PASS`        |
| 2    | Outer IPv4 first byte == `0x45` (IHL=5, no options)          | `XDP_PASS`        |
| 3    | Outer IPv4 protocol == `47` (GRE)                            | `XDP_PASS`        |
| 4    | GRE flags == `0` and GRE protocol == `0x0800` (IPv4)         | `XDP_PASS`        |
| 5    | Inner IPv4 first byte == `0x45`                              | `XDP_PASS`        |
| 6    | Inner IPv4 protocol: TCP → pass; not UDP → pass              | `XDP_PASS`        |
| 7    | Inner UDP dport == `5765` (heartbeat) → pass                 | `XDP_PASS`        |
| 8    | Inner UDP dport == `7733` (shred)                            | `XDP_PASS` if not |
| 9    | Inner IPv4 dst ∈ { `233.84.178.1`, `233.84.178.12` }         | `XDP_PASS` if not |
| 10   | `SOCKS.redirect(ctx.rx_queue_index, 0)`                      | redirect to AF_XDP |

Step 10 falls back to `XDP_PASS` if `redirect` fails (e.g. no XSK registered for this queue), so an unarmed queue cannot black-hole traffic.

Why outer-IPv4 (not GRE-specific) matching at step 3–4: the ixgbe Flow Director accepts an outer IPv4 5-tuple rule but rejects GRE protocol-specific rules, so steering is done at outer-IPv4 in `ethtool` and shape verification is done here.

## Header layout assumed

```
Ethernet (14 B)
  └─ outer IPv4 (20 B, IHL=5, proto=GRE)
       └─ GRE (4 B, flags=0, proto=IPv4)
            └─ inner IPv4 (20 B, IHL=5, proto=UDP)
                 └─ UDP (header) — dport=7733
                      └─ shred payload
```

Anything outside this shape (IPv4 options, GRE checksum/key/sequence, inner IPv6, etc.) is intentionally passed through to the kernel. The classifier is kept verifier-friendly and conservative on purpose.

## Constants

| Name                   | Value             | Meaning                                   |
|------------------------|-------------------|-------------------------------------------|
| `INNER_SHRED_PORT`     | 7733              | DoubleZero shred UDP dport                |
| `INNER_HEARTBEAT_PORT` | 5765              | DoubleZero heartbeat UDP dport (passed)   |
| `INNER_SHRED_MCAST`    | 233.84.178.1      | Accepted shred multicast destination      |
| `INNER_SHRED_MCAST_ALT`| 233.84.178.12     | Accepted shred multicast destination (alt)|

Change these in `src/main.rs` if the DoubleZero feed moves to a different port or group.

## License section

```rust
#[unsafe(link_section = "license")]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

This is the kernel-required license string read by the BPF verifier to decide whether GPL-only kernel helpers are usable. `Dual MIT/GPL` keeps that gate open. The Cargo-level license for this crate is AGPL-3.0-or-later; the in-object `license` string is a separate piece of kernel ABI metadata and is unrelated to the source license.

## Building

See the top-level [README](../README.md#build) and [SETUP.md](../SETUP.md#build). Summary:

```bash
cargo +nightly build --release \
  --target bpfel-unknown-none \
  -Z build-std=core \
  -p doublezero-xdp-ebpf
```

Output: `target/bpfel-unknown-none/release/doublezero-xdp-ebpf` (relative to the workspace root). `doublezero_xdp_rx` loads this object via `aya::Ebpf::load_file(...)`.
