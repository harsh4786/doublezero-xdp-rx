# DoubleZero XDP RX Setup

This repo contains the userspace AF_XDP receiver and the UDP-vs-XDP benchmark tooling for DoubleZero shred traffic.

It does **not** currently contain the Aya eBPF/XDP program source. The XDP program lives in the sibling repo:

- `/root/doublezero-xdp`

The userspace binary loads a built eBPF object from one of these locations:

1. `--bpf-object <path>`
2. `DOUBLEZERO_XDP_BPF_OBJECT=<path>`
3. default sibling path:
   `/root/doublezero-xdp/target/bpfel-unknown-none/release/doublezero-xdp-ebpf`

## Repo Layout

- This repo: userspace RX binaries
  - `doublezero_xdp_rx`
  - `doublezero_kernel_rx`
  - `run_doublezero_rx.sh`
  - `run_doublezero_rx_bench.sh`
- Sibling repo: Aya XDP program
  - `/root/doublezero-xdp`

So, no: the `doublezero-xdp` program is not in the same repo as this binary right now. The binary does not import the eBPF source directly during build. It loads the compiled eBPF object at runtime.

## Build

Build the userspace binaries in this repo:

```bash
cd /root/doublezero-xdp-rx
cargo build --release --bin doublezero_xdp_rx --bin doublezero_kernel_rx
```

Build the eBPF program in the sibling repo separately:

```bash
cd /root/doublezero-xdp
# build command depends on that repo's build flow
```

## DoubleZero Network Expectations

Current working assumptions:

- physical NIC receiving outer traffic: `enp1s0f0`
- DoubleZero tunnel interface for kernel-path multicast: `doublezero1`
- outer DoubleZero source IP: `<your-src-ip>`
- local public destination IP: `<your-dst-ip>`
- queue used for AF_XDP: `3`
- XDP attach mode: `drv`
- DoubleZero shred UDP port: `7733`
- expected multicast destination: `233.84.178.12`

DoubleZero shred delivery shape:

```text
Ethernet
IPv4 outer
GRE
IPv4 inner
UDP inner dst port 7733
shred payload
```

## Firewall Rules

These are the firewall rules we were using for DoubleZero:

```bash
sudo iptables -A OUTPUT -p gre -j ACCEPT
sudo iptables -A INPUT -i doublezero1 -s 169.254.0.0/16 -d 169.254.0.0/16 -p tcp --dport 179 -j ACCEPT
sudo iptables -A OUTPUT -o doublezero1 -s 169.254.0.0/16 -d 169.254.0.0/16 -p tcp --dport 179 -j ACCEPT
sudo iptables -A OUTPUT -o doublezero1 -p pim -j ACCEPT
sudo iptables -A INPUT -i doublezero1 -p udp --dport 7733 -j ACCEPT
sudo iptables -A INPUT -i doublezero0 -p udp --dport 44880 -j ACCEPT
```

What they are for:

- GRE transport itself
- BGP on the tunnel link (`tcp/179`)
- PIM control traffic
- shred UDP on `doublezero1:7733`
- unicast traffic on `doublezero0:44880`

## XDP Program Settings

The userspace launcher in this repo defaults to:

- `DEV=enp1s0f0`
- `QUEUE=3`
- `CPU=3`
- `ATTACH_MODE=drv`

The XDP RX benchmark defaults to:

- UDP core: `3`
- XDP core: `4`
- AF_XDP queue: `3`
- attach mode: `drv`

## FDIR Rule

We steer the outer IPv4 DoubleZero GRE packets to RX queue `3` with this Flow Director rule:

```bash
sudo ethtool -U enp1s0f0 flow-type ip4 \
  src-ip <your-src-ip> \
  dst-ip <your-dst-ip> \
  action 3 \
  loc 2043
```

The launcher script applies the same rule automatically after AF_XDP is armed:

```bash
FDIR_LOC=2043
FDIR_SRC_IP=<your-src-ip>
FDIR_DST_IP=<your-dst-ip>
FDIR_ACTION_QUEUE=3
```

Important ixgbe note:

- We could not install a GRE-specific `proto 47` FDIR rule.
- On this NIC/driver path, steering by outer IPv4 source/destination was the working shape.

## Run XDP RX

From this repo:

```bash
cd /root/doublezero-xdp-rx
./run_doublezero_rx.sh
```

For the demo startup view with DoubleZero route/status logs and `xdpdump`
showing XDP return actions (`PASS`/`REDIRECT`):

```bash
cd /root/doublezero-xdp-rx
SHOW_STARTUP_LOGS=1 SHOW_XDPDUMP_LOGS=1 ./run_doublezero_rx.sh
```

By default, the startup xdpdump stream runs until the launcher exits. To make it
bounded:

```bash
cd /root/doublezero-xdp-rx
SHOW_STARTUP_LOGS=1 SHOW_XDPDUMP_LOGS=1 XDPDUMP_DURATION_SECS=10 ./run_doublezero_rx.sh
```

If the eBPF object is not in the sibling default path:

```bash
cd /root/doublezero-xdp-rx
DOUBLEZERO_XDP_BPF_OBJECT=/path/to/doublezero-xdp-ebpf ./run_doublezero_rx.sh
```

What happens:

1. Clear the startup screen when startup logs are enabled
2. Wait for DoubleZero multicast routes before starting XDP RX
3. Start `doublezero_xdp_rx`
4. Load and attach the XDP program on `enp1s0f0`
5. Pin `xsks_map`
6. Bind AF_XDP socket on queue `3`
7. Wait for `XDP RX armed`
8. Install the FDIR rule to push the DoubleZero outer flow into queue `3`
9. Optionally start `xdpdump --rx-capture=exit` to print XDP actions

## Run Kernel vs XDP Benchmark

```bash
cd /root/doublezero-xdp-rx
BENCH_DURATION_SECS=30 ./run_doublezero_rx_bench.sh
```

This runs:

1. `doublezero_kernel_rx` on `doublezero1`
2. `doublezero_xdp_rx` on `enp1s0f0` queue `3`
3. prints a latency table from both logs

## Operational Checks

Check the DoubleZero client:

```bash
doublezero status
doublezero-solana shreds list --client-ip <your-dst-ip>
doublezero-solana shreds price --device-code cherlita
```

Check whether the tunnel exists:

```bash
ip -br link show
ip -br addr show
```

If `doublezero1` is missing, the UDP benchmark leg will fail immediately.

## Current Limitation

If you want the userspace binary repo to build the eBPF program directly as part of one tree, the next step is to fold `/root/doublezero-xdp` into this repo as:

1. a git submodule
2. a sibling workspace member
3. or a full merge of the eBPF source into this repo

Right now it is a two-repo setup by design.
