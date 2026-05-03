# DoubleZero XDP RX Notes

## What the log fields mean

Example log line:

```text
rx count=4665880 size=1294 outer_src=<your-src-ip> inner_src=148.51.121.165 inner_dst=233.84.178.12 dst_port=7733
```

- `outer_src=<your-src-ip>`
  This is the remote DoubleZero GRE tunnel endpoint.
  It is the machine on the other side of the GRE tunnel sending the outer packet to us.

- `outer_dst=<your-dst-ip>`
  This is not printed in the log right now, but it is our server's public IP.
  On this host, `doublezero1` is configured as:
  `local <your-dst-ip> remote <your-src-ip>`

- `inner_src=148.51.121.165`
  This is the original sender inside the tunnel.
  In practice, this is the source IP of the shred publisher or upstream sender within DoubleZero's carried traffic.

- `inner_dst=233.84.178.12`
  This is the multicast destination inside the tunnel.
  It is not our server's IP.
  It is the group address that the shred traffic is being delivered to inside the GRE payload.

- `dst_port=7733`
  This is the inner UDP destination port for shred traffic.

## Packet path in simple terms

The packet arrives on the physical NIC `enp1s0f0` first.
At that point it is still a GRE packet:

```text
Ethernet
  outer IPv4: <your-src-ip> -> <your-dst-ip>
  GRE
  inner IPv4: 148.51.121.165 -> 233.84.178.12
  UDP: * -> 7733
  shred payload
```

If the packet matches the XDP program's rules, XDP redirects it straight into AF_XDP on queue 3.
If it does not match, XDP returns `XDP_PASS`, and the kernel keeps processing it normally.

That normal kernel path is what feeds the Linux GRE interface `doublezero1`.
After kernel decapsulation, the same traffic appears there as ordinary inner UDP packets.

So:

- physical NIC `enp1s0f0`: outer GRE packet
- virtual GRE interface `doublezero1`: inner UDP packet after kernel decapsulation

## What DoubleZero GRE is doing

DoubleZero is delivering shred traffic through a GRE tunnel.
On this machine:

```text
doublezero1 local <your-dst-ip> remote <your-src-ip>
```

And the kernel routes the multicast destinations through that tunnel:

```text
233.84.178.1 via 169.254.12.8
233.84.178.12 via 169.254.12.8
```

The purpose of the GRE tunnel is to carry an inner IP packet across an outer IP path.
That lets DoubleZero transport multicast shred traffic to the subscriber over the public internet using the tunnel endpoints as the real routable outer addresses.

## Why XDP still works

XDP is attached to the physical NIC, not to `doublezero1`.
That means XDP runs before the kernel's GRE decapsulation logic.

So XDP sees the raw outer packet on `enp1s0f0` and can:

1. Check that the outer EtherType is IPv4.
2. Check that the outer IPv4 protocol is GRE.
3. Parse the GRE header.
4. Parse the inner IPv4 header.
5. Parse the inner UDP header.
6. Decide whether to redirect or pass.

That is why XDP can work with GRE traffic even though the kernel has not decapsulated it yet.
The eBPF program just walks the packet bytes itself.

## Why queue steering is needed

The AF_XDP socket is bound to a specific hardware RX queue.
In this setup the socket is bound to queue 3.

That only works if the matching packets also land on queue 3.
Initially the DoubleZero GRE packets were landing mostly on queue 0, so the AF_XDP socket on queue 3 saw nothing.

To fix that, we install a Flow Director rule on the NIC so the outer tunnel packets are steered to queue 3.

## The FDIR rule we apply

The launcher script applies this rule after the XDP program is attached:

```bash
ethtool -U enp1s0f0 flow-type ip4 \
  src-ip <your-src-ip> \
  dst-ip <your-dst-ip> \
  action 3 loc 2043
```

Why this shape:

- `src-ip <your-src-ip>`
  matches the remote DoubleZero GRE endpoint

- `dst-ip <your-dst-ip>`
  matches our server's public IP

- `action 3`
  steers those packets to hardware RX queue 3

We use an outer IPv4 rule, not a GRE protocol-specific rule, because the ixgbe Flow Director path here accepts the outer IPv4 source/destination shape, while GRE protocol-specific matching was not accepted.

## What the XDP program does

The program in the sibling `doublezero-xdp` repo at `/root/doublezero-xdp/doublezero-xdp-ebpf/src/main.rs` is intentionally conservative.

It redirects only packets that satisfy all of these:

1. Outer EtherType is IPv4.
2. Outer IPv4 header is the standard 20-byte form.
3. Outer IPv4 protocol is GRE.
4. GRE flags are zero.
5. GRE protocol is inner IPv4.
6. Inner IPv4 header is the standard 20-byte form.
7. Inner protocol is UDP.
8. Inner UDP destination port is `7733`.
9. Inner destination IP is either `233.84.178.1` or `233.84.178.12`.

If all checks pass, it does:

```text
xsks_map[rx_queue_index] -> XDP_REDIRECT
```

Everything else is passed back to the kernel with `XDP_PASS`.

## What it filters out

The current XDP program passes these packets to the kernel instead of redirecting them:

- non-IPv4 packets
- outer IPv4 packets that are not GRE
- GRE packets with non-zero GRE flags
- GRE packets whose inner payload is not IPv4
- inner TCP traffic
- inner non-UDP traffic
- inner UDP heartbeat traffic on port `5765`
- inner UDP traffic not destined to port `7733`
- inner UDP traffic not aimed at `233.84.178.1` or `233.84.178.12`
- malformed or truncated packets

That means control-plane and non-shred traffic stays on the normal Linux path.

## How the `doublezero_xdp_rx` binary works

The standalone binary is [doublezero_xdp_rx.rs](/root/doublezero-xdp-rx/src/bin/doublezero_xdp_rx.rs).

High-level flow:

1. Open the DoubleZero XDP object:
   `/root/doublezero-xdp/target/bpfel-unknown-none/release/doublezero-xdp-ebpf`
   or `DOUBLEZERO_XDP_BPF_OBJECT`
2. Load program `doublezero_xdp_redirect`.
3. Pin `xsks_map` at `/sys/fs/bpf/xsks_map`.
4. Attach the XDP program to `enp1s0f0` in `drv` mode by default.
5. Start the DoubleZero-integrated AF_XDP RX loop from `agave-xdp-rx`.
6. Bind an AF_XDP socket to queue 3.
7. Register that socket in `xsks_map[3]`.
8. Receive redirected frames from XDP.
9. Log per-packet metadata and per-second counters directly from the RX loop sink.

Important detail:

The RX loop currently receives the full original frame from AF_XDP.
That means userspace still sees:

```text
Ethernet + outer IPv4 + GRE + inner IPv4 + UDP + payload
```

The binary is not consuming an already-decapsulated inner UDP packet.
It parses the GRE structure in userspace only for logging.

## How we make it work end-to-end

The current working recipe is:

1. Build the DoubleZero eBPF object.
2. Build the standalone `doublezero_xdp_rx` binary.
3. Attach the XDP program to `enp1s0f0`.
4. Bind AF_XDP to queue 3 and register `xsks_map[3]`.
5. Apply the outer IPv4 FDIR rule so the tunnel packets land on queue 3.

The launcher [run_doublezero_rx.sh](/root/doublezero-xdp-rx/run_doublezero_rx.sh) automates that ordering.
It waits until the RX path logs `XDP RX armed`, then installs the FDIR rule.

## Decapsulation options

There are two places to decapsulate:

### 1. Decapsulation in userspace

This is the simpler path and what the current setup naturally supports.

The AF_XDP socket receives the full outer frame.
Userspace can then:

1. Parse Ethernet
2. Parse outer IPv4
3. Parse GRE
4. Parse inner IPv4
5. Parse inner UDP
6. Hand only the inner UDP payload to the next stage

Pros:

- simpler to implement
- easier to debug
- less verifier pressure
- no packet rewriting in eBPF

Cons:

- userspace still pays for parsing the outer headers
- downstream code must understand or strip GRE explicitly

### 2. Decapsulation in eBPF/XDP

This means stripping the outer Ethernet, outer IPv4, and GRE headers before the packet is delivered onward.

At XDP level, the usual mechanism is to adjust the packet head so the inner packet becomes the visible packet.
Conceptually, that means:

```text
before: Ethernet + outer IPv4 + GRE + inner IPv4 + UDP + payload
after:  inner IPv4 + UDP + payload
```

or, if desired, rebuild an Ethernet header around the inner payload before redirecting.

Pros:

- userspace receives a simpler packet
- less per-packet parsing in userspace
- makes the AF_XDP consumer look more like a native non-GRE UDP consumer

Cons:

- more complex verifier constraints
- more driver-specific risk
- more care needed around head adjustment and packet layout
- easier to get wrong than parse-only classification

## Practical recommendation

For the current setup, the right split is:

- use XDP/eBPF to classify and redirect only the wanted DoubleZero GRE shred packets
- use userspace to decapsulate the payload for the next stage

That keeps the XDP program small and verifier-friendly while still removing most of the kernel path overhead for the data plane.

If later we want the AF_XDP consumer to behave exactly like a native UDP consumer without GRE awareness, then moving decapsulation into the eBPF program becomes the next step.
