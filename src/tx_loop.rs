#![allow(clippy::arithmetic_side_effects)]

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    thread,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use caps::{
    CapSet,
    Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
};
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use libc::{_SC_PAGESIZE, CLOCK_MONOTONIC, clock_gettime, sysconf, timespec};
use log::{info, warn};

use crate::{
    device::{NetworkDevice, QueueId, RingSizes},
    netlink::MacAddress,
    packet::{
        ETH_HEADER_SIZE, IP_HEADER_SIZE, UDP_HEADER_SIZE, write_eth_header, write_ip_header,
        write_udp_header,
    },
    que_channel::{QueTracedPayload, XdpQueConsumer, XdpQuePayload},
    route::Router,
    rx_loop::xdp_verbose_trace_enabled,
    set_cpu_affinity,
    socket::{Socket, Tx, TxRing},
    umem::{Frame as _, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem as _},
};
static XDP_PACKET_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();
static XDP_PACKET_TRACE_MAX: OnceLock<u64> = OnceLock::new();
static XDP_PACKET_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static PIPELINE_LATENCY_HIST_ENABLED: OnceLock<bool> = OnceLock::new();
static XDP_TX_BATCH_SIZE: OnceLock<usize> = OnceLock::new();
static XDP_TX_MAX_BATCH_AGE_US: OnceLock<u64> = OnceLock::new();
const XDP_TRACE_KEY_PREFIX_BYTES: usize = 64;
const XDP_TRACE_HASH_OFFSET_BASIS: u32 = 0x811c_9dc5;
const XDP_TRACE_HASH_PRIME: u32 = 0x0100_0193;

#[inline(always)]
fn packet_trace_enabled() -> bool {
    *XDP_PACKET_TRACE_ENABLED.get_or_init(|| {
        env::var("XDP_PACKET_TRACE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

#[inline(always)]
fn packet_trace_max() -> u64 {
    *XDP_PACKET_TRACE_MAX.get_or_init(|| {
        env::var("XDP_PACKET_TRACE_MAX")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    })
}

#[inline(always)]
fn should_log_packet_trace() -> bool {
    if !packet_trace_enabled() {
        return false;
    }
    let n = XDP_PACKET_TRACE_COUNT.fetch_add(1, AtomicOrdering::Relaxed) + 1;
    let max = packet_trace_max();
    max == 0 || n <= max
}

#[inline(always)]
fn pipeline_latency_hist_enabled() -> bool {
    *PIPELINE_LATENCY_HIST_ENABLED.get_or_init(|| {
        env::var("PIPELINE_LATENCY_HIST")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

#[inline(always)]
fn xdp_tx_batch_size() -> usize {
    *XDP_TX_BATCH_SIZE.get_or_init(|| {
        env::var("XDP_TX_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.clamp(1, 1024))
            .unwrap_or(16)
    })
}

#[inline(always)]
fn xdp_tx_max_batch_age_us() -> u64 {
    *XDP_TX_MAX_BATCH_AGE_US.get_or_init(|| {
        env::var("XDP_TX_MAX_BATCH_AGE_US")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1))
            .unwrap_or(8)
    })
}

#[inline]
fn write_ring_health_state(path: &str, payload: &str) {
    let tmp = format!("{path}.tmp");
    let _ = std::fs::write(&tmp, payload);
    let _ = std::fs::rename(tmp, path);
}

const LAT_BUCKETS_US: [u64; 16] = [
    2, 4, 8, 16, 32, 64, 128, 256, 512, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000,
];

#[derive(Default)]
struct LatencyHist {
    counts: [u64; LAT_BUCKETS_US.len() + 1],
    samples: u64,
    sum_us: u128,
    min_us: u64,
    max_us: u64,
}

struct PendingTxTrace {
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload_len: usize,
    frame_len: usize,
    sig32: u32,
    t_ns: u128,
}

impl LatencyHist {
    fn record_ns(&mut self, ns: u64) {
        let us = ns / 1_000;
        let mut idx = LAT_BUCKETS_US.len();
        for (i, b) in LAT_BUCKETS_US.iter().enumerate() {
            if us <= *b {
                idx = i;
                break;
            }
        }
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.samples = self.samples.saturating_add(1);
        self.sum_us = self.sum_us.saturating_add(us as u128);
        if self.samples == 1 {
            self.min_us = us;
            self.max_us = us;
        } else {
            self.min_us = self.min_us.min(us);
            self.max_us = self.max_us.max(us);
        }
    }

    fn percentile_us(&self, pct: u64) -> u64 {
        if self.samples == 0 {
            return 0;
        }
        let target = self.samples.saturating_mul(pct).div_ceil(100);
        let mut seen = 0u64;
        for (i, c) in self.counts.iter().enumerate() {
            seen = seen.saturating_add(*c);
            if seen >= target {
                if i < LAT_BUCKETS_US.len() {
                    return LAT_BUCKETS_US[i];
                }
                return self.max_us;
            }
        }
        self.max_us
    }

    fn avg_us(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            (self.sum_us / self.samples as u128) as u64
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[inline(always)]
fn now_monotonic_ns() -> u128 {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    if rc == 0 {
        (ts.tv_sec as u128)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u128)
    } else {
        0
    }
}

struct FastClock {
    ticks_per_sec: u64,
}

impl FastClock {
    #[inline(always)]
    fn duration_to_ticks(&self, duration: Duration) -> u64 {
        let ticks = (duration
            .as_nanos()
            .saturating_mul(self.ticks_per_sec as u128))
            / 1_000_000_000u128;
        ticks.max(1) as u64
    }

    #[inline(always)]
    fn elapsed_ticks(&self, start: u64, end: u64) -> u64 {
        end.wrapping_sub(start)
    }

    #[inline(always)]
    fn elapsed_ns(&self, start: u64, end: u64) -> u64 {
        let ticks = self.elapsed_ticks(start, end) as u128;
        ((ticks.saturating_mul(1_000_000_000u128)) / self.ticks_per_sec as u128) as u64
    }

    #[inline(always)]
    fn elapsed_millis(&self, start: u64, end: u64) -> u128 {
        self.elapsed_ns(start, end) as u128 / 1_000_000
    }
}

static FAST_CLOCK: OnceLock<FastClock> = OnceLock::new();

fn fast_clock() -> &'static FastClock {
    FAST_CLOCK.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            let start_wall = Instant::now();
            let start_ticks = fast_now();
            loop {
                let elapsed = start_wall.elapsed();
                if elapsed >= Duration::from_millis(20) {
                    let end_ticks = fast_now();
                    let elapsed_ns = elapsed.as_nanos().max(1);
                    let ticks_per_sec = (((end_ticks.wrapping_sub(start_ticks)) as u128)
                        .saturating_mul(1_000_000_000u128)
                        / elapsed_ns)
                        .max(1) as u64;
                    return FastClock { ticks_per_sec };
                }
                std::hint::spin_loop();
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            FastClock {
                ticks_per_sec: 1_000_000_000,
            }
        }
    })
}

#[inline(always)]
fn fast_now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        now_monotonic_ns() as u64
    }
}

#[inline(always)]
fn payload_sig32(payload: &[u8]) -> u32 {
    let mut sig32 = XDP_TRACE_HASH_OFFSET_BASIS;
    for &b in payload.iter().take(XDP_TRACE_KEY_PREFIX_BYTES) {
        sig32 ^= b as u32;
        sig32 = sig32.wrapping_mul(XDP_TRACE_HASH_PRIME);
    }
    sig32
}

#[derive(Clone, Debug)]
pub enum Destinations {
    Single(SocketAddr),
    Multi(Arc<Vec<SocketAddr>>),
}

impl Destinations {
    #[inline(always)]
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multi(addrs) => addrs.len(),
        }
    }

    #[inline(always)]
    pub fn for_each<F: FnMut(&SocketAddr)>(&self, mut f: F) {
        match self {
            Self::Single(addr) => f(addr),
            Self::Multi(addrs) => {
                for addr in addrs.iter() {
                    f(addr);
                }
            }
        }
    }
}

impl From<Arc<Vec<SocketAddr>>> for Destinations {
    #[inline(always)]
    fn from(addrs: Arc<Vec<SocketAddr>>) -> Self {
        if addrs.len() == 1 {
            Self::Single(addrs[0])
        } else {
            Self::Multi(addrs)
        }
    }
}

/// Payload wrapper that carries the RX-side trace sig32 through the channel,
/// eliminating the need for the TX thread to recompute CRC32 and lock the
/// RX-side Mutex<HashMap> to check sampling state.
#[derive(Clone)]
pub struct TracedPayload {
    pub data: bytes::Bytes,
    /// `Some(sig32)` = this packet was trace-sampled on RX; use this sig32.
    /// `None` = not sampled, skip all trace work on TX.
    pub trace_sig32: Option<u32>,
}

impl AsRef<[u8]> for TracedPayload {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

trait TxPayload: AsRef<[u8]> {
    fn trace_sig32(&self) -> Option<u32>;
}

impl TxPayload for TracedPayload {
    #[inline(always)]
    fn trace_sig32(&self) -> Option<u32> {
        self.trace_sig32
    }
}

impl<const MAX: usize> TxPayload for QueTracedPayload<MAX> {
    #[inline(always)]
    fn trace_sig32(&self) -> Option<u32> {
        self.trace_sig32()
    }
}

enum TxPayloadRecvError {
    Empty,
    Disconnected,
}

trait TxPayloadReceiver<P> {
    fn try_recv_payload(&mut self) -> Result<P, TxPayloadRecvError>;
}

impl TxPayloadReceiver<TracedPayload> for Receiver<TracedPayload> {
    #[inline(always)]
    fn try_recv_payload(&mut self) -> Result<TracedPayload, TxPayloadRecvError> {
        self.try_recv().map_err(|err| match err {
            TryRecvError::Empty => TxPayloadRecvError::Empty,
            TryRecvError::Disconnected => TxPayloadRecvError::Disconnected,
        })
    }
}

struct QueTxPayloadReceiver {
    consumer: XdpQueConsumer,
    exit: Arc<AtomicBool>,
}

impl TxPayloadReceiver<XdpQuePayload> for QueTxPayloadReceiver {
    #[inline(always)]
    fn try_recv_payload(&mut self) -> Result<XdpQuePayload, TxPayloadRecvError> {
        match self.consumer.pop() {
            Some(payload) => Ok(payload),
            None if self.exit.load(AtomicOrdering::Relaxed) => {
                Err(TxPayloadRecvError::Disconnected)
            }
            None => Err(TxPayloadRecvError::Empty),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn tx_loop<T: AsRef<[u8]>, A: AsRef<[SocketAddr]>>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    receiver: Receiver<(A, T)>,
    drop_sender: Sender<(A, T)>,
) {
    log::info!(
        "starting xdp loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    // each queue is bound to its own CPU core
    set_cpu_affinity([cpu_id]).unwrap();

    let src_mac = src_mac.unwrap_or_else(|| {
        // if no source MAC is provided, use the device's MAC address
        dev.mac_addr()
            .expect("no src_mac provided, device must have a MAC address")
    });
    let src_ip = src_ip.unwrap_or_else(|| {
        // if no source IP is provided, use the device's IPv4 address
        dev.ipv4_addr()
            .expect("no src_ip provided, device must have an IPv4 address")
    });

    // some drivers require frame_size=page_size
    let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    let queue = dev
        .open_queue(queue_id)
        .expect("failed to open queue for AF_XDP socket");
    let RingSizes {
        rx: rx_size,
        tx: tx_size,
    } = queue.ring_sizes().unwrap_or_else(|| {
        log::info!(
            "using default ring sizes for {} queue {queue_id:?}",
            dev.name()
        );
        RingSizes::default()
    });

    let frame_count: usize = (rx_size + tx_size) * 2;

    // try to allocate huge pages first, then fall back to regular pages
    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    // we need NET_ADMIN and NET_RAW for the socket
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let (mut socket, tx) = match Socket::tx(queue, umem, zero_copy, tx_size * 2, tx_size) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "AF_XDP Socket::tx failed on queue {:?}: kind={:?} raw_os_error={:?} err={:?}",
                queue_id,
                e.kind(),
                e.raw_os_error(),
                e
            );
            panic!("failed to create AF_XDP socket on queue {queue_id:?}");
        }
    };

    let umem = socket.umem();
    let umem_tx_capacity = umem.available();
    let Tx {
        // this is where we'll queue frames
        ring,
        // this is where we'll get completion events once frames have been picked up by the NIC
        mut completion,
    } = tx;
    let mut ring = ring.unwrap();

    // get the routing table from netlink
    let router = Router::new().expect("failed to create router");

    // we don't need higher caps anymore
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // How long we sleep waiting to receive shreds from the channel.
    const RECV_TIMEOUT: Duration = Duration::from_nanos(1000);

    const MAX_TIMEOUTS: usize = 1;

    // We try to collect _at least_ BATCH_SIZE packets before queueing into the NIC. This is to
    // avoid introducing too much per-packet overhead and giving the NIC time to complete work
    // before we queue the next chunk of packets.
    const BATCH_SIZE: usize = 64;

    // Local buffer where we store packets before sending themi.
    let mut batched_items = Vec::with_capacity(BATCH_SIZE);

    // How many packets we've batched. This is _not_ batched_items.len(), but item * peers. For
    // example if we have 3 packets to transmit to 2 destination addresses each, we have 6 batched
    // packets.
    let mut batched_packets = 0;

    let mut timeouts = 0;
    loop {
        match receiver.try_recv() {
            Ok((addrs, payload)) => {
                batched_packets += addrs.as_ref().len();
                batched_items.push((addrs, payload));
                timeouts = 0;
                if batched_packets < BATCH_SIZE {
                    continue;
                }
            }
            Err(TryRecvError::Empty) => {
                if timeouts < MAX_TIMEOUTS {
                    timeouts += 1;
                    thread::sleep(RECV_TIMEOUT);
                } else {
                    timeouts = 0;
                    // we haven't received anything in a while, kick the driver
                    ring.commit();
                    kick(&ring);
                }
            }
            Err(TryRecvError::Disconnected) => {
                // keep looping until we've flushed all the packets
                if batched_packets == 0 {
                    break;
                }
            }
        };

        // this is the number of packets after which we commit the ring and kick the driver if
        // necessary
        let mut chunk_remaining = BATCH_SIZE.min(batched_packets);
        for (addrs, payload) in batched_items.drain(..) {
            for addr in addrs.as_ref() {
                if ring.available() == 0 || umem.available() == 0 {
                    let mut wait_iters: u64 = 0;
                    // loop until we have space for the next packet
                    loop {
                        completion.sync(true);
                        // we haven't written any frames so we only need to sync the consumer position
                        ring.sync(false);

                        // check if any frames were completed
                        while let Some(frame_offset) = completion.read() {
                            umem.release(frame_offset);
                        }

                        if ring.available() > 0 && umem.available() > 0 {
                            // we have space for the next packet, break out of the loop
                            break;
                        }

                        wait_iters = wait_iters.saturating_add(1);
                        // In full-ring stall state, always force wake. On ixgbe/SKB, NEEDS_WAKEUP
                        // can be stale and kick() can become a no-op indefinitely.
                        force_wake(&ring);
                    }
                }

                // at this point we're guaranteed to have a frame to write the next packet into and
                // a slot in the ring to submit it
                let mut frame = umem.reserve().unwrap();
                let IpAddr::V4(dst_ip) = addr.ip() else {
                    panic!("IPv6 not supported");
                };

                let dest_mac = if let Some(mac) = dest_mac {
                    mac
                } else {
                    let next_hop = router.route(addr.ip()).unwrap();

                    let mut skip = false;

                    // sanity check that the address is routable through our NIC
                    // if next_hop.if_index != dev.if_index() {
                    //     log::warn!(
                    //         "dropping packet: turbine peer {addr} must be routed through \
                    //          if_index: {} our if_index: {}",
                    //         next_hop.if_index,
                    //         dev.if_index()
                    //     );
                    //     skip = true;
                    // }

                    // we need the MAC address to send the packet
                    if next_hop.mac_addr.is_none() {
                        log::warn!(
                            "dropping packet: turbine peer {addr} must be routed through {} which \
                             has no known MAC address",
                            next_hop.ip_addr
                        );
                        skip = true;
                    };

                    if skip {
                        batched_packets -= 1;
                        umem.release(frame.offset());
                        continue;
                    }

                    next_hop.mac_addr.unwrap()
                };

                // const VLAN_TAG_SIZE: usize = 4;
                // const VLAN_ETH_HEADER_SIZE: usize = ETH_HEADER_SIZE + VLAN_TAG_SIZE;
                const PACKET_HEADER_SIZE: usize =
                    ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;

                let len = payload.as_ref().len();
                frame.set_len(PACKET_HEADER_SIZE + len);
                let packet = umem.map_frame_mut(&frame);

                // write the payload first as it's needed for checksum calculation (if enabled)
                packet[PACKET_HEADER_SIZE..][..len].copy_from_slice(payload.as_ref());

                write_eth_header(&mut packet[..ETH_HEADER_SIZE], &src_mac.0, &dest_mac.0);

                write_ip_header(
                    &mut packet[ETH_HEADER_SIZE..],
                    &src_ip,
                    &dst_ip,
                    (UDP_HEADER_SIZE + len) as u16,
                );

                write_udp_header(
                    &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
                    &src_ip,
                    src_port,
                    &dst_ip,
                    addr.port(),
                    len as u16,
                    // don't do checksums
                    false,
                );

                if should_log_packet_trace() {
                    info!(
                        "TX_PKT: q={:?} {}:{} -> {}:{} payload_len={} frame_len={}",
                        queue_id,
                        src_ip,
                        src_port,
                        dst_ip,
                        addr.port(),
                        len,
                        PACKET_HEADER_SIZE + len
                    );
                }

                // write the packet into the ring
                ring.write(frame, 0)
                    .map_err(|_| "ring full")
                    // this should never happen as we check for available slots above
                    .expect("failed to write to ring");

                batched_packets -= 1;
                chunk_remaining -= 1;

                // check if it's time to commit the ring and kick the driver
                if chunk_remaining == 0 {
                    chunk_remaining = BATCH_SIZE.min(batched_packets);

                    // commit new frames
                    ring.commit();
                    kick(&ring);
                }
            }
            let _ = drop_sender.try_send((addrs, payload));
        }
        debug_assert_eq!(batched_packets, 0);
    }
    debug_assert_eq!(batched_packets, 0);

    // drain the ring
    while umem.available() < umem_tx_capacity || ring.available() < ring.capacity() {
        log::debug!(
            "draining xdp ring umem {}/{} ring {}/{}",
            umem.available(),
            umem_tx_capacity,
            ring.available(),
            ring.capacity()
        );

        completion.sync(true);
        while let Some(frame_offset) = completion.read() {
            umem.release(frame_offset);
        }

        ring.sync(false);
        kick(&ring);
    }
}

// With some drivers, or always when we work in SKB mode, we need to explicitly kick the driver once
// we want the NIC to do something.
#[inline(always)]
fn kick(ring: &TxRing<SliceUmemFrame<'_>>) {
    if !ring.needs_wakeup() {
        return;
    }

    if let Err(e) = ring.wake() {
        kick_error(e);
    }
}

#[inline(always)]
fn force_wake(ring: &TxRing<SliceUmemFrame<'_>>) {
    if let Err(e) = ring.wake() {
        match e.raw_os_error() {
            Some(libc::EAGAIN | libc::ENOBUFS | libc::EBUSY) => {}
            _ => kick_error(e),
        }
    }
}

fn kick_error(e: std::io::Error) {
    match e.raw_os_error() {
        // these are non-fatal errors
        Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN) => {}
        // this can temporarily happen with some drivers when changing
        // settings (eg with ethtool)
        Some(libc::ENETDOWN) => {
            log::warn!("network interface is down")
        }
        // Common during teardown/races when XDP is detached while TX loop is still draining.
        Some(libc::EINVAL | libc::ENODEV | libc::EBADF) => {}
        // we should never get here, hopefully the driver recovers?
        _ => {
            log::error!("network interface driver error: {e:?}");
        }
    }
}

pub const VLAN_TAG_SIZE: usize = 4;
pub const TPID_8021Q: u16 = 0x8100;

#[inline]
pub fn write_eth_header_vlan(
    pkt: &mut [u8],
    src: &[u8; 6],
    dst: &[u8; 6],
    vlan_id: u16,
    _ethertype: u16,
) {
    // dst/src
    pkt[0..6].copy_from_slice(dst);
    pkt[6..12].copy_from_slice(src);
    // TPID 0x8100
    pkt[12..14].copy_from_slice(&TPID_8021Q.to_be_bytes());
    // TCI (priority=0, dei=0, vlan_id)
    let tci = vlan_id & 0x0FFF;
    pkt[14..16].copy_from_slice(&tci.to_be_bytes());
    // Inner EtherType (IPv4 = 0x0800)
    pkt[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
pub fn tx_loop_v1(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    receiver: Receiver<TracedPayload>,
    drop_sender: Sender<TracedPayload>,
) {
    tx_loop_v1_inner(
        cpu_id,
        dev,
        queue_id,
        zero_copy,
        src_mac,
        src_ip,
        src_port,
        dest_mac,
        unioned_dest_sockets,
        receiver,
        |payload| {
            let _ = drop_sender.try_send(payload);
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub fn tx_loop_v1_que(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    receiver: XdpQueConsumer,
    exit: Arc<AtomicBool>,
) {
    tx_loop_v1_inner(
        cpu_id,
        dev,
        queue_id,
        zero_copy,
        src_mac,
        src_ip,
        src_port,
        dest_mac,
        unioned_dest_sockets,
        QueTxPayloadReceiver {
            consumer: receiver,
            exit,
        },
        |_| {},
    );
}

#[allow(clippy::too_many_arguments)]
fn tx_loop_v1_inner<P, R, D>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    mut receiver: R,
    mut drop_payload: D,
) where
    P: TxPayload,
    R: TxPayloadReceiver<P>,
    D: FnMut(P),
{
    log::info!(
        "starting xdp loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    // each queue is bound to its own CPU core
    set_cpu_affinity([cpu_id]).unwrap();

    let src_mac = src_mac.unwrap_or_else(|| {
        // if no source MAC is provided, use the device's MAC address
        dev.mac_addr()
            .expect("no src_mac provided, device must have a MAC address")
    });
    let src_ip = src_ip.unwrap_or_else(|| {
        // if no source IP is provided, use the device's IPv4 address
        dev.ipv4_addr()
            .expect("no src_ip provided, device must have an IPv4 address")
    });

    // some drivers require frame_size=page_size
    let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    let queue = dev
        .open_queue(queue_id)
        .expect("failed to open queue for AF_XDP socket");
    let RingSizes {
        rx: rx_size,
        tx: tx_size,
    } = queue.ring_sizes().unwrap_or_else(|| {
        log::info!(
            "using default ring sizes for {} queue {queue_id:?}",
            dev.name()
        );
        RingSizes::default()
    });

    let frame_count: usize = (rx_size + tx_size) * 2;

    // try to allocate huge pages first, then fall back to regular pages
    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    // we need NET_ADMIN and NET_RAW for the socket
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let (mut socket, tx) = match Socket::tx(queue, umem, zero_copy, tx_size * 2, tx_size) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "AF_XDP Socket::tx failed on queue {:?}: kind={:?} raw_os_error={:?} err={:?}",
                queue_id,
                e.kind(),
                e.raw_os_error(),
                e
            );
            panic!("failed to create AF_XDP socket on queue {queue_id:?}");
        }
    };

    let umem = socket.umem();
    let umem_tx_capacity = umem.available();
    let Tx {
        ring,
        mut completion,
    } = tx;
    let mut ring = ring.unwrap();

    // get the routing table from netlink
    let router = Router::new().expect("failed to create router");

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // How long we sleep waiting to receive shreds from the channel.
    const RECV_TIMEOUT: Duration = Duration::from_nanos(1000);

    const MAX_TIMEOUTS: usize = 1;

    // We try to collect _at least_ BATCH_SIZE packets before queueing into the NIC. This is to
    // avoid introducing too much per-packet overhead and giving the NIC time to complete work
    // before we queue the next chunk of packets.
    let batch_size = xdp_tx_batch_size();
    let max_batch_age = Duration::from_micros(xdp_tx_max_batch_age_us());
    let clock = fast_clock();
    let one_sec_ticks = clock.duration_to_ticks(Duration::from_secs(1));
    let wait_warn_ticks = clock.duration_to_ticks(Duration::from_millis(100));
    let max_batch_age_ticks = clock.duration_to_ticks(max_batch_age);

    // Local buffer where we store packets before sending themi.
    let mut batched_items = Vec::with_capacity(batch_size);

    // How many packets we've batched. This is _not_ batched_items.len(), but item * peers. For
    // example if we have 3 packets to transmit to 2 destination addresses each, we have 6 batched
    // packets.
    let mut batched_packets = 0;
    let mut tx_total: u64 = 0;
    let mut tx_since_log: u64 = 0;
    let mut last_tx_log = fast_now();
    let hist_enabled = pipeline_latency_hist_enabled();
    let mut lat_hist = LatencyHist::default();
    let mut last_lat_log = fast_now();
    let tx_capacity = ring.capacity();
    let completion_capacity = completion.capacity();
    let mut batch_started_at: Option<u64> = None;
    let mut pending_submit_hist: Vec<u64> = Vec::with_capacity(batch_size);
    let mut pending_submit_trace = Vec::with_capacity(batch_size);
    ring.sync(false);
    completion.sync(false);
    write_ring_health_state(
        &format!("/tmp/xdp_tx_ring_health_q{}.start", queue_id.0),
        &format!(
            "queue={}\ntx_pending={}\ntx_cap={}\ntx_free={}\ntx_prod_idx={}\ntx_cons_idx={}\ncompletion_backlog={}\ncompletion_cap={}\ncompletion_prod_idx={}\ncompletion_cons_idx={}\numem_avail={}\n",
            queue_id.0,
            tx_capacity.saturating_sub(ring.available()),
            tx_capacity,
            ring.available(),
            ring.producer_index(),
            ring.consumer_index(),
            completion.available(),
            completion_capacity,
            completion.producer_index(),
            completion.consumer_index(),
            umem.available()
        ),
    );
    let mut tx_peak_used = 0usize;
    let mut tx_last_non_zero_used = 0usize;
    let mut tx_pending_sampled = 0usize;
    let mut comp_peak_used = 0usize;
    let mut comp_last_non_zero_used = 0usize;
    let mut batch_destinations: Option<Destinations> = None;
    let flush_pending_submit = |pending_submit_hist: &mut Vec<u64>,
                                pending_submit_trace: &mut Vec<PendingTxTrace>,
                                lat_hist: &mut LatencyHist| {
        if hist_enabled {
            for deq_start in pending_submit_hist.drain(..) {
                lat_hist.record_ns(clock.elapsed_ns(deq_start, fast_now()));
            }
        } else {
            pending_submit_hist.clear();
        }

        for trace in pending_submit_trace.drain(..) {
            // Trace flag already verified on RX side — no Mutex needed here.
            info!(
                "TX_SUBMIT: q={:?} {}:{} -> {}:{} payload_len={} frame_len={} sig32={:08x} t_ns={}",
                queue_id,
                src_ip,
                src_port,
                trace.dst_ip,
                trace.dst_port,
                trace.payload_len,
                trace.frame_len,
                trace.sig32,
                trace.t_ns
            );
        }
    };

    let mut timeouts = 0;
    loop {
        match receiver.try_recv_payload() {
            Ok(payload) => {
                let now_ticks = fast_now();
                let payload_len = payload.as_ref().len();
                // Use trace flag from RX side — no Mutex, no sig32 recomputation.
                let (deq_sig32, trace_sampled) = match payload.trace_sig32() {
                    Some(sig) => (sig, true),
                    None => (0, false),
                };
                let verbose_trace = trace_sampled && xdp_verbose_trace_enabled();
                let deq_start = now_ticks;
                if batched_items.is_empty() {
                    batch_started_at = Some(deq_start);
                    batch_destinations = Some(Destinations::from(unioned_dest_sockets.load_full()));
                }
                let batch_fanout = batch_destinations
                    .as_ref()
                    .map(Destinations::len)
                    .unwrap_or(0);
                tx_total += 1;
                tx_since_log += 1;
                if clock.elapsed_ticks(last_tx_log, now_ticks) >= one_sec_ticks {
                    info!("TX_LOOP: batch={} total={}", tx_since_log, tx_total);
                    ring.sync(false);
                    completion.sync(false);
                    let completion_backlog = completion.available();
                    tx_peak_used = tx_peak_used.max(tx_pending_sampled);
                    comp_peak_used = comp_peak_used.max(completion_backlog);
                    if tx_pending_sampled > 0 {
                        tx_last_non_zero_used = tx_pending_sampled;
                    }
                    if completion_backlog > 0 {
                        comp_last_non_zero_used = completion_backlog;
                    }
                    write_ring_health_state(
                        &format!("/tmp/xdp_tx_ring_health_q{}.state", queue_id.0),
                        &format!(
                            "queue={}\ntx_pending={}\ntx_cap={}\ntx_free={}\ntx_peak_used={}\ntx_last_non_zero_used={}\ntx_prod_idx={}\ntx_cons_idx={}\ncompletion_backlog={}\ncompletion_cap={}\ncomp_peak_used={}\ncomp_last_non_zero_used={}\ncompletion_prod_idx={}\ncompletion_cons_idx={}\numem_avail={}\n",
                            queue_id.0,
                            tx_pending_sampled,
                            tx_capacity,
                            tx_capacity.saturating_sub(tx_pending_sampled),
                            tx_peak_used,
                            tx_last_non_zero_used,
                            ring.producer_index(),
                            ring.consumer_index(),
                            completion_backlog,
                            completion_capacity,
                            comp_peak_used,
                            comp_last_non_zero_used,
                            completion.producer_index(),
                            completion.consumer_index(),
                            umem.available()
                        ),
                    );
                    tx_since_log = 0;
                    last_tx_log = now_ticks;
                }
                if verbose_trace {
                    let trace_ns = now_monotonic_ns();
                    info!(
                        "TX_DEQ: q={:?} fanout={} payload_len={} sig32={:08x} t_ns={}",
                        queue_id, batch_fanout, payload_len, deq_sig32, trace_ns
                    );
                }
                batched_packets += batch_fanout;
                batched_items.push((payload, deq_start));
                timeouts = 0;
                let age_expired = batch_started_at
                    .map(|t| clock.elapsed_ticks(t, now_ticks) >= max_batch_age_ticks)
                    .unwrap_or(false);
                if batched_packets < batch_size && !age_expired {
                    continue;
                }
            }
            Err(TxPayloadRecvError::Empty) => {
                if !batched_items.is_empty() {
                    let now_ticks = fast_now();
                    let age_expired = batch_started_at
                        .map(|t| clock.elapsed_ticks(t, now_ticks) >= max_batch_age_ticks)
                        .unwrap_or(false);
                    if age_expired {
                        // Flush partial batch if it waited too long.
                    } else {
                        if timeouts < MAX_TIMEOUTS {
                            timeouts += 1;
                            thread::sleep(RECV_TIMEOUT);
                        } else {
                            timeouts = 0;
                            // we haven't received anything in a while, kick the driver
                            ring.commit();
                            kick(&ring);
                            flush_pending_submit(
                                &mut pending_submit_hist,
                                &mut pending_submit_trace,
                                &mut lat_hist,
                            );
                        }
                        continue;
                    }
                } else if timeouts < MAX_TIMEOUTS {
                    timeouts += 1;
                    thread::sleep(RECV_TIMEOUT);
                    continue;
                } else {
                    timeouts = 0;
                    // we haven't received anything in a while, kick the driver
                    ring.commit();
                    kick(&ring);
                    flush_pending_submit(
                        &mut pending_submit_hist,
                        &mut pending_submit_trace,
                        &mut lat_hist,
                    );
                    continue;
                }
            }
            Err(TxPayloadRecvError::Disconnected) => {
                // keep looping until we've flushed all the packets
                if batched_items.is_empty() {
                    break;
                }
            }
        };

        // this is the number of packets after which we commit the ring and kick the driver if
        // necessary
        let mut chunk_remaining = batch_size.min(batched_packets);
        let addrs = batch_destinations
            .take()
            .unwrap_or_else(|| Destinations::from(unioned_dest_sockets.load_full()));
        for (payload, deq_start) in batched_items.drain(..) {
            // Use trace flag from RX side — no Mutex, no sig32 recomputation.
            let (trace_sig32, trace_sampled) = match payload.trace_sig32() {
                Some(sig) => (sig, true),
                None => (0, false),
            };
            let verbose_trace = trace_sampled && xdp_verbose_trace_enabled();
            addrs.for_each(|addr| {
                if ring.available() == 0 || umem.available() == 0 {
                    // Flush any pending producer descriptors before waiting for completions.
                    // Without this, pending-but-uncommitted TX frames can silently starve progress.
                    ring.commit();
                    kick(&ring);
                    flush_pending_submit(
                        &mut pending_submit_hist,
                        &mut pending_submit_trace,
                        &mut lat_hist,
                    );
                    let wait_start = fast_now();
                    let mut wait_iters: u64 = 0;
                    // loop until we have space for the next packet
                    loop {
                        completion.sync(true);
                        // we haven't written any frames so we only need to sync the consumer position
                        ring.sync(false);

                        // check if any frames were completed
                        while let Some(frame_offset) = completion.read() {
                            umem.release(frame_offset);
                        }

                        if ring.available() > 0 && umem.available() > 0 {
                            // we have space for the next packet, break out of the loop
                            break;
                        }

                        wait_iters = wait_iters.saturating_add(1);
                        let now_ticks = fast_now();
                        if clock.elapsed_ticks(wait_start, now_ticks) >= wait_warn_ticks
                            && wait_iters % 10_000 == 0
                        {
                            warn!(
                                "TX_WAIT: q={:?} stalled_ms={} ring_avail={}/{} umem_avail={} tx_total={}",
                                queue_id,
                                clock.elapsed_millis(wait_start, now_ticks),
                                ring.available(),
                                ring.capacity(),
                                umem.available(),
                                tx_total
                            );
                        }

                        // In full-ring stall state, always force wake. On ixgbe/SKB, NEEDS_WAKEUP
                        // can be stale and kick() can become a no-op indefinitely.
                        force_wake(&ring);
                    }
                }

                // at this point we're guaranteed to have a frame to write the next packet into and
                // a slot in the ring to submit it
                let mut frame = umem.reserve().unwrap();
                let IpAddr::V4(dst_ip) = addr.ip() else {
                    panic!("IPv6 not supported");
                };

                let dest_mac_opt = if let Some(mac) = dest_mac {
                    Some(mac)
                } else {
                    let next_hop = router.route(addr.ip()).unwrap();

                    // sanity check that the address is routable through our NIC
                    // if next_hop.if_index != dev.if_index() {
                    //     log::warn!(
                    //         "dropping packet: turbine peer {addr} must be routed through \
                    //          if_index: {} our if_index: {}",
                    //         next_hop.if_index,
                    //         dev.if_index()
                    //     );
                    // }

                    if next_hop.mac_addr.is_none() {
                        log::warn!(
                            "dropping packet: turbine peer {addr} must be routed through {} which \
                             has no known MAC address",
                            next_hop.ip_addr
                        );
                    }

                    next_hop.mac_addr
                };

                if dest_mac_opt.is_none() {
                    batched_packets -= 1;
                    umem.release(frame.offset());
                } else {
                    let dest_mac = dest_mac_opt.unwrap();

                    const PACKET_HEADER_SIZE: usize =
                        ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;

                    let len = payload.as_ref().len();
                    frame.set_len(PACKET_HEADER_SIZE + len);
                    let packet = umem.map_frame_mut(&frame);

                    // write the payload first as it's needed for checksum calculation (if enabled)
                    packet[PACKET_HEADER_SIZE..][..len].copy_from_slice(payload.as_ref());

                    write_eth_header(
                        &mut packet[..ETH_HEADER_SIZE],
                        &src_mac.0,
                        &dest_mac.0,
                    );

                    write_ip_header(
                        &mut packet[ETH_HEADER_SIZE..],
                        &src_ip,
                        &dst_ip,
                        (UDP_HEADER_SIZE + len) as u16,
                    );

                    write_udp_header(
                        &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
                        &src_ip,
                        src_port,
                        &dst_ip,
                        addr.port(),
                        len as u16,
                        // don't do checksums
                        false,
                    );

                    if verbose_trace {
                        let sig32 = trace_sig32;
                        info!(
                            "TX_PKT: q={:?} {}:{} -> {}:{} payload_len={} frame_len={} sig32={:08x} t_ns={}",
                            queue_id,
                            src_ip,
                            src_port,
                            dst_ip,
                            addr.port(),
                            len,
                            PACKET_HEADER_SIZE + len,
                            sig32,
                            now_monotonic_ns()
                        );
                    }
                    // write the packet into the ring
                    ring.write(frame, 0)
                        .map_err(|_| "ring full")
                        // this should never happen as we check for available slots above
                        .expect("failed to write to ring");

                    // Capture t_ns at ring-write time, not at log time,
                    // so logger contention doesn't inflate measured latency.
                    if trace_sampled {
                        pending_submit_trace.push(PendingTxTrace {
                            dst_ip,
                            dst_port: addr.port(),
                            payload_len: len,
                            frame_len: PACKET_HEADER_SIZE + len,
                            sig32: trace_sig32,
                            t_ns: now_monotonic_ns(),
                        });
                    }
                    let tx_pending_now = tx_capacity.saturating_sub(ring.available());
                    tx_pending_sampled = tx_pending_now;
                    tx_peak_used = tx_peak_used.max(tx_pending_now);
                    if tx_pending_now > 0 {
                        tx_last_non_zero_used = tx_pending_now;
                    }
                    if hist_enabled {
                        pending_submit_hist.push(deq_start);
                    }

                    batched_packets -= 1;
                    chunk_remaining -= 1;

                    // check if it's time to commit the ring and kick the driver
                    if chunk_remaining == 0 {
                        chunk_remaining = batch_size.min(batched_packets);

                        // commit new frames
                        ring.commit();
                        kick(&ring);
                        flush_pending_submit(
                            &mut pending_submit_hist,
                            &mut pending_submit_trace,
                            &mut lat_hist,
                        );
                    }
                }
            });
            drop_payload(payload);
        }
        batch_started_at = None;
        let now_ticks = fast_now();
        if hist_enabled
            && clock.elapsed_ticks(last_lat_log, now_ticks) >= one_sec_ticks
            && lat_hist.samples > 0
        {
            info!(
                "PIPELINE_LAT: mode=xdp stage=deq_to_txsubmit samples={} min_us={} p50_us={} p90_us={} p99_us={} avg_us={} max_us={}",
                lat_hist.samples,
                lat_hist.min_us,
                lat_hist.percentile_us(50),
                lat_hist.percentile_us(90),
                lat_hist.percentile_us(99),
                lat_hist.avg_us(),
                lat_hist.max_us
            );
            lat_hist.reset();
            last_lat_log = now_ticks;
        }
        // Flush any leftover descriptors for partial batches so TX progress doesn't wait
        // for timeout path.
        ring.commit();
        kick(&ring);
        flush_pending_submit(
            &mut pending_submit_hist,
            &mut pending_submit_trace,
            &mut lat_hist,
        );
        debug_assert_eq!(batched_packets, 0);
    }
    debug_assert_eq!(batched_packets, 0);
    if tx_since_log > 0 {
        info!("TX_LOOP: batch={} total={}", tx_since_log, tx_total);
    }

    // drain the ring
    while umem.available() < umem_tx_capacity || ring.available() < ring.capacity() {
        log::debug!(
            "draining xdp ring umem {}/{} ring {}/{}",
            umem.available(),
            umem_tx_capacity,
            ring.available(),
            ring.capacity()
        );

        completion.sync(true);
        while let Some(frame_offset) = completion.read() {
            umem.release(frame_offset);
        }

        ring.sync(false);
        kick(&ring);
    }
}
