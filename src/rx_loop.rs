use std::{
    cell::RefCell,
    collections::{HashMap, hash_map::IterMut},
    env, mem,
    net::{IpAddr, Ipv4Addr},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};

use aya::Ebpf;
use bytes::{Buf, Bytes};
use caps::{
    CapSet,
    Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
};
use crc32fast::Hasher;
use crossbeam_channel::Sender;
use libc::{_SC_PAGESIZE, CLOCK_MONOTONIC, clock_gettime, sysconf, timespec};
use log::{info, warn};

use crate::{
    device::{NetworkDevice, QueueId, RingSizes, RxFillRing, XdpDesc},
    netlink::MacAddress,
    packet::{ETH_HEADER_SIZE, IP_HEADER_SIZE, UDP_HEADER_SIZE},
    set_cpu_affinity,
    socket::{Rx, RxRing, Socket},
    tx_loop::TracedPayload,
    umem::{Frame, FrameOffset, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem},
};
const BATCH_SIZE: usize = 512;
const XDP_TRACE_KEY_PREFIX_BYTES: usize = 64;
const XDP_TRACE_HASH_OFFSET_BASIS: u32 = 0x811c_9dc5;
const XDP_TRACE_HASH_PRIME: u32 = 0x0100_0193;
const DOUBLEZERO_GRE_PAYLOAD_OFFSET: usize = ETH_HEADER_SIZE + 20 + 4 + 20 + UDP_HEADER_SIZE;
const DOUBLEZERO_GRE_HDR_LEN: usize = 4;
const ETH_P_IPV4: u16 = 0x0800;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_UDP: u8 = 17;
const GRE_PROTO_IPV4: u16 = 0x0800;
static XDP_PACKET_TRACE_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static XDP_VERBOSE_TRACE_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static XDP_PACKET_TRACE_MAX: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
static XDP_PACKET_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static XDP_PACKET_TRACE_SAMPLES: std::sync::OnceLock<Mutex<HashMap<(u32, usize), u64>>> =
    std::sync::OnceLock::new();
static RX_PATH_BENCH_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
static XDP_RX_HOT_PATH_OBSERVABILITY_ENABLED: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();

struct PendingRxTrace {
    sig32: u32,
    frame_len: usize,
    rx_ns: u128,
}

struct RxReadBatch {
    available: usize,
    avail_before_read_batch: usize,
    read_start_ns: u128,
}

/// Flush buffered RX trace records: sampling bookkeeping and logging happen
/// here, outside the per-packet hot path.
fn flush_pending_rx_traces(pending: &mut Vec<PendingRxTrace>, queue_id: QueueId) {
    for trace in pending.drain(..) {
        // Record in the sample tracker (Mutex acquisition is fine here,
        // outside the packet processing loop).
        let key = (trace.sig32, trace.frame_len);
        {
            let mut guard = packet_trace_samples().lock().unwrap();
            let entry = guard.entry(key).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        info!(
            "RX_PKT: q={:?} payload_len={} sig32={:08x} t_ns={}",
            queue_id, trace.frame_len, trace.sig32, trace.rx_ns
        );
    }
}

fn rx_loop_v1_read_descriptors<const N: usize>(
    rx_ring: &mut RxRing,
    descs: &mut [XdpDesc; N],
    need_rx_timestamp: bool,
) -> RxReadBatch {
    rx_ring.sync(false);
    let avail_before_read_batch = rx_ring.available();
    // Timestamp before read_batch when packets are visible, so it
    // reflects ring-ready time, not post-descriptor-copy time.
    // Skip the syscall when ring is empty to avoid the clock_gettime
    // hotspot on empty polls.
    let ts_before = if need_rx_timestamp && avail_before_read_batch > 0 {
        now_monotonic_ns()
    } else {
        0
    };
    let available = rx_ring.read_batch(descs).unwrap_or(0);
    // Use pre-read timestamp when we saw availability; fall back to
    // now only for the race where available() was 0 but read_batch
    // returned packets.
    let read_start_ns = if need_rx_timestamp && available > 0 && ts_before == 0 {
        now_monotonic_ns()
    } else {
        ts_before
    };

    RxReadBatch {
        available,
        avail_before_read_batch,
        read_start_ns,
    }
}

fn rx_loop_v1_account_rx_batch(available: usize, total_rx: &mut u64, rx_packet_count: &AtomicU64) {
    if available > 0 {
        *total_rx = total_rx.saturating_add(available as u64);
        rx_packet_count.fetch_add(available as u64, AtomicOrdering::Relaxed);
    }
}

unsafe fn rx_loop_v1_process_bulk<S: RxPayloadSink>(
    descs: &[XdpDesc],
    frames: &mut [FrameOffset],
    umem_base: *const u8,
    umem: &mut SliceUmem<'_>,
    payload_sink: &mut S,
    read_start_ns: u128,
    pending_rx_traces: &mut Vec<PendingRxTrace>,
) -> usize {
    let mut recycled = 0usize;
    for (chunk, frame) in descs.chunks_exact(4).zip(frames.chunks_mut(4)) {
        unsafe {
            let p0 = umem_base.add(chunk[0].addr as usize);
            let p1 = umem_base.add(chunk[1].addr as usize);
            let p2 = umem_base.add(chunk[2].addr as usize);
            let p3 = umem_base.add(chunk[3].addr as usize);

            payload_sink.handle_packet(p0, chunk[0].len as usize, read_start_ns, pending_rx_traces);
            payload_sink.handle_packet(p1, chunk[1].len as usize, read_start_ns, pending_rx_traces);
            payload_sink.handle_packet(p2, chunk[2].len as usize, read_start_ns, pending_rx_traces);
            payload_sink.handle_packet(p3, chunk[3].len as usize, read_start_ns, pending_rx_traces);

            umem.release(FrameOffset(chunk[0].addr as usize));
            umem.release(FrameOffset(chunk[1].addr as usize));
            umem.release(FrameOffset(chunk[2].addr as usize));
            umem.release(FrameOffset(chunk[3].addr as usize));

            frame[0] = FrameOffset(chunk[0].addr as usize);
            frame[1] = FrameOffset(chunk[1].addr as usize);
            frame[2] = FrameOffset(chunk[2].addr as usize);
            frame[3] = FrameOffset(chunk[3].addr as usize);
        }
        recycled += 4;
    }
    recycled
}

unsafe fn rx_loop_v1_process_tail<S: RxPayloadSink>(
    descs: &[XdpDesc],
    frames: &mut [FrameOffset],
    recycled: &mut usize,
    umem_base: *const u8,
    umem: &mut SliceUmem<'_>,
    payload_sink: &mut S,
    read_start_ns: u128,
    pending_rx_traces: &mut Vec<PendingRxTrace>,
) {
    for d in descs {
        unsafe {
            let p = umem_base.add(d.addr as usize);
            payload_sink.handle_packet(p, d.len as usize, read_start_ns, pending_rx_traces);
        }
        let off = FrameOffset(d.addr as usize);
        umem.release(off);
        frames[*recycled] = off;
        *recycled += 1;
    }
}

fn rx_loop_v1_sync_payload_sink<S: RxPayloadSink>(payload_sink: &mut S, available: usize) {
    if available > 0 {
        payload_sink.sync();
    }
}

fn rx_loop_v1_flush_rx_traces(pending_rx_traces: &mut Vec<PendingRxTrace>, queue_id: QueueId) {
    if !pending_rx_traces.is_empty() {
        flush_pending_rx_traces(pending_rx_traces, queue_id);
    }
}

fn rx_loop_v1_refill_ring<'a>(
    fill_ring: &mut RxFillRing<SliceUmemFrame<'a>>,
    umem: &mut SliceUmem<'a>,
    frames: &[FrameOffset],
) -> usize {
    fill_ring.write_batch(umem, frames).unwrap_or(0)
}

#[derive(Default)]
struct RxBenchHist {
    samples: u64,
    sum_ns: u128,
    min_ns: u64,
    max_ns: u64,
    values_ns: Vec<u64>,
}

impl RxBenchHist {
    fn record_ns(&mut self, ns: u64) {
        self.samples = self.samples.saturating_add(1);
        self.sum_ns = self.sum_ns.saturating_add(ns as u128);
        self.values_ns.push(ns);
        if self.samples == 1 {
            self.min_ns = ns;
            self.max_ns = ns;
        } else {
            self.min_ns = self.min_ns.min(ns);
            self.max_ns = self.max_ns.max(ns);
        }
    }

    fn percentile_ns(&self, pct: u64) -> u64 {
        if self.values_ns.is_empty() {
            return 0;
        }
        let mut values = self.values_ns.clone();
        values.sort_unstable();
        let idx = values
            .len()
            .saturating_mul(pct as usize)
            .div_ceil(100)
            .saturating_sub(1)
            .min(values.len().saturating_sub(1));
        values[idx]
    }

    fn avg_ns(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            (self.sum_ns / self.samples as u128) as u64
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
struct RxBenchState {
    end_to_chan_hist: RxBenchHist,
    cumulative_hist: RxBenchHist,
    packets: u64,
    drops: u64,
    cumulative_packets: u64,
    cumulative_drops: u64,
    last_log: Option<Instant>,
}

thread_local! {
    static RX_BENCH_STATE: RefCell<RxBenchState> = RefCell::new(RxBenchState::default());
}

#[inline(always)]
fn rx_path_bench_enabled() -> bool {
    *RX_PATH_BENCH_ENABLED.get_or_init(|| {
        env::var("RX_PATH_BENCH")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

#[inline(always)]
fn xdp_rx_hot_path_observability_enabled() -> bool {
    *XDP_RX_HOT_PATH_OBSERVABILITY_ENABLED.get_or_init(|| {
        env::var("XDP_RX_HOT_PATH_OBSERVABILITY")
            .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(true)
    })
}

#[inline]
fn write_ring_health_state(path: &str, payload: &str) {
    let tmp = format!("{path}.tmp");
    let _ = std::fs::write(&tmp, payload);
    let _ = std::fs::rename(tmp, path);
}

#[inline(always)]
fn rx_path_bench_record(end_to_chan_ns: u64, dropped: bool) {
    RX_BENCH_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.end_to_chan_hist.record_ns(end_to_chan_ns.max(1));
        state.cumulative_hist.record_ns(end_to_chan_ns.max(1));
        state.packets = state.packets.saturating_add(1);
        state.cumulative_packets = state.cumulative_packets.saturating_add(1);
        if dropped {
            state.drops = state.drops.saturating_add(1);
            state.cumulative_drops = state.cumulative_drops.saturating_add(1);
        }
        let now = Instant::now();
        let should_log = match state.last_log {
            Some(t) => now.duration_since(t) >= Duration::from_secs(1),
            None => true,
        };
        if should_log && state.end_to_chan_hist.samples > 0 {
            log::info!(
                "RX_PATH_BENCH: mode=xdp_rx_loop_v1 stage=xdp_entry_to_crossbeam_send samples={} window_samples={} packets={} window_packets={} drops={} window_drops={} min_ns={} p50_ns={} p90_ns={} p95_ns={} p99_ns={} avg_ns={} max_ns={}",
                state.cumulative_hist.samples,
                state.end_to_chan_hist.samples,
                state.cumulative_packets,
                state.packets,
                state.cumulative_drops,
                state.drops,
                state.cumulative_hist.min_ns,
                state.cumulative_hist.percentile_ns(50),
                state.cumulative_hist.percentile_ns(90),
                state.cumulative_hist.percentile_ns(95),
                state.cumulative_hist.percentile_ns(99),
                state.cumulative_hist.avg_ns(),
                state.cumulative_hist.max_ns,
            );
            state.end_to_chan_hist.reset();
            state.packets = 0;
            state.drops = 0;
            state.last_log = Some(now);
        }
    });
}

#[inline(always)]
fn packet_trace_enabled() -> bool {
    *XDP_PACKET_TRACE_ENABLED.get_or_init(|| {
        env::var("XDP_PACKET_TRACE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

#[inline(always)]
pub(crate) fn xdp_verbose_trace_enabled() -> bool {
    *XDP_VERBOSE_TRACE_ENABLED.get_or_init(|| {
        env::var("XDP_VERBOSE_TRACE")
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
fn packet_trace_samples() -> &'static Mutex<HashMap<(u32, usize), u64>> {
    XDP_PACKET_TRACE_SAMPLES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[inline(always)]
fn sample_xdp_packet(payload: &[u8]) -> Option<u32> {
    if !should_log_packet_trace() {
        return None;
    }
    let sig32 = payload_sig32(payload);
    let key = (sig32, payload.len());
    let mut guard = packet_trace_samples().lock().unwrap();
    let entry = guard.entry(key).or_insert(0);
    *entry = entry.saturating_add(1);
    Some(sig32)
}

#[inline(always)]
pub(crate) fn xdp_packet_is_sampled(sig32: u32, len: usize) -> bool {
    packet_trace_samples()
        .lock()
        .unwrap()
        .get(&(sig32, len))
        .copied()
        .unwrap_or(0)
        > 0
}

#[inline(always)]
pub(crate) fn consume_xdp_packet_sample(sig32: u32, len: usize) -> bool {
    let key = (sig32, len);
    let mut guard = packet_trace_samples().lock().unwrap();
    if let Some(count) = guard.get_mut(&key) {
        if *count > 1 {
            *count -= 1;
        } else {
            guard.remove(&key);
        }
        true
    } else {
        false
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

#[inline(always)]
fn payload_sig32(payload: &[u8]) -> u32 {
    let payload = doublezero_inner_udp_payload(payload).unwrap_or(payload);
    let mut sig32 = XDP_TRACE_HASH_OFFSET_BASIS;
    for &b in payload.iter().take(XDP_TRACE_KEY_PREFIX_BYTES) {
        sig32 ^= b as u32;
        sig32 = sig32.wrapping_mul(XDP_TRACE_HASH_PRIME);
    }
    sig32
}

#[inline(always)]
fn doublezero_inner_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < DOUBLEZERO_GRE_PAYLOAD_OFFSET {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return None;
    }
    if frame[ETH_HEADER_SIZE] != 0x45 || frame[ETH_HEADER_SIZE + 9] != 47 {
        return None;
    }
    let gre_start = ETH_HEADER_SIZE + 20;
    if u16::from_be_bytes([frame[gre_start], frame[gre_start + 1]]) != 0
        || u16::from_be_bytes([frame[gre_start + 2], frame[gre_start + 3]]) != 0x0800
    {
        return None;
    }
    let inner_ip_start = gre_start + 4;
    if frame[inner_ip_start] != 0x45 || frame[inner_ip_start + 9] != 17 {
        return None;
    }
    Some(&frame[DOUBLEZERO_GRE_PAYLOAD_OFFSET..])
}

#[allow(clippy::too_many_arguments)]
pub fn rx_loop<T: AsRef<[u8]>>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    sender: Sender<Vec<u8>>,
    // drop_sender: Sender<Vec<u8>>,
    bpf_opt: Option<&mut Ebpf>,
) {
    log::info!(
        "starting xdp rx loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );
    if rx_path_bench_enabled() {
        log::info!("RX_PATH_BENCH enabled for mode=xdp_rx_loop_v1");
    }

    set_cpu_affinity([cpu_id]).unwrap();

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

    let frame_count = (rx_size + tx_size) * 2;

    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let Ok((mut socket, rx)) = Socket::rx(queue, umem, zero_copy, rx_size, rx_size) else {
        panic!("failed to create AF_XDP socket on queue {queue_id:?}");
    };

    // Register this socket in xsks_map for its queue so XDP_REDIRECT can deliver packets
    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");
    } else {
        log::warn!(
            "RX_LOOP: no eBPF handle provided; cannot populate xsks_map - packets will not be redirected!"
        );
    }

    let umem = socket.umem();

    let Rx {
        mut fill,
        ring: rx_ring,
    } = rx;

    let mut rx_ring = rx_ring.unwrap();

    // kick(&fill);

    // we don't need higher caps anymore
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    rx_ring.sync(false);

    loop {
        // let batch_start = Instant::now();
        fill.sync(true);
        // log::info!("RX_LOOP: available: {}", rx_ring.available());
        let refill_threshold = rx_ring.available().min(BATCH_SIZE);
        let mut packets_to_consume = rx_ring.available();
        // .min(BATCH_SIZE);
        // kick(&fill);

        while packets_to_consume > 0 {
            let Some(desc) = rx_ring.read() else {
                continue;
            };
            packets_to_consume -= 1;

            let frame =
                umem.frame_from_offset_len(FrameOffset(desc.addr as usize), desc.len as usize);
            let bytes = umem.map_frame(&frame);
            // info!("received packet from xdp {:?}", bytes.len());

            sender.try_send(bytes.to_vec()).unwrap();
            umem.release(FrameOffset(desc.addr as usize));
        }

        rx_ring.sync(true);
        top_up_fill_exact(&mut fill, umem, refill_threshold);

        kick(&fill);

        fill.sync(true);
    }
}

pub fn rx_loop_batched<T: AsRef<[u8]>>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    sender: Sender<Bytes>, // one batch per send
    bpf_opt: Option<&mut Ebpf>,
) {
    log::info!(
        "starting xdp rx loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    set_cpu_affinity([cpu_id]).unwrap();

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

    let frame_count = (rx_size + tx_size) * 2;

    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| PageAlignedMemory::alloc(frame_size, frame_count))
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let (mut socket, rx) = match Socket::rx(queue, umem, zero_copy, rx_size * 2, rx_size) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "AF_XDP Socket::rx failed on queue {:?}: kind={:?} raw_os_error={:?} err={:?}",
                queue_id,
                e.kind(),
                e.raw_os_error(),
                e
            );
            panic!("failed to create AF_XDP socket on queue {queue_id:?}");
        }
    };

    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");

        // log::info!("Maps in bpf object:");
        // for (name, map) in bpf.maps() {
        //     log::info!("  {} -> id {:?}", name, map);
        // }
    } else {
        log::warn!(
            "RX_LOOP: no eBPF handle provided; cannot populate xsks_map - packets will not be redirected!"
        );
    }

    let umem = socket.umem();

    let Rx {
        fill: mut fill_ring,
        ring: rx_ring,
    } = rx;

    let mut rx_ring = rx_ring.unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    let umem_base = umem.as_ptr();

    let mut descs: [XdpDesc; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut frames: [FrameOffset; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    // if rx_ring.available() == 0 {
    kick(&fill_ring);
    // }

    // let packet_handler = |bytes: *const u8, len: usize| {
    //     let byte_slice = unsafe { std::slice::from_raw_parts(bytes, len) };
    //     let bytes = bytes::Bytes::copy_from_slice(byte_slice);
    //     let _ = sender.try_send(bytes);
    // };

    // rx_ring.sync(true);
    // let mut wakeup_count = 0;
    loop {
        // fill_ring.sync(true);
        // log::info!("RX_LOOP: read {} packets", rx_ring.available());
        let available = rx_ring.read_batch(&mut descs).unwrap_or(0);

        let mut recycled = 0usize;
        for (chunk, frame) in descs[..available]
            .chunks_exact(4)
            .zip(frames[..available].chunks_mut(4))
        {
            unsafe {
                let p0 = umem_base.add(chunk[0].addr as usize);
                let p1 = umem_base.add(chunk[1].addr as usize);
                let p2 = umem_base.add(chunk[2].addr as usize);
                let p3 = umem_base.add(chunk[3].addr as usize);

                // info!("RX_LOOP: sending packet from xdp {:?}", chunk[0].len as usize);

                handle_packet::<Bytes>(p0, chunk[0].len as usize, &sender);
                handle_packet::<Bytes>(p1, chunk[1].len as usize, &sender);
                handle_packet::<Bytes>(p2, chunk[2].len as usize, &sender);
                handle_packet::<Bytes>(p3, chunk[3].len as usize, &sender);
                // packet_handler(p0, chunk[0].len as usize);
                // packet_handler(p1, chunk[1].len as usize);
                // packet_handler(p2, chunk[2].len as usize);
                // packet_handler(p3, chunk[3].len as usize);

                // lets try to release the frames and then reserve to avoid packet corruption
                umem.release(FrameOffset(chunk[0].addr as usize));
                umem.release(FrameOffset(chunk[1].addr as usize));
                umem.release(FrameOffset(chunk[2].addr as usize));
                umem.release(FrameOffset(chunk[3].addr as usize));

                frame[0] = FrameOffset(chunk[0].addr as usize);
                frame[1] = FrameOffset(chunk[1].addr as usize);
                frame[2] = FrameOffset(chunk[2].addr as usize);
                frame[3] = FrameOffset(chunk[3].addr as usize);
            }
            recycled += 4;
        }

        // for chunk in &descs[..available] {
        //     unsafe {
        //         let p0 = umem_base.add(chunk.addr as usize);
        //         packet_handler(p0, chunk.len as usize);
        //         umem.release(FrameOffset(chunk.addr as usize));
        //     }
        // }

        for d in &descs[recycled..available] {
            unsafe {
                let p = umem_base.add(d.addr as usize);
                handle_packet::<Bytes>(p, d.len as usize, &sender);
            }
            let off = FrameOffset(d.addr as usize);
            umem.release(off);
            frames[recycled] = off;
            recycled += 1;
        }

        if recycled > 0 {
            let _ = fill_ring.write_batch(umem, &frames[..recycled]);
        }

        // if fill_ring.needs_wakeup() {
        //     // wakeup_count += 1;
        //     // info!("RX_LOOP: fill needs wakeup after recycle, waking driver, wakeup count: {}", wakeup_count);
        //     let _ = fill_ring.wake();
        // }
    }
}

pub fn rx_loop_v1(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    sender: Sender<TracedPayload>,
    bpf_opt: Option<&mut Ebpf>,
    ready: Option<Sender<()>>,
    rx_packet_count: Arc<AtomicU64>,
    exit: Arc<AtomicBool>,
) {
    rx_loop_v1_inner(
        cpu_id,
        dev,
        queue_id,
        zero_copy,
        CrossbeamRxPayloadSink { sender },
        bpf_opt,
        ready,
        rx_packet_count,
        exit,
    );
}

pub fn rx_loop_v1_doublezero(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    packet_log_limit: u64,
    bpf_opt: Option<&mut Ebpf>,
    ready: Option<Sender<()>>,
    rx_packet_count: Arc<AtomicU64>,
    exit: Arc<AtomicBool>,
) {
    rx_loop_v1_inner(
        cpu_id,
        dev,
        queue_id,
        zero_copy,
        DoublezeroRxPayloadSink::new(queue_id, packet_log_limit),
        bpf_opt,
        ready,
        rx_packet_count,
        exit,
    );
}

#[allow(clippy::too_many_arguments)]
fn rx_loop_v1_inner<S: RxPayloadSink>(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    mut payload_sink: S,
    bpf_opt: Option<&mut Ebpf>,
    ready: Option<Sender<()>>,
    rx_packet_count: Arc<AtomicU64>,
    exit: Arc<AtomicBool>,
) {
    log::info!(
        "starting xdp rx loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    set_cpu_affinity([cpu_id]).unwrap();

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

    let frame_count = (rx_size + tx_size) * 2;

    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let (mut socket, rx) = match Socket::rx(queue, umem, zero_copy, rx_size * 2, rx_size) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "AF_XDP Socket::rx failed on queue {:?}: kind={:?} raw_os_error={:?} err={:?}",
                queue_id,
                e.kind(),
                e.raw_os_error(),
                e
            );
            panic!("failed to create AF_XDP socket on queue {queue_id:?}");
        }
    };

    // Register this socket in xsks_map for its queue so XDP_REDIRECT can deliver packets.
    // Fail-fast if we cannot arm redirect.
    let mut ready = ready;
    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");
        log::info!("XDP RX armed: xsks_map[{queue_id:?}] set");
        if let Some(ready_tx) = ready.take() {
            let _ = ready_tx.try_send(());
        }
    } else {
        log::error!("RX_LOOP: no eBPF handle provided; cannot populate xsks_map, aborting RX loop");
        for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
            let _ = caps::drop(None, CapSet::Effective, cap);
        }
        return;
    }

    let umem = socket.umem();

    let Rx {
        fill: mut fill_ring,
        ring: rx_ring,
    } = rx;

    let mut rx_ring = rx_ring.unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // Pure RX perf focus: keep the hot loop as read -> copy -> send -> recycle.
    let need_rx_timestamp = packet_trace_enabled() || rx_path_bench_enabled();
    let hot_path_observability = xdp_rx_hot_path_observability_enabled();
    let umem_base = umem.as_ptr();

    let mut descs: [XdpDesc; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut frames: [FrameOffset; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    kick(&fill_ring);
    rx_ring.sync(false);
    fill_ring.sync(false);
    let fill_capacity = fill_ring.capacity();
    let rx_capacity = rx_ring.capacity();
    let fill_mask = fill_capacity.saturating_sub(1);
    let rx_mask = rx_capacity.saturating_sub(1);
    let rx_start_slot = rx_ring.consumer_index() as usize & rx_mask;
    let fill_start_slot = fill_ring.producer_index() as usize & fill_mask;
    if hot_path_observability {
        write_ring_health_state(
            &format!("/tmp/xdp_rx_ring_health_q{}.start", queue_id.0),
            &format!(
                "queue={}\nfill_ready={}\nfill_cap={}\nfill_free={}\nfill_prod_idx={}\nfill_cons_idx={}\nrx_pending={}\nrx_cap={}\nrx_prod_idx={}\nrx_cons_idx={}\nread_batch_calls={}\nread_batch_descs={}\nfill_write_batch_calls={}\nfill_write_batch_descs={}\nread_batch_slot={}\nfill_write_slot={}\nread_batch_before={}\nread_batch_after={}\nread_batch_n={}\nfill_write_before={}\nfill_write_after={}\nfill_write_n={}\n",
                queue_id.0,
                fill_capacity.saturating_sub(fill_ring.available()),
                fill_capacity,
                fill_ring.available(),
                fill_ring.producer_index(),
                fill_ring.consumer_index(),
                rx_ring.available(),
                rx_capacity,
                rx_ring.producer_index(),
                rx_ring.consumer_index(),
                0,
                0,
                0,
                0,
                rx_start_slot,
                fill_start_slot,
                rx_start_slot,
                rx_start_slot,
                0,
                fill_start_slot,
                fill_start_slot,
                0
            ),
        );
    }

    let mut pending_rx_traces: Vec<PendingRxTrace> = Vec::with_capacity(BATCH_SIZE);

    let mut total_rx: u64 = 0;
    let mut last_ring_health = Instant::now();
    let mut fill_peak_used = fill_capacity.saturating_sub(fill_ring.available());
    let mut fill_last_non_zero_used = fill_peak_used;
    let mut fill_last_non_zero_free = fill_ring.available();
    let mut fill_ready_sampled: usize = 0;
    let mut fill_free_sampled: usize = 0;
    let mut rx_peak_used = 0usize;
    let mut rx_last_non_zero_used = 0usize;
    let mut rx_pending_sampled: usize = 0;
    let mut rx_batch_max = 0usize;
    let mut rx_batch_sum = 0u64;
    let mut rx_batch_polls = 0u64;
    let mut read_batch_calls = 0u64;
    let mut read_batch_descs = 0u64;
    let mut fill_write_batch_calls = 0u64;
    let mut fill_write_batch_descs = 0u64;
    let mut read_batch_slot = rx_start_slot;
    let mut read_batch_before: usize = 0;
    let mut read_batch_after: usize = 0;
    let mut read_batch_n: usize = 0;
    let mut fill_write_slot = fill_start_slot;
    let mut fill_write_before: usize = 0;
    let mut fill_write_n: usize = 0;

    loop {
        if exit.load(AtomicOrdering::Relaxed) {
            break;
        }
        let read_batch = rx_loop_v1_read_descriptors(&mut rx_ring, &mut descs, need_rx_timestamp);
        let available = read_batch.available;
        if hot_path_observability {
            read_batch_before = read_batch_slot;
            read_batch_n = available;
            read_batch_after = read_batch_slot.wrapping_add(available) & rx_mask;
            read_batch_slot = read_batch_after;
            read_batch_calls = read_batch_calls.saturating_add(1);
            read_batch_descs = read_batch_descs.saturating_add(available as u64);
            rx_pending_sampled = read_batch.avail_before_read_batch;
            rx_batch_polls = rx_batch_polls.saturating_add(1);
            rx_batch_sum = rx_batch_sum.saturating_add(available as u64);
            rx_batch_max = rx_batch_max.max(available);
            rx_peak_used = rx_peak_used.max(available);
        }

        rx_loop_v1_account_rx_batch(available, &mut total_rx, &rx_packet_count);
        if available > 0 && hot_path_observability {
            rx_last_non_zero_used = available;
        }

        // if available > 0 {
        //     total_rx += available as u64;
        //     rx_packet_count.fetch_add(available as u64, AtomicOrdering::Relaxed);
        //     if last_log.elapsed() >= Duration::from_secs(1) {
        //         let sizes: Vec<u32> = descs[..available.min(8)].iter().map(|d| d.len).collect();
        //         info!("RX_LOOP: total={} batch={} sizes={:?}", total_rx, available, sizes);
        //         last_log = Instant::now();
        //     }
        // }

        let mut recycled = 0usize;
        let bulk = available & !3;
        if bulk > 0 {
            unsafe {
                recycled = rx_loop_v1_process_bulk(
                    &descs[..bulk],
                    &mut frames[..bulk],
                    umem_base,
                    umem,
                    &mut payload_sink,
                    read_batch.read_start_ns,
                    &mut pending_rx_traces,
                );
            }
        }

        // Scalar tail: handle remaining 1-3 packets that chunks_exact(4) skips.
        if bulk != available {
            unsafe {
                rx_loop_v1_process_tail(
                    &descs[bulk..available],
                    &mut frames,
                    &mut recycled,
                    umem_base,
                    umem,
                    &mut payload_sink,
                    read_batch.read_start_ns,
                    &mut pending_rx_traces,
                );
            }
        }

        rx_loop_v1_sync_payload_sink(&mut payload_sink, available);
        rx_loop_v1_flush_rx_traces(&mut pending_rx_traces, queue_id);

        if hot_path_observability {
            fill_ring.sync(false);
            fill_ready_sampled = fill_capacity.saturating_sub(fill_ring.available());
            fill_free_sampled = fill_ring.available();
            fill_peak_used = fill_peak_used.max(fill_ready_sampled);
            if fill_ready_sampled > 0 {
                fill_last_non_zero_used = fill_ready_sampled;
            }
            if fill_free_sampled > 0 {
                fill_last_non_zero_free = fill_free_sampled;
            }

            fill_write_before = fill_write_slot;
            fill_write_n = recycled;
            fill_write_batch_calls = fill_write_batch_calls.saturating_add(1);
            fill_write_batch_descs = fill_write_batch_descs.saturating_add(recycled as u64);
        }
        let wrote = rx_loop_v1_refill_ring(&mut fill_ring, umem, &frames[..recycled]);
        if hot_path_observability {
            fill_write_slot = fill_write_slot.wrapping_add(wrote) & fill_mask;

            rx_ring.sync(false);
            fill_ring.sync(false);
            if last_ring_health.elapsed() >= Duration::from_secs(1) {
                write_ring_health_state(
                    &format!("/tmp/xdp_rx_ring_health_q{}.state", queue_id.0),
                    &format!(
                        "queue={}\nfill_ready={}\nfill_cap={}\nfill_free={}\nfill_peak_used={}\nfill_last_non_zero_used={}\nfill_last_non_zero_free={}\nfill_prod_idx={}\nfill_cons_idx={}\nrx_pending={}\nrx_cap={}\nrx_peak_used={}\nrx_last_non_zero_used={}\nrx_prod_idx={}\nrx_cons_idx={}\nread_batch_calls={}\nread_batch_descs={}\nfill_write_batch_calls={}\nfill_write_batch_descs={}\nread_batch_slot={}\nfill_write_slot={}\nread_batch_before={}\nread_batch_after={}\nread_batch_n={}\nfill_write_before={}\nfill_write_after={}\nfill_write_n={}\nrx_batch_max={}\nrx_batch_avg={:.2}\nrx_batch_polls={}\ntotal_rx={}\n",
                        queue_id.0,
                        fill_ready_sampled,
                        fill_capacity,
                        fill_free_sampled,
                        fill_peak_used,
                        fill_last_non_zero_used,
                        fill_last_non_zero_free,
                        fill_ring.producer_index(),
                        fill_ring.consumer_index(),
                        rx_pending_sampled,
                        rx_capacity,
                        rx_peak_used,
                        rx_last_non_zero_used,
                        rx_ring.producer_index(),
                        rx_ring.consumer_index(),
                        read_batch_calls,
                        read_batch_descs,
                        fill_write_batch_calls,
                        fill_write_batch_descs,
                        read_batch_slot,
                        fill_write_slot,
                        read_batch_before,
                        read_batch_after,
                        read_batch_n,
                        fill_write_before,
                        fill_write_slot,
                        fill_write_n,
                        rx_batch_max,
                        if rx_batch_polls > 0 {
                            rx_batch_sum as f64 / rx_batch_polls as f64
                        } else {
                            0.0
                        },
                        rx_batch_polls,
                        total_rx
                    ),
                );
                last_ring_health = Instant::now();
            }
        }
    }
}

#[inline(always)]
fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE {
        return None;
    }

    let mut l2_len = ETH_HEADER_SIZE;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);

    // Support single/double-tagged VLAN frames.
    while matches!(ether_type, 0x8100 | 0x88A8 | 0x9100) {
        if frame.len() < l2_len + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[l2_len + 2], frame[l2_len + 3]]);
        l2_len += 4;
    }

    // IPv4 only.
    if ether_type != 0x0800 {
        return None;
    }

    if frame.len() < l2_len + IP_HEADER_SIZE + UDP_HEADER_SIZE {
        return None;
    }

    // IPv4 IHL is low nibble in 32-bit words.
    let ihl_words = (frame[l2_len] & 0x0f) as usize;
    if ihl_words < 5 {
        return None;
    }
    let ip_header_len = ihl_words * 4;

    let ip_proto = frame[l2_len + 9];
    if ip_proto != 17 {
        return None;
    }

    let udp_start = l2_len + ip_header_len;
    if frame.len() < udp_start + UDP_HEADER_SIZE {
        return None;
    }

    let udp_len = u16::from_be_bytes([frame[udp_start + 4], frame[udp_start + 5]]) as usize;
    if udp_len < UDP_HEADER_SIZE {
        return None;
    }

    let payload_start = udp_start + UDP_HEADER_SIZE;
    let payload_len = udp_len - UDP_HEADER_SIZE;
    let payload_end = payload_start.checked_add(payload_len)?;
    if payload_end > frame.len() {
        return None;
    }

    Some(&frame[payload_start..payload_end])
}

#[inline(always)]
fn parse_udp_tuple(frame: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16)> {
    if frame.len() < ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE {
        return None;
    }

    let mut l2_len = ETH_HEADER_SIZE;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);

    // Support single/double-tagged VLAN frames.
    while matches!(ether_type, 0x8100 | 0x88A8 | 0x9100) {
        if frame.len() < l2_len + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[l2_len + 2], frame[l2_len + 3]]);
        l2_len += 4;
    }

    if ether_type != 0x0800 {
        return None;
    }

    if frame.len() < l2_len + IP_HEADER_SIZE + UDP_HEADER_SIZE {
        return None;
    }

    let ihl_words = (frame[l2_len] & 0x0f) as usize;
    if ihl_words < 5 {
        return None;
    }
    let ip_header_len = ihl_words * 4;

    let ip_proto = frame[l2_len + 9];
    if ip_proto != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(
        frame[l2_len + 12],
        frame[l2_len + 13],
        frame[l2_len + 14],
        frame[l2_len + 15],
    );
    let dst_ip = Ipv4Addr::new(
        frame[l2_len + 16],
        frame[l2_len + 17],
        frame[l2_len + 18],
        frame[l2_len + 19],
    );

    let udp_start = l2_len + ip_header_len;
    if frame.len() < udp_start + UDP_HEADER_SIZE {
        return None;
    }

    let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);

    Some((src_ip, dst_ip, src_port, dst_port))
}

// #[inline(always)]
// pub fn rx_loop_inner(
//     rx_ring: &mut RxRing,
//     fill_ring: &mut RxFillRing<SliceUmemFrame<'_>>,
//     umem: &mut SliceUmem<'_>,
//     packet_handler: impl Fn(*const u8, usize)
// ) {
//     let umem_base = umem.as_ptr();

//     let mut descs: [XdpDesc; BATCH_SIZE] = unsafe { std::mem::zeroed() };
//     let mut frames: [FrameOffset; BATCH_SIZE] = unsafe { std::mem::zeroed() };

//     loop{
//         rx_ring.sync(false);
//         fill_ring.sync(true);

//         // log::info!("RX_LOOP: read {} packets", rx_ring.available());
//         let available = rx_ring.read_batch(&mut descs, &mut frames).unwrap_or(0);
//         log::info!("RX_LOOP: available: {}", available);
//         // log::info!("RX_LOOP: frames: {:?}", frames.len());

//         // for chunk in descs[..available].chunks_exact(4) {
//         //     unsafe {
//         //         let p0 = umem_base.add(chunk[0].addr as usize);
//         //         let p1 = umem_base.add(chunk[1].addr as usize);
//         //         let p2 = umem_base.add(chunk[2].addr as usize);
//         //         let p3 = umem_base.add(chunk[3].addr as usize);

//         //         packet_handler(p0, chunk[0].len as usize);
//         //         packet_handler(p1, chunk[1].len as usize);
//         //         packet_handler(p2, chunk[2].len as usize);
//         //         packet_handler(p3, chunk[3].len as usize);

//         //         umem.release(FrameOffset(chunk[0].addr as usize));
//         //         umem.release(FrameOffset(chunk[1].addr as usize));
//         //         umem.release(FrameOffset(chunk[2].addr as usize));
//         //         umem.release(FrameOffset(chunk[3].addr as usize));

//         //         frames[0] = FrameOffset(chunk[0].addr as usize);
//         //         frames[1] = FrameOffset(chunk[1].addr as usize);
//         //         frames[2] = FrameOffset(chunk[2].addr as usize);
//         //         frames[3] = FrameOffset(chunk[3].addr as usize);
//         //     }
//         // }

//         // fill_ring.write_batch(&frames);
//         // if fill_ring.needs_wakeup() {
//         //     // info!("RX_LOOP: fill needs wakeup after recycle, waking driver");
//         //     let _ = fill_ring.wake();
//         // }
//     }
// }

fn top_up_fill_exact<'a>(
    fill: &mut RxFillRing<SliceUmemFrame<'a>>,
    umem: &mut SliceUmem<'a>,
    want: usize,
) {
    fill.sync(true);

    let mut pushed = 0usize;
    while pushed < want {
        let Some(f) = umem.reserve() else {
            break;
        };
        let f_offset = f.offset();
        if let Err(_e) = fill.write(f) {
            umem.release(f_offset);
            break;
        }
        pushed += 1;
    }

    if pushed > 0 {
        fill.commit();
    }
}

#[inline(always)]
fn recycle_fill_offsets(fill: &mut RxFillRing<SliceUmemFrame<'_>>, recycled: &[FrameOffset]) {
    if recycled.is_empty() {
        return;
    }

    fill.sync(true);

    let mut pushed = 0usize;
    for &offset in recycled {
        if fill.write_single(offset).is_err() {
            break;
        }
        pushed += 1;
    }

    if pushed > 0 {
        fill.commit();
    }
}

pub fn top_up_fill_try<'a>(
    fill: &mut RxFillRing<SliceUmemFrame<'a>>,
    umem: &mut SliceUmem<'a>,
    chunk: usize,
) {
    fill.sync(true);

    let mut pushed = 0usize;
    for _ in 0..chunk {
        let Some(f) = umem.reserve() else {
            break;
        };
        let f_offset = f.offset();
        if let Err(_e) = fill.write(f) {
            umem.release(f_offset);
            break;
        }
        pushed += 1;
    }

    if pushed > 0 {
        fill.commit();
    }
}

// With some drivers, or always when we work in SKB mode, we need to explicitly kick the driver once
// we want the NIC to do something.
#[inline(always)]
pub fn kick(ring: &RxFillRing<SliceUmemFrame<'_>>) {
    if !ring.needs_wakeup() {
        return;
    }

    if let Err(e) = ring.wake() {
        kick_error(e);
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
        // we should never get here, hopefully the driver recovers?
        _ => {
            log::error!("network interface driver error: {e:?}");
        }
    }
}

pub fn rx_loop_v2(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    sender: Sender<TracedPayload>,
    bpf_opt: Option<&mut Ebpf>,
    ready: Option<Sender<()>>,
    rx_packet_count: Arc<AtomicU64>,
    exit: Arc<AtomicBool>,
) {
    log::info!(
        "starting xdp rx loop v2 on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    set_cpu_affinity([cpu_id]).unwrap();

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

    let frame_count = (rx_size + tx_size) * 2;

    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let (mut socket, rx) = match Socket::rx(queue, umem, zero_copy, rx_size * 2, rx_size) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "AF_XDP Socket::rx failed on queue {:?}: kind={:?} raw_os_error={:?} err={:?}",
                queue_id,
                e.kind(),
                e.raw_os_error(),
                e
            );
            panic!("failed to create AF_XDP socket on queue {queue_id:?}");
        }
    };

    let mut ready = ready;
    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");
        log::info!("XDP RX armed: xsks_map[{queue_id:?}] set");
        if let Some(ready_tx) = ready.take() {
            let _ = ready_tx.try_send(());
        }
    } else {
        log::error!(
            "RX_LOOP_V2: no eBPF handle provided; cannot populate xsks_map, aborting RX loop"
        );
        for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
            let _ = caps::drop(None, CapSet::Effective, cap);
        }
        return;
    }

    let umem = socket.umem();

    let Rx {
        fill: mut fill_ring,
        ring: rx_ring,
    } = rx;

    let mut rx_ring = rx_ring.unwrap();

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    kick(&fill_ring);

    let mut recycled = [FrameOffset(0); BATCH_SIZE];
    let mut recycled_len = 0usize;
    let mut total_rx: u64 = 0;
    let mut last_log = Instant::now();

    loop {
        if exit.load(AtomicOrdering::Relaxed) {
            break;
        }

        rx_ring.sync(true);

        while let Some(desc) = rx_ring.read() {
            let frame =
                umem.frame_from_offset_len(FrameOffset(desc.addr as usize), desc.len as usize);
            let payload = TracedPayload {
                data: Bytes::copy_from_slice(umem.map_frame(&frame)),
                trace_sig32: None,
            };
            sender.try_send(payload).unwrap();

            recycled[recycled_len] = FrameOffset(desc.addr as usize);
            recycled_len += 1;
            total_rx += 1;
            rx_packet_count.fetch_add(1, AtomicOrdering::Relaxed);

            if recycled_len == recycled.len() {
                recycle_fill_offsets(&mut fill_ring, &recycled[..recycled_len]);
                kick(&fill_ring);
                recycled_len = 0;
            }
        }

        if recycled_len > 0 {
            recycle_fill_offsets(&mut fill_ring, &recycled[..recycled_len]);
            kick(&fill_ring);
            recycled_len = 0;
        }

        if last_log.elapsed() >= Duration::from_secs(1) {
            info!("RX_LOOP_V2: total={}", total_rx);
            last_log = Instant::now();
        }
    }
}

#[inline]
pub fn rx_accept(
    _dev: &NetworkDevice,
    packet: &[u8],
    src_ip: Ipv4Addr,
    src_mac: MacAddress,
) -> bool {
    if packet.len() < ETH_HEADER_SIZE + 20 {
        log::warn!("dropping runt packet: only {} bytes", packet.len());
        return false;
    }

    let dst_mac = &packet[0..6];
    if dst_mac != src_mac.as_bytes() {
        return false;
    }

    let pkt_src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[ETH_HEADER_SIZE + 12],
        packet[ETH_HEADER_SIZE + 13],
        packet[ETH_HEADER_SIZE + 14],
        packet[ETH_HEADER_SIZE + 15],
    ));

    let pkt_dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[ETH_HEADER_SIZE + 16],
        packet[ETH_HEADER_SIZE + 17],
        packet[ETH_HEADER_SIZE + 18],
        packet[ETH_HEADER_SIZE + 19],
    ));

    let IpAddr::V4(_) = pkt_src_ip else {
        log::warn!("dropping packet: IPv6 not supported (peer={pkt_src_ip})");
        return false;
    };

    if pkt_dst_ip != IpAddr::V4(src_ip) {
        return false;
    }

    // let Ok(next_hop) = router.route(pkt_src_ip.into()) else {
    //     log::warn!("dropping packet: no route to peer {pkt_src_ip}");
    //     return false;
    // };

    // // // Must route out through our NIC’s queue device.
    // // if next_hop.if_index != dev.if_index() {
    // //     log::warn!(
    // //         "dropping packet: peer {pkt_src_ip} must be routed through if_index: {} our if_index: {}",
    // //         next_hop.if_index,
    // //         dev.if_index(),
    // //     );
    // //     return false;
    // // }

    // // Must have a resolved L2 next-hop.
    // if next_hop.mac_addr.is_none() {
    //     log::warn!(
    //         "dropping packet: peer {pkt_src_ip} must be routed through {} which has no known MAC address",
    //         next_hop.ip_addr
    //     );
    //     return false;
    // }

    true
}

#[inline(always)]
pub unsafe fn parse_ipv4_src(frame: *const u8, len: usize) -> Option<Ipv4Addr> {
    if len < 34 {
        return None; // Ethernet (14) + IPv4 (20)
    }

    // Source IPv4 starts at byte offset 26 from Ethernet header
    // (14 bytes eth + 12 bytes into IPv4 header)
    let src = Ipv4Addr::new(
        unsafe { *frame.add(26) },
        unsafe { *frame.add(27) },
        unsafe { *frame.add(28) },
        unsafe { *frame.add(29) },
    );

    Some(src)
}

const MAGIC: u64 = 0xfeed_beef_cafe_d00d_u64;
const SOLANA_TXN_BYTES: usize = 64;

#[inline(always)]
pub unsafe fn verify_packet(buf: *const u8, len: usize) -> Result<u64, &'static str> {
    if len < 64 {
        log::warn!("verify_packet FAIL: len={} < 64", len);
        return Err("bad_len_too_short");
    }

    let ethertype = u16::from_be_bytes([unsafe { *buf.add(12) }, unsafe { *buf.add(13) }]);
    let mut offset = 14usize;

    if ethertype == 0x8100 {
        offset += 4;
    }

    offset += 20;
    offset += 8;

    if len <= offset {
        log::warn!("verify_packet FAIL: len={} <= offset={}", len, offset);
        return Err("bad_len_offset");
    }
    let payload_len = len - offset;
    if payload_len != SOLANA_TXN_BYTES {
        log::warn!(
            "verify_packet FAIL: payload_len={} != SOLANA_TXN_BYTES={}, len={}, offset={}",
            payload_len,
            SOLANA_TXN_BYTES,
            len,
            offset
        );
        return Err("bad_len_payload");
    }

    let payload = unsafe { buf.add(offset) };

    let magic = unsafe { *(payload as *const u64) };
    if magic != MAGIC {
        log::warn!(
            "verify_packet FAIL: magic=0x{:016x} != expected=0x{:016x}",
            magic,
            MAGIC
        );
        return Err("bad_magic");
    }

    let seq = unsafe { *(payload.add(8) as *const u64) };
    let saved_crc = unsafe { *(payload.add(24) as *const u32) };

    let mut temp = [0u8; SOLANA_TXN_BYTES];
    unsafe { std::ptr::copy_nonoverlapping(payload, temp.as_mut_ptr(), SOLANA_TXN_BYTES) };
    unsafe { std::ptr::write_bytes(temp.as_mut_ptr().add(24), 0, 4) };

    let mut h = Hasher::new();
    h.update(&temp);
    let calc = h.finalize();

    if calc != saved_crc {
        log::warn!(
            "verify_packet FAIL: CRC mismatch calc=0x{:08x} saved=0x{:08x}, seq={}",
            calc,
            saved_crc,
            seq
        );
        return Err("crc_mismatch");
    }

    Ok(seq)
}

#[inline(always)]
pub unsafe fn handle_packet<T: AsRef<[u8]>>(
    raw_packet: *const u8,
    len: usize,
    sender: &Sender<Bytes>,
) {
    let byte_slice = unsafe { std::slice::from_raw_parts(raw_packet, len) };
    let bytes = bytes::Bytes::copy_from_slice(byte_slice);
    sender.try_send(bytes).unwrap();
}

#[inline(always)]
unsafe fn handle_packet_v1(
    raw_packet: *const u8,
    len: usize,
    rx_start_ns: u128,
    sender: &Sender<TracedPayload>,
    pending_rx_traces: &mut Vec<PendingRxTrace>,
) {
    let byte_slice = unsafe { std::slice::from_raw_parts(raw_packet, len) };
    let trace_sig32 = if should_log_packet_trace() {
        let sig32 = payload_sig32(byte_slice);
        pending_rx_traces.push(PendingRxTrace {
            sig32,
            frame_len: len,
            rx_ns: rx_start_ns,
        });
        Some(sig32)
    } else {
        None
    };
    let payload = TracedPayload {
        data: bytes::Bytes::copy_from_slice(byte_slice),
        trace_sig32,
    };
    let bench_start_ns = if rx_path_bench_enabled() {
        rx_start_ns
    } else {
        0
    };
    sender.try_send(payload).unwrap();
    if bench_start_ns > 0 {
        rx_path_bench_record(
            now_monotonic_ns().saturating_sub(bench_start_ns) as u64,
            false,
        );
    }
}

trait RxPayloadSink {
    unsafe fn handle_packet(
        &mut self,
        raw_packet: *const u8,
        len: usize,
        rx_start_ns: u128,
        pending_rx_traces: &mut Vec<PendingRxTrace>,
    );

    #[inline(always)]
    fn sync(&mut self) {}
}

struct CrossbeamRxPayloadSink {
    sender: Sender<TracedPayload>,
}

impl RxPayloadSink for CrossbeamRxPayloadSink {
    #[inline(always)]
    unsafe fn handle_packet(
        &mut self,
        raw_packet: *const u8,
        len: usize,
        rx_start_ns: u128,
        pending_rx_traces: &mut Vec<PendingRxTrace>,
    ) {
        unsafe {
            handle_packet_v1(
                raw_packet,
                len,
                rx_start_ns,
                &self.sender,
                pending_rx_traces,
            );
        }
    }
}

struct DoublezeroRxPayloadSink {
    queue_id: QueueId,
    packet_log_limit: u64,
    total_packets: u64,
    total_bytes: u64,
    last_packets: u64,
    last_bytes: u64,
    last: Instant,
}

impl DoublezeroRxPayloadSink {
    fn new(queue_id: QueueId, packet_log_limit: u64) -> Self {
        Self {
            queue_id,
            packet_log_limit,
            total_packets: 0,
            total_bytes: 0,
            last_packets: 0,
            last_bytes: 0,
            last: Instant::now(),
        }
    }
}

impl RxPayloadSink for DoublezeroRxPayloadSink {
    #[inline(always)]
    unsafe fn handle_packet(
        &mut self,
        raw_packet: *const u8,
        len: usize,
        rx_start_ns: u128,
        pending_rx_traces: &mut Vec<PendingRxTrace>,
    ) {
        let byte_slice = unsafe { std::slice::from_raw_parts(raw_packet, len) };
        if should_log_packet_trace() {
            let sig32 = payload_sig32(byte_slice);
            pending_rx_traces.push(PendingRxTrace {
                sig32,
                frame_len: len,
                rx_ns: rx_start_ns,
            });
        }

        self.total_packets = self.total_packets.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(len as u64);
        if self.packet_log_limit > 0 && self.total_packets <= self.packet_log_limit {
            log_doublezero_packet(self.total_packets, byte_slice);
        }

        let bench_start_ns = if rx_path_bench_enabled() {
            rx_start_ns
        } else {
            0
        };
        if bench_start_ns > 0 {
            rx_path_bench_record(
                now_monotonic_ns().saturating_sub(bench_start_ns) as u64,
                false,
            );
        }
    }

    #[inline(always)]
    fn sync(&mut self) {
        if self.last.elapsed() < Duration::from_secs(1) {
            return;
        }

        let packet_delta = self.total_packets.saturating_sub(self.last_packets);
        let byte_delta = self.total_bytes.saturating_sub(self.last_bytes);
        println!(
            "rx queue={} total_packets={} total_bytes={} pps={} bytes_per_sec={}",
            self.queue_id.0, self.total_packets, self.total_bytes, packet_delta, byte_delta
        );
        self.last_packets = self.total_packets;
        self.last_bytes = self.total_bytes;
        self.last = Instant::now();
    }
}

fn log_doublezero_packet(count: u64, frame: &[u8]) {
    let size = frame.len();
    if let Some(meta) = parse_doublezero_packet(frame) {
        println!(
            "rx count={} size={} inner_src={} inner_dst={} dst_port={}",
            count, size, meta.inner_src, meta.inner_dst, meta.inner_dst_port
        );
    } else {
        println!("rx count={} size={} src=unknown", count, size);
    }
}

struct DoublezeroPacketMeta {
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_dst_port: u16,
}

fn parse_doublezero_packet(frame: &[u8]) -> Option<DoublezeroPacketMeta> {
    if frame.len()
        < ETH_HEADER_SIZE
            + IP_HEADER_SIZE
            + DOUBLEZERO_GRE_HDR_LEN
            + IP_HEADER_SIZE
            + UDP_HEADER_SIZE
    {
        return None;
    }

    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETH_P_IPV4 {
        return None;
    }

    let outer_ihl = (frame[ETH_HEADER_SIZE] & 0x0f) as usize * 4;
    if outer_ihl < IP_HEADER_SIZE
        || frame.len() < ETH_HEADER_SIZE + outer_ihl + DOUBLEZERO_GRE_HDR_LEN
    {
        return None;
    }
    if frame[ETH_HEADER_SIZE + 9] != IPPROTO_GRE {
        return None;
    }

    let gre_start = ETH_HEADER_SIZE + outer_ihl;
    let gre_flags = u16::from_be_bytes([frame[gre_start], frame[gre_start + 1]]);
    let gre_proto = u16::from_be_bytes([frame[gre_start + 2], frame[gre_start + 3]]);
    if gre_flags != 0 || gre_proto != GRE_PROTO_IPV4 {
        return None;
    }

    let inner_ip_start = gre_start + DOUBLEZERO_GRE_HDR_LEN;
    let inner_ihl = (frame[inner_ip_start] & 0x0f) as usize * 4;
    if inner_ihl < IP_HEADER_SIZE || frame.len() < inner_ip_start + inner_ihl + UDP_HEADER_SIZE {
        return None;
    }
    if frame[inner_ip_start + 9] != IPPROTO_UDP {
        return None;
    }

    let inner_src = ipv4_addr_at(frame, inner_ip_start + 12)?;
    let inner_dst = ipv4_addr_at(frame, inner_ip_start + 16)?;
    let udp_start = inner_ip_start + inner_ihl;
    let inner_dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);

    Some(DoublezeroPacketMeta {
        inner_src,
        inner_dst,
        inner_dst_port,
    })
}

fn ipv4_addr_at(frame: &[u8], start: usize) -> Option<Ipv4Addr> {
    let bytes = frame.get(start..start + 4)?;
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}
