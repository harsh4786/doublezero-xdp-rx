use std::{
    cell::RefCell,
    collections::HashMap,
    env,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};

use aya::Ebpf;
use caps::{
    CapSet,
    Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
};
use libc::{_SC_PAGESIZE, CLOCK_MONOTONIC, clock_gettime, sysconf, timespec};
use log::info;

use crate::{
    device::{NetworkDevice, QueueId, RingSizes, RxFillRing, XdpDesc},
    packet::{ETH_HEADER_SIZE, IP_HEADER_SIZE, UDP_HEADER_SIZE},
    set_cpu_affinity,
    socket::{Rx, Socket},
    umem::{FrameOffset, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem},
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
                "RX_PATH_BENCH: mode=doublezero_xdp_rx stage=af_xdp_ring_to_packet_handled samples={} window_samples={} packets={} window_packets={} drops={} window_drops={} min_ns={} p50_ns={} p90_ns={} p95_ns={} p99_ns={} avg_ns={} max_ns={}",
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

pub fn doublezero_xdp_rx_loop(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    packet_log_limit: u64,
    bpf_opt: Option<&mut Ebpf>,
    rx_packet_count: Arc<AtomicU64>,
    exit: Arc<AtomicBool>,
) {
    log::info!(
        "starting xdp rx loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );
    let mut payload_sink = DoublezeroRxPayloadSink::new(queue_id, packet_log_limit);

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
    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");
        log::info!("XDP RX armed: xsks_map[{queue_id:?}] set");
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

        rx_ring.sync(false);
        let avail_before_read_batch = rx_ring.available();
        let ts_before = if need_rx_timestamp && avail_before_read_batch > 0 {
            now_monotonic_ns()
        } else {
            0
        };
        let available = rx_ring.read_batch(&mut descs).unwrap_or(0);
        let read_start_ns = if need_rx_timestamp && available > 0 && ts_before == 0 {
            now_monotonic_ns()
        } else {
            ts_before
        };

        if hot_path_observability {
            read_batch_before = read_batch_slot;
            read_batch_n = available;
            read_batch_after = read_batch_slot.wrapping_add(available) & rx_mask;
            read_batch_slot = read_batch_after;
            read_batch_calls = read_batch_calls.saturating_add(1);
            read_batch_descs = read_batch_descs.saturating_add(available as u64);
            rx_pending_sampled = avail_before_read_batch;
            rx_batch_polls = rx_batch_polls.saturating_add(1);
            rx_batch_sum = rx_batch_sum.saturating_add(available as u64);
            rx_batch_max = rx_batch_max.max(available);
            rx_peak_used = rx_peak_used.max(available);
        }

        if available > 0 {
            total_rx = total_rx.saturating_add(available as u64);
            rx_packet_count.fetch_add(available as u64, AtomicOrdering::Relaxed);
        }
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
        for (chunk, frame) in descs[..bulk]
            .chunks_exact(4)
            .zip(frames[..bulk].chunks_mut(4))
        {
            unsafe {
                let p0 = umem_base.add(chunk[0].addr as usize);
                let p1 = umem_base.add(chunk[1].addr as usize);
                let p2 = umem_base.add(chunk[2].addr as usize);
                let p3 = umem_base.add(chunk[3].addr as usize);

                payload_sink.handle_packet(
                    p0,
                    chunk[0].len as usize,
                    read_start_ns,
                    &mut pending_rx_traces,
                );
                payload_sink.handle_packet(
                    p1,
                    chunk[1].len as usize,
                    read_start_ns,
                    &mut pending_rx_traces,
                );
                payload_sink.handle_packet(
                    p2,
                    chunk[2].len as usize,
                    read_start_ns,
                    &mut pending_rx_traces,
                );
                payload_sink.handle_packet(
                    p3,
                    chunk[3].len as usize,
                    read_start_ns,
                    &mut pending_rx_traces,
                );

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

        for d in &descs[bulk..available] {
            unsafe {
                let p = umem_base.add(d.addr as usize);
                payload_sink.handle_packet(
                    p,
                    d.len as usize,
                    read_start_ns,
                    &mut pending_rx_traces,
                );
            }
            let off = FrameOffset(d.addr as usize);
            umem.release(off);
            frames[recycled] = off;
            recycled += 1;
        }

        if available > 0 {
            payload_sink.sync();
        }
        if !pending_rx_traces.is_empty() {
            flush_pending_rx_traces(&mut pending_rx_traces, queue_id);
        }

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
        let wrote = if recycled > 0 {
            fill_ring
                .write_batch(umem, &frames[..recycled])
                .unwrap_or(0)
        } else {
            0
        };
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
