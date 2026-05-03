use {
    agave_xdp_rx::{
        device::{NetworkDevice, QueueId},
        load_xdp_pass_program, set_cpu_affinity,
        tx_loop::tx_loop,
    },
    caps::{CapSet, Capability},
    clap::Parser,
    std::{
        hint,
        net::{IpAddr, SocketAddr},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
        fs,
    },
};

// Match RX verifier expectations
const SOLANA_TXN_BYTES: usize = 1232;
const MAGIC: u64 = 0xfeed_beef_cafe_d00d_u64;

#[inline]
fn build_benchmark_payload(seq: u64, requested_len: usize) -> Vec<u8> {
    use crc32fast::Hasher;

    // Enforce the canonical payload size used by RX validation
    let len = requested_len.min(SOLANA_TXN_BYTES);
    let mut packet = vec![0u8; len];

    // MAGIC at offset 0
    packet[0..8].copy_from_slice(&MAGIC.to_le_bytes());

    // sequence at offset 8
    packet[8..16].copy_from_slice(&seq.to_le_bytes());

    // timestamp at offset 16
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    if len >= 24 {
        packet[16..24].copy_from_slice(&timestamp.to_le_bytes());
    }

    // zero CRC field at 24..28 before computing
    if len >= 28 {
        packet[24..28].fill(0);
    }

    // fill remainder with deterministic pattern
    for i in 28..len { packet[i] = (i as u8).wrapping_mul(31).wrapping_add(0xAB); }

    // compute CRC32 over entire payload with CRC field zeroed
    if len >= 28 {
        let mut h = Hasher::new();
        h.update(&packet);
        let crc = h.finalize();
        packet[24..28].copy_from_slice(&crc.to_le_bytes());
    }

    packet
}

#[derive(Parser, Debug)]
#[command(author, version, about = "AF_XDP UDP sender", long_about = None)]
struct Opt {
    #[arg(short, long, default_value = "enp1s0f1")]
    interface: String,

    #[arg(long, default_value = "127.0.0.1")]
    dest_ip: String,

    #[arg(long, default_value = "20000")]
    dest_port: u16,

    #[arg(short, long, default_value = "64")]
    payload_size: usize,

    #[arg(short, long, default_value = "1000")]
    batch_size: usize,

    #[arg(long, default_value = "0")]
    idle_sleep_us: u64,

    #[arg(long, default_value = "0")]
    churn_threads: usize,

    #[arg(short, long)]
    zero_copy: bool,
}

// Metrics structure to share between threads
struct Metrics {
    tx_packets: AtomicUsize,
    tx_bytes: AtomicUsize,
}

// Helper function to format bitrate with appropriate units
fn format_bitrate(bits_per_second: f64) -> String {
    if bits_per_second < 1000.0 {
        format!("{:.2} bps", bits_per_second)
    } else if bits_per_second < 1_000_000.0 {
        format!("{:.2} Kbps", bits_per_second / 1000.0)
    } else if bits_per_second < 1_000_000_000.0 {
        format!("{:.2} Mbps", bits_per_second / 1_000_000.0)
    } else {
        format!("{:.2} Gbps", bits_per_second / 1_000_000_000.0)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let exit = Arc::new(AtomicBool::new(false));

    // Use ctrlc for graceful shutdown
    ctrlc::set_handler({
        let exit = Arc::clone(&exit);
        move || {
            println!("exiting...");
            exit.store(true, Ordering::Relaxed);
        }
    })?;

    for cap in [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW, Capability::CAP_BPF] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let mut cores = core_affinity::get_core_ids()
        .expect("Failed to get core IDs")
        .into_iter()
        .map(|id| id.id)
        .collect::<Vec<_>>();
    if cores.len() > 2 { cores.remove(2); }

    set_cpu_affinity(cores).unwrap();

    for _ in 0..opt.churn_threads {
        thread::spawn(|| loop {
            hint::black_box(())
        });
    }

    set_cpu_affinity([2]).unwrap();

    // NOTE: We will drop capabilities after XDP attach below

    let metrics = Arc::new(Metrics {
        tx_packets: AtomicUsize::new(0),
        tx_bytes: AtomicUsize::new(0),
    });

    // capture only the fields we need in the metrics thread
    let iface_name = opt.interface.clone();
    let payload_size = opt.payload_size;

    let metrics_thread = thread::Builder::new()
        .name("metrics".to_string())
        .spawn({
            let metrics = metrics.clone();
            let exit = Arc::clone(&exit);
            move || {
                let mut last_time = Instant::now();
                let mut last_packets = 0;
                let mut last_bytes = 0;

                // Baseline hardware counters
                let tx_pkts_path = format!(
                    "/sys/class/net/{}/statistics/tx_packets",
                    iface_name
                );
                let mut last_hw_packets: u64 = fs::read_to_string(&tx_pkts_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0);

                while exit.load(Ordering::SeqCst) == false {
                    thread::sleep(Duration::from_secs(1));

                    let current_time = Instant::now();
                    let elapsed = current_time.duration_since(last_time).as_secs_f64();

                    // Get current metrics from shared metrics
                    let packets = metrics.tx_packets.load(Ordering::SeqCst);
                    let bytes = metrics.tx_bytes.load(Ordering::SeqCst);

                    let pps = (packets - last_packets) as f64 / elapsed;
                    let bps = ((bytes - last_bytes) as f64 * 8.0) / elapsed;

                    // Compute corrected wire-rate including VLAN tag and preamble/IFG time.
                    // Overheads (bytes): Ethernet(14) + VLAN(4) + IPv4(20) + UDP(8) + FCS(4) + Preamble+IFG(20 time-bytes)
                    let vlan_overhead = 4.0;
                    let frame_overhead_no_preamble = 14.0 + vlan_overhead + 20.0 + 8.0 + 4.0;
                    let preamble_ifg = 20.0; // 8B preamble + 12B IFG (time on the wire)

                    let correction_factor =
                        (payload_size as f64 + frame_overhead_no_preamble + preamble_ifg)
                            / (payload_size as f64);
                    let corrected_gbps = bps / 1e9 * correction_factor;

                    // Also display theoretical pps at 10GbE for the configured payload size.
                    let wire_bits_per_packet =
                        (payload_size as f64 + frame_overhead_no_preamble) * 8.0
                            + preamble_ifg * 8.0;
                    let pps_at_10g = 10_000_000_000.0 / wire_bits_per_packet;

                    // Read hardware tx_packets (actual packets that exited the interface)
                    let hw_packets_now: u64 = fs::read_to_string(&tx_pkts_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(last_hw_packets);
                    let hw_pps = (hw_packets_now.saturating_sub(last_hw_packets)) as f64 / elapsed;

                    println!(
                        "throughput: {:>6.3} Mpps | {:>5.2} Gbps payload | {:>5.2} Gbps wire | {:>6.3} Mpps @10G | hw: {:>6.3} Mpps",
                        pps / 1e6,
                        bps / 1e9,
                        corrected_gbps,
                        pps_at_10g / 1e6,
                        hw_pps / 1e6,
                    );

                    last_time = current_time;
                    last_packets = packets;
                    last_bytes = bytes;
                    last_hw_packets = hw_packets_now;
                }
            }
        })
        .unwrap();

    let udp_payload_size = opt.payload_size;

    println!("sending UDP packets to {}:{} (proxy port)", opt.dest_ip, opt.dest_port);
    // Build a benchmark-style payload with MAGIC + seq + timestamp + CRC32
    let payload = build_benchmark_payload(0, udp_payload_size);
    let packet_data = Packet(Arc::new(payload));

    let (drop_sender, drop_receiver) = crossbeam_channel::bounded::<(Addrs, Packet)>(2_000_000);
    let metrics2 = metrics.clone();
    let drop_thread = thread::spawn(move || {
        loop {
            match drop_receiver.try_recv() {
                Ok((addrs, data)) => {
                    metrics2
                        .tx_packets
                        .fetch_add(addrs.as_ref().len(), Ordering::Relaxed);
                    metrics2.tx_bytes.fetch_add(
                        addrs.as_ref().len() * data.as_ref().len(),
                        Ordering::Relaxed,
                    );
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    // no frames to drop, just sleep for a bit
                    thread::sleep(Duration::from_millis(1));
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    // channel is closed, exit the loop
                    break;
                }
            };
        }
    });

    // Use the requested NIC and queue 0 by default
    let nic_name = opt.interface.clone();
    let interfaces: Vec<(&str, usize)> = vec![(nic_name.as_str(), 0)];
    let (_devs, _xdps) = interfaces
        .iter()
        .map(|(iface, _)| {
            let dev = NetworkDevice::new(*iface).unwrap();
            // Attach XDP_PASS when zero_copy requested so device has an XDP prog but does not redirect
            let ebpf = if opt.zero_copy {
                Some(load_xdp_pass_program(dev.if_index()).unwrap())
            } else { None };
            (dev, ebpf)
        })
        .unzip::<_, _, Vec<_>, Vec<_>>();

    // Now that XDP is attached (if any), drop elevated caps
    for cap in [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW, Capability::CAP_BPF] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }
    let tx_loops = (0..1usize)
        .into_iter()
        .map(|i| {
            let (iface, cpu) = interfaces[i];
            let dev = NetworkDevice::new(iface).unwrap();
            let drop_sender = drop_sender.clone();
            let (sender, receiver) = crossbeam_channel::bounded(500_000);
            (
                sender,
                thread::Builder::new()
                    .name("agave_xdp_tx_loop".to_string())
                    .spawn(move || {
                        tx_loop(
                            cpu,
                            &dev,
                            QueueId(i as u64),
                            opt.zero_copy,
                            None,
                            // Let the library pick the NIC's IPv4 address
                            Some("198.18.0.2".parse().unwrap()),
                            1234,
                            None,
                            receiver,
                            drop_sender,
                        );
                    })
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    drop(drop_sender);

    let addrs = Addrs(Arc::new(vec![
        (
            opt.dest_ip.parse::<IpAddr>().unwrap(),
            opt.dest_port
        )
            .into();
        1
    ]));

    for (i, (sender, _)) in tx_loops.iter().cycle().enumerate() {
        if exit.load(Ordering::Relaxed) {
            break;
        }
        if let Err(_) = sender.try_send((addrs.clone(), packet_data.clone())) {
            if i > 0 && i % tx_loops.len() == 0 {
                // thread::sleep(Duration::from_micros(500));
            }
        }
        if opt.idle_sleep_us > 0 { thread::sleep(Duration::from_micros(opt.idle_sleep_us)); }
    }

    for (i, (sender, tx_loop)) in tx_loops.into_iter().enumerate() {
        drop(sender);
        eprintln!("joining {i}");
        tx_loop.join().unwrap();
    }
    drop_thread.join().unwrap();
    metrics_thread.join().unwrap();

    println!("terminated");
    Ok(())
}

#[derive(Clone)]
struct Addrs(Arc<Vec<SocketAddr>>);

impl AsRef<[SocketAddr]> for Addrs {
    fn as_ref(&self) -> &[SocketAddr] {
        &self.0
    }
}

#[derive(Clone)]
struct Packet(Arc<Vec<u8>>);

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}


