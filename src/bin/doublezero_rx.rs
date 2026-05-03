use std::{
    env,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use agave_xdp_rx::{
    device::{NetworkDevice, QueueId},
    rx_loop::rx_loop_v1,
    tx_loop::TracedPayload,
};
use aya::{
    Ebpf,
    programs::{Xdp, xdp::XdpFlags},
};
use clap::{Parser, ValueEnum};
use crossbeam_channel::RecvTimeoutError;

const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_LEN: usize = 20;
const GRE_HDR_LEN: usize = 4;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IPV4: u16 = 0x0800;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_UDP: u8 = 17;
const GRE_PROTO_IPV4: u16 = 0x0800;
#[derive(Clone, Copy, Debug, ValueEnum)]
enum AttachMode {
    Auto,
    Skb,
    Drv,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "enp1s0f0")]
    iface: String,
    #[arg(long, default_value_t = 3)]
    queue: usize,
    #[arg(long, default_value_t = 3)]
    cpu: usize,
    #[arg(long)]
    bpf_object: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = AttachMode::Drv)]
    attach_mode: AttachMode,
    #[arg(long, default_value_t = true)]
    zero_copy: bool,
    #[arg(long, default_value_t = 1_000_000)]
    channel_capacity: usize,
    #[arg(long, default_value_t = 100)]
    packet_log_limit: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let bpf_object = resolve_bpf_object(args.bpf_object)?;

    let _ = std::fs::remove_file("/sys/fs/bpf/xsks_map");
    let dev = NetworkDevice::new(args.iface.clone())?;
    let mut ebpf = load_doublezero_xdp_program(&args.iface, &bpf_object, args.attach_mode)?;

    let (sender, receiver) = crossbeam_channel::bounded::<TracedPayload>(args.channel_capacity);
    let exit = Arc::new(AtomicBool::new(false));
    let rx_packet_count = Arc::new(AtomicU64::new(0));

    {
        let exit = exit.clone();
        ctrlc::set_handler(move || {
            exit.store(true, Ordering::Relaxed);
        })?;
    }

    let consumer_exit = exit.clone();
    std::thread::spawn(move || {
        let mut total_packets = 0u64;
        let mut total_bytes = 0u64;
        let mut last_packets = 0u64;
        let mut last_bytes = 0u64;
        let mut last = Instant::now();

        while !consumer_exit.load(Ordering::Relaxed) || !receiver.is_empty() {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(payload) => {
                    total_packets += 1;
                    total_bytes += payload.data.len() as u64;
                    if args.packet_log_limit > 0 && total_packets <= args.packet_log_limit {
                        log_doublezero_packet(total_packets, payload.data.as_ref());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if last.elapsed() >= Duration::from_secs(1) {
                let packet_delta = total_packets - last_packets;
                let byte_delta = total_bytes - last_bytes;
                println!(
                    "rx queue={} total_packets={} total_bytes={} pps={} bytes_per_sec={}",
                    args.queue, total_packets, total_bytes, packet_delta, byte_delta
                );
                last_packets = total_packets;
                last_bytes = total_bytes;
                last = Instant::now();
            }
        }
    });

    println!(
        "attached doublezero_xdp_redirect on {} queue={} cpu={} object={}; Ctrl-C to stop",
        args.iface,
        args.queue,
        args.cpu,
        bpf_object.display()
    );

    rx_loop_v1(
        args.cpu,
        &dev,
        QueueId(args.queue as u64),
        args.zero_copy,
        sender,
        Some(&mut ebpf),
        None,
        rx_packet_count,
        exit,
    );

    Ok(())
}

fn resolve_bpf_object(cli_path: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = cli_path {
        return Ok(path);
    }

    if let Ok(path) = env::var("DOUBLEZERO_XDP_BPF_OBJECT") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    let candidates = [
        PathBuf::from("/root/doublezero-xdp/target/bpfel-unknown-none/release/doublezero-xdp-ebpf"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../doublezero-xdp/target/bpfel-unknown-none/release/doublezero-xdp-ebpf"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(
        "DoubleZero XDP eBPF object not found; pass --bpf-object or set DOUBLEZERO_XDP_BPF_OBJECT"
            .into(),
    )
}

fn load_doublezero_xdp_program(
    iface: &str,
    bpf_object: &PathBuf,
    attach_mode: AttachMode,
) -> Result<Ebpf, Box<dyn std::error::Error>> {
    let mut ebpf = Ebpf::load_file(bpf_object)?;

    if let Some(map) = ebpf.map("xsks_map") {
        if let Err(err) = map.pin("/sys/fs/bpf/xsks_map") {
            let _ = std::fs::remove_file("/sys/fs/bpf/xsks_map");
            map.pin("/sys/fs/bpf/xsks_map").map_err(|retry_err| {
                format!("failed to pin xsks_map: {err:?}; retry failed: {retry_err:?}")
            })?;
        }
    }

    let program: &mut Xdp = ebpf
        .program_mut("doublezero_xdp_redirect")
        .ok_or("doublezero_xdp_redirect program not found")?
        .try_into()?;
    program.load()?;

    let flags = match attach_mode {
        AttachMode::Auto => XdpFlags::default(),
        AttachMode::Skb => XdpFlags::SKB_MODE,
        AttachMode::Drv => XdpFlags::DRV_MODE,
    };
    program.attach(iface, flags)?;

    Ok(ebpf)
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
    if frame.len() < ETH_HDR_LEN + IPV4_MIN_LEN + GRE_HDR_LEN + IPV4_MIN_LEN + UDP_HDR_LEN {
        return None;
    }

    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != ETH_P_IPV4 {
        return None;
    }

    let outer_ihl = (frame[ETH_HDR_LEN] & 0x0f) as usize * 4;
    if outer_ihl < IPV4_MIN_LEN || frame.len() < ETH_HDR_LEN + outer_ihl + GRE_HDR_LEN {
        return None;
    }
    if frame[ETH_HDR_LEN + 9] != IPPROTO_GRE {
        return None;
    }

    let _outer_src = ipv4_addr_at(frame, ETH_HDR_LEN + 12)?;

    let gre_start = ETH_HDR_LEN + outer_ihl;
    let gre_flags = u16::from_be_bytes([frame[gre_start], frame[gre_start + 1]]);
    let gre_proto = u16::from_be_bytes([frame[gre_start + 2], frame[gre_start + 3]]);
    if gre_flags != 0 || gre_proto != GRE_PROTO_IPV4 {
        return None;
    }

    let inner_ip_start = gre_start + GRE_HDR_LEN;
    let inner_ihl = (frame[inner_ip_start] & 0x0f) as usize * 4;
    if inner_ihl < IPV4_MIN_LEN || frame.len() < inner_ip_start + inner_ihl + UDP_HDR_LEN {
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
