use std::{
    env,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use agave_xdp_rx::{
    device::{NetworkDevice, QueueId},
    rx_loop::rx_loop_v1_doublezero,
};
use aya::{
    Ebpf,
    programs::{Xdp, xdp::XdpFlags},
};
use clap::{Parser, ValueEnum};

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

    let exit = Arc::new(AtomicBool::new(false));
    let rx_packet_count = Arc::new(AtomicU64::new(0));

    {
        let exit = exit.clone();
        ctrlc::set_handler(move || {
            exit.store(true, Ordering::Relaxed);
        })?;
    }

    println!(
        "attached doublezero_xdp_redirect on {} queue={} cpu={} object={}; Ctrl-C to stop",
        args.iface,
        args.queue,
        args.cpu,
        bpf_object.display()
    );

    rx_loop_v1_doublezero(
        args.cpu,
        &dev,
        QueueId(args.queue as u64),
        args.zero_copy,
        args.packet_log_limit,
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
