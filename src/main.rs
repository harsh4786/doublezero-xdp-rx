use std::{
    ffi::CString,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd as _,
    sync::Arc,
    thread,
    time::Duration,
};

use agave_xdp_rx::{
    device::{NetworkDevice, QueueId},
    load_xdp_program,
    netlink::MacAddress,
    rx_loop::{rx_loop, rx_loop_batched},
    tx_loop::tx_loop,
};
use aya::Ebpf;
use bytes::Bytes;
use crossbeam_channel as chan;

fn main() {
    // Minimal config via env vars; reasonable defaults otherwise
    env_logger::init();
    let iface = std::env::var("IFACE").ok();
    let tx_iface = std::env::var("TX_IFACE").ok().or_else(|| iface.clone());
    let rx_iface = std::env::var("RX_IFACE").ok().or_else(|| iface.clone());
    let dest_ip_env = std::env::var("DEST_IP").ok();
    // let dest_port: u16 = std::env::var("DEST_PORT")
    //     .ok()
    //     .and_then(|p| p.parse().ok())
    //     .unwrap_or(20000);
    let zero_copy = std::env::var("ZERO_COPY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let accept_all = std::env::var("ACCEPT_ALL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let src_ip_env = std::env::var("SRC_IP").ok();
    // let dest_mac_env = std::env::var("DEST_MAC").ok();

    let enable_rx = std::env::var("ENABLE_RX")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    // CPU and queue selection; NUMA-optimized defaults:
    // Queue 1: Unused by kernel, dedicated for AF_XDP
    // CPU 1: Pinned to IRQ 119 (queue 1) for optimal cache locality

    let rx_cpu: usize = std::env::var("RX_CPU")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let rx_queue_id: u64 = std::env::var("RX_QUEUE_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let dev = iface
        .as_deref()
        .map(NetworkDevice::new)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            NetworkDevice::new_from_default_route().expect("failed to open default-route device")
        });

    // Attach XDP in DRV mode when zero_copy requested on TX/RX selected ifaces
    // let tx_ifname = tx_iface.clone().unwrap_or_else(|| dev.name().to_string());
    let rx_ifname = rx_iface.clone().unwrap_or_else(|| dev.name().to_string());

    // Attach XDP on the RX interface for AF_XDP (required for both zero-copy and copy modes)
    let mut _xdp_rx: Option<Ebpf> = {
        let ifindex = NetworkDevice::new(rx_ifname.clone())
            .expect("open RX iface for XDP")
            .if_index();
        match load_xdp_program(ifindex) {
            Ok(mut ebpf) => {
                if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
                    log::warn!("failed to init aya logger: {}", e);
                }

                log::info!(
                    "XDP program loaded successfully on {} in DRV_MODE",
                    rx_ifname
                );
                log::info!("XDP redirect program is active - packets will be redirected to AF_XDP");
                Some(ebpf)
            }
            Err(e) => {
                log::error!("ERROR: XDP attach on RX iface failed: {e:?}");
                log::error!("This will prevent AF_XDP from receiving packets!");
                None
            }
        }
    };

    // Destination: Use RX interface IP if not provided, otherwise RFC 2544 test range
    let dest_ip: IpAddr = dest_ip_env
        .and_then(|s| s.parse::<IpAddr>().ok())
        .or_else(|| {
            // Try to get the RX interface IP address
            NetworkDevice::new(rx_ifname.clone())
                .ok()
                .and_then(|dev| dev.ipv4_addr().ok())
                .map(IpAddr::V4)
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(198, 19, 0, 1)));
    // let dest_sock = SocketAddr::from((dest_ip, dest_port));

    // Source IPv4: default to RFC 2544 test range to avoid NIC IP dependency
    let src_ip_opt = src_ip_env
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .or_else(|| Some(std::net::Ipv4Addr::new(198, 18, 0, 1)));

    // Destination MAC: prefer provided; else default to TX iface MAC to avoid ARP
    // let tx_dev_for_mac = NetworkDevice::new(tx_ifname.clone()).expect("open TX iface for MAC");
    // let dest_mac_opt = dest_mac_env
    //     .as_deref()
    //     .and_then(parse_mac)
    //     .or_else(|| tx_dev_for_mac.mac_addr().ok());

    // // Channels for TX (only used if AF_XDP TX enabled)
    // let (tx_sender, tx_receiver) = chan::bounded::<(Vec<SocketAddr>, Vec<u8>)>(500_000);
    // let (tx_drop_sender, tx_drop_receiver) = chan::bounded::<(Vec<SocketAddr>, Vec<u8>)>(2_000_000);

    // // Channels for RX (accepted and dropped)
    let (rx_accept_sender, rx_accept_receiver) = chan::unbounded();
    // let (rx_drop_sender, rx_drop_receiver) = chan::bounded::<Vec<u8>>(2_000_000);

    // // Spawn TX loop on selected TX_IFACE
    // let dev_tx = NetworkDevice::new(tx_ifname.clone()).expect("failed to open TX iface");
    // let tx_thread = if enable_tx {
    //     Some(
    //         thread::Builder::new()
    //             .name("xdp_tx_loop".to_string())
    //             .spawn(move || {
    //                 tx_loop(
    //                     tx_cpu,
    //                     &dev_tx,
    //                     QueueId(tx_queue_id),
    //                     zero_copy,
    //                     None,
    //                     src_ip_opt,
    //                     1234,
    //                     dest_mac_opt,
    //                     tx_receiver,
    //                     tx_drop_sender,
    //                 );
    //             })
    //             .expect("failed to spawn tx loop"),
    //     )
    // } else {
    //     None
    // };

    // Spawn RX loop on selected RX_IFACE
    let dev_rx = NetworkDevice::new(rx_ifname.clone()).expect("failed to open RX iface");
    let rx_thread = if enable_rx {
        Some(
            thread::Builder::new()
                .name("xdp_rx_loop".to_string())
                .spawn(move || {
                    // fn deliver(_bytes: &[u8]) {}
                    rx_loop_batched::<Bytes>(
                        rx_cpu,
                        &dev_rx,
                        QueueId(rx_queue_id),
                        zero_copy,
                        // 1234,
                        // dev_rx.mac_addr().ok(),
                        // deliver,
                        rx_accept_sender,
                        // rx_drop_sender,
                        _xdp_rx.as_mut(),
                    );
                })
                .expect("failed to spawn rx loop"),
        )
    } else {
        None
    };

    // Feeder thread to generate traffic for AF_XDP TX path (disabled by default)
    // let tx_feeder = if enable_tx {
    //     let addrs = vec![dest_sock];
    //     let payload: Arc<Vec<u8>> =
    //         Arc::new((0..tx_payload_size).map(|i| (i % 256) as u8).collect());
    //     Some(
    //         thread::Builder::new()
    //             .name("tx_feeder".to_string())
    //             .spawn({
    //                 let payload = payload.clone();
    //                 move || loop {
    //                     match tx_sender.try_send((addrs.clone(), (*payload).clone())) {
    //                         Ok(_) => {}
    //                         Err(chan::TrySendError::Full(_)) => {
    //                             thread::sleep(Duration::from_micros(50))
    //                         }
    //                         Err(chan::TrySendError::Disconnected(_)) => break,
    //                     }
    //                 }
    //             })
    //             .expect("failed to spawn tx feeder"),
    //     )
    // } else {
    //     None
    // };

    // // Drain TX drop channel (counts what was queued to NIC)
    // let tx_drop_drain = if enable_tx {
    //     Some(
    //         thread::Builder::new()
    //             .name("tx_drop_drain".to_string())
    //             .spawn(move || {
    //                 let mut pkts: u64 = 0;
    //                 let mut bytes: u64 = 0;
    //                 loop {
    //                     match tx_drop_receiver.try_recv() {
    //                         Ok((addrs, data)) => {
    //                             pkts += addrs.len() as u64;
    //                             bytes += (addrs.len() * data.len()) as u64;
    //                             if pkts % 100000 == 0 {
    //                                 log::info!("tx queued={} bytes={}", pkts, bytes);
    //                             }
    //                         }
    //                         Err(chan::TryRecvError::Empty) => {
    //                             thread::sleep(Duration::from_millis(1))
    //                         }
    //                         Err(chan::TryRecvError::Disconnected) => break,
    //                     }
    //                 }
    //             })
    //             .expect("failed to spawn tx drop drainer"),
    //     )
    // } else {
    //     None
    // };

    // // UDP blaster threads (userspace TX via standard NIC) to drive RX path
    // let udp_threads = if enable_tx_udp {
    //     let mut handles = Vec::new();
    //     let cores: Vec<usize> = tx_cores
    //         .as_deref()
    //         .unwrap_or("")
    //         .split(',')
    //         .filter_map(|s| s.trim().parse::<usize>().ok())
    //         .collect();
    //     for t in 0..tx_threads {
    //         let dest = dest_sock;
    //         let bind_dev = tx_bind_dev.clone();
    //         let core_pin = if cores.is_empty() {
    //             None
    //         } else {
    //             cores.get(t % cores.len()).copied()
    //         };
    //         let payload_len = tx_payload_size;
    //         handles.push(
    //             thread::Builder::new()
    //                 .name(format!("udp_blaster_{}", t))
    //                 .spawn(move || {
    //                     if let Some(cpu) = core_pin {
    //                         let _ = agave_xdp_rx::set_cpu_affinity([cpu]);
    //                     }
    //                     let sock = std::net::UdpSocket::bind(match dest.is_ipv4() {
    //                         true => "0.0.0.0:0",
    //                         false => "[::]:0",
    //                     })
    //                     .expect("bind udp socket");
    //                     if let Some(dev) = bind_dev.as_deref() {
    //                         let ifname = CString::new(dev).unwrap();
    //                         unsafe {
    //                             libc::setsockopt(
    //                                 sock.as_raw_fd(),
    //                                 libc::SOL_SOCKET,
    //                                 libc::SO_BINDTODEVICE,
    //                                 ifname.as_ptr() as *const libc::c_void,
    //                                 (ifname.as_bytes_with_nul().len()) as libc::socklen_t,
    //                             );
    //                         }
    //                     }
    //                     sock.connect(dest).expect("udp connect dest");
    //                     let mut payload = vec![0u8; payload_len];
    //                     for i in 0..payload_len {
    //                         payload[i] = (i % 256) as u8;
    //                     }
    //                     loop {
    //                         let _ = sock.send(&payload);
    //                     }
    //                 })
    //                 .expect("spawn udp blaster thread"),
    //         );
    //     }
    //     Some(handles)
    // } else {
    //     None
    // };

    // // Drain RX accepted and dropped channels
    // let rx_accept_drain = thread::Builder::new()
    //     .name("rx_accept_drain".to_string())
    //     .spawn(move || {
    //         let mut cnt: u64 = 0;
    //         let mut bad: u64 = 0;
    //         loop {
    //             match rx_accept_receiver.try_recv() {
    //                 Ok(pkt) => {
    //                     log::info!("RX_PATH: received packet with {} bytes", pkt.len());
    //                     if verify {
    //                         const ETH: usize = 14;
    //                         const IP: usize = 20;
    //                         const UDP: usize = 8;
    //                         if pkt.len() >= ETH + IP + UDP + tx_payload_size {
    //                             let off = ETH + IP + UDP;
    //                             let slice = &pkt[off..off + tx_payload_size];
    //                             for (i, b) in slice.iter().enumerate() {
    //                                 if *b != (i % 256) as u8 {
    //                                     bad += 1;
    //                                     break;
    //                                 }
    //                             }
    //                         } else {
    //                             bad += 1;
    //                         }
    //                     }
    //                     cnt += 1;
    //                     if cnt % 100000 == 0 {
    //                         if verify {
    //                             log::info!("rx accepted={} bad={} ", cnt, bad);
    //                         } else {
    //                             log::info!("rx accepted={} ", cnt);
    //                         }
    //                     }
    //                 }
    //                 Err(chan::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
    //                 Err(chan::TryRecvError::Disconnected) => break,
    //             }
    //         }
    //     })
    //     .expect("failed to spawn rx accept drainer");

    // let rx_drop_drain = thread::Builder::new()
    //     .name("rx_drop_drain".to_string())
    //     .spawn(move || {
    //         let mut cnt: u64 = 0;
    //         loop {
    //             match rx_drop_receiver.try_recv() {
    //                 Ok(_pkt) => {
    //                     cnt += 1;
    //                     if cnt % 100000 == 0 {
    //                         log::info!("rx dropped={} ", cnt);
    //                     }
    //                 }
    //                 Err(chan::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
    //                 Err(chan::TryRecvError::Disconnected) => break,
    //             }
    //         }
    //     })
    //     .expect("failed to spawn rx drop drainer");

    // Join threads (Ctrl-C to terminate not wired here; minimal demo)
    // if let Some(t) = tx_feeder {
    //     let _ = t.join();
    // }
    // if let Some(t) = tx_thread {
    //     let _ = t.join();
    // }
    if let Some(t) = rx_thread {
        let _ = t.join();
    }
    // if let Some(t) = tx_drop_drain {
    //     let _ = t.join();
    // }
    // let _ = rx_accept_drain.join();
    // let _ = rx_drop_drain.join();
    // if let Some(v) = udp_threads {
    //     for h in v {
    //         let _ = h.join();
    //     }
    // }
}

fn parse_mac(s: &str) -> Option<MacAddress> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        let Ok(v) = u8::from_str_radix(p, 16) else {
            return None;
        };
        bytes[i] = v;
    }
    Some(MacAddress::new(bytes))
}
