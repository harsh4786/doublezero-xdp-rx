use std::net::{IpAddr, Ipv4Addr};

use aya::Ebpf;
use caps::{
    CapSet,
    Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
};
use libc::{_SC_PAGESIZE, sysconf};

use crate::{
    device::{NetworkDevice, QueueId, RingSizes, XdpDesc},
    netlink::MacAddress,
    packet::{
        ETH_HEADER_SIZE, IP_HEADER_SIZE, UDP_HEADER_SIZE, write_eth_header, write_ip_header,
        write_udp_header,
    },
    route::Router,
    set_cpu_affinity,
    socket::{Rx, Socket, Tx},
    umem::{PageAlignedMemory, SliceUmem, Umem as _},
};

/// Header sizes for in-place modification
const TOTAL_HEADER_SIZE: usize = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;

/// Batch size for RX/TX processing - matches typical ring sizes for maximum throughput
const BATCH_SIZE: usize = 512;

/// Combined RX → TX forwarding loop with in-place header modification.
///
/// Frame lifecycle: Fill Ring → RX Ring → TX Ring → Completion Ring → Fill Ring
///
/// This is a zero-copy forwarding path where packets are modified in-place in UMEM
/// and the same frame is reused for transmission.
#[allow(clippy::too_many_arguments)]
pub fn xdp_combined_loop(
    cpu_id: usize,
    dev: &NetworkDevice,
    queue_id: QueueId,
    zero_copy: bool,
    src_mac: Option<MacAddress>,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
    dest_mac: Option<MacAddress>,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    bpf_opt: Option<&mut Ebpf>,
) {
    log::info!(
        "starting combined RX→TX loop on {} queue {:?} cpu {}",
        dev.name(),
        queue_id,
        cpu_id
    );

    // Pin to single CPU for optimal cache locality
    set_cpu_affinity([cpu_id]).unwrap();

    // Resolve source MAC/IP from device if not provided
    let src_mac = src_mac.unwrap_or_else(|| {
        dev.mac_addr()
            .expect("no src_mac provided, device must have a MAC address")
    });
    let src_ip = src_ip.unwrap_or_else(|| {
        dev.ipv4_addr()
            .expect("no src_ip provided, device must have an IPv4 address")
    });

    // Resolve destination MAC via routing if not provided
    let router = Router::new().expect("failed to create router");
    let dest_mac = dest_mac.unwrap_or_else(|| {
        let next_hop = router
            .route(IpAddr::V4(dest_ip))
            .expect("no route to destination");
        next_hop.mac_addr.expect("no MAC address for next hop")
    });

    let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    let queue = dev
        .open_queue(queue_id)
        .expect("failed to open queue for AF_XDP socket");

    let RingSizes {
        rx: rx_size,
        tx: tx_size,
    } = queue.ring_sizes().unwrap_or_else(|| {
        log::info!(
            "using default ring sizes for {} queue {:?}",
            dev.name(),
            queue_id
        );
        RingSizes::default()
    });

    // Allocate UMEM: need frames for both RX and TX paths
    // RX: fill_ring + rx_ring
    // TX: tx_ring + completion_ring
    let frame_count = (rx_size + tx_size) * 2;

    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular pages");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .expect("failed to allocate UMEM");

    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    // Raise capabilities for socket creation
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    // Create combined RX+TX socket sharing the same UMEM
    let Ok((mut socket, rx, tx)) = Socket::full_socket(
        queue,
        umem,
        zero_copy,
        rx_size * 2, // fill ring size
        rx_size,     // rx ring size
        tx_size,     // tx ring size
        tx_size * 2, // completion ring size
    ) else {
        panic!("failed to create AF_XDP socket");
    };

    // Register socket in XSK map for XDP_REDIRECT
    if let Some(bpf) = bpf_opt {
        log::info!("Registering AF_XDP socket in xsks_map...");
        socket.register_in_xskmap(bpf);
        log::info!("AF_XDP socket registration completed");
    } else {
        log::warn!("no eBPF handle provided; packets will not be redirected!");
    }

    let umem = socket.umem();
    let umem_base = umem.as_ptr();

    // Extract ring structures
    let Rx {
        fill: mut fill_ring,
        ring: rx_ring,
    } = rx;
    let mut rx_ring = rx_ring.expect("RX ring not available");

    let Tx {
        ring: tx_ring,
        completion: mut completion_ring,
    } = tx;
    let mut tx_ring = tx_ring.expect("TX ring not available");

    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // Pre-cache values for hot path
    let src_mac_bytes = src_mac.0;
    let dest_mac_bytes = dest_mac.0;

    // Preallocated arrays for batch processing
    let mut rx_descs: [XdpDesc; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    kick_fill(&fill_ring);

    log::info!("combined loop initialized, entering hot path");

    loop {
        // 1. Process TX completions first - recycle frames back to fill ring
        //    This ensures we have frames available for new RX packets
        completion_ring.sync(true);
        let mut recycled = 0usize;
        while let Some(frame_offset) = completion_ring.read() {
            // Frame is done transmitting, return to fill ring for reuse
            if fill_ring.write_single(frame_offset).is_ok() {
                recycled += 1;
            }
        }
        if recycled > 0 {
            fill_ring.commit();
        }

        // 2. Read batch of packets from RX ring
        let rx_available = rx_ring.read_batch(&mut rx_descs).unwrap_or(0);

        if rx_available == 0 {
            // No packets available - ensure fill ring is awake
            kick_fill(&fill_ring);
            continue;
        }

        // 3. Check TX ring capacity before processing
        tx_ring.sync(false);
        let tx_available = tx_ring.available();

        // Only process as many packets as TX ring can accept
        let to_process = rx_available.min(tx_available);

        if to_process == 0 {
            // TX ring is full - kick it and retry
            kick_tx(&tx_ring);
            continue;
        }

        // 4. Process packets: modify headers in-place and forward to TX
        //    4-way unrolled for better instruction pipelining
        let chunks = to_process / 4;

        for chunk_idx in 0..chunks {
            let base = chunk_idx * 4;

            // Load 4 descriptors
            let (d0, d1, d2, d3) = (
                &rx_descs[base],
                &rx_descs[base + 1],
                &rx_descs[base + 2],
                &rx_descs[base + 3],
            );

            // Get mutable pointers to packet data
            let (p0, p1, p2, p3) = unsafe {
                (
                    std::slice::from_raw_parts_mut(
                        umem_base.add(d0.addr as usize) as *mut u8,
                        d0.len as usize,
                    ),
                    std::slice::from_raw_parts_mut(
                        umem_base.add(d1.addr as usize) as *mut u8,
                        d1.len as usize,
                    ),
                    std::slice::from_raw_parts_mut(
                        umem_base.add(d2.addr as usize) as *mut u8,
                        d2.len as usize,
                    ),
                    std::slice::from_raw_parts_mut(
                        umem_base.add(d3.addr as usize) as *mut u8,
                        d3.len as usize,
                    ),
                )
            };

            // Modify headers in-place (4 packets)
            rewrite_headers(
                p0,
                &src_mac_bytes,
                &dest_mac_bytes,
                &src_ip,
                src_port,
                &dest_ip,
                dest_port,
            );
            rewrite_headers(
                p1,
                &src_mac_bytes,
                &dest_mac_bytes,
                &src_ip,
                src_port,
                &dest_ip,
                dest_port,
            );
            rewrite_headers(
                p2,
                &src_mac_bytes,
                &dest_mac_bytes,
                &src_ip,
                src_port,
                &dest_ip,
                dest_port,
            );
            rewrite_headers(
                p3,
                &src_mac_bytes,
                &dest_mac_bytes,
                &src_ip,
                src_port,
                &dest_ip,
                dest_port,
            );

            // Write to TX ring (reusing same UMEM frames)
            tx_ring.write_raw(d0.addr, d0.len);
            tx_ring.write_raw(d1.addr, d1.len);
            tx_ring.write_raw(d2.addr, d2.len);
            tx_ring.write_raw(d3.addr, d3.len);
        }

        for i in (chunks * 4)..to_process {
            let desc = &rx_descs[i];
            let packet = unsafe {
                std::slice::from_raw_parts_mut(
                    umem_base.add(desc.addr as usize) as *mut u8,
                    desc.len as usize,
                )
            };
            rewrite_headers(
                packet,
                &src_mac_bytes,
                &dest_mac_bytes,
                &src_ip,
                src_port,
                &dest_ip,
                dest_port,
            );
            tx_ring.write_raw(desc.addr, desc.len);
        }

        tx_ring.commit();
        kick_tx(&tx_ring);

        rx_ring.commit();
    }
}

/// Rewrite Ethernet, IP, and UDP headers in-place for forwarding.
///
/// Optimized for the common case: fixed destination, no checksum recalculation.
#[inline(always)]
fn rewrite_headers(
    packet: &mut [u8],
    src_mac: &[u8; 6],
    dest_mac: &[u8; 6],
    src_ip: &Ipv4Addr,
    src_port: u16,
    dest_ip: &Ipv4Addr,
    dest_port: u16,
) {
    if packet.len() < TOTAL_HEADER_SIZE {
        return; // Runt packet, skip
    }

    // Extract payload length from existing packet
    let payload_len = packet.len().saturating_sub(TOTAL_HEADER_SIZE);

    // Rewrite Ethernet header
    write_eth_header(&mut packet[..ETH_HEADER_SIZE], src_mac, dest_mac);

    // Rewrite IP header
    write_ip_header(
        &mut packet[ETH_HEADER_SIZE..ETH_HEADER_SIZE + IP_HEADER_SIZE],
        src_ip,
        dest_ip,
        (UDP_HEADER_SIZE + payload_len) as u16,
    );

    // Rewrite UDP header (skip checksum for performance)
    write_udp_header(
        &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..TOTAL_HEADER_SIZE],
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        payload_len as u16,
        false, // Skip UDP checksum
    );
}

/// Kick fill ring if driver needs wakeup
#[inline(always)]
fn kick_fill<F: crate::umem::Frame>(ring: &crate::device::RxFillRing<F>) {
    if !ring.needs_wakeup() {
        return;
    }
    if let Err(e) = ring.wake() {
        handle_kick_error(e);
    }
}

/// Kick TX ring if driver needs wakeup
#[inline(always)]
fn kick_tx<F: crate::umem::Frame>(ring: &crate::socket::TxRing<F>) {
    if !ring.needs_wakeup() {
        return;
    }
    if let Err(e) = ring.wake() {
        handle_kick_error(e);
    }
}

fn handle_kick_error(e: std::io::Error) {
    match e.raw_os_error() {
        Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN) => {}
        Some(libc::ENETDOWN) => log::warn!("network interface is down"),
        _ => log::error!("driver error: {:?}", e),
    }
}
