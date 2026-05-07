use std::{
    ffi::CString,
    io, mem,
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "doublezero1")]
    iface: String,
    #[arg(long, default_value = "233.84.178.12")]
    group: Ipv4Addr,
    #[arg(long, default_value_t = 7733)]
    port: u16,
    #[arg(long)]
    cpu: Option<usize>,
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,
    #[arg(long, default_value_t = 100)]
    packet_log_limit: u64,
    #[arg(long, default_value_t = 0)]
    summary_interval_secs: u64,
    #[arg(long, default_value_t = 64)]
    recv_buffer_mb: usize,
}

#[derive(Default)]
struct LatencyHist {
    samples: u64,
    sum_ns: u128,
    min_ns: u64,
    max_ns: u64,
    buckets: Vec<u64>,
    values_ns: Vec<u64>,
}

impl LatencyHist {
    fn new(max_us: usize) -> Self {
        Self {
            min_ns: u64::MAX,
            buckets: vec![0; max_us + 1],
            ..Self::default()
        }
    }

    fn record(&mut self, ns: u64) {
        self.samples += 1;
        self.sum_ns += ns as u128;
        self.min_ns = self.min_ns.min(ns);
        self.max_ns = self.max_ns.max(ns);
        let us = (ns / 1_000) as usize;
        let idx = us.min(self.buckets.len().saturating_sub(1));
        self.buckets[idx] += 1;
        self.values_ns.push(ns);
    }

    fn percentile_us(&self, pct: u64) -> u64 {
        if self.samples == 0 {
            return 0;
        }
        let target = self.samples.saturating_mul(pct).div_ceil(100);
        let mut seen = 0u64;
        for (us, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                return us as u64;
            }
        }
        self.max_ns / 1_000
    }

    fn avg_us(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            (self.sum_ns / self.samples as u128 / 1_000) as u64
        }
    }

    fn min_us(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            self.min_ns / 1_000
        }
    }

    fn max_us(&self) -> u64 {
        self.max_ns / 1_000
    }

    fn avg_ns(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            (self.sum_ns / self.samples as u128) as u64
        }
    }

    fn min_ns(&self) -> u64 {
        if self.samples == 0 { 0 } else { self.min_ns }
    }

    fn percentiles_ns<const N: usize>(&self, pcts: &[u64; N]) -> [u64; N] {
        if self.values_ns.is_empty() {
            return [0; N];
        }
        let mut values = self.values_ns.clone();
        values.sort_unstable();
        pcts.map(|pct| {
            let idx = values
                .len()
                .saturating_mul(pct as usize)
                .div_ceil(100)
                .saturating_sub(1)
                .min(values.len().saturating_sub(1));
            values[idx]
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    if let Some(cpu) = args.cpu {
        if let Some(core) = core_affinity::get_core_ids()
            .unwrap_or_default()
            .into_iter()
            .find(|core| core.id == cpu)
        {
            core_affinity::set_for_current(core);
        }
    }

    let socket = create_multicast_socket(args.port, args.recv_buffer_mb)?;
    join_multicast_by_index(&socket, args.group, &args.iface)?;
    set_multicast_all(&socket, false)?;
    enable_software_rx_timestamps(&socket)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let socket_fd = socket.as_raw_fd();
    let exit = Arc::new(AtomicBool::new(false));
    {
        let exit = Arc::clone(&exit);
        ctrlc::set_handler(move || {
            exit.store(true, Ordering::Relaxed);
        })?;
    }

    println!(
        "doublezero_kernel_rx listening iface={} group={} port={} cpu={:?} recv_buffer_mb={} effective_recv_buffer_bytes={}",
        args.iface,
        args.group,
        args.port,
        args.cpu,
        args.recv_buffer_mb,
        socket.recv_buffer_size().unwrap_or(0)
    );

    let started = Instant::now();
    let mut last = Instant::now();
    let mut buf = vec![0u8; 2048];
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut hist = LatencyHist::new(100_000);
    let mut kernel_ts_missing = 0u64;

    while !exit.load(Ordering::Relaxed) {
        if args.duration_secs > 0 && started.elapsed() >= Duration::from_secs(args.duration_secs) {
            break;
        }

        match recvmsg_with_timestamp(socket_fd, &mut buf) {
            Ok(packet) => {
                packets += 1;
                bytes += packet.len as u64;

                let latency_ns = if let Some(latency_ns) = packet.kernel_to_user_ns {
                    latency_ns
                } else {
                    kernel_ts_missing = kernel_ts_missing.saturating_add(1);
                    0
                };
                if packet.kernel_to_user_ns.is_some() {
                    hist.record(latency_ns);
                }

                if args.packet_log_limit > 0 && packets <= args.packet_log_limit {
                    println!(
                        "kernel_rx count={} size={} src={} kernel_to_user_ns={} kernel_to_user_us={} kernel_ts_present={}",
                        packets,
                        packet.len,
                        packet.src,
                        latency_ns,
                        latency_ns / 1_000,
                        packet.kernel_to_user_ns.is_some()
                    );
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(err) => eprintln!("doublezero_kernel_rx recv error: {err}"),
        }

        if args.summary_interval_secs > 0
            && last.elapsed() >= Duration::from_secs(args.summary_interval_secs)
        {
            print_summary(
                "kernel_rx_summary",
                packets,
                bytes,
                kernel_ts_missing,
                &hist,
            );
            last = Instant::now();
        }
    }

    print_summary("kernel_rx_final", packets, bytes, kernel_ts_missing, &hist);
    Ok(())
}

struct TimestampedPacket {
    len: usize,
    src: String,
    kernel_to_user_ns: Option<u64>,
}

fn create_multicast_socket(
    port: u16,
    recv_buffer_mb: usize,
) -> Result<Socket, Box<dyn std::error::Error>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    if recv_buffer_mb > 0 {
        set_recv_buffer_size(&socket, recv_buffer_mb.saturating_mul(1024 * 1024))?;
    }

    let bind_addr: SocketAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    socket.bind(&bind_addr.into())?;
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn set_recv_buffer_size(socket: &Socket, bytes: usize) -> Result<(), Box<dyn std::error::Error>> {
    let val: libc::c_int = bytes.min(i32::MAX as usize) as libc::c_int;
    let force_ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if force_ret == 0 {
        return Ok(());
    }
    socket.set_recv_buffer_size(bytes)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_recv_buffer_size(socket: &Socket, bytes: usize) -> Result<(), Box<dyn std::error::Error>> {
    socket.set_recv_buffer_size(bytes)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_software_rx_timestamps(socket: &Socket) -> Result<(), Box<dyn std::error::Error>> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_software_rx_timestamps(_socket: &Socket) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn recvmsg_with_timestamp(fd: libc::c_int, buf: &mut [u8]) -> io::Result<TimestampedPacket> {
    let mut src: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control = [0u64; 32];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut src as *mut _ as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = mem::size_of_val(&control);

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let userspace_return_ns = realtime_now_ns()?;
    let kernel_rx_ns = unsafe { extract_kernel_timestamp_ns(&msg) };
    let src = unsafe { sockaddr_to_string(&src, msg.msg_namelen) };
    Ok(TimestampedPacket {
        len: n as usize,
        src,
        kernel_to_user_ns: kernel_rx_ns.map(|rx_ns| userspace_return_ns.saturating_sub(rx_ns)),
    })
}

#[cfg(not(target_os = "linux"))]
fn recvmsg_with_timestamp(_fd: libc::c_int, _buf: &mut [u8]) -> io::Result<TimestampedPacket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recvmsg timestamping is Linux-only",
    ))
}

#[cfg(target_os = "linux")]
unsafe fn extract_kernel_timestamp_ns(msg: &libc::msghdr) -> Option<u64> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_TIMESTAMPNS {
            let ts = unsafe { *(libc::CMSG_DATA(cmsg) as *const libc::timespec) };
            return Some(timespec_to_ns(ts));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

#[cfg(target_os = "linux")]
unsafe fn sockaddr_to_string(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> String {
    if len as usize >= mem::size_of::<libc::sockaddr_in>()
        && storage.ss_family as libc::c_int == libc::AF_INET
    {
        let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        return format!("{ip}:{port}");
    }
    "unknown".to_string()
}

fn realtime_now_ns() -> io::Result<u64> {
    let mut ts: libc::timespec = unsafe { mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(timespec_to_ns(ts))
}

fn timespec_to_ns(ts: libc::timespec) -> u64 {
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(target_os = "linux")]
fn join_multicast_by_index(
    socket: &Socket,
    multicast_ip: Ipv4Addr,
    iface_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let iface_index = unsafe {
        let name = CString::new(iface_name)?;
        libc::if_nametoindex(name.as_ptr())
    };
    if iface_index == 0 {
        return Err(format!("interface '{iface_name}' not found").into());
    }

    let mreqn = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from_be_bytes(multicast_ip.octets()).to_be(),
        },
        imr_address: libc::in_addr { s_addr: 0 },
        imr_ifindex: iface_index as libc::c_int,
    };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &mreqn as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn join_multicast_by_index(
    socket: &Socket,
    multicast_ip: Ipv4Addr,
    _iface_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    socket.join_multicast_v4(&multicast_ip, &Ipv4Addr::UNSPECIFIED)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_multicast_all(socket: &Socket, enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
    let val: libc::c_int = i32::from(enabled);
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_ALL,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_multicast_all(_socket: &Socket, _enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn print_summary(
    label: &str,
    packets: u64,
    bytes: u64,
    kernel_ts_missing: u64,
    hist: &LatencyHist,
) {
    let percentiles = hist.percentiles_ns(&[50, 90, 95, 99]);
    println!(
        "{label} packets={} bytes={} samples={} kernel_ts_missing={} kernel_to_user_min_ns={} kernel_to_user_p50_ns={} kernel_to_user_p90_ns={} kernel_to_user_p95_ns={} kernel_to_user_p99_ns={} kernel_to_user_avg_ns={} kernel_to_user_max_ns={} kernel_to_user_min_us={} kernel_to_user_p50_us={} kernel_to_user_p90_us={} kernel_to_user_p95_us={} kernel_to_user_p99_us={} kernel_to_user_avg_us={} kernel_to_user_max_us={}",
        packets,
        bytes,
        hist.samples,
        kernel_ts_missing,
        hist.min_ns(),
        percentiles[0],
        percentiles[1],
        percentiles[2],
        percentiles[3],
        hist.avg_ns(),
        hist.max_ns,
        hist.min_us(),
        hist.percentile_us(50),
        hist.percentile_us(90),
        hist.percentile_us(95),
        hist.percentile_us(99),
        hist.avg_us(),
        hist.max_us()
    );
}
