#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_GRE: u8 = 47;
const GRE_HDR_LEN: usize = 4;
const GRE_PROTO_IPV4: u16 = 0x0800;
const IPV4_MIN_IHL: u8 = 0x45;
const INNER_SHRED_PORT: u16 = 7733;
const INNER_HEARTBEAT_PORT: u16 = 5765;
const INNER_SHRED_MCAST: u32 = u32::from_be_bytes([233, 84, 178, 1]);
const INNER_SHRED_MCAST_ALT: u32 = u32::from_be_bytes([233, 84, 178, 12]);
#[map(name = "xsks_map")]
static SOCKS: XskMap = XskMap::pinned(64, 0);

#[xdp]
pub fn doublezero_xdp_redirect(ctx: XdpContext) -> u32 {
    match try_doublezero_xdp_redirect(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_doublezero_xdp_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    if read_be_u16(ctx, 12)? != ETH_P_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Keep the first working path verifier-friendly: DZ packets observed here
    // use standard IPv4 headers without options.
    if read_u8(ctx, ETH_HDR_LEN)? != IPV4_MIN_IHL {
        return Ok(xdp_action::XDP_PASS);
    }
    if read_u8(ctx, ETH_HDR_LEN + 9)? != IPPROTO_GRE {
        return Ok(xdp_action::XDP_PASS);
    }

    let gre_start = ETH_HDR_LEN + 20;
    let gre_flags = read_be_u16(ctx, gre_start)?;
    let gre_proto = read_be_u16(ctx, gre_start + 2)?;

    // Keep the first version conservative: only decapsulate basic GRE-over-IPv4.
    if gre_flags != 0 || gre_proto != GRE_PROTO_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let inner_ip_start = gre_start + GRE_HDR_LEN;
    if read_u8(ctx, inner_ip_start)? != IPV4_MIN_IHL {
        return Ok(xdp_action::XDP_PASS);
    }
    let inner_proto = read_u8(ctx, inner_ip_start + 9)?;

    if inner_proto == IPPROTO_TCP {
        // Preserve control-plane traffic such as BGP.
        return Ok(xdp_action::XDP_PASS);
    }
    if inner_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_start = inner_ip_start + 20;
    let dst_port = read_be_u16(ctx, udp_start + 2)?;
    if dst_port == INNER_HEARTBEAT_PORT {
        return Ok(xdp_action::XDP_PASS);
    }
    if dst_port != INNER_SHRED_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let dst_addr = read_be_u32(ctx, inner_ip_start + 16)?;
    if dst_addr != INNER_SHRED_MCAST && dst_addr != INNER_SHRED_MCAST_ALT {
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(SOCKS
        .redirect(unsafe { (*ctx.ctx).rx_queue_index }, 0)
        .unwrap_or(xdp_action::XDP_PASS))
}

#[inline(always)]
fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + 1 > end {
        return Err(());
    }
    Ok(unsafe { *((start + offset) as *const u8) })
}

#[inline(always)]
fn read_be_u16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + 2 > end {
        return Err(());
    }
    let ptr = (start + offset) as *const [u8; 2];
    Ok(u16::from_be_bytes(unsafe { *ptr }))
}

#[inline(always)]
fn read_be_u32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + 4 > end {
        return Err(());
    }
    let ptr = (start + offset) as *const [u8; 4];
    Ok(u32::from_be_bytes(unsafe { *ptr }))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
