#![allow(clippy::arithmetic_side_effects)]

use std::{
    env,
    io::{Cursor, Write},
    net::Ipv4Addr,
};

use aya::EbpfLoader;
#[cfg(target_os = "linux")]
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap as AyaHashMap},
    programs::{Xdp, xdp::XdpFlags},
};

use crate::device::NetworkDevice;

const XSKS_MAP_PIN: &str = "/sys/fs/bpf/xsks_map";
const CLASSIFIER_PROG_ENV: &str = "AGAVE_XDP_EBPF_OBJECT";
const CLASSIFIER_PROG_DEFAULT: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/agave-xdp-rx-classifier-prog");
const XDP_INGRESS_TS_MAP_PIN: &str = "/sys/fs/bpf/xdp_ingress_timestamps";
const XDP_REDIRECT_COUNT_MAP_PIN: &str = "/sys/fs/bpf/xdp_redirect_count";
const CONFIG_INDEX: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct XdpConfigMapValue {
    listen_ip4_addr: u32,
    allowed_gre: u32,
    _pad: [u32; 2],
}

unsafe impl Pod for XdpConfigMapValue {}

macro_rules! write_fields {
    ($w:expr, $($x:expr),*) => {
        $(
            $w.write_all(&$x.to_le_bytes())?;
        )*
    };
}

// XDP program (pass stub): r0 = XDP_PASS; exit
const XDP_PROG_PASS: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // r0 = XDP_PASS
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

// the string table - calculating exact positions:
// \0xdp\0.symtab\0.strtab\0maps/xsks_map\0xdp_pass\0.rel.xdp\0xsks_map\0
// 0: \0
// 1-3: xdp
// 4: \0
// 5-11: .symtab
// 12: \0
// 13-19: .strtab
// 20: \0
// 21-25: .maps
// 26: \0
// 27-34: xdp_pass
// 35: \0
// 36-43: .rel.xdp
// 44: \0
// 45-52: xsks_map
// 53: \0
const STRTAB: &[u8] = b"\0xdp\0.symtab\0.strtab\0.maps\0xdp_pass\0.rel.xdp\0xsks_map\0";

pub fn load_xdp_program(if_index: u32) -> Result<Ebpf, Box<dyn std::error::Error>> {
    let dev = NetworkDevice::new_from_index(if_index)?;
    let broken_frags = dev.driver().map(|driver| driver == "i40e").unwrap_or(false);
    let config = classifier_config_from_env(&dev);
    let classifier_prog =
        env::var(CLASSIFIER_PROG_ENV).unwrap_or_else(|_| CLASSIFIER_PROG_DEFAULT.to_string());

    // Load XDP redirect program with embedded XSKMAP
    // This is required for AF_XDP to work - XDP_PASS won't reach AF_XDP sockets
    // Try to load with detailed error reporting
    match EbpfLoader::new()
        .set_global("AGAVE_XDP_DROP_MULTI_FRAGS", &u8::from(broken_frags), true)
        .load_file(&classifier_prog)
    {
        Ok(mut ebpf) => {
            log::info!("ELF loaded successfully by Aya from {}", classifier_prog);

            // Debug: print available maps and programs
            debug_ebpf_object(&ebpf);

            populate_classifier_maps(&mut ebpf, &config)?;

            // CRITICAL FIX: Pin the XSKMAP to filesystem so userspace can access the same instance
            log::info!("MAP PINNING: Attempting to pin xsks_map to {XSKS_MAP_PIN}");
            if let Some(map) = ebpf.map("xsks_map") {
                if let Err(e) = map.pin(XSKS_MAP_PIN) {
                    // Try to remove existing pin and retry
                    let _ = std::fs::remove_file(XSKS_MAP_PIN);
                    if let Err(e2) = map.pin(XSKS_MAP_PIN) {
                        log::error!("Failed to pin xsks_map: {:?}, retry failed: {:?}", e, e2);
                    } else {
                        log::info!(
                            "SUCCESS: xsks_map pinned to {XSKS_MAP_PIN} (after removing old pin)"
                        );
                    }
                } else {
                    log::info!("SUCCESS: xsks_map pinned to {XSKS_MAP_PIN}");
                }
            } else {
                log::error!("CRITICAL: xsks_map not found in loaded eBPF object");
            }

            if let Some(map) = ebpf.map("xdp_ingress_timestamps") {
                if let Err(e) = map.pin(XDP_INGRESS_TS_MAP_PIN) {
                    let _ = std::fs::remove_file(XDP_INGRESS_TS_MAP_PIN);
                    if let Err(e2) = map.pin(XDP_INGRESS_TS_MAP_PIN) {
                        log::error!(
                            "Failed to pin xdp_ingress_timestamps: {:?}, retry failed: {:?}",
                            e,
                            e2
                        );
                    } else {
                        log::info!(
                            "SUCCESS: xdp_ingress_timestamps pinned to {XDP_INGRESS_TS_MAP_PIN} (after removing old pin)"
                        );
                    }
                } else {
                    log::info!(
                        "SUCCESS: xdp_ingress_timestamps pinned to {XDP_INGRESS_TS_MAP_PIN}"
                    );
                }
            } else {
                log::warn!("xdp_ingress_timestamps not found in loaded eBPF object");
            }

            if let Some(map) = ebpf.map("xdp_redirect_count") {
                if let Err(e) = map.pin(XDP_REDIRECT_COUNT_MAP_PIN) {
                    let _ = std::fs::remove_file(XDP_REDIRECT_COUNT_MAP_PIN);
                    if let Err(e2) = map.pin(XDP_REDIRECT_COUNT_MAP_PIN) {
                        log::error!(
                            "Failed to pin xdp_redirect_count: {:?}, retry failed: {:?}",
                            e,
                            e2
                        );
                    } else {
                        log::info!(
                            "SUCCESS: xdp_redirect_count pinned to {XDP_REDIRECT_COUNT_MAP_PIN} (after removing old pin)"
                        );
                    }
                } else {
                    log::info!(
                        "SUCCESS: xdp_redirect_count pinned to {XDP_REDIRECT_COUNT_MAP_PIN}"
                    );
                }
            } else {
                log::warn!("xdp_redirect_count not found in loaded eBPF object");
            }

            let p: &mut Xdp = ebpf
                .program_mut("xdp_redirect")
                .ok_or("xdp program not found")?
                .try_into()?;

            match p.load() {
                Ok(()) => {
                    log::info!("XDP program loaded successfully by kernel verifier");
                }
                Err(e) => {
                    log::error!("XDP program failed kernel verification: {:?}", e);
                    return Err(Box::new(e));
                }
            }

            attach_xdp_program(p, if_index)?;

            log::info!(
                "XDP redirect program attached successfully - AF_XDP packets will be redirected"
            );
            Ok(ebpf)
        }
        Err(e) => {
            log::error!("ELF loading failed: {:?}", e);
            Err(Box::new(e))
        }
    }
}

#[derive(Clone, Debug)]
struct XdpProgramConfig {
    listen_ip4_addr: Option<Ipv4Addr>,
    ports: Vec<u16>,
    allowed_gre: bool,
}

fn classifier_config_from_env(dev: &NetworkDevice) -> XdpProgramConfig {
    let listen_ip4_addr = env::var("RX_DST_IP")
        .ok()
        .or_else(|| env::var("PUBLIC_IP").ok())
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .or_else(|| dev.ipv4_addr().ok());
    let bind_port = env::var("BIND_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(20000);
    let allowed_gre = env::var("XDP_ALLOW_GRE")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    XdpProgramConfig {
        listen_ip4_addr,
        ports: vec![bind_port],
        allowed_gre,
    }
}

fn populate_classifier_maps(
    ebpf: &mut Ebpf,
    config: &XdpProgramConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_map: Array<_, XdpConfigMapValue> =
        Array::try_from(ebpf.map_mut("CONFIG").ok_or("CONFIG map not found")?)?;
    config_map.set(
        CONFIG_INDEX,
        XdpConfigMapValue {
            listen_ip4_addr: config.listen_ip4_addr.map(u32::from).unwrap_or(0),
            allowed_gre: u32::from(config.allowed_gre),
            _pad: [0; 2],
        },
        0,
    )?;

    let mut ports_map: AyaHashMap<_, u16, u8> =
        AyaHashMap::try_from(ebpf.map_mut("PORTS").ok_or("PORTS map not found")?)?;
    for port in &config.ports {
        ports_map.insert(*port, 1u8, 0)?;
    }

    log::info!(
        "Configured classifier listen_ip4_addr={:?} ports={:?} allowed_gre={}",
        config.listen_ip4_addr,
        config.ports,
        config.allowed_gre
    );
    Ok(())
}

fn debug_ebpf_object(ebpf: &Ebpf) {
    log::info!("EBPF OBJECT ANALYSIS:");

    // List all programs
    log::info!("PROGRAMS:");
    for (name, _program) in ebpf.programs() {
        log::info!("  Program: '{}'", name);
    }

    // List all maps
    log::info!("MAPS:");
    for (name, _map) in ebpf.maps() {
        log::info!("  Map: '{}'", name);
    }
}

const SHT_NULL: u32 = 0;
// text section
const SHT_PROGBITS: u32 = 1;
// symbol table
const SHT_SYMTAB: u32 = 2;
// string table
const SHT_STRTAB: u32 = 3;

// flags required for the text section
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;

// symbol visibility
const STB_GLOBAL: u8 = 1 << 4;
// symbol type
const STT_FUNC: u8 = 2;

// we just let all packets in
const XDP_PROG: &[u8] = &[
    0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // r0 = XDP_PASS
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

// the string table
const STRTAB_PASS: &[u8] = b"\0xdp\0.symtab\0.strtab\0agave_xdp\0";

pub fn load_xdp_pass_program(dev: &NetworkDevice) -> Result<Ebpf, Box<dyn std::error::Error>> {
    let mut loader = EbpfLoader::new();
    let broken_frags = dev.driver()? == "i40e";
    let mut ebpf = if broken_frags {
        loader.set_global("AGAVE_XDP_DROP_MULTI_FRAGS", &1u8, true);
        loader.load(&agave_xdp_ebpf::AGAVE_XDP_EBPF_PROGRAM)
    } else {
        loader.load(&generate_xdp_elf())
    }?;
    let p: &mut Xdp = ebpf.program_mut("agave_xdp").unwrap().try_into().unwrap();
    p.load()?;

    attach_xdp_program(p, dev.if_index())?;

    Ok(ebpf)
}

fn configured_attach_mode() -> String {
    env::var("XDP_ATTACH_MODE")
        .unwrap_or_else(|_| "auto".to_string())
        .trim()
        .to_ascii_lowercase()
}

fn attach_xdp_program(p: &mut Xdp, if_index: u32) -> Result<(), Box<dyn std::error::Error>> {
    let attach_mode = configured_attach_mode();
    match attach_mode.as_str() {
        "skb" | "generic" => {
            p.attach_to_if_index(if_index, XdpFlags::SKB_MODE)?;
            log::info!("XDP program attached in SKB_MODE");
        }
        "drv" | "native" => {
            p.attach_to_if_index(if_index, XdpFlags::DRV_MODE)?;
            log::info!("XDP program attached in DRV_MODE");
        }
        _ => {
            if let Err(e) = p.attach_to_if_index(if_index, XdpFlags::DRV_MODE) {
                log::warn!("DRV_MODE failed: {:?}, trying SKB_MODE", e);
                p.attach_to_if_index(if_index, XdpFlags::SKB_MODE)?;
                log::info!("XDP program attached in SKB_MODE (fallback)");
            } else {
                log::info!("XDP program attached in DRV_MODE");
            }
        }
    }
    Ok(())
}

fn generate_xdp_elf() -> Vec<u8> {
    let mut buffer = vec![0u8; 4096];
    let mut cursor = Cursor::new(&mut buffer);

    // start after the header
    let xdp_off = 64;
    cursor.set_position(xdp_off);
    cursor.write_all(XDP_PROG).unwrap();
    let xdp_size = cursor.position() - xdp_off;

    // write the string table
    let strtab_off = cursor.position();
    cursor.write_all(STRTAB_PASS).unwrap();
    let strtab_size = cursor.position() - strtab_off;

    // write the symbol table
    let symtab_off = align_cursor(&mut cursor, 8);
    write_symbol(&mut cursor, 0, 0, 0, 0, 0, 0).unwrap();
    write_symbol(
        &mut cursor,
        21, // index
        0,
        XDP_PROG.len() as u64,
        STB_GLOBAL | STT_FUNC,
        0,
        1, // section index
    )
    .unwrap();
    let symtab_size = cursor.position() - symtab_off;

    // write the section headers
    let shdrs_off = align_cursor(&mut cursor, 8);
    write_section_headers(
        &mut cursor,
        xdp_off,
        xdp_size,
        strtab_off,
        strtab_size,
        symtab_off,
        symtab_size,
    )
    .unwrap();

    // finally go back and write the header
    const SECTIONS: u16 = 4;
    const STRTAB_INDEX: u16 = 2;
    cursor.set_position(0);
    write_elf_header(&mut cursor, shdrs_off, SECTIONS, STRTAB_INDEX).unwrap();

    buffer
}

fn align_cursor(cursor: &mut Cursor<&mut Vec<u8>>, alignment: usize) -> u64 {
    let pos = cursor.position() as usize;
    let padding = (alignment - (pos % alignment)) % alignment;
    cursor.set_position((pos + padding) as u64);
    cursor.position()
}

fn write_elf_header(
    w: &mut impl Write,
    sh_offset: u64,
    sh_num: u16,
    sh_strndx: u16,
) -> std::io::Result<()> {
    let mut header = [
        0x7f, 0x45, 0x4c, 0x46, // EI_MAG: 0x7F 'ELF'
        0x02, 0x01, 0x01, 0x00, // CLASS64, LSB, Version1
        0x00, 0x00, 0x00, 0x00, // EI_PAD
        0x00, 0x00, 0x00, 0x00, // EI_PAD
        0x01, 0x00, // e_type: ET_REL
        0xf7, 0x00, // e_machine: EM_BPF
        0x01, 0x00, 0x00, 0x00, // e_version: EV_CURRENT
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x40, 0x00, // e_ehsize: 64
        0x00, 0x00, // e_phentsize
        0x00, 0x00, // e_phnum
        0x40, 0x00, // e_shentsize: 64
        0x00, 0x00, // e_shnum
        0x00, 0x00, // e_shstrndx
    ];

    header[40..48].copy_from_slice(&sh_offset.to_le_bytes());
    header[60..62].copy_from_slice(&sh_num.to_le_bytes());
    header[62..64].copy_from_slice(&sh_strndx.to_le_bytes());

    w.write_all(&header)
}

#[allow(clippy::too_many_arguments)]
fn write_section_header(
    w: &mut impl Write,
    name: u32,
    type_: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
) -> std::io::Result<()> {
    write_fields!(
        w, name, type_, flags, addr, offset, size, link, info, addralign, entsize
    );

    Ok(())
}

fn write_symbol(
    w: &mut impl Write,
    name: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
) -> std::io::Result<()> {
    write_fields!(
        w,
        name,
        ((other as u16) << 8) | info as u16,
        shndx,
        value,
        size
    );

    Ok(())
}

// don't format the write_section_headers calls 1-2 digit arguments are annoying
#[rustfmt::skip]
fn write_section_headers(
    w: &mut impl Write,
    xdp_off: u64,
    xdp_size: u64,
    strtab_off: u64,
    strtab_size: u64,
    symtab_off: u64,
    symtab_size: u64,
) -> std::io::Result<()> {
    const STRTAB_XDP_OFF: u32 = 1;
    const STRTAB_SYMTAB_OFF: u32 = 5;
    const STRTAB_STRTAB_OFF: u32 = 13;
    write_section_header(w, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)?;
    write_section_header(w, STRTAB_XDP_OFF, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, xdp_off, xdp_size, 0, 0, 0, 0)?;
    write_section_header(w, STRTAB_STRTAB_OFF, SHT_STRTAB, 0, 0, strtab_off, strtab_size, 0, 0, 0, 0)?;
    write_section_header(w, STRTAB_SYMTAB_OFF, SHT_SYMTAB, 0, 0, symtab_off, symtab_size, 2, 1, 0, 0)?;
    Ok(())
}
