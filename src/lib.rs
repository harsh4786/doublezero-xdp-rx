// Activate some of the Rust 2024 lints to make the future migration easier.
#![warn(if_let_rescope)]
#![warn(keyword_idents_2024)]
#![warn(missing_unsafe_on_extern)]
#![warn(rust_2024_guarded_string_incompatible_syntax)]
#![warn(rust_2024_incompatible_pat)]
#![warn(tail_expr_drop_order)]
#![warn(unsafe_attr_outside_unsafe)]
#![warn(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
pub mod combined_loop;
#[cfg(target_os = "linux")]
pub mod device;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod packet;
#[cfg(target_os = "linux")]
pub mod program;
#[cfg(target_os = "linux")]
pub mod que_channel;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
pub mod rx_loop;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
pub mod stats;
#[cfg(target_os = "linux")]
pub mod tx_loop;
#[cfg(target_os = "linux")]
pub mod umem;

// #[cfg(target_os = "linux")]
// pub mod udp_blaster;

// `xdp_blaster` is built as a standalone binary (see Cargo.toml [[bin]]),
// not as a library module.

use std::io;

#[cfg(target_os = "linux")]
pub use program::load_xdp_program;

#[cfg(target_os = "linux")]
pub fn set_cpu_affinity(cpus: impl IntoIterator<Item = usize>) -> Result<(), io::Error> {
    unsafe {
        let mut cpu_set = std::mem::zeroed();

        for cpu in cpus {
            libc::CPU_SET(cpu, &mut cpu_set);
        }

        let result = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set as *const libc::cpu_set_t,
        );
        if result != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_cpu_affinity(_cpus: impl IntoIterator<Item = usize>) -> Result<(), io::Error> {
    unimplemented!()
}
