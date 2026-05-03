use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::Arc,
};

use bytemuck::{AnyBitPattern, Zeroable};
use que::{
    Channel,
    error::QueError,
    lossless::{consumer::Consumer, producer::Producer},
};

pub const XDP_QUE_PAYLOAD_MAX: usize = 1280;
pub const XDP_QUE_CAPACITY: usize = 32_768;

pub type XdpQuePayload = QueTracedPayload<XDP_QUE_PAYLOAD_MAX>;
pub type XdpQueProducer = Producer<XdpQuePayload, XDP_QUE_CAPACITY>;
pub type XdpQueConsumer = Consumer<XdpQuePayload, XDP_QUE_CAPACITY>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QueTracedPayload<const MAX: usize> {
    pub len: u16,
    pub trace_present: u8,
    pub _pad0: u8,
    pub trace_sig32: u32,
    pub data: [u8; MAX],
}

unsafe impl<const MAX: usize> Zeroable for QueTracedPayload<MAX> {}
unsafe impl<const MAX: usize> AnyBitPattern for QueTracedPayload<MAX> {}

impl<const MAX: usize> QueTracedPayload<MAX> {
    #[inline(always)]
    pub fn zeroed() -> Self {
        Self {
            len: 0,
            trace_present: 0,
            _pad0: 0,
            trace_sig32: 0,
            data: [0; MAX],
        }
    }

    #[inline(always)]
    pub unsafe fn set_from_raw(
        &mut self,
        raw_packet: *const u8,
        len: usize,
        trace_sig32: Option<u32>,
    ) {
        debug_assert!(len <= MAX);
        self.len = len as u16;
        match trace_sig32 {
            Some(sig32) => {
                self.trace_present = 1;
                self.trace_sig32 = sig32;
            }
            None => {
                self.trace_present = 0;
                self.trace_sig32 = 0;
            }
        }
        unsafe {
            std::ptr::copy_nonoverlapping(raw_packet, self.data.as_mut_ptr(), len);
        }
    }

    #[inline(always)]
    pub fn trace_sig32(&self) -> Option<u32> {
        if self.trace_present != 0 {
            Some(self.trace_sig32)
        } else {
            None
        }
    }
}

impl<const MAX: usize> AsRef<[u8]> for QueTracedPayload<MAX> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

pub struct XdpQueChannelGuard {
    ptr: NonNull<u8>,
    layout: Layout,
}

unsafe impl Send for XdpQueChannelGuard {}
unsafe impl Sync for XdpQueChannelGuard {}

impl XdpQueChannelGuard {
    fn allocate<T: AnyBitPattern, const N: usize>() -> Result<Self, QueError> {
        let layout = Layout::from_size_align(std::mem::size_of::<Channel<T, N>>(), 128)
            .map_err(|_| QueError::InvalidSize)?;
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).ok_or(QueError::InvalidSize)?;
        Ok(Self { ptr, layout })
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for XdpQueChannelGuard {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

pub fn new_payload_spsc<T: AnyBitPattern, const N: usize>()
-> Result<(Producer<T, N>, Consumer<T, N>, Arc<XdpQueChannelGuard>), QueError> {
    let guard = Arc::new(XdpQueChannelGuard::allocate::<T, N>()?);
    let producer = unsafe { Producer::<T, N>::initialize_in(guard.as_ptr())? };
    let consumer = unsafe { Consumer::<T, N>::join(guard.as_ptr())? };
    Ok((producer, consumer, guard))
}

pub fn new_xdp_que_channel()
-> Result<(XdpQueProducer, XdpQueConsumer, Arc<XdpQueChannelGuard>), QueError> {
    new_payload_spsc::<XdpQuePayload, XDP_QUE_CAPACITY>()
}
