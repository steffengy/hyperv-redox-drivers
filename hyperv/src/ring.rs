use core::arch::asm;
use core::{cmp, slice};
use core::mem;
use core::{marker::PhantomData, ptr};
use std::borrow::Cow;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use common::dma::Dma;
use log::{info, warn};
use ptr::NonNull;

use crate::gpadl::SinglePageGpaRange;
use crate::{vmbus, HvCall, PAGE_SIZE};

#[repr(C, packed)]
pub struct HvRingBuffer {
    pub write_index: u32,
    pub read_index: u32,
    /// used only guest -> host, when sending requests to host
    pub interrupt_mask: u32,
    pub pending_send_sz: u32,
    _reserved1: [u32; 12],
    pub feature_bits: u32,
    _reserved2: [u8; 4028],
    /// Ring Data
    pub buffer: [u8; 0], 
}

pub struct Producer;
pub struct Consumer;

// HINT: We can optimize performance by using circular memory mapped pages
// But keep it simple for now. Couldnt get that to work with redox mmaps EPERM?.
// TODO: does this even work with uncircular if its full?
pub struct RingBuffer<T> {
    signal_hv: Rc<dyn Fn()>,

    ring: RingBackingPages,

    pub ring_full: bool,

    pub verbose: bool,
    
    /// Internal read index, that was not written to memory yet
    /// (So the data passed to the caller is still safe to read without copying it)
    pub uncomitted_read_index: Option<usize>,
    
    pub mode: PhantomData<T>,
}

impl<T> RingBuffer<T> {
    pub(crate) fn new(signal_hv: Rc<dyn Fn()>, ptr: *mut u8, len: usize) -> RingBuffer<T> {
        RingBuffer {
            signal_hv,
            ring: RingBackingPages { ptr: NonNull::new(ptr).unwrap(), len },
            ring_full: false,
            uncomitted_read_index: None,
            mode: PhantomData,
            verbose: false,
        }
    }
}

pub async fn new(vmbus: &crate::vmbus::VmBusOuter, signal_hv: Rc<dyn Fn()>,
    channel_id: u32, producer_page_count: usize, consumer_page_count: usize) -> (RingBuffer<Producer>, RingBuffer<Consumer>) {
    // Atleast 1 data page required per ring
    assert!(producer_page_count >= 1);
    assert!(consumer_page_count >= 1);

    let ring_page_count = 2 + producer_page_count + consumer_page_count; // 2 HvRingBuffer structs + given amount of ring data pages
    
    let mut backing_buf: Dma<[u8]> = unsafe {
        crate::Dma::zeroed_slice(ring_page_count * PAGE_SIZE).unwrap().assume_init()
    };
    assert_eq!(backing_buf.physical() % PAGE_SIZE, 0);


    let pages: &mut [u64] = &mut [0; 512][..ring_page_count];

    let gpadl_handle = {
        for i in 0..pages.len() {
            pages[i] = (backing_buf.physical() + i*PAGE_SIZE) as u64;
        }
        vmbus.map_gpadl(channel_id, pages).await
    };

    info!("Opening channel... {}\n", channel_id);
    let mut req: vmbus::VmBusChannelOpenChannel = unsafe { mem::zeroed() };
    req.header.msg_type = vmbus::VmBusChannelMsgType::OpenChannel as u64;
    req.req_id = channel_id;
    req.channel_id = channel_id;
    req.recv_ring_page_offset = 1 + producer_page_count as u32;
    req.gpadl = gpadl_handle;

    unsafe {
        vmbus.post_message(&req);
    }
    let msg = vmbus.wait_message().await.unwrap();

    // print!("Channel response: {:?}\n", msg);
    let payload = msg.payload;
    assert_eq!(payload[0], vmbus::VmBusChannelMsgType::OpenChannelResult as u64);
    assert_eq!(payload[1], req.channel_id as u64 | (req.req_id as u64) << 32);
    assert_eq!(payload[2] & (u32::max_value() as u64), 0); // Success

    signal_hv(); // JUST DEBUGGING

    let mut producer_ring = RingBuffer::<Producer>::new(
        signal_hv.clone(),
        backing_buf.as_mut_ptr(),
        (1 + producer_page_count) * PAGE_SIZE
    );
    let mut consumer_ring = RingBuffer::<Consumer>::new(
        signal_hv,
        backing_buf.as_mut_ptr().wrapping_add((1 + producer_page_count) * PAGE_SIZE), 
        (1 + consumer_page_count) * PAGE_SIZE
    );

    producer_ring.ring.hv_ring().feature_bits = 1; // flow control
    consumer_ring.ring.hv_ring().feature_bits = 1; // flow control

    // TODO proper lifetime management...
    mem::forget(backing_buf);

    (producer_ring, consumer_ring)
}

/// Underlying ring buffer pages that are written/read by HyperV
struct RingBackingPages {
    ptr: ptr::NonNull<u8>, 
    len: usize,
}
unsafe impl Send for RingBackingPages {}

impl RingBackingPages {
    fn hv_ring<'b>(&'b mut self) -> &'b mut HvRingBuffer {
        unsafe {
            &mut *(self.ptr.as_ptr() as *mut HvRingBuffer)
        }
    }

    fn data<'b>(&'b mut self) -> &'b mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self.hv_ring().buffer.as_mut_ptr(),
                self.len - mem::size_of::<HvRingBuffer>()
            )
        }
    }
}

impl RingBuffer<Consumer> {
    fn len(&mut self) -> usize {
        let write_index = self.ring.hv_ring().write_index as usize;
        let read_index = self.uncomitted_read_index.unwrap_or_else(|| {
            self.ring.hv_ring().read_index as usize
        });

        let avail = if write_index < read_index {
            // <readable_part2> w@4 ... r@8 <readable_part1> end
            self.ring.data().len()/2 - read_index + write_index
        } else {
            // r@4 <readable> w@8
            write_index - read_index
        };
        avail
    }

    // Data is not valid after next next() call (!)
    pub fn next<'b>(&'b mut self) -> Option<Cow<'b, [u8]>> {
        let mut read_index = self.uncomitted_read_index.unwrap_or_else(|| {
            self.ring.hv_ring().interrupt_mask = 1;
            // crate::memory_barrier();
            
            self.ring.hv_ring().read_index as usize
        });
        let commited_read_index = self.ring.hv_ring().read_index;

        let write_index = self.ring.hv_ring().write_index as usize;

        let avail = self.len();
        if self.verbose {
            info!("WR: {}, RD: {} {}, avail: {}\n", write_index, read_index, commited_read_index, avail);
        }
        
        // Check if the writer has even produced enough data yet
        if avail < mem::size_of::<vmbus::VmPacketDescriptor>() {
            self.uncomitted_read_index = Some(read_index);
            // If data is directly available again, try again, we wont receive an interrupt!
            if self.flush() {
                return self.next();
            }
            return None;
        }
        let ring_data = self.ring.data();
        let packet_desc = unsafe { &*(ring_data.as_ptr().add(read_index) as *const vmbus::VmPacketDescriptor) };
        assert!(avail >= packet_desc.len());

        let ret = if read_index + packet_desc.len() < ring_data.len() {
            Cow::Borrowed(&ring_data[read_index..][..packet_desc.len()])
        } else {
            warn!("WR: copy wraparound :/");
            Cow::Owned(ring_data.iter().chain(ring_data.iter()).skip(read_index).take(packet_desc.len()).copied().collect::<Vec<u8>>())
        };
        read_index += packet_desc.len() + 8;
        read_index = read_index % ring_data.len();
        self.uncomitted_read_index = Some(read_index);

        Some(ret)
    }

    fn flush(&mut self) -> bool {
        // print!("FLUSH {:?}\n", self.uncomitted_read_index);
        // crate::memory_barrier();  // TODO virt_rmb
        unsafe { asm!(""); }
        if let Some(uncomitted_read_index) = self.uncomitted_read_index.take() {
            unsafe {
                let hv_ring = self.ring.hv_ring();
                let ring_read_index = core::ptr::addr_of_mut!(hv_ring.read_index);
                ptr::write_volatile(ring_read_index, uncomitted_read_index as u32);
                // crate::memory_barrier();
                let ring_interrupt_mask = core::ptr::addr_of_mut!(hv_ring.interrupt_mask);
                ptr::write_volatile(ring_interrupt_mask, 0);
                // crate::memory_barrier();
            }

            // Check if we raced and data is still available
            if self.len() > 0 {
                return true;
            }
            
            // TODO: hv_pkt_iter_close: HINT can be optimized to signal less
            let hv_ring = self.ring.hv_ring();
            let feature_bits = hv_ring.feature_bits;
            assert_eq!(feature_bits, 1);
            let pending_send_sz = core::ptr::addr_of!(hv_ring.pending_send_sz);
            if unsafe { ptr::read_volatile(pending_send_sz) } == 0 {
                return false;
            }

            // TODO: vmbus_setevent Only if no dedicated interrupt / latency optimized
            (self.signal_hv)();
        }
        false
    }
}

impl RingBuffer<Producer> {
    pub fn write(&mut self, vmbus: &mut vmbus::VmBus, bufs: &mut [&[u8]]) {
        // TODO: Prevent interrupt from interferring
        let mut write_index = self.ring.hv_ring().write_index as usize;
        let old_write_index = write_index;
        let read_index = self.ring.hv_ring().read_index as usize;

        let mut ring_full = self.ring_full;
        let ring_data = self.ring.data();
        let mut single_write = |buf: &mut &[u8], mut write_index: usize| {
            assert!(!ring_full);
            let max_write_amount = if write_index < read_index {
                // w @ 4 [...] r @ 8
                read_index - write_index
            } else {
                // w @ 4 [...] end   (what about w@4 [..end..] r@2 ? + read_index?)
                ring_data.len() - write_index
            };
            let amount = cmp::min(max_write_amount, buf.len());
            if self.verbose {
                info!("Writing {} {} {} {}\n", read_index, write_index, amount, ring_data.len());
            }

            ring_data[write_index..][..amount].copy_from_slice(&buf[..amount]);
            *buf = &buf[amount..];
            write_index += amount;
            if write_index == ring_data.len() {
                write_index = 0;
            }
            ring_full = write_index == read_index;
            write_index
        };

        for buf in bufs.iter_mut() {
            while !buf.is_empty() {
                write_index = single_write(buf, write_index);
            }
        }
        assert!(write_index % 8 == 0);
        let tmp_buf = ((old_write_index as u64) << 32 | read_index as u64).to_le_bytes();
        let mut tmp_buf_ptr = &tmp_buf[..];
        write_index = single_write(&mut tmp_buf_ptr, write_index);
        assert!(tmp_buf_ptr.is_empty());
        // crate::memory_barrier();
        self.ring_full = ring_full;
        
        unsafe {
            let ring_write_index = core::ptr::addr_of_mut!(self.ring.hv_ring().write_index);
            ptr::write_volatile(ring_write_index, write_index as u32);

            // Only if no dedicated interrupt / latency optimized TODO: Signaling only needed for first msg!
            (self.signal_hv)();
            /*let monitor_page = vmbus::VM_BUS.monitor_pages[1].load(::core::sync::atomic::Ordering::SeqCst);
            let monitor_id = 0; // TODO monitor id of channel
            let monitor_group = monitor_id / 32;
            let monitor_bit = monitor_id % 32;
            print!("Trigger Group: {}, Bit {}\n", monitor_group, monitor_bit);
            let target = monitor_page.add(8 + 8 * monitor_group as usize) as *mut u32;
            ptr::write_volatile(target, ptr::read_volatile(target) | 1<<monitor_bit);*/
        }
    }

    pub fn send_vmpacket(&mut self, vmbus: &mut vmbus::VmBus, payload_bufs: &[&[u8]], request_response: bool) {
        let temp_aligned = [0u8; 8];
        
        let bufs_bytes: usize = payload_bufs.iter().map(|x| x.len()).sum();
        let mut aligned_len = mem::size_of::<vmbus::VmPacketDescriptor>() + bufs_bytes;
        let delta_align = aligned_len % 8;
        aligned_len += delta_align;

        let mut desc = vmbus::VmPacketDescriptor::default();
        desc.ty = vmbus::VmBusPacketType::DataInband as u16;
        desc.set_completion_requested(request_response);
        desc.set_offset(mem::size_of::<vmbus::VmPacketDescriptor>());
        desc.set_len(aligned_len);
        desc.trans_id = payload_bufs.as_ptr() as u64;
    
        let mut bufs = 1+payload_bufs.len();
        if delta_align > 0 {
            bufs += 1;
        }
        let buf_tmp = &mut [&[0u8] as &[u8]; 16][..bufs];
        buf_tmp[0] = unsafe { slice::from_raw_parts(
            &desc as *const _ as *const u8, 
            mem::size_of::<vmbus::VmPacketDescriptor>())
        };
        buf_tmp[1..1+payload_bufs.len()].copy_from_slice(payload_bufs);
        if delta_align > 0 {
            buf_tmp[buf_tmp.len()-1] = &temp_aligned[..delta_align];
        }
    
        self.write(vmbus, buf_tmp);
    }

    /// Send a VMPacket using GPA Direct, passing some pages directly to the host
    pub fn send_vmpacket_gpa_direct(&mut self, vmbus: &mut vmbus::VmBus, inline_payload_bufs: &[&[u8]], gpa_bufs: &[&[u8]]) {
        let inline_bytes: usize = inline_payload_bufs.iter().map(|x| x.len()).sum();
        let required_bytes = mem::size_of::<vmbus::VmDataGpaDirect>() + gpa_bufs.len() * mem::size_of::<SinglePageGpaRange>();
        let aligned_len = required_bytes + inline_bytes;
        // print!("Desc size {}, Overall size {}\n", required_bytes, aligned_len);
        assert_eq!(aligned_len % 8, 0);

        let buf = &mut [0u8; 256][..required_bytes];
        
        // Setup header
        let direct = unsafe { &mut *(buf.as_mut_ptr() as *mut vmbus::VmDataGpaDirect) };
        direct.descriptor.ty = vmbus::VmBusPacketType::DataGpaDirect as u16;
        direct.descriptor.set_completion_requested(true);
        direct.descriptor.set_offset(buf.len());
        direct.descriptor.set_len(aligned_len);
        direct.descriptor.trans_id = inline_payload_bufs.as_ptr() as u64;
        direct.range_count = gpa_bufs.len() as u32;

        // Pass through given buffers as "GPA buffers"
        let gpa_range = unsafe {
            slice::from_raw_parts_mut(buf[mem::size_of::<vmbus::VmDataGpaDirect>()..].as_mut_ptr() as *mut SinglePageGpaRange, gpa_bufs.len())
        };

        for (gpa_buf, gpa) in gpa_bufs.iter().zip(gpa_range.iter_mut()) {
            let phys_addr: u64 = unsafe {
                let ptr: *const u8 = gpa_buf.as_ptr();
                syscall::virttophys(ptr as usize).unwrap() as u64
            };
            gpa.range.length = gpa_buf.len() as u32;
            gpa.range.offset = (phys_addr % 4096) as u32;
            gpa.pfn = phys_addr / 4096;
            assert_eq!(phys_addr / 4096, (phys_addr + gpa_buf.len() as u64) / 4096); // TODO page boundary
            // print!("BUF: {:?}\n", gpa);
        }
        
        // Setup inline data
        let buf_tmp = &mut [&[0u8] as &[u8]; 16][..1+inline_payload_bufs.len()];
        buf_tmp[0] = buf;
        buf_tmp[1..].copy_from_slice(inline_payload_bufs);
        self.write(vmbus, buf_tmp);

    }
}
