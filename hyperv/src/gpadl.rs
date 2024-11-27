use core::cmp;
use core::ptr;
use core::{sync::atomic, mem};
use atomic::Ordering;
use crate::vmbus;

static NEXT_GPADL_HANDLE: atomic::AtomicU32 = atomic::AtomicU32::new(1);

/// GPADL (Guest Physical Addresss Descriptor List)
#[repr(C, packed)]
struct VmBusChannelGpadlHeader {
    header: vmbus::VmBusChannelMsgHeader,
    channel_id: u32,
    gpadl: u32,
    ranges: VmBusChannelGpadlHeaderRangeDescriptors,
}

#[repr(C,packed)]
struct VmBusChannelGpadlBody {
    header: vmbus::VmBusChannelMsgHeader,
    msg_number: u32,
    gpadl: u32,
    pfn: [u64; 0],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct GpaRange {
    pub length: u32,
    pub offset: u32,
    /// (guest) PFN (page frame numbers)
    pfn_array: [u64; 0]
}

#[repr(C)]
#[derive(Debug)]
pub struct SinglePageGpaRange {
    pub range: GpaRange,
    /// (guest) PFN (page frame number)
    pub pfn: u64,
}

#[repr(C, packed)]
struct VmBusChannelGpadlHeaderRangeDescriptors {
    /// Byte length of range descriptors
    pub len: u16,
    /// Count of range descriptors
    pub count: u16,
    pub data: [GpaRange; 0]
}

/// Returns amount of consumed `phys_page_addrs`
fn post_gpadl_header(vmbus: &mut vmbus::VmBus, channel_id: u32, gpadl_handle: u32, phys_page_addrs: &[u64]) -> usize {
    const AVAIL_BYTES_GPADL_HEADER: usize = 8*crate::HV_MESSAGE_PAYLOAD_QWORD_COUNT 
        - mem::size_of::<VmBusChannelGpadlHeader>()
        - mem::size_of::<GpaRange>();
    const MAX_GPADL_HEADER_PAGES: usize = AVAIL_BYTES_GPADL_HEADER / 8;
    let consumed_pages = cmp::min(phys_page_addrs.len(), MAX_GPADL_HEADER_PAGES);

    let descriptor = GpaRange {
        length: phys_page_addrs.len() as u32 * 4096,
        offset: 0,
        ..GpaRange::default()
    };

    let mut buf = [0u8; 8*crate::HV_MESSAGE_PAYLOAD_QWORD_COUNT];

    unsafe {
        ptr::write_unaligned(&mut buf[mem::size_of::<VmBusChannelGpadlHeader>()] as *mut _ as *mut GpaRange, descriptor);

        let pfn_array: &mut [u8] = ::core::slice::from_raw_parts_mut(
            &mut buf[mem::size_of::<VmBusChannelGpadlHeader>() + mem::size_of::<GpaRange>()] as *mut _ as *mut u8,
            8 * consumed_pages,
        );
        for i in 0..consumed_pages {
            ptr::write_unaligned(&mut pfn_array[8*i] as *mut u8 as *mut u64, phys_page_addrs[i] / 4096);
        }
    }
    let gpadl = unsafe { &mut *(buf.as_mut_ptr() as *mut VmBusChannelGpadlHeader) };

    gpadl.header.msg_type = vmbus::VmBusChannelMsgType::GpadlHeader as u64;
    gpadl.channel_id = channel_id;
    gpadl.gpadl = gpadl_handle;
    gpadl.ranges.len = (mem::size_of_val(&descriptor) + 8 * phys_page_addrs.len()) as u16;
    gpadl.ranges.count = 1;
    
    unsafe {
        vmbus.post_message_slice(&buf[..buf.len() - 8 * (MAX_GPADL_HEADER_PAGES - consumed_pages)]);
    }

    consumed_pages
}

/// Post pages that didnt fit into the header in additional body messages
fn post_gpadl_body(vmbus: &mut vmbus::VmBus, gpadl_handle: u32, phys_page_addrs: &[u64]) -> usize {
    const AVAIL_BYTES_GPADL_BODY: usize = 8*crate::HV_MESSAGE_PAYLOAD_QWORD_COUNT 
        - mem::size_of::<VmBusChannelGpadlBody>();
    const MAX_GPADL_BODY_PAGES: usize = AVAIL_BYTES_GPADL_BODY / 8;
    let consumed_pages = cmp::min(phys_page_addrs.len(), MAX_GPADL_BODY_PAGES);

    let mut buf = [0u8; 8*crate::HV_MESSAGE_PAYLOAD_QWORD_COUNT];

    let gpadl = unsafe { &mut *(buf.as_mut_ptr() as *mut VmBusChannelGpadlBody) };
    gpadl.header.msg_type = vmbus::VmBusChannelMsgType::GpadlBody as u64;
    gpadl.gpadl = gpadl_handle;

    let pfn_array: &mut [u8] = unsafe { 
        ::core::slice::from_raw_parts_mut(
            &mut buf[mem::size_of::<VmBusChannelGpadlBody>()] as *mut u8,
            8 * consumed_pages,
        )
    };

    unsafe {
        for i in 0..consumed_pages {
            ptr::write_unaligned(&mut pfn_array[8*i] as *mut u8 as *mut u64, phys_page_addrs[i] / 4096);
        }

        vmbus.post_message_slice(&buf[..buf.len() - 8 * (MAX_GPADL_BODY_PAGES - consumed_pages)]);
    }
    consumed_pages
}

/// Map a list of physical page addresses to "guest physical address descriptor list" for a given channel
impl vmbus::VmBusOuter {
    pub async fn map_gpadl(&self, channel_id: u32, mut phys_page_addrs: &[u64]) -> u32 {
        // print!("Mapping GPADL... {}\n", phys_page_addrs.len());
        let gpadl_handle = NEXT_GPADL_HANDLE.fetch_add(1, Ordering::SeqCst);
        {
            let mut vmbus = (*self.0).borrow_mut();
            let pages_in_header = post_gpadl_header(&mut vmbus, channel_id, gpadl_handle, phys_page_addrs);
            phys_page_addrs = &phys_page_addrs[pages_in_header..];
            while !phys_page_addrs.is_empty() {
                let pages_in_body = post_gpadl_body(&mut vmbus, gpadl_handle, phys_page_addrs);
                phys_page_addrs = &phys_page_addrs[pages_in_body..];
            }
        }
        
        let gpadl_response = self.wait_message().await.unwrap();
        let payload = gpadl_response.payload;
        // print!("GPADL response: {:?}\n", gpadl_response);
        assert_eq!(payload[0], vmbus::VmBusChannelMsgType::GpadlCreated as u64);
        assert_eq!(payload[1], channel_id as u64 | (gpadl_handle as u64) << 32);
        assert_eq!(payload[2] & (u32::max_value() as u64), 0); // Creation was successful

        gpadl_handle
    }
}
