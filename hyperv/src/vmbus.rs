use common::dma::Dma;
use log::info;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::sync::atomic;
use std::sync::atomic::Ordering;
use crate::HvCall;
use crate::HvMessage;
use crate::UUID;
use crate::{try_from_enum, PAGE_SIZE};

const VMBUS_MESSAGE_CONNECTION_ID_4: u32 = 4;
const VMBUS_MESSAGE_SINT: u32 = 2;
const VMBUS_VERSION_WIN10_V5_2: u32 = (5 << 16) | 2;
const MAX_USER_DEFINED_BYTES: usize = 120;
const MAX_PIPE_USER_DEFINED_BYTES: usize = 116;

try_from_enum!(
    #[repr(u64)]
    #[derive(Debug)]
    pub enum VmBusChannelMsgType {
        Invalid = 0,
        OfferChannel = 1,
        RequestOffers = 3,
        AllOffersDelivered = 4,
        OpenChannel = 5,
        OpenChannelResult = 6,
        GpadlHeader = 8,
        GpadlBody = 9,
        GpadlCreated = 10,
        InitiateContact = 14,
        VersionResponse = 15,
    }
);

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct VmBusChannelMsgHeader {
    pub msg_type: u64,
}

#[repr(C)]
struct VmBusChannelInitiateContact {
    header: VmBusChannelMsgHeader,
    version_requested: u32,
    target_vcpu: u32,
    union: VmBusChannelInitiateContact_union,
    monitor_pages: [u64; 2],
}

#[repr(C)]
union VmBusChannelInitiateContact_union {
    interrupt_page: u64,
    other: VmBusChannelInitiateContact_union_member,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct VmBusChannelInitiateContact_union_member {
    msg_sint: u8,
    padding1: [u8; 3],
    padding2: u32,
}

#[repr(C, packed)]
pub struct VmBusChannelOpenChannel {
    pub header: VmBusChannelMsgHeader,

    /// ID of the channel being opened
    pub channel_id: u32,
    /// ID of this request
    pub req_id: u32,
    pub gpadl: u32,
    /// Which vCPU should receive interrupts for this
    pub target_vp: u32,
    /// Amount of pages at which the receiving ring buffer (downstream) is located at
    pub recv_ring_page_offset: u32,
    user_data: [u8; MAX_USER_DEFINED_BYTES],
}

enum VmBusChQueueEntry {
    Ready,
    Sender(crate::notify::NotifySender),
    Subscribed(crate::notify::NotifySender),
}

pub struct VmBus {
    pub conn_id: u32,
    monitor_pages: [Dma<[u8; PAGE_SIZE]>; 2],
    hypercall_fd: std::fs::File,
    pub fasthypercall8_fd: std::fs::File,
    simp_page: Dma<[u8; PAGE_SIZE]>,
    siefp_page: Dma<[u8; PAGE_SIZE]>,
    msr: crate::msr::Msr,

    irq_receiver: Option<crate::notify::arc::NotifyReceiver>,
    msg_queue: VecDeque<futures::channel::oneshot::Sender<HvMessage>>,
    pub ch_offers: Vec<VmBusChannelOfferChannel>,
    ch_queue: HashMap<u32, VecDeque<VmBusChQueueEntry>>,
}


#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct VmBusChannelOffer {
    pub if_type: UUID,
    if_instance: UUID,
    reserved1: u64,
    reserved2: u64,
    ch_flags: u16,
    mmio_megabytes: u16,
    u: VmBusChannelOffer_u,
    sub_ch_index: u16,
    reserved3: u16,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
union VmBusChannelOffer_u {
    std: [u8; MAX_USER_DEFINED_BYTES],
    pipe: VmBusChannelOffer_u_pipe,
}

impl fmt::Debug for VmBusChannelOffer_u {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VmBusChannelOffer_u")
    }
}

#[repr(packed)]
#[derive(Copy, Clone)]
#[allow(dead_code)]
struct VmBusChannelOffer_u_pipe {
    pipe_mode: u32,
    user_def: [u8; MAX_PIPE_USER_DEFINED_BYTES],
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct VmBusChannelOfferChannel {
    pub header: VmBusChannelMsgHeader,
    pub offer: VmBusChannelOffer,
    pub child_relid: u32,
    pub monitor_id: u8,
    pub monitor_allocated: u8,
    pub is_dedicated_interrupt: u16,
    pub connection_id: u32,
}


#[repr(C, packed)]
#[derive(Default, Clone, Copy, Debug)]
pub struct VmPacketDescriptor {
    pub ty: u16,
    pub offset8: u16,
    pub len8: u16,
    pub flags: u16,
    pub trans_id: u64,
}

impl VmPacketDescriptor {
    pub fn len(&self) -> usize {
        (self.len8 as usize) << 3
    }

    pub fn offset(&self) -> usize {
        (self.offset8 as usize) << 3
    }

    pub fn set_len(&mut self, len: usize) {
        self.len8 = (len >> 3) as u16;
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset8 = (offset >> 3) as u16;
    }

    /// VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED
    pub fn set_completion_requested(&mut self, val: bool) {
        self.flags = val as u16;
    }
}

#[repr(C, packed)]
#[derive(Default)]
pub struct VmDataGpaDirect {
    pub descriptor: VmPacketDescriptor,
    _reserved: u32,
    pub range_count: u32,
    ranges: [crate::gpadl::GpaRange; 0],
}

try_from_enum!(
    #[repr(u16)]
    #[derive(Debug, Eq, PartialEq)]
    pub enum VmBusPacketType {
        DataInband = 0x6,
        DataTransferPages = 0x7,
        DataGpaDirect = 0x9,
        /// Complete a transaction ID?
        Complete = 0xB,
    }
);


#[derive(Copy, Clone, Debug)]
pub struct VmDataTransferPageRange {
    pub length: u32,
    pub offset: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct VmDataTransferPages {
    pub descriptor: VmPacketDescriptor,
    pub transfer_pageset_id: u16,
    pub sender_owns_set: u8,
    _reserved: u8,
    pub range_count: u32,
    pub ranges: [VmDataTransferPageRange; 0],
}

#[repr(C, packed)]
pub struct SynIcEventFlags {
    flags: [u64; 32],
}

pub struct VmBusOuter(pub Rc<RefCell<VmBus>>);

impl VmBus {
    pub fn init(hypercall_fd: std::fs::File, fasthypercall8_fd: std::fs::File, msr: &mut crate::msr::Msr, irq_receiver: crate::notify::arc::NotifyReceiver) -> VmBusOuter {
        let simp_page = Dma::new([0u8; PAGE_SIZE]).expect("could not allocate SIMP page");
        assert_eq!(simp_page.physical() % PAGE_SIZE, 0);
        let siefp_page = Dma::new([0u8; PAGE_SIZE]).expect("could not allocate SIEFP page");
        assert_eq!(siefp_page.physical() % PAGE_SIZE, 0);
        let monitor_pages: [Dma<[u8; PAGE_SIZE]>; 2] = [
            Dma::new([0u8; PAGE_SIZE]).unwrap(),
            Dma::new([0u8; PAGE_SIZE]).unwrap()
        ];
        assert_eq!(monitor_pages[0].physical() % PAGE_SIZE, 0);
        assert_eq!(monitor_pages[1].physical() % PAGE_SIZE, 0);
        info!("vmbus init, dma allocated.");

        // FIXME: also here for all MSRs or with previous value

        // setup SIMP (message page) for SynIC (synthetic interrupt controller)
        msr.hv_simp.set(
            1 | // SIMP enable
            (simp_page.physical() as u64) & crate::bit_range(12..=63)
        ).unwrap();

        // setup SIEFP (needed?)
        msr.hv_siefp.set(
            1 | // SIEFP enable
            (siefp_page.physical() as u64) & crate::bit_range(12..=63)
        ).unwrap();

        // Setup SynIC
        let old = msr.hv_sint2.get().unwrap();
        let sint_val = old | crate::HYPERV_CALLBACK_VECTOR as u64 & crate::bit_range(0..=8);
        let sint_val = sint_val & !(1<<16); // Do not mask interrupt
        msr.hv_sint2.set(sint_val).unwrap();
        
        let old = msr.hv_scontrol.get().unwrap();
        msr.hv_scontrol.set(old | 1).unwrap(); // Enable SynIC (for this virtual processor)

        VmBusOuter(Rc::new(RefCell::new(VmBus {
            conn_id: VMBUS_MESSAGE_CONNECTION_ID_4,
            monitor_pages,
            hypercall_fd,
            fasthypercall8_fd,
            simp_page,
            siefp_page,
            msr: msr.clone(),
            irq_receiver: Some(irq_receiver),
            msg_queue: VecDeque::new(),
            ch_offers: vec![],
            ch_queue: Default::default(),
        })))
    }

    pub unsafe fn post_message<T>(&mut self, payload_struct: &T) {
        let payload = ::core::slice::from_raw_parts(
            payload_struct as *const _ as *const u8, 
            mem::size_of_val(payload_struct)
        );

        self.post_message_slice(payload)
    }

    pub unsafe fn post_message_slice(&mut self, payload: &[u8]) {
        const HV_STATUS_INSUFFICIENT_BUFFERS: u32 = 19;
        let mut msg: crate::HvInputPostMessage = unsafe { core::mem::zeroed() };
        msg.msg_type = 1;
        msg.conn_id = self.conn_id;
        msg.payload_size = payload.len() as u32;
        
        ptr::copy(payload.as_ptr(), &mut msg.payload[0] as *mut _ as *mut u8, msg.payload_size as usize);

        let mut buf = [0u8; 8 + 4096];
        buf[8..].copy_from_slice(unsafe { std::slice::from_raw_parts(&msg as *const _ as *const u8, core::mem::size_of_val(&msg)) });
        buf[..8].copy_from_slice(&(HvCall::PostMessage as u64).to_ne_bytes()[..]);

        loop {
            let hv_status = self.hypercall_fd.write(&buf).unwrap();
            match hv_status as u32 {
                0 => return, // HV_STATUS_SUCCESS
                HV_STATUS_INSUFFICIENT_BUFFERS => {
                    print!("HV_INSUFFICIENT_BUFFERS\n");
                    for _ in 0..10000000 {} // TODO: replace with sleep?
                    print!("Retry\n");
                },
                x => panic!("HV_STATUS: 0x{:x}", x),
            }
        }
    }

    pub fn tick(&mut self) {
        // Dispatch messages
        let next_msg = unsafe { &mut *(self.simp_page.as_mut_ptr() as *mut crate::HvMessage).wrapping_add(VMBUS_MESSAGE_SINT as usize) };
        let ty_ptr = ptr::addr_of_mut!((*next_msg).header.ty);
        let ty = unsafe { *ty_ptr };

        if ty != crate::HV_MSG_NONE {
            self.msg_queue.pop_front().unwrap().send(*next_msg).unwrap();
            unsafe { ptr::write_volatile(ty_ptr, crate::HV_MSG_NONE); }
            self.msr.hv_eom.set(0).unwrap(); // TODO only if pending is set?
        }
        
        // Dispatch events
        let siefp_page = unsafe { &mut *(self.siefp_page.as_mut_ptr() as *mut SynIcEventFlags).wrapping_add(VMBUS_MESSAGE_SINT as usize) };
        let flags = core::ptr::addr_of!((*siefp_page).flags);
        for (i, flag) in unsafe { (*flags).iter().enumerate() } {
            // HINT: Atomic not necessary here? But easier to use
            let target_element = unsafe { &*(flag as *const u64 as *const atomic::AtomicU64) };
            for bit in 0..64 {
                if target_element.fetch_and(!(1<<bit), Ordering::SeqCst) & (1<<bit) != 0 {
                    let notified_channel = 64 * i as u32 + bit as u32;
                    // print!("Channel {} now ready\n", notified_channel);

                    match self.ch_queue.entry(notified_channel).or_default().front() {
                        Some(VmBusChQueueEntry::Sender(_)) => {
                            match self.ch_queue.get_mut(&notified_channel).unwrap().pop_front().unwrap() {
                                VmBusChQueueEntry::Sender(sender) => sender.notify(),
                                _ => unreachable!()
                            }
                        },
                        Some(VmBusChQueueEntry::Subscribed(sender)) => {
                            sender.notify();
                        },
                        Some(_) => unreachable!(),
                        None => {
                            self.ch_queue.get_mut(&notified_channel).unwrap().push_back(VmBusChQueueEntry::Ready);
                        }
                    };
                }
            }
        }

        self.msr.hv_eoi.set(0).unwrap();
    }

    pub fn wait_message(&mut self) -> futures::channel::oneshot::Receiver<HvMessage> {
        let (sender, receiver) = futures::channel::oneshot::channel();
        self.msg_queue.push_back(sender);
        receiver
    }

    pub fn wait_for_channel(&mut self, ch: u32) -> crate::notify::NotifyReceiver {
        let (sender, receiver) = crate::notify::notify_pair();
        let ch_queue = self.ch_queue.entry(ch).or_default();
        if let Some(VmBusChQueueEntry::Ready) = ch_queue.front() {
            ch_queue.pop_front();
            sender.notify();
        } else {
            ch_queue.push_back(VmBusChQueueEntry::Sender(sender));
        }
        receiver
    }

    pub fn subscribe_channel(&mut self, ch: u32) -> crate::notify::NotifyReceiver {
        let (sender, receiver) = crate::notify::notify_pair();
        let ch_queue = self.ch_queue.entry(ch).or_default();
        while let Some(x) = ch_queue.pop_front() {
            match x {
                VmBusChQueueEntry::Ready => sender.notify(),
                _ => unreachable!(),
            }
        }
        ch_queue.push_back(VmBusChQueueEntry::Subscribed(sender));
        receiver
    }
}

impl VmBusOuter {
    pub unsafe fn post_message<T>(&self, payload_struct: &T) {
        (*self.0).borrow_mut().post_message(payload_struct);
    }

    pub fn wait_message(&self) -> futures::channel::oneshot::Receiver<HvMessage> {
        (*self.0).borrow_mut().wait_message()
    }

    pub fn wait_for_channel(&self, ch: u32) -> crate::notify::NotifyReceiver {
        (*self.0).borrow_mut().wait_for_channel(ch)
    }

    pub async fn initiate_contact(&self) {
        let mut payload: VmBusChannelInitiateContact = unsafe { std::mem::zeroed() };
        payload.header.msg_type = VmBusChannelMsgType::InitiateContact as u64;
        payload.version_requested = VMBUS_VERSION_WIN10_V5_2;
        payload.union.other.msg_sint = VMBUS_MESSAGE_SINT as u8;
        {
            let mut vmbus = (*self.0).borrow_mut();

            payload.monitor_pages[0] = vmbus.monitor_pages[0].physical() as u64;
            payload.monitor_pages[1] = vmbus.monitor_pages[1].physical() as u64;

            info!("initiate_contact posting....");
            unsafe {
                vmbus.post_message(&payload)
            }
            info!("initiate_contact posted....");
        }
        let msg: HvMessage = self.wait_message().await.unwrap();

        let mut vmbus = (*self.0).borrow_mut();
        info!("initiate_contact got msg");
        let payload = msg.payload;
        assert_eq!(payload[0], VmBusChannelMsgType::VersionResponse as u64);
        assert_eq!(payload[1] as u8, 1); // Whether our requested version is supported by HV
        vmbus.conn_id = (payload[1] >> 32) as _;
        info!("new connID: {}\n", vmbus.conn_id);
    }

    pub async fn enumerate_devices(&self) {
        let mut header: VmBusChannelMsgHeader = unsafe { mem::zeroed() };
        header.msg_type = VmBusChannelMsgType::RequestOffers as u64;
        unsafe {
            self.post_message(&header);
        }

        loop {
            let offer = {
                let msg = self.wait_message().await.unwrap();

                // Handle part of received offer response
                let payload = msg.payload;
                if payload[0] == VmBusChannelMsgType::AllOffersDelivered as u64 {
                    break;
                }
                assert_eq!(payload[0], VmBusChannelMsgType::OfferChannel as u64);

                unsafe { *(payload.as_ptr() as *const VmBusChannelOfferChannel) }
            };
            (*self.0).borrow_mut().ch_offers.push(offer);
        }
    }

    pub async fn run_irq_ticks(&self) {
        let mut irq_receiver = (*self.0).borrow_mut().irq_receiver.take().expect("IRQ receiver already taken");
        
        loop {
            let _ = (&mut irq_receiver).await;

            (*self.0).borrow_mut().tick();
        }
    }
}
