//! Network VSC (virtual service client) connects to NetVSP (Virtual service Provider)
//! Layer wise: US <--> NVSP <-> RNDIS

#![allow(dead_code)] // TODO

pub const DUUID: UUID = UUID([0x63, 0x51, 0x61, 0xf8, /**/ 0x3e, 0xdf, /**/ 0xc5, 0x46, /**/ 0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e]);

use core::convert::TryFrom;
use core::mem;
use core::ptr;
use core::slice;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;
use bitflags::bitflags;
use common::dma::Dma;
use event::user_data;
use event::EventQueue;
use futures::FutureExt;
use log::info;
use crate::ring::RingBuffer;
use crate::vmbus::VmDataTransferPageRange;
use crate::PAGE_SIZE;
use crate::{UUID, vmbus};
use crate::try_from_enum;

pub struct DriverInstance {
    initial: bool,
    offer: vmbus::VmBusChannelOfferChannel,
    
    receive_pages: Dma<[u8]>,
    send_pages: Dma<[u8]>,
    send_pages_idx: usize,

    producer_ring: RingBuffer<crate::ring::Producer>,

    init_req: Dma<RndisInitializeRequest>,
    query_req: Dma<RndisQueryReq>,
    rndis_next_id: u32,
    read_queue: VecDeque<Vec<u8>>,
    write_queue: VecDeque<Vec<u8>>,

    mac: [u8; 6]
}
// unsafe impl Send for DriverInstance {}

const NVSP_PROTOCOL_VERSION_61: u32 = 0x60001;
const NVSP_MESSAGE_SIZE: usize = 40;
const NETVSC_RECEIVE_BUFFER_ID: u16 = 0xcafe;
const NETVSC_SEND_BUFFER_ID: u16 = 0;
const RNDIS_OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x00010106;
const RNDIS_OID_802_3_PERMANENT_ADDRESS: u32 = 0x01010101;

try_from_enum!(
    #[repr(u32)]
    #[derive(Debug)]
    enum NvspMessageType {
        Init = 1,
        InitComplete = 2,
        V1SendNdisVersion = 100,
        V1SendReceiveBuffer = 101,
        V1SendReceiveBufferComplete = 102,
        V1SendSendBuffer = 104,
        V1SendSendBufferComplete = 105,
        V1SendRndisPacket = 107,
        V1SendRndisPacketComplete = 108,
        V2SendNdisConfig = 125,
    }
);

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
struct NvspMessageHeader {
    ty: u32,
}

impl NvspMessageHeader {
    fn ty(&self) -> Result<NvspMessageType, u32> {
        NvspMessageType::try_from(self.ty)
    }
}

#[repr(C, packed)]
struct NvspInitMessage {
    header: NvspMessageHeader,
    min_protocol_version: u32,
    max_protocol_version: u32,
}

#[repr(C, packed)]
struct NvspInitResponse {
    header: NvspMessageHeader,
    negotiated_protocol_version: u32,
    max_mdl_chain_length: u32,
    status: u32,
}

#[repr(C, packed)]
struct NvspV1NdisSendVersion {
    header: NvspMessageHeader,
    ndis_major_version: u32,
    ndis_minor_version: u32,
}

#[repr(C, packed)]
struct NvspV1SendReceiveBuffer {
    header: NvspMessageHeader,
    gpadl: u32,
    id: u16,
}

#[repr(C, packed)]
struct NvspV1SendReceiveBufferComplete {
    header: NvspMessageHeader,
    status: u32,
    num_sections: u32,

    /// There are separate sections for small and large allocations
    section_start_offset: u32,
    sub_alloc_size: u32,
    sub_alloc_count: u32,
    section_end_offset: u32,
}

type NvspV1SendSendBuffer = NvspV1SendReceiveBuffer;
#[repr(C, packed)]
struct NvspV1SendSendBufferComplete {
    header: NvspMessageHeader,
    status: u32,
    section_size: u32,
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone, Debug)]
struct NvspV1SendRndisPacket {
    header: NvspMessageHeader,
    channel_ty: u32,
    /// 0xFFFFFFFF if the send buffer is not used to send data but e.g. VMBUS (GPA only?)
    send_buffer_section_offset: u32,
    send_buffer_section_size: u32,
}

#[repr(C, packed)]
struct NvspV1SendRndisPacketComplete {
    header: NvspMessageHeader,
    status: u32,
}

#[repr(C, packed)]
struct NvspV2NdisConfigMessage {
    header: NvspMessageHeader,
    mtu: u32,
    _reserved: u32,
    capabilities: NvspV2Capabilities
}

try_from_enum!(
    #[repr(u32)]
    #[derive(Debug)]
    enum RndisMessageType {
        Packet = 1,
        Init = 2,
        InitComplete = 0x80000002,
        Query = 0x00000004,
        QueryComplete = 0x80000004,
    }
);

#[repr(C)]
#[derive(Default, Debug)]
struct RndisMessageHeader {
    ty: u32,
    len: u32,
}

#[repr(C)]
#[derive(Default)]
struct RndisInitializeRequest {
    header: RndisMessageHeader,
    req_id: u32,
    major_version: u32,
    minor_version: u32,
    max_transfer_size: u32,
}

#[repr(C)]
#[derive(Default, Debug)]
struct RndisInitializeComplete {
    header: RndisMessageHeader,
    req_id: u32,
    status: u32,
    major_version: u32,
    minor_version: u32,
    device_flags: u32,
    medium: u32,
    max_packets_per_message: u32,
    max_transfer_size: u32,
    packet_alignment_factor: u32,
    af_list_offset: u32,
    af_list_size: u32,
}

#[repr(C)]
#[derive(Debug)]
struct RndisPacket {
    header: RndisMessageHeader,
    data_offset: u32,
    data_length: u32,
    /// "OOB data is a logically independent transmission channel associated with each pair of connected stream sockets. 
    /// OOB data may be delivered to the user independently of normal data"
    oob_data_offset: u32,
    oob_data_length: u32,
    oob_data_num_elements: u32,
    per_packet_info_offset: u32,
    per_packet_info_length: u32,
    vc_handle: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Default, Debug)]
struct RndisQueryReq {
    header: RndisMessageHeader,
    req_id: u32,
	oid: u32,
	info_buflen: u32,
	info_buf_offset: u32,
	dev_vc_handle: u32,
}

#[repr(C)]
#[derive(Debug)]
struct RndisQueryResp {
    header: RndisMessageHeader,
    req_id: u32,
    status: u32,
    info_buflen: u32,
    info_buf_offset: u32
}

bitflags! {
    pub struct NvspV2Capabilities: u64 {
        const VMQ =             1 << 0;
        const CHIMNEY =         1 << 1;
        const SRIOV =           1 << 2;
        const IEEE8021Q =       1 << 3;
        const CORRELATION_ID =  1 << 4;
        const TEAMING =         1 << 5;
        const VS_SUBNET_ID =    1 << 6;
        const RSC =             1 << 7;
    }
}

const RECEIVE_PAGE_COUNT: usize = 128;

impl DriverInstance {
    pub fn new(offer: vmbus::VmBusChannelOfferChannel) -> Self {
        let producer_ring = crate::ring::RingBuffer::<crate::ring::Producer>::new(
            Rc::new(|| ()),
            0xcc as *mut u8,
            0
        );
        let receive_pages = unsafe { Dma::zeroed_slice(RECEIVE_PAGE_COUNT * PAGE_SIZE).unwrap().assume_init() };
        assert_eq!(receive_pages.physical() % PAGE_SIZE, 0);
        let send_pages = unsafe { Dma::zeroed_slice(1 * PAGE_SIZE).unwrap().assume_init() };
        assert_eq!(send_pages.physical() % PAGE_SIZE, 0);

        DriverInstance {
            initial: true,
            receive_pages,
            send_pages,
            send_pages_idx: 0,
            producer_ring,
            offer,
            init_req: Dma::new(RndisInitializeRequest::default()).unwrap(),
            query_req: Dma::new(RndisQueryReq::default()).unwrap(),
            rndis_next_id: 1,
            mac: [0u8; 6],
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    async fn handle_init_complete(&mut self, vmbus: &vmbus::VmBusOuter, buf: &[u8]) {
        {
            let resp = unsafe { &*(buf.as_ptr() as *const _ as *const NvspInitResponse) };
            assert_eq!(resp.status & 1, 1, "Not successful");
            info!("NetVSC VSP connected\n");
        }

        // "Negotiate" Version & Send NDIS version
        let mut buf = [0u8; NVSP_MESSAGE_SIZE];
        {
            let init = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV2NdisConfigMessage) };
            init.header.ty = NvspMessageType::V2SendNdisConfig as u32;
            init.mtu = 1514; // linux does MTU + 14?
            // init.capabilities = NvspV2Capabilities::IEEE8021Q | NvspV2Capabilities::SRIOV | NvspV2Capabilities::TEAMING | NvspV2Capabilities::RSC;
            self.producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), &[&buf], false);
        }
        let mut buf = [0u8; NVSP_MESSAGE_SIZE];
        {
            const NDIS_VERSION: u32 = 0x0006001e;
            let send_version = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1NdisSendVersion) };
            send_version.header.ty = NvspMessageType::V1SendNdisVersion as u32;
            send_version.ndis_major_version = (NDIS_VERSION & 0xFFFF0000) >> 16;
            send_version.ndis_minor_version = NDIS_VERSION & 0xFFFF;
            self.producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), &[&buf], false);
        }

        // TODO: init receive & send buffers
        print!("Sending recv GPADL to netvsc\n");
        
        let mut buf = [0u8; NVSP_MESSAGE_SIZE];
        {
            let recv_gpadl_handle = {
                let mut recv_pages = [0u64; RECEIVE_PAGE_COUNT];
                for i in 0..RECEIVE_PAGE_COUNT {
                    recv_pages[i] = (self.receive_pages.physical() + i*PAGE_SIZE) as u64;
                }
                vmbus.map_gpadl(self.offer.child_relid, &recv_pages).await
            };

            let send_recv_buffer = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1SendReceiveBuffer) };
            send_recv_buffer.header.ty = NvspMessageType::V1SendReceiveBuffer as u32;
            send_recv_buffer.gpadl = recv_gpadl_handle;
            send_recv_buffer.id = NETVSC_RECEIVE_BUFFER_ID;
            self.producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), &[&buf], true);
        }
    }

    async fn handle_send_recv_buffer_complete(&mut self, vmbus: &vmbus::VmBusOuter, buf: &[u8]) {
        println!("handle_send_recv_buffer_complete");
        {
            let resp = unsafe { &*(buf.as_ptr() as *const _ as *const NvspV1SendReceiveBufferComplete) };
            let status = resp.status;
            let num_sections = resp.num_sections;
            let section_start_offset = resp.section_start_offset;
            assert_eq!(status, 1); // NVSP_STAT_SUCCESS
            assert_eq!(num_sections, 1);
            assert_eq!(section_start_offset, 0);
        }

        let mut buf = [0u8; NVSP_MESSAGE_SIZE];
        {
            let mut send_pages = [0u64; 1]; // TODO: use 256 if we even use intend to use send buffer?
            let send_gpadl_handle = {
                for i in 0..send_pages.len() {
                    send_pages[i] = (self.send_pages.physical() + i*PAGE_SIZE) as u64;
                }
                vmbus.map_gpadl(self.offer.child_relid, &send_pages).await
            };
            
            let send_send_buffer = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1SendSendBuffer) };
            send_send_buffer.header.ty = NvspMessageType::V1SendSendBuffer as u32;
            send_send_buffer.gpadl = send_gpadl_handle;
            send_send_buffer.id = NETVSC_SEND_BUFFER_ID;
            self.producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), &[&buf], true);
        }
    }

    async fn handle_send_packet(&mut self, vmbus: &vmbus::VmBusOuter, buf: &[u8]) {
        // println!("handle_send_packet");

        let xfer = unsafe { &*(buf.as_ptr() as *const _ as *const vmbus::VmDataTransferPages) };
        // print!("{:?}\n", xfer);
        let tpid = xfer.transfer_pageset_id;
        assert_eq!(tpid, NETVSC_RECEIVE_BUFFER_ID);
        
        let rc = xfer.range_count;
        assert_eq!(rc, 1); // keep it simple for now
        let range = unsafe {
            ptr::read_unaligned(core::ptr::addr_of!(xfer.ranges) as *const VmDataTransferPageRange)
        };

        let data = unsafe { slice::from_raw_parts(
            self.receive_pages.as_ptr().wrapping_add(range.offset as usize), 
            range.length as usize)
        };
        let rndis_type = RndisMessageType::try_from(unsafe { *(data.as_ptr() as *const u32) });
        // print!("RNDIS_TY {:?}\n", rndis_type);
        match rndis_type {
            Ok(RndisMessageType::InitComplete) => {
                let ret = unsafe { &*(data.as_ptr() as *const RndisInitializeComplete) };
                print!("InitComplete: {:?}\n", ret);
                assert_eq!(ret.status, 0); // RNDIS_STATUS_SUCCESS

                self.query_rndis(vmbus, RNDIS_OID_GEN_MAXIMUM_FRAME_SIZE).await;
                self.query_rndis(vmbus, RNDIS_OID_802_3_PERMANENT_ADDRESS).await;
            }
            Ok(RndisMessageType::Packet) => {
                let rndis_packet = unsafe { &*(data.as_ptr() as *const RndisPacket) };
                // print!("Packet: {:?}\n", rndis_packet);
                let data_portion = &data[mem::size_of::<RndisMessageHeader>()..][rndis_packet.data_offset as usize..][..rndis_packet.data_length as usize];
                // print!("DATA {:?}\n", data_portion);
                let per_packet = &data[mem::size_of::<RndisMessageHeader>()..][rndis_packet.per_packet_info_offset as usize..][..rndis_packet.per_packet_info_length as usize];
                // print!("PER_PACKET: {:?}", per_packet);
                self.read_queue.push_back(data_portion.to_owned());
            },
            Ok(RndisMessageType::QueryComplete) => {
                let resp = unsafe { &*(data.as_ptr() as *const RndisQueryResp) };
                // println!("RNDIS QUERY: {:?}", resp);
                if resp.req_id == 3 {
                    self.mac.copy_from_slice(&data[mem::size_of::<RndisMessageHeader>() + resp.info_buf_offset as usize..]);
                    println!("RNDIS MAC: {:?}", self.mac);
                    return
                }

                let mut tmp = [0u8; 4];
                tmp.copy_from_slice(&data[mem::size_of::<RndisMessageHeader>() + resp.info_buf_offset as usize..]);
                // println!("RNDIS U32: {}",  u32::from_le_bytes(tmp));
            },
            x => ()
        }
    }

    async fn query_rndis(&mut self, vmbus: &vmbus::VmBusOuter, oid: u32) {
        let info_buf_offset = (mem::size_of::<RndisQueryReq>() - mem::size_of::<RndisMessageHeader>()) as u32;
        assert_eq!(info_buf_offset, 5*4);

        *self.query_req = RndisQueryReq {
            header: RndisMessageHeader {
                ty: RndisMessageType::Query as u32,
                len: mem::size_of_val(&*self.query_req) as u32,
            },
            req_id: self.rndis_next_id,
            oid,
            dev_vc_handle: 0,
            info_buflen: 0,
            info_buf_offset,
        };
        self.rndis_next_id += 1;

        let mut buf: [u8; 40] = [0u8; NVSP_MESSAGE_SIZE];
        let nvmsg: &mut NvspV1SendRndisPacket = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1SendRndisPacket) };
        nvmsg.header.ty = NvspMessageType::V1SendRndisPacket as u32;
        nvmsg.channel_ty = 1; // RMC_CONTROL 
        nvmsg.send_buffer_section_offset = u32::max_value(); // TODO trying if we can get around using the sendbuffer yet

        println!("QUERY");
        self.producer_ring.send_vmpacket_gpa_direct(
            &mut *(vmbus.0).borrow_mut(),
            &[ &buf ],
            &[ unsafe { slice::from_raw_parts(&*self.query_req as *const RndisQueryReq as *const u8, mem::size_of_val(&*self.query_req)) } ]
        );


    }

    async fn handle_send_buffer_complete(&mut self, vmbus: &vmbus::VmBusOuter, buf: &[u8]) {
        println!("handle_send_buffer_complete");
        let resp = unsafe { &*(buf.as_ptr() as *const _ as *const NvspV1SendSendBufferComplete) };
        let status = resp.status;
        assert_eq!(status, 1); // NVSP_STAT_SUCCESS
        
        // We store this outside this functions scope, so its kept alive until the response arrives
        self.init_req.header.ty = RndisMessageType::Init as u32;
        self.init_req.header.len = mem::size_of_val(&*self.init_req) as u32;
        self.init_req.major_version = 1; // RNDIS_MAJOR_VERSION
        self.init_req.minor_version = 0;
        self.init_req.max_transfer_size = 0x4000;
        self.init_req.req_id = self.rndis_next_id;
        self.rndis_next_id += 1;
        assert_eq!(mem::size_of_val(&*self.init_req), 24);

        let mut buf: [u8; 40] = [0u8; NVSP_MESSAGE_SIZE];
        let nvmsg: &mut NvspV1SendRndisPacket = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1SendRndisPacket) };
        nvmsg.header.ty = NvspMessageType::V1SendRndisPacket as u32;
        nvmsg.channel_ty = 1; // RMC_CONTROL 
        nvmsg.send_buffer_section_offset = u32::max_value(); // TODO trying if we can get around using the sendbuffer yet

        println!("RNDIS INIT");
        self.producer_ring.send_vmpacket_gpa_direct(
            &mut *(vmbus.0).borrow_mut(),
            &[ &buf ],
            &[ unsafe { slice::from_raw_parts(&*self.init_req as *const RndisInitializeRequest as *const u8, mem::size_of_val(&*self.init_req)) } ]
        );
    }

    async fn handle_event(&mut self, vmbus: &vmbus::VmBusOuter, event: &[u8]) {
        let (ptr, packet_ty) = {
            let desc = unsafe { &*(event.as_ptr() as *const vmbus::VmPacketDescriptor) };
            let packet_ty = vmbus::VmBusPacketType::try_from(desc.ty);
            
            //assert_eq!(desc.ty, vmbus::VmBusPacketType::Inband as u16);
            (&event[desc.offset()..], packet_ty)
        };
        // println!("VM Ty {:?}", packet_ty);

        let header_ty = { 
            let header = unsafe { &*(ptr.as_ptr() as *const NvspMessageHeader) };
            header.ty()
        };
        match header_ty {
            Ok(NvspMessageType::InitComplete) if self.initial => {
                self.initial = false;
                self.handle_init_complete(vmbus, ptr).await;
            },
            Ok(NvspMessageType::V1SendReceiveBufferComplete) => {
                self.handle_send_recv_buffer_complete(vmbus, ptr).await;
            }
            Ok(NvspMessageType::V1SendSendBufferComplete) => {
                self.handle_send_buffer_complete(vmbus, ptr).await;
            }
            Ok(NvspMessageType::V1SendRndisPacketComplete) => {
                let resp = unsafe { &*(ptr.as_ptr() as *const _ as *const NvspV1SendRndisPacketComplete) };
                let status = resp.status;
                assert_eq!(status, 1);
                // println!("RNDIS SENT");
            }
            Ok(NvspMessageType::V1SendRndisPacket) => {
                assert_eq!(packet_ty, Ok(vmbus::VmBusPacketType::DataTransferPages));

                self.handle_send_packet(vmbus, event).await;
            }
            x => print!("Unknown NetVSC packet Type: {:?}\n", x)
        }
    }

    async fn write_packet(&mut self, vmbus: &crate::vmbus::VmBusOuter, pkt_buf_param: Vec<u8>) {
        let mut pkt_buf = unsafe { Dma::zeroed_slice(pkt_buf_param.len()).unwrap().assume_init() };
        pkt_buf.copy_from_slice(&pkt_buf_param[..]);

        /*let ppi = Dma::new([
            16, 0, 0, 0, // len
            0, 0, 0, 0,  // type = 0, TCPIP_CHKSUM_PKTINFO?
            12, 0, 0, 0, // offset
            0, 0, 0, 0
        ]).unwrap();*/

        let packet: Dma<RndisPacket> = Dma::new(RndisPacket {
            header: RndisMessageHeader {
                ty: RndisMessageType::Packet as u32,
                len: (mem::size_of::<RndisPacket>() + pkt_buf.len()) as u32,
            },
            per_packet_info_offset: (mem::size_of::<RndisPacket>() - mem::size_of::<RndisMessageHeader>()) as u32,
            per_packet_info_length: 0 as u32, //ppi.len() as u32,
            data_offset: (mem::size_of::<RndisPacket>() - mem::size_of::<RndisMessageHeader>()) as u32,
            data_length: pkt_buf.len() as u32,
            oob_data_offset: 0,
            oob_data_length: 0,
            oob_data_num_elements: 0,
            vc_handle: 0,
            _reserved: 0,
        }).unwrap();
        let mut buf: [u8; 40] = [0u8; NVSP_MESSAGE_SIZE];
        let nvmsg: &mut NvspV1SendRndisPacket = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspV1SendRndisPacket) };
        nvmsg.header.ty = NvspMessageType::V1SendRndisPacket as u32;
        nvmsg.channel_ty = 1; // RMC_CONTROL 
        nvmsg.send_buffer_section_offset = u32::max_value(); // TODO trying if we can get around using the sendbuffer yet

        // println!("RNDIS WRITE PACKET");
        self.producer_ring.send_vmpacket_gpa_direct(
            &mut *(vmbus.0).borrow_mut(),
            &[ &buf ],
            &[
                unsafe { slice::from_raw_parts(&*packet as *const RndisPacket as *const u8, mem::size_of::<RndisPacket>()) },
                &pkt_buf[..]
            ]
        );

        // TODO
        mem::forget(pkt_buf); 
        mem::forget(packet);
    }

    pub async fn run<F: FnOnce() -> ()>(mut self, vmbus: &crate::vmbus::VmBusOuter, mut signal_daemon_ready: Option<F>) {
        info!("NETVSC Driver starting...");

        let fasthypercall8_fd = {
            RefCell::new(vmbus.0.borrow_mut().fasthypercall8_fd.try_clone().unwrap())
        };
        let cid = self.offer.connection_id as u64;
        let signal_hv = move || {
            use std::io::Write;
            let mut tmp = [0u8; 16];

            tmp[..8].copy_from_slice(&(crate::HvCall::SignalEvent as u64).to_ne_bytes()[..]);
            tmp[8..].copy_from_slice(&(cid as u64).to_ne_bytes()[..]);
            let status: usize = fasthypercall8_fd.borrow_mut().write(&tmp).unwrap();
            assert_eq!(status, 0);
        };

        let (producer_ring, mut consumer_ring) = crate::ring::new(
            vmbus,
            Rc::new(signal_hv),
            self.offer.child_relid,
            4,
            4
        ).await;
        self.producer_ring = producer_ring;

        {
            let mut buf = [0u8; NVSP_MESSAGE_SIZE];
            let init = unsafe { &mut *(buf.as_mut_ptr() as *mut NvspInitMessage) };
            init.header.ty = NvspMessageType::Init as u32;
            init.min_protocol_version = NVSP_PROTOCOL_VERSION_61;
            init.max_protocol_version = NVSP_PROTOCOL_VERSION_61;
            
            // print!("Write netvsc producer ring\n");
            self.producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), &[&buf], true);
            // print!("Done\n");
        }

        let mut self_ = Na(Rc::new(RefCell::new(self)));
        let mut scheme = driver_network::NetworkScheme::new(self_.clone(), format!("network.netvsc"));
        let eh = scheme.event_handle();
        let (event_sender, event_receiver) = crate::notify::arc::notify_pair();
        
        // Spawn thread that can pass notify from external event queue into our one
        std::thread::spawn(move || {
            user_data! {
                enum Source {
                    Scheme,
                }
            }
            
            let event_queue = EventQueue::<Source>::new().expect("hyperv: Could not create event queue.");
            event_queue
                .subscribe(
                    eh  as usize,
                    Source::Scheme,
                    event::EventFlags::READ,
                )
                .unwrap();

            for event in event_queue.map(|e| e.expect("hyperv: failed to get next event")) {
                match event.user_data {
                    Source::Scheme => {
                        // println!("thread: netvsc scheme eq");
                        event_sender.notify();
                    }
                }
            }
        });

        struct JoinedFutState {
            vmbus: crate::notify::NotifyReceiver,
            event: crate::notify::arc::NotifyReceiver,
        };
        let relid: u32 = { (&mut self_.0).borrow().offer.child_relid };
        let mut jfs = JoinedFutState {
            vmbus: vmbus.0.borrow_mut().subscribe_channel(relid),
            event: event_receiver,
        };
        struct JoinedFut<'a> {
            vmbus: &'a crate::vmbus::VmBusOuter,
            state: &'a mut JoinedFutState,
        }
        impl<'a> std::future::Future for JoinedFut<'a> {
            type Output = bool;
        
            fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                let mut ret = Poll::Pending;
                if let Poll::Ready(_) = self.state.vmbus.poll_unpin(cx) {
                    ret = Poll::Ready(false);
                }
                if let Poll::Ready(_) = self.state.event.poll_unpin(cx) {
                    ret = Poll::Ready(true);
                }
                ret
            }
        }

        loop {
            if signal_daemon_ready.is_some() {
                let mac = (self_.0).borrow_mut().mac;
                if mac != [0u8; 6] {
                    // Only signal it here, so redox has a chance to see a network interface and start smolnetd for it
                    (signal_daemon_ready.take().unwrap())();
                }
            }

            let mut run_scheme_tick = JoinedFut { vmbus: vmbus, state: &mut jfs }.await;
            run_scheme_tick |= self_.0.borrow().read_queue.len() > 0;
            
            while let Some(event) = consumer_ring.next() {
                (&mut self_.0).borrow_mut().handle_event(vmbus, &*event).await;
            }

            if run_scheme_tick {
                // info!("netvsc scheme tick");
                scheme.tick().expect("NetVsc scheme tick error");
                loop {
                    let next = {
                        self_.0.borrow_mut().write_queue.pop_front()
                    };
                    match next {
                        Some(buf) => self_.0.borrow_mut().write_packet(&vmbus, buf).await,
                        None => break
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct Na(Rc<RefCell<DriverInstance>>);

impl driver_network::NetworkAdapter for Na {
    fn mac_address(&mut self) -> [u8; 6] {
        self.0.borrow().mac
    }

    // The doc on this one is wrong, its bytes available for current packet and not packets :/
    fn available_for_read(&mut self) -> usize {
        let ret = self.0.borrow().read_queue.front().map(Vec::len).unwrap_or_default();
        ret
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> syscall::Result<Option<usize>> {
        let ret = match self.0.borrow_mut().read_queue.pop_front() {
            None => None,
            Some(rdbuf) => {
                let oplen = std::cmp::min(buf.len(), rdbuf.len());
                buf[..oplen].copy_from_slice(&rdbuf[..oplen]);
                assert!(oplen < 1500);
                Some(oplen)
            }
        };
        syscall::Result::Ok(ret)
    }

    fn write_packet(&mut self, buf: &[u8]) -> syscall::Result<usize> {
        // println!("WRITEq(queue) PACKET: {:?}", buf.len());
        assert!(buf.len() < 1500);
        self.0.borrow_mut().write_queue.push_back(buf.to_owned());

        syscall::Result::Ok(buf.len())
    }
}
