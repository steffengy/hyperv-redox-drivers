//! HyperV Synthetic Mouse Driver
use core::convert::TryFrom;
use core::{mem, slice};
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use log::{info, warn};
use orbclient::{ButtonEvent, MouseEvent};

use crate::{UUID, vmbus};
use crate::try_from_enum;

pub const DUUID: UUID = UUID([0x9e, 0xb6, 0xa8, 0xcf, /**/ 0x4a, 0x5b, /**/ 0xc0, 0x4c, /**/ 0xb9, 0x8b, 0x8b, 0xa1, 0xa1, 0xf3, 0xf9, 0x5a]);

try_from_enum!(
    #[repr(u32)]
    #[derive(Debug)]
    enum SynthHidMessageType {
        ProtocolRequest = 0,
        ProtocolResponse = 1,
        InitialDeviceInfo = 2,
        InitialDeviceInfoAck = 3,
        InputReport = 4,
        Max = 5,
    }
);

#[derive(Copy, Clone)]
#[derive(Debug)]
#[repr(C)]
struct SynthHidMessageHeader {
    ty: u32,
    size: u32
}

impl SynthHidMessageHeader {
    fn ty(&self) -> Result<SynthHidMessageType, u32> {
        SynthHidMessageType::try_from(self.ty)
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
struct SynthHidProtocolRequest {
    header: SynthHidMessageHeader,
    requested_version: u32,
}


#[derive(Copy, Clone)]
#[repr(C)]
struct SynthHidProtocolResponse {
    header: SynthHidMessageHeader,
    requested_version: u32,
    approved: u8
}

#[derive(Copy, Clone)]
#[repr(C)]
struct HvInputDevInfo {
    size: u16,
    vendor: u16,
    product: u16,
    version: u16,
    reserved: [u8; 11]
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct HidClassDescriptor {
    ty: u8,
    len: u16,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct HidDescriptor {
    length: u8,
    descriptor_ty: u8,
    bcd_hid: u16,
    country_code: u8,
    num_descriptors: u8,

    desc: [HidClassDescriptor; 1]
}

#[derive(Copy, Clone)]
#[repr(C)]
struct SynthHidDeviceInfo {
    header: SynthHidMessageHeader,
    hid_def_info: HvInputDevInfo,
    hid_descriptor: HidDescriptor,
}


#[derive(Copy, Clone)]
#[repr(C)]
struct SynthHidDeviceInfoAck {
    header: SynthHidMessageHeader,
    reserved: u8
}

struct SynthHidInputReport {
    header: SynthHidMessageHeader,
    buf: [u8; 0]
}

try_from_enum!(
    #[repr(u32)]
    #[derive(Debug, PartialEq)]
    enum PipePrtMsgTy {
        Invalid = 0,
        Data = 1,
        Maximum = 2,
    }
);

#[repr(C)]
struct PipePrtMsg {
    ty: PipePrtMsgTy,
    size: u32,
    data: [u32; 0]
}

#[repr(C)]
struct MouseSvcPrtMsg {
    ty: PipePrtMsgTy,
    size: u32,
    val: MouseSvcPrtMsg_u
}

#[repr(C)]
union MouseSvcPrtMsg_u {
    protocol_req: SynthHidProtocolRequest,
    ack_req: SynthHidDeviceInfoAck,
}

pub struct DriverInstance {
    initial: bool,
}

impl DriverInstance {
    pub fn new() -> DriverInstance {
        DriverInstance { initial: true }
    }

    fn handle_mouse_event(&mut self, input: &mut std::fs::File, event: &[u8]) -> Option<MouseSvcPrtMsg> {
        let desc = unsafe { &*(event.as_ptr() as *const vmbus::VmPacketDescriptor) };
        let desc_ty = desc.ty;
        assert_eq!(desc_ty, vmbus::VmBusPacketType::DataInband as u16);
        
        let event_ptr = event[desc.offset()..].as_ptr();
        let pipe = unsafe { &*(event_ptr as *const PipePrtMsg) };
        if pipe.ty == PipePrtMsgTy::Data {
            let header = unsafe { &*(pipe.data.as_ptr() as *const SynthHidMessageHeader) };
            match header.ty() {
                Ok(SynthHidMessageType::ProtocolResponse) if self.initial => {
                    let resp = unsafe { &*(pipe.data.as_ptr() as *const SynthHidProtocolResponse) };
                    self.initial = false;
                    assert_eq!(resp.header.ty, SynthHidMessageType::ProtocolResponse as u32);
                    assert!(resp.approved != 0);
                    info!("Mouse VSP connected\n");
                },
                Ok(SynthHidMessageType::InitialDeviceInfo) => {
                    // print!("Mouse VSP intial device info");
                    let resp = unsafe { &*(pipe.data.as_ptr() as *const SynthHidDeviceInfo) };
                    assert_eq!(resp.header.ty, SynthHidMessageType::InitialDeviceInfo as u32);

                    let mut req: MouseSvcPrtMsg = unsafe { mem::zeroed() };
                    req.ty = PipePrtMsgTy::Data;
                    req.size = mem::size_of::<SynthHidDeviceInfoAck>() as u32;
                    req.val.ack_req = SynthHidDeviceInfoAck {
                        header: SynthHidMessageHeader {
                            ty: SynthHidMessageType::InitialDeviceInfoAck as u32,
                            size: mem::size_of::<u32>() as u32
                        },
                        reserved: 0
                    };
                    return Some(req);
                },
                Ok(SynthHidMessageType::InputReport) => {
                    let resp = unsafe { &*(pipe.data.as_ptr() as *const SynthHidInputReport) };
                    assert_eq!(resp.header.ty, SynthHidMessageType::InputReport as u32);
                    
                    let payload = unsafe { std::slice::from_raw_parts(resp.buf.as_ptr(), resp.header.size as usize) };
    
                    let mut tmp = [0u8; 2];
                    tmp.copy_from_slice(&payload[1..3]);
                    let x  = u16::from_le_bytes(tmp) as i32;
                    tmp.copy_from_slice(&payload[3..5]);
                    let y = u16::from_le_bytes(tmp) as i32;
                    
                    // print!("InputReport: len={}: {} x{} y{} {} {}\n", payload.len(), payload[0], x, y, payload[5], payload[6]);

                    let mev = MouseEvent { x: 2*x, y: 2*y }; // Orbital uses 0..=65535
                    let bev = ButtonEvent {
                        left: payload[0] & 1 != 0,
                        middle: payload[0] & 4 != 0,
                        right: payload[0] & 2 != 0,
                    };
                    input.write(&mev.to_event()).expect("hyperv: failed to write mouse event");
                    input.write(&bev.to_event()).expect("hyperv: failed to write button event");
                },
                x => warn!("Unknown HID packet Type: {:?}", x)
            }
        }
        None
    }
   
    pub async fn run(mut self, mut input: std::fs::File, vmbus: &crate::vmbus::VmBusOuter, offer: vmbus::VmBusChannelOfferChannel) {
        let fasthypercall8_fd = {
            RefCell::new(vmbus.0.borrow_mut().fasthypercall8_fd.try_clone().unwrap())
        };

        let cid = offer.connection_id as u64;
        let signal_hv = move || {
            use std::io::Write;
            let mut tmp = [0u8; 16];

            tmp[..8].copy_from_slice(&(crate::HvCall::SignalEvent as u64).to_ne_bytes()[..]);
            tmp[8..].copy_from_slice(&(cid as u64).to_ne_bytes()[..]);
            let status: usize = fasthypercall8_fd.borrow_mut().write(&tmp).unwrap();
            assert_eq!(status, 0);
        };

        let (mut producer_ring, mut consumer_ring) = crate::ring::new(
                       vmbus,
                       Rc::new(signal_hv),
            offer.child_relid,
            1,
            1
        ).await;
        
        // Mouse VSP init through vmbus_sendpacket, ring_write...
        const SYNTHHID_INPUT_VERSION: u32 = 2 << 16 | 0; // 2.0
        let mut req: MouseSvcPrtMsg = unsafe { mem::zeroed() };
        req.ty = PipePrtMsgTy::Data;
        req.size = mem::size_of::<SynthHidProtocolRequest>() as u32;
        req.val.protocol_req = SynthHidProtocolRequest {
            header: SynthHidMessageHeader {
                ty: SynthHidMessageType::ProtocolRequest as u32,
                size: mem::size_of::<u32>() as u32
            },
            requested_version: SYNTHHID_INPUT_VERSION,
        };

        // print!("Write producer ring\n");
        let payload_bufs = &[
            unsafe { slice::from_raw_parts(&req as *const _ as *const u8, mem::size_of_val(&req)) }
        ];
        producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), payload_bufs, true);
        // print!("Done\n");

        loop {
            while let Some(event) = consumer_ring.next() {
                let handled = self.handle_mouse_event(&mut input, &*event);
                if let Some(req) = handled {
                    // print!("Sending response");
                    let payload_bufs = &[
                        unsafe { slice::from_raw_parts(&req as *const _ as *const u8, mem::size_of_val(&req)) }
                    ];
                    producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), payload_bufs, true);
                }
            }

            // print!("Mouse: Waiting for other message\n");
            vmbus.wait_for_channel(offer.child_relid).await;
        }
    }

}
