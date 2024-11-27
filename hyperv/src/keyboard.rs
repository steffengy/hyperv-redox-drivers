//! HyperV Synthetic Keyboard Driver
use core::convert::TryFrom;
use core::mem;
use core::slice;
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use log::info;
use orbclient::KeyEvent;

use crate::{UUID, vmbus};
use crate::try_from_enum;

pub const DUUID: UUID = UUID([0x6d, 0xad, 0x12, 0xf9, /**/ 0x17, 0x2b, /**/ 0xea, 0x48, /**/ 0xbd, 0x65, 0xf9, 0x27, 0xa6, 0x1c, 0x76, 0x84]);

static US: [[char; 2]; 58] = [
        ['\0', '\0'],
        ['\x1B', '\x1B'],
        ['1', '!'],
        ['2', '@'],
        ['3', '#'],
        ['4', '$'],
        ['5', '%'],
        ['6', '^'],
        ['7', '&'],
        ['8', '*'],
        ['9', '('],
        ['0', ')'],
        ['-', '_'],
        ['=', '+'],
        ['\x7F', '\x7F'],
        ['\t', '\t'],
        ['q', 'Q'],
        ['w', 'W'],
        ['e', 'E'],
        ['r', 'R'],
        ['t', 'T'],
        ['y', 'Y'],
        ['u', 'U'],
        ['i', 'I'],
        ['o', 'O'],
        ['p', 'P'],
        ['[', '{'],
        [']', '}'],
        ['\n', '\n'],
        ['\0', '\0'],
        ['a', 'A'],
        ['s', 'S'],
        ['d', 'D'],
        ['f', 'F'],
        ['g', 'G'],
        ['h', 'H'],
        ['j', 'J'],
        ['k', 'K'],
        ['l', 'L'],
        [';', ':'],
        ['\'', '"'],
        ['`', '~'],
        ['\0', '\0'],
        ['\\', '|'],
        ['z', 'Z'],
        ['x', 'X'],
        ['c', 'C'],
        ['v', 'V'],
        ['b', 'B'],
        ['n', 'N'],
        ['m', 'M'],
        [',', '<'],
        ['.', '>'],
        ['/', '?'],
        ['\0', '\0'],
        ['\0', '\0'],
        ['\0', '\0'],
        [' ', ' '],
    ];

    pub fn get_char(scancode: u8, shift: bool) -> char {
        if let Some(c) = US.get(scancode as usize) {
            if shift {
                c[1]
            } else {
                c[0]
            }
        } else {
            '\0'
        }
    }


try_from_enum!(
    #[repr(u32)]
    #[derive(Debug)]
    enum SynthKeyboardMessageType {
        ProtocolRequest = 1,
        ProtocolResponse = 2,
        Event = 3,
    }
);

#[derive(Debug)]
#[repr(C)]
struct SynthKeyboardMessageHeader {
    ty: u32,
}

impl SynthKeyboardMessageHeader {
    fn ty(&self) -> Result<SynthKeyboardMessageType, u32> {
        SynthKeyboardMessageType::try_from(self.ty)
    }
}

#[repr(C)]
struct SynthKeyboardProtocolRequest {
    header: SynthKeyboardMessageHeader,
    requested_version: u32,
}

#[repr(C)]
struct SynthKeyboardProtocolResponse {
    header: SynthKeyboardMessageHeader,
    status: u32,
}

#[derive(Debug)]
#[repr(C)]
struct SynthKeyboardKeystroke {
    header: SynthKeyboardMessageHeader,
    scan_code: u16,
    _reserved: u16,
    info: u32,
}

pub struct DriverInstance {
    initial: bool,
    rshift: bool,
    lshift: bool,
}

impl DriverInstance {
    pub fn new() -> DriverInstance {
        DriverInstance { initial: true, rshift: false, lshift: false }
    }

    fn handle_keyboard_event(&mut self, input: &mut std::fs::File, event: &[u8]) {
        let desc = unsafe { &*(event.as_ptr() as *const vmbus::VmPacketDescriptor) };
        let desc_ty = desc.ty;
        assert_eq!(desc_ty, vmbus::VmBusPacketType::DataInband as u16);
        
        let event_ptr = event[desc.offset()..].as_ptr();
        let header = unsafe { &*(event_ptr as *const SynthKeyboardMessageHeader) };
        
        match header.ty() {
            Ok(SynthKeyboardMessageType::ProtocolResponse) if self.initial => {
                let resp = unsafe { &*(event_ptr as *const SynthKeyboardProtocolResponse) };
                self.initial = false;
                assert_eq!(resp.header.ty, SynthKeyboardMessageType::ProtocolResponse as u32);
                assert_eq!(resp.status & 1, 1, "Protocol not accepted");
                info!("Keyboard VSP connected\n");
            },
            Ok(SynthKeyboardMessageType::Event) => {
                let event = unsafe { &*(event_ptr as *const SynthKeyboardKeystroke) };

                assert!(!self.initial);
                let pressed = event.info & 2 == 0;
                //print!("Got Keyboard Event {:?} {}\n", event.scan_code, event.info & 2);

                if event.scan_code < u8::MAX as u16 {
                    // handle shift state
                    match event.scan_code as u8 {
                        0x2A => self.lshift = pressed,
                        0x36 => self.rshift = pressed,
                        _ => ()
                    }

                    let chr = get_char(event.scan_code as u8, self.lshift || self.rshift);

                    input
                    .write(
                        &KeyEvent {
                            character: chr,
                            scancode: event.scan_code as u8,
                            pressed,
                        }
                        .to_event(),
                    )
                    .expect("hyperv: failed to write key event");
                }
            }
            x => panic!("Unknown Keyboard packet Type: {:?}", x)
        }
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
        
        // Keyboard VSP init through vmbus_sendpacket, ring_write...
        const SYNTH_KBD_VERSION: u32 = 1 << 16 | 0; // 1.0
        let mut req: SynthKeyboardProtocolRequest = unsafe { mem::zeroed() };
        req.header.ty = SynthKeyboardMessageType::ProtocolRequest as u32;
        req.requested_version = SYNTH_KBD_VERSION;
        
        // print!("Write producer ring\n");
        let payload_bufs = &[unsafe { slice::from_raw_parts(&req as *const _ as *const u8, mem::size_of_val(&req)) }];
        producer_ring.send_vmpacket(&mut *(vmbus.0).borrow_mut(), payload_bufs, true);
        // print!("Done\n");

        loop {
            while let Some(event) = consumer_ring.next() {
                self.handle_keyboard_event(&mut input, &*event);
            }

            // print!("Keyboard: Waiting for other message\n");
            vmbus.wait_for_channel(offer.child_relid).await;
        }
    }

}
