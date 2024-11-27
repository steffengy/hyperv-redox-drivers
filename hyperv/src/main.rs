//#![deny(warnings)]
use common::dma::Dma;
use event::{user_data, EventQueue};
use futures::FutureExt;
use log::info;
use std::fmt;
use std::future::Future;
use std::io::{Read, Write};
use std::ops::RangeInclusive;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{RawWaker, RawWakerVTable, Waker};
pub const HYPERV_CALLBACK_VECTOR: usize = 90;
pub const HYPERV_STIMER0_VECTOR: usize = 91;

pub const PAGE_SIZE: usize = 4096;
const HV_MSG_NONE: u32 = 0;
const HV_MESSAGE_PAYLOAD_QWORD_COUNT: usize = 30;

#[repr(C, align(4096))]
struct HvInputPostMessage {
    conn_id: u32,
    reserved: u32,
    msg_type: u32,
    payload_size: u32,
    payload: [u64; HV_MESSAGE_PAYLOAD_QWORD_COUNT],
}

#[repr(u32)]
enum HvCall {
    PostMessage = 0x005c,
    SignalEvent = 0x005d,
}

#[derive(Debug, Copy, Clone)]
#[repr(packed)]
#[allow(dead_code)]
struct HvMessageHeader {
    ty: u32,
    payload_size: u8,
    flags: u8,
    reserved: [u8; 2],
    sender: u64,
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct HvMessage {
    header: HvMessageHeader,
    payload: [u64; HV_MESSAGE_PAYLOAD_QWORD_COUNT],
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
struct UUID([u8; 16]);

impl fmt::Debug for UUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
            "{:x}{:x}{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}{:x}{:x}{:x}{:x}",
            self.0[3], self.0[2], self.0[1], self.0[0],
            self.0[7], self.0[6], self.0[5], self.0[4],
            self.0[11], self.0[10], self.0[9], self.0[8],
            self.0[12], self.0[13], self.0[14], self.0[15])
    }
}

mod notify;
mod vmbus;
mod msr;
mod ring;
mod gpadl;
mod keyboard;
mod mouse;
mod netvsc;
mod timer;

const fn bit_range(x: RangeInclusive<u64>) -> u64 {
    let start = *x.start();
    let end = *x.end() + 1;
    // ((1<<end)-1) & !((1<<start)-1)
    u64::max_value() >> (64-end) & !((1<<start)-1)
}

#[macro_export]
macro_rules! try_from_enum {
    ( #[repr($repr:ident)] $( #[ $attr:meta ] )* $vis:vis enum $name:ident { $( $( #[ $variant_attr:meta ] )* $variant:ident = $value:expr, )* }) => {
        #[repr($repr)]
        $( #[$attr] )*
        pub enum $name {
            $(
                $( #[$variant_attr] )* // So that doc strings work
                $variant = $value,
            )*
        }

        impl ::core::convert::TryFrom<$repr> for $name {
            type Error = $repr;

            fn try_from(value: $repr) -> ::core::result::Result<$name, $repr> {
                match value {
                    $( x if x == $name::$variant as $repr => Ok($name::$variant), )*
                    _ => Err(value)
                }
            }
        }
    }
}

fn main() {
    let log_level = log::LevelFilter::Debug;

    common::setup_logging("bus", "pci", "hyperv", log_level, log::LevelFilter::Trace);

    redox_daemon::Daemon::new(move |daemon| main_inner(daemon)).unwrap();

}

// make r.drivers live
fn main_inner(daemon: redox_daemon::Daemon) -> ! {
    println!("Ttest2!!");

    let (irq_sender, irq_receiver) = notify::arc::notify_pair();

    std::thread::spawn(move || {
        let mut irq_file = std::fs::File::create(format!("/scheme/irq/cpu-00/{}", HYPERV_CALLBACK_VECTOR - 32))
            .expect("Could not open IRQ HYPERV_CALLBACK");
        let mut timer_file = std::fs::File::create(format!("/scheme/irq/cpu-00/{}", HYPERV_STIMER0_VECTOR - 32))
            .expect("Could not open IRQ HYPERV_STIMER0_VECTOR");
        let event_queue = EventQueue::<Source>::new().expect("hyperv: Could not create event queue.");
        event_queue.subscribe(irq_file.as_raw_fd() as usize, Source::Irq, event::EventFlags::READ).unwrap();
        event_queue.subscribe(timer_file.as_raw_fd() as usize, Source::TimerIrq,event::EventFlags::READ).unwrap();
        
        println!("Running EventLoop...");
        for event in event_queue.map(|e| e.expect("hyperv: failed to get next event")) {
            match event.user_data {
                Source::Irq => {
                    let mut irq = [0; 8];
                    irq_file.read(&mut irq).unwrap();
                    irq_sender.notify();
                },
                Source::TimerIrq => {
                    let mut irq = [0; 8];
                    timer_file.read(&mut irq).unwrap();
                }
            }
        }
    });

    user_data! {
        enum Source {
            Irq,
            TimerIrq,
        }
    }

    let our_goid = 
    1<<63 |      // "Open Source Convention" Flag
    0x4242 << 48; // Random OS ID we chose;
    
    // TODO: OR to existing MSR value
    let mut msr = msr::Msr::open_all();
    msr.hv_guest_os_id.set(our_goid).unwrap();
    assert_eq!(msr.hv_guest_os_id.get().unwrap(), our_goid);

    // Pass hypercall address to kernel driver...
    let mut hypercall_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/scheme/hyperv/hypercall"))
        .expect("hyperv: failed to open /scheme/hyperv/hypercall");
    let hypercall_phys = hypercall_fd.write(&1u64.to_ne_bytes()[..]).unwrap();
    assert!(hypercall_phys > 4096);
    /*let tsc_phys = hypercall_fd.write(&2u64.to_ne_bytes()[..]).unwrap();
    assert!(tsc_phys > 4096);*/

    let fasthypercall8_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/scheme/hyperv/fast_hypercall8"))
        .expect("hyperv: failed to open /scheme/hyperv/fast_hypercall8");

    let input = std::fs::OpenOptions::new()
        .write(true)
        .open("/scheme/input/producer")
        .expect("hyperv: failed to open /scheme/input/producer");


    let old = msr.hv_hypercall.get().unwrap();
    msr.hv_hypercall.set(
        old |
        1 |          // Enable Hypercall Page
        (hypercall_phys as u64) & bit_range(12..=63)
    ).unwrap();

    /*let old = msr.hv_msr_reference_tsc.get().unwrap();
    msr.hv_msr_reference_tsc.set(
        old
        | 1 // Enable
        | (tsc_phys as u64) & bit_range(12..=63)
    ).unwrap();*/

    timer::setup_stimer0(&mut msr);
   
    let signal_daemon_ready = || {
        daemon.ready().unwrap();
        // For debugging comment this line and you'll just see the output on screen.
        // Else can use `cat sys:/log`. Other easy way is adding `tail -f sys:/log` to desktop.toml init.d.
    };

    info!("vmbus init...");
    let vmbus = vmbus::VmBus::init(hypercall_fd, fasthypercall8_fd, &mut msr, irq_receiver);
    let fut = futures::future::join(vmbus.run_irq_ticks(), async {
        vmbus.initiate_contact().await;
        vmbus.enumerate_devices().await;

        let mut pool: Vec<Pin<Box<dyn Future<Output=()>>>> = vec![];
        let offer = {
            (*vmbus.0).borrow_mut().ch_offers.iter().filter(|x| x.offer.if_type == keyboard::DUUID).nth(0).cloned()
        };
        if let Some(kof) = offer {
            pool.push(Box::pin(keyboard::DriverInstance::new().run(input.try_clone().unwrap(), &vmbus, kof)));
        }
        let offer = {
            (*vmbus.0).borrow_mut().ch_offers.iter().filter(|x| x.offer.if_type == mouse::DUUID).nth(0).cloned()
        };
        if let Some(mof) = offer {
            pool.push(Box::pin(mouse::DriverInstance::new().run(input.try_clone().unwrap(), &vmbus, mof)));
        }
        let offer = {
            (*vmbus.0).borrow_mut().ch_offers.iter().filter(|x| x.offer.if_type == netvsc::DUUID).nth(0).cloned()
        };
        if let Some(nof) = offer {
            pool.push(Box::pin(netvsc::DriverInstance::new(nof).run(&vmbus, Some(signal_daemon_ready))));
        }
        futures::future::join_all(pool).await;
    });
    futures::executor::block_on(fut);

    eprintln!("ETest!!");
    panic!("Daemon exit");
}

