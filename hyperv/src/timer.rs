use bitflags::bitflags;

use crate::msr::Msr;

bitflags! {
    struct TimerConfiguration: u64 {
        const ENABLE =          1 << 0;
        const PERIODIC =        1 << 1;
        const LAZY =            1 << 2;
        const AUTO_ENABLE =     1 << 3;
        const DIRECT_MODE =     1 << 12;
    }
}

pub fn setup_stimer0(msr: &mut Msr) { 
    // value measured in 100 nanosecond units (expiration time or duration for periodic timers)
    msr.hv_stimer0_count.set(10_000u64).unwrap(); 

    let cfg = (TimerConfiguration::ENABLE | TimerConfiguration::DIRECT_MODE | TimerConfiguration::PERIODIC).bits()
        | (((crate::HYPERV_STIMER0_VECTOR as u64) << 4) & crate::bit_range(4..=11));
    msr.hv_stimer0_config.set(cfg).unwrap();
}

// TODO register irq_handler and assert MSR EOI as well
