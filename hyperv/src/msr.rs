use std::fs::OpenOptions;
use std::io::{self, Read, Write};

#[derive(Clone)]
pub struct Msr {
    pub hv_guest_os_id: MsrFd,
    pub hv_hypercall: MsrFd,
    pub hv_simp: MsrFd,
    pub hv_siefp: MsrFd,
    pub hv_sint2: MsrFd,
    pub hv_scontrol: MsrFd,
    pub hv_eoi: MsrFd,
    pub hv_eom: MsrFd,
    pub hv_msr_reference_tsc: MsrFd,
    pub hv_stimer0_config: MsrFd,
    pub hv_stimer0_count: MsrFd,
}
impl Msr {
    pub fn open_all() -> Msr {
        Msr {
            hv_guest_os_id: MsrFd::open("HV_X64_MSR_GUEST_OS_ID"),
            hv_hypercall: MsrFd::open("HV_X64_MSR_HYPERCALL"),
            hv_simp: MsrFd::open("HV_X64_MSR_SIMP"),
            hv_siefp: MsrFd::open("HV_X64_MSR_SIEFP"),
            hv_sint2: MsrFd::open("HV_X64_MSR_SINT2"),
            hv_scontrol: MsrFd::open("HV_X64_MSR_SCONTROL"),
            hv_eom: MsrFd::open("HV_X64_MSR_EOM"),
            hv_eoi: MsrFd::open("HV_X64_MSR_EOI"),
            hv_msr_reference_tsc: MsrFd::open("HV_X64_MSR_REFERENCE_TSC"),
            hv_stimer0_config: MsrFd::open("HV_X64_MSR_STIMER0_CONFIG"),
            hv_stimer0_count: MsrFd::open("HV_X64_MSR_STIMER0_COUNT"),
        }
    }
}

pub struct MsrFd(std::fs::File);

impl Clone for MsrFd {
    fn clone(&self) -> Self {
        Self(self.0.try_clone().unwrap())
    }
}

impl MsrFd {
    fn open(s: &'static str) -> MsrFd {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/scheme/hyperv/msr/{}", s))
            .expect("hyperv: failed to open /scheme/hyperv/msr");
        MsrFd(fd)
    }

    pub fn get(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.0.read(&mut buf).expect("couldnt read");
        Ok(u64::from_ne_bytes(buf))
    }

    pub fn set(&mut self, val: u64) -> io::Result<()> {
        let b = val.to_ne_bytes();
        self.0.write(&b[..])?;
        Ok(())
    }
}
