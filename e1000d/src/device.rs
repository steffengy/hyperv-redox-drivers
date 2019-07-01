use std::{cmp, mem, ptr, slice, thread};
use std::collections::BTreeMap;

use netutils::setcfg;
use syscall::error::{Error, EACCES, EBADF, EINVAL, EWOULDBLOCK, Result};
use syscall::flag::O_NONBLOCK;
use syscall::io::Dma;
use syscall::scheme::SchemeBlockMut;

const CTRL: u32 = 0x00;
const CTRL_LRST: u32 = 1 << 3;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_ILOS: u32 = 1 << 7;
const CTRL_RST: u32 = 1 << 26;
const CTRL_VME: u32 = 1 << 30;
const CTRL_PHY_RST: u32 = 1 << 31;

const STATUS: u32 = 0x08;

const FCAL: u32 = 0x28;
const FCAH: u32 = 0x2C;
const FCT: u32 = 0x30;
const FCTTV: u32 = 0x170;

const ICR: u32 = 0xC0;

const IMS: u32 = 0xD0;
const IMS_TXDW: u32 = 1;
const IMS_TXQE: u32 = 1 << 1;
const IMS_LSC: u32 = 1 << 2;
const IMS_RXSEQ: u32 = 1 << 3;
const IMS_RXDMT: u32 = 1 << 4;
const IMS_RX: u32 = 1 << 6;
const IMS_RXT: u32 = 1 << 7;

const RCTL: u32 = 0x100;
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_LPE: u32 = 1 << 5;
const RCTL_LBM: u32 = 1 << 6 | 1 << 7;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE1: u32 = 1 << 16;
const RCTL_BSIZE2: u32 = 1 << 17;
const RCTL_BSEX: u32 = 1 << 25;
const RCTL_SECRC: u32 = 1 << 26;

const RDBAL: u32 = 0x2800;
const RDBAH: u32 = 0x2804;
const RDLEN: u32 = 0x2808;
const RDH: u32 = 0x2810;
const RDT: u32 = 0x2818;

const RAL0: u32 = 0x5400;
const RAH0: u32 = 0x5404;

#[derive(Debug, Copy, Clone)]
#[repr(packed)]
struct Rd {
    buffer: u64,
    length: u16,
    checksum: u16,
    status: u8,
    error: u8,
    special: u16,
}
const RD_DD: u8 = 1;
const RD_EOP: u8 = 1 << 1;

const TCTL: u32 = 0x400;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

const TDBAL: u32 = 0x3800;
const TDBAH: u32 = 0x3804;
const TDLEN: u32 = 0x3808;
const TDH: u32 = 0x3810;
const TDT: u32 = 0x3818;

#[derive(Debug, Copy, Clone)]
#[repr(packed)]
struct Td {
    buffer: u64,
    length: u16,
    cso: u8,
    command: u8,
    status: u8,
    css: u8,
    special: u16,
}
const TD_CMD_EOP: u8 = 1;
const TD_CMD_IFCS: u8 = 1 << 1;
const TD_CMD_RS: u8 = 1 << 3;
const TD_DD: u8 = 1;

pub struct Intel8254x {
    base: usize,
    receive_buffer: [Dma<[u8; 16384]>; 16],
    receive_ring: Dma<[Rd; 16]>,
    transmit_buffer: [Dma<[u8; 16384]>; 16],
    transmit_ring: Dma<[Td; 16]>,
    next_id: usize,
    pub handles: BTreeMap<usize, usize>,
}

impl SchemeBlockMut for Intel8254x {
    fn open(&mut self, _path: &[u8], flags: usize, uid: u32, _gid: u32) -> Result<Option<usize>> {
        if uid == 0 {
            self.next_id += 1;
            self.handles.insert(self.next_id, flags);
            Ok(Some(self.next_id))
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn dup(&mut self, id: usize, buf: &[u8]) -> Result<Option<usize>> {
        if ! buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let flags = {
            let flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;
            *flags
        };
        self.next_id += 1;
        self.handles.insert(self.next_id, flags);
        Ok(Some(self.next_id))
    }

    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        let flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let head = unsafe { self.read_reg(RDH) };
        let mut tail = unsafe { self.read_reg(RDT) };

        tail += 1;
        if tail >= self.receive_ring.len() as u32 {
            tail = 0;
        }

        if tail != head {
            let rd = unsafe { &mut * (self.receive_ring.as_ptr().offset(tail as isize) as *mut Rd) };
            if rd.status & RD_DD == RD_DD {
                rd.status = 0;

                let data = &self.receive_buffer[tail as usize][.. rd.length as usize];

                let mut i = 0;
                while i < buf.len() && i < data.len() {
                    buf[i] = data[i];
                    i += 1;
                }

                unsafe { self.write_reg(RDT, tail) };

                return Ok(Some(i));
            }
        }

        if flags & O_NONBLOCK == O_NONBLOCK {
            Err(Error::new(EWOULDBLOCK))
        } else {
            Ok(None)
        }
    }

    fn write(&mut self, id: usize, buf: &[u8]) -> Result<Option<usize>> {
        let _flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        loop {
            let head = unsafe { self.read_reg(TDH) };
            let mut tail = unsafe { self.read_reg(TDT) };
            let old_tail = tail;

            tail += 1;
            if tail >= self.transmit_ring.len() as u32 {
                tail = 0;
            }

            if tail != head {
                let td = unsafe { &mut * (self.transmit_ring.as_ptr().offset(old_tail as isize) as *mut Td) };

                td.cso = 0;
                td.command = TD_CMD_EOP | TD_CMD_IFCS | TD_CMD_RS;
                td.status = 0;
                td.css = 0;
                td.special = 0;

                td.length = (cmp::min(buf.len(), 0x3FFF)) as u16;

                let data = unsafe { slice::from_raw_parts_mut(self.transmit_buffer[old_tail as usize].as_ptr() as *mut u8, td.length as usize) };

                let mut i = 0;
                while i < buf.len() && i < data.len() {
                    data[i] = buf[i];
                    i += 1;
                }

                unsafe { self.write_reg(TDT, tail) };

                while td.status == 0 {
                    thread::yield_now();
                }

                return Ok(Some(i));
            }
        }
    }

    fn fevent(&mut self, id: usize, _flags: usize) -> Result<Option<usize>> {
        let _flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;
        Ok(Some(0))
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        let _flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let mut i = 0;
        let scheme_path = b"network:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(Some(i))
    }

    fn fsync(&mut self, id: usize) -> Result<Option<usize>> {
        let _flags = self.handles.get(&id).ok_or(Error::new(EBADF))?;
        Ok(Some(0))
    }

    fn close(&mut self, id: usize) -> Result<Option<usize>> {
        self.handles.remove(&id).ok_or(Error::new(EBADF))?;
        Ok(Some(0))
    }
}

impl Intel8254x {
    pub unsafe fn new(base: usize) -> Result<Self> {
        let mut module = Intel8254x {
            base: base,
            receive_buffer: [Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?],
            receive_ring: Dma::zeroed()?,
            transmit_buffer: [Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?,
                            Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?, Dma::zeroed()?],
            transmit_ring: Dma::zeroed()?,
            next_id: 0,
            handles: BTreeMap::new()
        };

        module.init();

        Ok(module)
    }

    pub unsafe fn irq(&self) -> bool {
        let icr = self.read_reg(ICR);
        icr != 0
    }

    pub fn next_read(&self) -> usize {
        let head = unsafe { self.read_reg(RDH) };
        let mut tail = unsafe { self.read_reg(RDT) };

        tail += 1;
        if tail >= self.receive_ring.len() as u32 {
            tail = 0;
        }

        if tail != head {
            let rd = unsafe { &* (self.receive_ring.as_ptr().offset(tail as isize) as *const Rd) };
            if rd.status & RD_DD == RD_DD {
                return rd.length as usize;
            }
        }

        0
    }

    pub unsafe fn read_reg(&self, register: u32) -> u32 {
        ptr::read_volatile((self.base + register as usize) as *mut u32)
    }

    pub unsafe fn write_reg(&self, register: u32, data: u32) -> u32 {
        ptr::write_volatile((self.base + register as usize) as *mut u32, data);
        ptr::read_volatile((self.base + register as usize) as *mut u32)
    }

    pub unsafe fn flag(&self, register: u32, flag: u32, value: bool) {
        if value {
            self.write_reg(register, self.read_reg(register) | flag);
        } else {
            self.write_reg(register, self.read_reg(register) & !flag);
        }
    }

    pub unsafe fn init(&mut self) {
        self.flag(CTRL, CTRL_RST, true);
        while self.read_reg(CTRL) & CTRL_RST == CTRL_RST {
            print!("   - Waiting for reset: {:X}\n", self.read_reg(CTRL));
        }

        // Enable auto negotiate, link, clear reset, do not Invert Loss-Of Signal
        self.flag(CTRL, CTRL_ASDE | CTRL_SLU, true);
        self.flag(CTRL, CTRL_LRST | CTRL_PHY_RST | CTRL_ILOS, false);

        // No flow control
        self.write_reg(FCAH, 0);
        self.write_reg(FCAL, 0);
        self.write_reg(FCT, 0);
        self.write_reg(FCTTV, 0);

        // Do not use VLANs
        self.flag(CTRL, CTRL_VME, false);

        // TODO: Clear statistical counters

        let mac_low = self.read_reg(RAL0);
        let mac_high = self.read_reg(RAH0);
        let mac = [mac_low as u8,
                    (mac_low >> 8) as u8,
                    (mac_low >> 16) as u8,
                    (mac_low >> 24) as u8,
                    mac_high as u8,
                    (mac_high >> 8) as u8];
        print!("{}", format!("   - MAC: {:>02X}:{:>02X}:{:>02X}:{:>02X}:{:>02X}:{:>02X}\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));
        let _ = setcfg("mac", &format!("{:>02X}-{:>02X}-{:>02X}-{:>02X}-{:>02X}-{:>02X}\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));

        //
        // MTA => 0;
        //

        // Receive Buffer
        for i in 0..self.receive_ring.len() {
            self.receive_ring[i].buffer = self.receive_buffer[i].physical() as u64;
        }

        self.write_reg(RDBAH, (self.receive_ring.physical() >> 32) as u32);
        self.write_reg(RDBAL, self.receive_ring.physical() as u32);
        self.write_reg(RDLEN, (self.receive_ring.len() * mem::size_of::<Rd>()) as u32);
        self.write_reg(RDH, 0);
        self.write_reg(RDT, self.receive_ring.len() as u32 - 1);

        // Transmit Buffer
        for i in 0..self.transmit_ring.len() {
            self.transmit_ring[i].buffer = self.transmit_buffer[i].physical() as u64;
        }

        self.write_reg(TDBAH, (self.transmit_ring.physical() >> 32) as u32);
        self.write_reg(TDBAL, self.transmit_ring.physical() as u32);
        self.write_reg(TDLEN, (self.transmit_ring.len() * mem::size_of::<Td>()) as u32);
        self.write_reg(TDH, 0);
        self.write_reg(TDT, 0);

        self.write_reg(IMS, IMS_RXT | IMS_RX | IMS_RXDMT | IMS_RXSEQ); // | IMS_LSC | IMS_TXQE | IMS_TXDW

        self.flag(RCTL, RCTL_EN, true);
        self.flag(RCTL, RCTL_UPE, true);
        // self.flag(RCTL, RCTL_MPE, true);
        self.flag(RCTL, RCTL_LPE, true);
        self.flag(RCTL, RCTL_LBM, false);
        // RCTL.RDMTS = Minimum threshold size ???
        // RCTL.MO = Multicast offset
        self.flag(RCTL, RCTL_BAM, true);
        self.flag(RCTL, RCTL_BSIZE1, true);
        self.flag(RCTL, RCTL_BSIZE2, false);
        self.flag(RCTL, RCTL_BSEX, true);
        self.flag(RCTL, RCTL_SECRC, true);

        self.flag(TCTL, TCTL_EN, true);
        self.flag(TCTL, TCTL_PSP, true);
        // TCTL.CT = Collision threshold
        // TCTL.COLD = Collision distance
        // TIPG Packet Gap
        // TODO ...

        while self.read_reg(STATUS) & 2 != 2 {
            print!("   - Waiting for link up: {:X}\n", self.read_reg(STATUS));
        }
        print!("   - Link is up with speed {}\n", match (self.read_reg(STATUS) >> 6) & 0b11 {
            0b00 => "10 Mb/s",
            0b01 => "100 Mb/s",
            _ => "1000 Mb/s",
        });
    }
}
