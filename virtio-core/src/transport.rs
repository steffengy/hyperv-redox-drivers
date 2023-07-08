use crate::spec::*;
use crate::utils::align;

use event::EventQueue;
use syscall::{Dma, PHYSMAP_WRITE};

use core::mem::size_of;
use core::sync::atomic::{AtomicU16, Ordering};

use std::fs::File;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("syscall failed")]
    SyscallError(syscall::Error),
    #[error("pcid client handle error")]
    PcidClientHandle(pcid_interface::PcidClientHandleError),
    #[error("the device is incapable of {0:?}")]
    InCapable(CfgType),
}

impl From<pcid_interface::PcidClientHandleError> for Error {
    fn from(value: pcid_interface::PcidClientHandleError) -> Self {
        Self::PcidClientHandle(value)
    }
}

impl From<syscall::Error> for Error {
    fn from(value: syscall::Error) -> Self {
        Self::SyscallError(value)
    }
}

/// Returns the queue part sizes in bytes.
///
/// ## Reference
/// Section 2.7 Split Virtqueues of the specfication v1.2 describes the alignment
/// and size of the queue parts.
///
/// ## Panics
/// If `queue_size` is not a power of two or is zero.
const fn queue_part_sizes(queue_size: usize) -> (usize, usize, usize) {
    assert!(queue_size.is_power_of_two() && queue_size != 0);

    const DESCRIPTOR_ALIGN: usize = 16;
    const AVAILABLE_ALIGN: usize = 2;
    const USED_ALIGN: usize = 4;

    let queue_size = queue_size as usize;
    let desc = size_of::<Descriptor>() * queue_size;

    // `avail_header`: Size of the available ring header and the footer.
    let avail_header = size_of::<AvailableRing>() + size_of::<AvailableRingExtra>();
    let avail = avail_header + size_of::<AvailableRingElement>() * queue_size;

    // `used_header`: Size of the used ring header and the footer.
    let used_header = size_of::<UsedRing>() + size_of::<UsedRingExtra>();
    let used = used_header + size_of::<UsedRingElement>() * queue_size;

    (
        align(desc, DESCRIPTOR_ALIGN),
        align(avail, AVAILABLE_ALIGN),
        align(used, USED_ALIGN),
    )
}

pub struct PendingRequest<'a> {
    queue: Arc<Queue<'a>>,
    first_descriptor: u32,
}

impl<'a> Future for PendingRequest<'a> {
    type Output = u32;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // XXX: Register the waker before checking the queue to avoid the race condition
        //      where you lose a notification.
        self.queue
            .waker
            .lock()
            .unwrap()
            .insert(self.first_descriptor, cx.waker().clone());

        let used_head = self.queue.used.head_index();

        if used_head == self.queue.used_head.load(Ordering::SeqCst) {
            // No new requests have been completed.
            return Poll::Pending;
        }

        let used_element = self.queue.used.get_element_at((used_head - 1) as usize);
        let written = used_element.written.get();

        let mut table_index = used_element.table_index.get();

        if table_index == self.first_descriptor {
            // The request has been completed; recycle the descriptors used.
            while self.queue.descriptor[table_index as usize]
                .flags()
                .contains(DescriptorFlags::NEXT)
            {
                let next_index = self.queue.descriptor[table_index as usize].next();
                self.queue.descriptor_stack.push(table_index as u16);
                table_index = next_index.into();
            }

            // Push the last descriptor.
            self.queue.descriptor_stack.push(table_index as u16);
            self.queue
                .waker
                .lock()
                .unwrap()
                .remove(&self.first_descriptor);

            self.queue.used_head.store(used_head, Ordering::SeqCst);
            return Poll::Ready(written);
        } else {
            return Poll::Pending;
        }
    }
}

pub struct Queue<'a> {
    pub queue_index: u16,
    pub waker: Mutex<std::collections::HashMap<u32, Waker>>,
    pub used: Used<'a>,
    pub descriptor: Dma<[Descriptor]>,
    pub available: Available<'a>,
    pub used_head: AtomicU16,

    notification_bell: &'a mut AtomicU16,
    descriptor_stack: crossbeam_queue::SegQueue<u16>,
    sref: Weak<Self>,
}

impl<'a> Queue<'a> {
    pub fn new(
        descriptor: Dma<[Descriptor]>,
        available: Available<'a>,
        used: Used<'a>,

        notification_bell: &'a mut AtomicU16,
        queue_index: u16,
    ) -> Arc<Self> {
        let descriptor_stack = crossbeam_queue::SegQueue::new();
        (0..descriptor.len() as u16).for_each(|i| descriptor_stack.push(i));

        Arc::new_cyclic(|sref| Self {
            notification_bell,
            available,
            descriptor,
            used,
            waker: Mutex::new(std::collections::HashMap::new()),
            queue_index,
            descriptor_stack,
            used_head: AtomicU16::new(0),
            sref: sref.clone(),
        })
    }

    #[must_use = "The function returns a future that must be awaited to ensure the sent request is completed."]
    pub fn send(&self, chain: Vec<Buffer>) -> PendingRequest<'a> {
        let mut first_descriptor: Option<usize> = None;
        let mut last_descriptor: Option<usize> = None;

        for buffer in chain.iter() {
            let descriptor = self.descriptor_stack.pop().unwrap() as usize;

            if first_descriptor.is_none() {
                first_descriptor = Some(descriptor);
            }

            self.descriptor[descriptor].set_addr(buffer.buffer as u64);
            self.descriptor[descriptor].set_flags(buffer.flags);
            self.descriptor[descriptor].set_size(buffer.size as u32);

            if let Some(index) = last_descriptor {
                self.descriptor[index].set_next(Some(descriptor as u16));
            }

            last_descriptor = Some(descriptor);
        }

        let last_descriptor = last_descriptor.unwrap();
        let first_descriptor = first_descriptor.unwrap();

        self.descriptor[last_descriptor].set_next(None);

        let index = self.available.head_index() as usize;

        self.available
            .get_element_at(index)
            .set_table_index(first_descriptor as u16);

        self.available.set_head_idx(index as u16 + 1);
        self.notification_bell
            .store(self.queue_index, Ordering::SeqCst);

        PendingRequest {
            queue: self.sref.upgrade().unwrap(),
            first_descriptor: first_descriptor as u32,
        }
    }

    /// Returns the number of descriptors in the descriptor table of this queue.
    pub fn descriptor_len(&self) -> usize {
        self.descriptor.len()
    }
}

unsafe impl Sync for Queue<'_> {}
unsafe impl Send for Queue<'_> {}

pub struct Available<'a> {
    addr: usize,
    size: usize,

    queue_size: usize,

    ring: &'a mut AvailableRing,
}

impl<'a> Available<'a> {
    pub fn new(queue_size: usize) -> Result<Self, Error> {
        let (_, size, _) = queue_part_sizes(queue_size);
        let size = size.next_multiple_of(syscall::PAGE_SIZE); // align to page size

        let addr = unsafe { syscall::physalloc(size) }.map_err(Error::SyscallError)?;
        let virt =
            unsafe { syscall::physmap(addr, size, PHYSMAP_WRITE) }.map_err(Error::SyscallError)?;

        let ring = unsafe { &mut *(virt as *mut AvailableRing) };

        Ok(Self {
            addr,
            size,
            ring,
            queue_size,
        })
    }

    /// ## Panics
    /// This function panics if the index is out of bounds.
    pub fn get_element_at(&self, index: usize) -> &AvailableRingElement {
        // SAFETY: We have exclusive access to the elements and the number of elements
        //         is correct; same as the queue size.
        unsafe {
            self.ring
                .elements
                .as_slice(self.queue_size)
                .get(index % self.queue_size)
                .expect("virtio-core::available: index out of bounds")
        }
    }

    pub fn head_index(&self) -> u16 {
        self.ring.head_index.load(Ordering::SeqCst)
    }

    pub fn set_head_idx(&self, index: u16) {
        self.ring.head_index.store(index, Ordering::SeqCst);
    }

    pub fn phys_addr(&self) -> usize {
        self.addr
    }
}

impl Drop for Available<'_> {
    fn drop(&mut self) {
        log::warn!("virtio-core: dropping 'available' ring at {:#x}", self.addr);

        unsafe {
            syscall::physunmap(self.addr).unwrap();
            syscall::physfree(self.addr, self.size).unwrap();
        }
    }
}

pub struct Used<'a> {
    addr: usize,
    size: usize,

    queue_size: usize,

    ring: &'a mut UsedRing,
}

impl<'a> Used<'a> {
    pub fn new(queue_size: usize) -> Result<Self, Error> {
        let (_, _, size) = queue_part_sizes(queue_size);
        let size = size.next_multiple_of(syscall::PAGE_SIZE); // align to page size

        let addr = unsafe { syscall::physalloc(size) }.map_err(Error::SyscallError)?;
        let virt =
            unsafe { syscall::physmap(addr, size, PHYSMAP_WRITE) }.map_err(Error::SyscallError)?;

        let ring = unsafe { &mut *(virt as *mut UsedRing) };

        Ok(Self {
            addr,
            size,
            ring,
            queue_size,
        })
    }

    /// ## Panics
    /// This function panics if the index is out of bounds.
    pub fn get_element_at(&self, index: usize) -> &UsedRingElement {
        // SAFETY: We have exclusive access to the elements and the number of elements
        //         is correct; same as the queue size.
        unsafe {
            self.ring
                .elements
                .as_slice(self.queue_size)
                .get(index % self.queue_size)
                .expect("virtio-core::used: index out of bounds")
        }
    }

    /// ## Panics
    /// This function panics if the index is out of bounds.
    pub fn get_mut_element_at(&mut self, index: usize) -> &mut UsedRingElement {
        // SAFETY: We have exclusive access to the elements and the number of elements
        //         is correct; same as the queue size.
        unsafe {
            self.ring
                .elements
                .as_mut_slice(self.queue_size)
                .get_mut(index % 256)
                .expect("virtio-core::used: index out of bounds")
        }
    }

    pub fn flags(&self) -> u16 {
        self.ring.flags.get()
    }

    pub fn head_index(&self) -> u16 {
        self.ring.head_index.get()
    }

    pub fn phys_addr(&self) -> usize {
        self.addr
    }
}

impl Drop for Used<'_> {
    fn drop(&mut self) {
        log::warn!("virtio-core: dropping 'used' ring at {:#x}", self.addr);

        unsafe {
            syscall::physunmap(self.addr).unwrap();
            syscall::physfree(self.addr, self.size).unwrap();
        }
    }
}

pub struct StandardTransport<'a> {
    common: Mutex<&'a mut CommonCfg>,
    notify: *const u8,
    notify_mul: u32,

    queue_index: AtomicU16,
}

impl<'a> StandardTransport<'a> {
    pub fn new(common: &'a mut CommonCfg, notify: *const u8, notify_mul: u32) -> Arc<Self> {
        Arc::new(Self {
            common: Mutex::new(common),
            notify,
            notify_mul,

            queue_index: AtomicU16::new(0),
        })
    }

    pub fn reset(&self) {
        let mut common = self.common.lock().unwrap();
        common.device_status.set(DeviceStatusFlags::empty());
    }

    pub fn check_device_feature(&self, feature: u32) -> bool {
        let mut common = self.common.lock().unwrap();

        common.device_feature_select.set(feature >> 5);
        (common.device_feature.get() & (1 << (feature & 31))) != 0
    }

    pub fn ack_driver_feature(&self, feature: u32) {
        let mut common = self.common.lock().unwrap();

        common.driver_feature_select.set(feature >> 5);

        let current = common.driver_feature.get();
        common.driver_feature.set(current | (1 << (feature & 31)));
    }

    pub fn finalize_features(&self) {
        // Check VirtIO version 1 compliance.
        assert!(self.check_device_feature(VIRTIO_F_VERSION_1));
        self.ack_driver_feature(VIRTIO_F_VERSION_1);

        let mut common = self.common.lock().unwrap();

        let status = common.device_status.get();
        common
            .device_status
            .set(status | DeviceStatusFlags::FEATURES_OK);

        // Re-read device status to ensure the `FEATURES_OK` bit is still set: otherwise,
        // the device does not support our subset of features and the device is unusable.
        let confirm = common.device_status.get();
        assert!((confirm & DeviceStatusFlags::FEATURES_OK) == DeviceStatusFlags::FEATURES_OK);
    }

    pub fn run_device(&self) {
        let mut common = self.common.lock().unwrap();

        let status = common.device_status.get();
        common
            .device_status
            .set(status | DeviceStatusFlags::DRIVER_OK);
    }

    pub fn setup_queue(&self, vector: u16, irq_handle: &File) -> Result<Arc<Queue<'a>>, Error> {
        let mut common = self.common.lock().unwrap();

        let queue_index = self.queue_index.fetch_add(1, Ordering::SeqCst);
        common.queue_select.set(queue_index);

        let queue_size = common.queue_size.get() as usize;
        let queue_notify_idx = common.queue_notify_off.get();

        // Allocate memory for the queue structues.
        let descriptor = unsafe {
            Dma::<[Descriptor]>::zeroed_unsized(queue_size).map_err(Error::SyscallError)?
        };

        let avail = Available::new(queue_size)?;
        let mut used = Used::new(queue_size)?;

        for i in 0..queue_size {
            // XXX: Fill the `table_index` of the elements with `T::MAX` to help with
            //      debugging since qemu reports them as illegal values.
            avail
                .get_element_at(i)
                .table_index
                .store(u16::MAX, Ordering::Relaxed);
            used.get_mut_element_at(i).table_index.set(u32::MAX);
        }

        common.queue_desc.set(descriptor.physical() as u64);
        common.queue_driver.set(avail.phys_addr() as u64);
        common.queue_device.set(used.phys_addr() as u64);

        // Set the MSI-X vector.
        common.queue_msix_vector.set(vector);
        assert!(common.queue_msix_vector.get() == vector);

        // Enable the queue.
        common.queue_enable.set(1);

        let notification_bell = unsafe {
            let offset = self.notify_mul * queue_notify_idx as u32;
            &mut *(self.notify.add(offset as usize) as *mut AtomicU16)
        };

        log::info!("virtio-core: enabled queue #{queue_index} (size={queue_size})");

        let queue = Queue::new(descriptor, avail, used, notification_bell, queue_index);

        let queue_copy = queue.clone();
        let irq_fd = irq_handle.as_raw_fd();

        std::thread::spawn(move || {
            let mut event_queue = EventQueue::<usize>::new().unwrap();

            event_queue
                .add(irq_fd, move |_| -> Result<Option<usize>, std::io::Error> {
                    // Wake up the tasks waiting on the queue.
                    for (_, task) in queue_copy.waker.lock().unwrap().iter() {
                        task.wake_by_ref();
                    }
                    Ok(None)
                })
                .unwrap();

            loop {
                event_queue.run().unwrap();
            }
        });

        Ok(queue)
    }
}