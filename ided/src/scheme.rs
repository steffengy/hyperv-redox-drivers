use std::collections::BTreeMap;
use std::{cmp, str};
use std::convert::{TryFrom};
use std::fmt::Write;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io;
use std::sync::{Arc, Mutex};

use syscall::{
    Error, EACCES, EBADF, EINVAL, EISDIR, ENOENT, EOVERFLOW, Result,
    Io, SchemeBlockMut, Stat, MODE_DIR, MODE_FILE, O_DIRECTORY,
    O_STAT, SEEK_CUR, SEEK_END, SEEK_SET};

use crate::ide::{Channel, Disk};

use partitionlib::{LogicalBlockSize, PartitionTable};

#[derive(Clone)]
enum Handle {
    List(Vec<u8>, usize), // Dir contents buffer, position
    Disk(usize, usize), // Disk index, position
    Partition(usize, u32, usize), // Disk index, partition index, position
}

pub struct DiskWrapper {
    disk: Box<dyn Disk>,
    pt: Option<PartitionTable>,
}

impl DiskWrapper {
    fn pt(disk: &mut dyn Disk) -> Option<PartitionTable> {
        let bs = match disk.block_length() {
            Ok(512) => LogicalBlockSize::Lb512,
            Ok(4096) => LogicalBlockSize::Lb4096,
            _ => return None,
        };
        struct Device<'a, 'b> { disk: &'a mut dyn Disk, offset: u64, block_bytes: &'b mut [u8] }

        impl<'a, 'b> Seek for Device<'a, 'b> {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                let size = i64::try_from(self.disk.size()).or(Err(io::Error::new(io::ErrorKind::Other, "Disk larger than 2^63 - 1 bytes")))?;

                self.offset = match from {
                    SeekFrom::Start(new_pos) => cmp::min(self.disk.size(), new_pos),
                    SeekFrom::Current(new_pos) => cmp::max(0, cmp::min(size, self.offset as i64 + new_pos)) as u64,
                    SeekFrom::End(new_pos) => cmp::max(0, cmp::min(size + new_pos, size)) as u64,
                };

                Ok(self.offset)
            }
        }
        // TODO: Perhaps this impl should be used in the rest of the scheme.
        impl<'a, 'b> Read for Device<'a, 'b> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let blksize = self.disk.block_length().map_err(|err| io::Error::from_raw_os_error(err.errno))?;
                let size_in_blocks = self.disk.size() / u64::from(blksize);

                let disk = &mut self.disk;

                let read_block = |block: u64, block_bytes: &mut [u8]| {
                    if block >= size_in_blocks {
                        return Err(io::Error::from_raw_os_error(syscall::EOVERFLOW));
                    }
                    loop {
                         match disk.read(block, block_bytes) {
                             Ok(Some(bytes)) => {
                                 assert_eq!(bytes, block_bytes.len());
                                 assert_eq!(bytes, blksize as usize);
                                 return Ok(());
                             }
                             Ok(None) => { std::thread::yield_now(); continue }
                             Err(err) => return Err(io::Error::from_raw_os_error(err.errno)),
                         }
                     }
                };
                let bytes_read = block_io_wrapper::read(self.offset, blksize, buf, self.block_bytes, read_block)?;

                self.offset += bytes_read as u64;
                Ok(bytes_read)
            }
        }

        let mut block_bytes = [0u8; 4096];

        partitionlib::get_partitions(&mut Device { disk, offset: 0, block_bytes: &mut block_bytes[..bs.into()] }, bs).ok().flatten()
    }
    fn new(mut disk: Box<dyn Disk>) -> Self {
        Self {
            pt: Self::pt(&mut *disk),
            disk,
        }
    }
}

impl std::ops::Deref for DiskWrapper {
    type Target = dyn Disk;

    fn deref(&self) -> &Self::Target {
        &*self.disk
    }
}
impl std::ops::DerefMut for DiskWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.disk
    }
}

pub struct DiskScheme {
    scheme_name: String,
    chans: Box<[Arc<Mutex<Channel>>]>,
    disks: Box<[DiskWrapper]>,
    handles: BTreeMap<usize, Handle>,
    next_id: usize
}

impl DiskScheme {
    pub fn new(scheme_name: String, chans: Vec<Arc<Mutex<Channel>>>, disks: Vec<Box<dyn Disk>>) -> DiskScheme {
        DiskScheme {
            scheme_name: scheme_name,
            chans: chans.into_boxed_slice(),
            disks: disks.into_iter().map(DiskWrapper::new).collect::<Vec<_>>().into_boxed_slice(),
            handles: BTreeMap::new(),
            next_id: 0
        }
    }
}

impl DiskScheme {
    pub fn irq(&mut self, chan_i: usize) -> bool {
        let mut chan = self.chans[chan_i].lock().unwrap();
        //TODO: check chan for irq
        true
    }
}

impl SchemeBlockMut for DiskScheme {
    fn open(&mut self, path: &str, flags: usize, uid: u32, _gid: u32) -> Result<Option<usize>> {
        if uid == 0 {
            let path_str = path.trim_matches('/');
            if path_str.is_empty() {
                if flags & O_DIRECTORY == O_DIRECTORY || flags & O_STAT == O_STAT {
                    let mut list = String::new();

                    for (disk_index, disk) in self.disks.iter().enumerate() {
                        write!(list, "{}\n", disk_index).unwrap();

                        if disk.pt.is_none() {
                            continue
                        }
                        for part_index in 0..disk.pt.as_ref().unwrap().partitions.len() {
                            write!(list, "{}p{}\n", disk_index, part_index).unwrap();
                        }
                    }

                    let id = self.next_id;
                    self.next_id += 1;
                    self.handles.insert(id, Handle::List(list.into_bytes(), 0));
                    Ok(Some(id))
                } else {
                    Err(Error::new(EISDIR))
                }
            } else if let Some(p_pos) = path_str.chars().position(|c| c == 'p') {
                let disk_id_str = &path_str[..p_pos];
                if p_pos + 1 >= path_str.len() {
                    return Err(Error::new(ENOENT));
                }
                let part_id_str = &path_str[p_pos + 1..];
                let i = disk_id_str.parse::<usize>().or(Err(Error::new(ENOENT)))?;
                let p = part_id_str.parse::<u32>().or(Err(Error::new(ENOENT)))?;

                if let Some(disk) = self.disks.get(i) {
                    if disk.pt.is_none() || disk.pt.as_ref().unwrap().partitions.get(p as usize).is_none() {
                        return Err(Error::new(ENOENT));
                    }
                    let id = self.next_id;
                    self.next_id += 1;

                    self.handles.insert(id, Handle::Partition(i, p, 0));

                    Ok(Some(id))
                } else {
                    Err(Error::new(ENOENT))
                }
            } else {
                let i = path_str.parse::<usize>().or(Err(Error::new(ENOENT)))?;

                if self.disks.get(i).is_some() {
                    let id = self.next_id;
                    self.next_id += 1;
                    self.handles.insert(id, Handle::Disk(i, 0));
                    Ok(Some(id))
                } else {
                    Err(Error::new(ENOENT))
                }
            }
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn dup(&mut self, id: usize, buf: &[u8]) -> Result<Option<usize>> {
        if ! buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let new_handle = {
            let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let new_id = self.next_id;
        self.next_id += 1;
        self.handles.insert(new_id, new_handle);
        Ok(Some(new_id))
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat) -> Result<Option<usize>> {
        match *self.handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::List(ref data, _) => {
                stat.st_mode = MODE_DIR;
                stat.st_size = data.len() as u64;
                Ok(Some(0))
            },
            Handle::Disk(number, _) => {
                let disk = self.disks.get_mut(number).ok_or(Error::new(EBADF))?;
                stat.st_mode = MODE_FILE;
                stat.st_size = disk.size();
                stat.st_blksize = disk.block_length()?;
                Ok(Some(0))
            }
            Handle::Partition(disk_id, part_num, _) => {
                let disk = self.disks.get_mut(disk_id).ok_or(Error::new(EBADF))?;
                let size = {
                    let pt = disk.pt.as_ref().ok_or(Error::new(EBADF))?;
                    let partition = pt.partitions.get(part_num as usize).ok_or(Error::new(EBADF))?;
                    partition.size
                };

                stat.st_mode = MODE_FILE; // TODO: Block device?
                stat.st_size = size * u64::from(disk.block_length()?);
                stat.st_blksize = disk.block_length()?;
                stat.st_blocks = size;
                Ok(Some(0))
            }
        }
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        let handle = self.handles.get(&id).ok_or(Error::new(EBADF))?;

        let mut i = 0;

        let scheme_name = self.scheme_name.as_bytes();
        let mut j = 0;
        while i < buf.len() && j < scheme_name.len() {
            buf[i] = scheme_name[j];
            i += 1;
            j += 1;
        }

        if i < buf.len() {
            buf[i] = b':';
            i += 1;
        }

        match *handle {
            Handle::List(_, _) => (),
            Handle::Disk(number, _) => {
                let number_str = format!("{}", number);
                let number_bytes = number_str.as_bytes();
                j = 0;
                while i < buf.len() && j < number_bytes.len() {
                    buf[i] = number_bytes[j];
                    i += 1;
                    j += 1;
                }
            }
            Handle::Partition(disk_num, part_num, _) => {
                let path = format!("{}p{}", disk_num, part_num);
                let path_bytes = path.as_bytes();
                j = 0;
                while i < buf.len() && j < path_bytes.len() {
                    buf[i] = path_bytes[j];
                    i += 1;
                    j += 1;
                }
            }
        }

        Ok(Some(i))
    }

    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<Option<usize>> {
        match *self.handles.get_mut(&id).ok_or(Error::new(EBADF))? {
            Handle::List(ref handle, ref mut size) => {
                let count = (&handle[*size..]).read(buf).unwrap();
                *size += count;
                Ok(Some(count))
            },
            Handle::Disk(number, ref mut size) => {
                let disk = self.disks.get_mut(number).ok_or(Error::new(EBADF))?;
                let blk_len = disk.block_length()?;
                if let Some(count) = disk.read((*size as u64)/(blk_len as u64), buf)? {
                    *size += count;
                    Ok(Some(count))
                } else {
                    Ok(None)
                }
            }
            Handle::Partition(disk_num, part_num, ref mut position) => {
                let disk = self.disks.get_mut(disk_num).ok_or(Error::new(EBADF))?;
                let blksize = disk.block_length()?;

                // validate that we're actually reading within the bounds of the partition
                let rel_block = *position as u64 / blksize as u64;

                let abs_block = {
                    let pt = disk.pt.as_ref().ok_or(Error::new(EBADF))?;
                    let partition = pt.partitions.get(part_num as usize).ok_or(Error::new(EBADF))?;

                    let abs_block = partition.start_lba + rel_block;
                    if rel_block >= partition.size {
                        return Err(Error::new(EOVERFLOW));
                    }
                    abs_block
                };

                if let Some(count) = disk.read(abs_block, buf)? {
                    Ok(Some(count))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn write(&mut self, id: usize, buf: &[u8]) -> Result<Option<usize>> {
        match *self.handles.get_mut(&id).ok_or(Error::new(EBADF))? {
            Handle::List(_, _) => {
                Err(Error::new(EBADF))
            },
            Handle::Disk(number, ref mut size) => {
                let disk = self.disks.get_mut(number).ok_or(Error::new(EBADF))?;
                let blk_len = disk.block_length()?;
                if let Some(count) = disk.write((*size as u64)/(blk_len as u64), buf)? {
                    *size += count;
                    Ok(Some(count))
                } else {
                    Ok(None)
                }
            }
            Handle::Partition(disk_num, part_num, ref mut position) => {
                let disk = self.disks.get_mut(disk_num).ok_or(Error::new(EBADF))?;
                let blksize = disk.block_length()?;

                // validate that we're actually reading within the bounds of the partition
                let rel_block = *position as u64 / blksize as u64;

                let abs_block = {
                    let pt = disk.pt.as_ref().ok_or(Error::new(EBADF))?;
                    let partition = pt.partitions.get(part_num as usize).ok_or(Error::new(EBADF))?;

                    let abs_block = partition.start_lba + rel_block;
                    if rel_block >= partition.size {
                        return Err(Error::new(EOVERFLOW));
                    }
                    abs_block
                };

                if let Some(count) = disk.write(abs_block, buf)? {
                    Ok(Some(count))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn seek(&mut self, id: usize, pos: isize, whence: usize) -> Result<Option<isize>> {
        let pos = pos as usize;

        match *self.handles.get_mut(&id).ok_or(Error::new(EBADF))? {
            Handle::List(ref mut handle, ref mut size) => {
                let len = handle.len() as usize;
                *size = match whence {
                    SEEK_SET => cmp::min(len, pos),
                    SEEK_CUR => cmp::max(0, cmp::min(len as isize, *size as isize + pos as isize)) as usize,
                    SEEK_END => cmp::max(0, cmp::min(len as isize, len as isize + pos as isize)) as usize,
                    _ => return Err(Error::new(EINVAL))
                };

                Ok(Some(*size as isize))
            },
            Handle::Disk(number, ref mut size) => {
                let disk = self.disks.get_mut(number).ok_or(Error::new(EBADF))?;
                let len = disk.size() as usize;
                *size = match whence {
                    SEEK_SET => cmp::min(len, pos),
                    SEEK_CUR => cmp::max(0, cmp::min(len as isize, *size as isize + pos as isize)) as usize,
                    SEEK_END => cmp::max(0, cmp::min(len as isize, len as isize + pos as isize)) as usize,
                    _ => return Err(Error::new(EINVAL))
                };

                Ok(Some(*size as isize))
            }
            Handle::Partition(disk_num, part_num, ref mut position) => {
                let disk = self.disks.get_mut(disk_num).ok_or(Error::new(EBADF))?;
                let block_count = disk.pt.as_ref().ok_or(Error::new(EBADF))?.partitions.get(part_num as usize).ok_or(Error::new(EBADF))?.size;
                let len = u64::from(disk.block_length()?) * block_count;

                *position = match whence {
                    SEEK_SET => cmp::min(len as usize, pos) as usize, // Why isn't pos u64?
                    SEEK_CUR => cmp::max(0, cmp::min(len as isize, *position as isize + pos as isize)) as usize,
                    SEEK_END => cmp::max(0, cmp::min(len as isize, len as isize + pos as isize)) as usize,
                    _ => return Err(Error::new(EINVAL)),
                };
                Ok(Some(*position as isize))
            }
        }
    }

    fn close(&mut self, id: usize) -> Result<Option<usize>> {
        self.handles.remove(&id).ok_or(Error::new(EBADF)).and(Ok(Some(0)))
    }
}
