//! Fast scanning of NTFS volumes by reading the Master File Table directly (the technique used by
//! Everything and WizTree). One sequential read of the MFT gives every file's name, parent folder
//! and size, which is far faster than opening millions of folders one by one.
//!
//! Read-only. Needs administrator rights (opening `\\.\C:` for reading). Callers fall back to a
//! normal folder walk when this fails (not elevated, or not NTFS).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ROOT_RECORD: usize = 5;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;
const REF_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Every in-use record of the volume, indexed by MFT record number.
pub struct Volume {
    /// Parent folder's record number (u32::MAX if unknown).
    pub parent: Vec<u32>,
    pub name: Vec<Option<Box<str>>>,
    /// Size on disk of the unnamed data stream.
    pub size: Vec<u64>,
    pub is_dir: Vec<bool>,
    pub in_use: Vec<bool>,
}

impl Volume {
    pub const ROOT: usize = ROOT_RECORD;
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).unwrap_or(0)
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}

/// Raw, read-only access to a volume's bytes: through the volume itself, or through the physical
/// disk at the partition's offset when something above the disk refuses volume reads.
struct Raw {
    f: File,
    base: u64,
}

impl Raw {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.f.seek(SeekFrom::Start(self.base + offset))?;
        self.f.read_exact(buf)
    }

    /// Reads `len` bytes at `offset`, rounding to whole sectors as raw reads require.
    fn read_at(&mut self, offset: u64, len: usize, sector: u64) -> std::io::Result<Vec<u8>> {
        let start = offset / sector * sector;
        let end = (offset + len as u64).div_ceil(sector) * sector;
        let mut buf = vec![0u8; (end - start) as usize];
        self.read_exact_at(start, &mut buf)?;
        let skip = (offset - start) as usize;
        Ok(buf[skip..skip + len].to_vec())
    }
}

/// Opens `\\.\D:` and checks it can be read; if not, finds the partition on its physical disk.
/// Returns the reader and the volume's boot sector.
fn open_raw(letter: &str) -> Result<(Raw, Vec<u8>), String> {
    let volume = File::open(format!(r"\\.\{letter}")).map_err(|e| format!("Can't open the volume for fast scanning ({e})."))?;
    let mut boot = vec![0u8; 4096];
    let mut raw = Raw { f: volume.try_clone().map_err(|e| e.to_string())?, base: 0 };
    let volume_error = match raw.read_exact_at(0, &mut boot) {
        Ok(()) => return Ok((raw, boot)),
        Err(e) => e,
    };
    let (disk, offset) = disk_extent(&volume).ok_or(format!("volume read refused ({volume_error}) and the partition's disk couldn't be found"))?;
    let physical = File::open(format!(r"\\.\PhysicalDrive{disk}")).map_err(|e| format!("volume read refused ({volume_error}); disk open: {e}"))?;
    let mut raw = Raw { f: physical, base: offset };
    raw.read_exact_at(0, &mut boot).map_err(|e| format!("volume read refused ({volume_error}); disk read: {e}"))?;
    Ok((raw, boot))
}

/// Disk number and byte offset of a simple (single-extent) volume.
fn disk_extent(volume: &File) -> Option<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
    // VOLUME_DISK_EXTENTS: count (u32) + padding, then extents of {disk u32, pad, offset i64, length i64}.
    let mut out = [0u8; 8 + 24 * 4];
    let mut returned = 0u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            volume.as_raw_handle() as _,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            out.as_mut_ptr() as _,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || u32_at(&out, 0) != 1 {
        return None; // failed, or a spanned volume over several disks
    }
    Some((u32_at(&out, 8), u64_at(&out, 16)))
}

/// Applies the NTFS "update sequence" fixup in place; false if the record is torn/invalid.
fn fixup(rec: &mut [u8], sector: usize) -> bool {
    let usa_off = u16_at(rec, 4) as usize;
    let usa_count = u16_at(rec, 6) as usize;
    if usa_count == 0 || usa_off + usa_count * 2 > rec.len() {
        return false;
    }
    let check = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_count {
        let end = i * sector;
        if end > rec.len() {
            break;
        }
        if rec[end - 2..end] != check {
            return false;
        }
        rec[end - 2] = rec[usa_off + i * 2];
        rec[end - 1] = rec[usa_off + i * 2 + 1];
    }
    true
}

/// Decodes a non-resident attribute's run list into (cluster, cluster count) extents.
fn data_runs(rec: &[u8], attr: usize) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut p = attr + u16_at(rec, attr + 0x20) as usize;
    let mut lcn: i64 = 0;
    while p < rec.len() && rec[p] != 0 {
        let header = rec[p];
        let len_size = (header & 0x0F) as usize;
        let off_size = (header >> 4) as usize;
        p += 1;
        if len_size == 0 || len_size > 8 || off_size > 8 || p + len_size + off_size > rec.len() {
            break;
        }
        let mut len: u64 = 0;
        for i in 0..len_size {
            len |= (rec[p + i] as u64) << (8 * i);
        }
        p += len_size;
        if off_size == 0 {
            continue; // sparse run: no clusters on disk
        }
        let mut delta: i64 = 0;
        for i in 0..off_size {
            delta |= (rec[p + i] as i64) << (8 * i);
        }
        // Sign-extend the relative offset.
        let shift = 64 - 8 * off_size as u32;
        delta = (delta << shift) >> shift;
        p += off_size;
        lcn += delta;
        out.push((lcn as u64, len));
    }
    out
}

/// Reads the whole MFT of `drive` (e.g. `D:\`). `progress` is called with the number of records
/// processed so far.
pub fn read_volume(drive: &str, mut progress: impl FnMut(usize, usize)) -> Result<Volume, String> {
    let letter = drive.trim_end_matches('\\');
    // Boot sector: geometry and where the MFT starts (4 KB read so 4K-sector disks work too).
    let (mut f, boot) = open_raw(letter)?;
    if &boot[3..11] != b"NTFS    " {
        return Err("Not an NTFS volume.".into());
    }
    let sector = u16_at(&boot, 0x0B) as u64;
    let cluster = sector * boot[0x0D] as u64;
    let mft_lcn = u64_at(&boot, 0x30);
    let per_record = boot[0x40] as i8;
    let record_size = if per_record < 0 { 1u64 << (-per_record) as u32 } else { per_record as u64 * cluster };
    if sector == 0 || cluster == 0 || record_size < 512 {
        return Err("Unexpected NTFS geometry.".into());
    }

    // Record 0 is the MFT itself; its $DATA run list says where the rest of the MFT lives.
    let mut rec0 = f
        .read_at(mft_lcn * cluster, record_size as usize, sector)
        .map_err(|e| format!("MFT record 0 at {} (sector {sector}, cluster {cluster}, record {record_size}): {e}", mft_lcn * cluster))?;
    if &rec0[0..4] != b"FILE" || !fixup(&mut rec0, sector as usize) {
        return Err("Couldn't read the MFT.".into());
    }
    let (mut runs, mut mft_bytes) = (Vec::new(), 0u64);
    let mut a = u16_at(&rec0, 0x14) as usize;
    while a + 8 < rec0.len() {
        let t = u32_at(&rec0, a);
        let len = u32_at(&rec0, a + 4) as usize;
        if t == ATTR_END || len == 0 {
            break;
        }
        if t == ATTR_DATA && rec0[a + 8] == 1 && rec0[a + 9] == 0 {
            runs = data_runs(&rec0, a);
            mft_bytes = u64_at(&rec0, a + 0x30);
            break;
        }
        a += len;
    }
    if runs.is_empty() || mft_bytes == 0 {
        return Err("Couldn't locate the MFT's data.".into());
    }

    let total = (mft_bytes / record_size) as usize;
    let mut vol = Volume {
        parent: vec![u32::MAX; total],
        name: vec![None; total],
        size: vec![0; total],
        is_dir: vec![false; total],
        in_use: vec![false; total],
    };
    // Which name each record got so far: prefer Win32 names over 8.3 DOS names.
    let mut name_rank = vec![0u8; total];

    let rs = record_size as usize;
    let chunk_records = (4 * 1024 * 1024 / rs).max(1);
    let mut index = 0usize;
    'extents: for (lcn, clusters) in runs {
        let mut pos = lcn * cluster;
        let mut left = clusters * cluster;
        while left > 0 && index < total {
            let want = (chunk_records as u64 * record_size).min(left);
            let mut buf = vec![0u8; want as usize];
            f.read_exact_at(pos, &mut buf).map_err(|e| format!("MFT read of {want} bytes at {pos} (record {index}/{total}): {e}"))?;
            for rec in buf.chunks_exact_mut(rs) {
                if index >= total {
                    break 'extents;
                }
                parse_record(rec, index, sector as usize, &mut vol, &mut name_rank);
                index += 1;
            }
            pos += want;
            left -= want;
            progress(index, total);
        }
    }
    Ok(vol)
}

fn parse_record(rec: &mut [u8], index: usize, sector: usize, vol: &mut Volume, name_rank: &mut [u8]) {
    if &rec[0..4] != b"FILE" || !fixup(rec, sector) {
        return;
    }
    let flags = u16_at(rec, 0x16);
    if flags & 0x01 == 0 {
        return; // deleted / free record
    }
    let base = (u64_at(rec, 0x20) & REF_MASK) as usize;
    // Extension records carry attributes of their base record.
    let target = if base != 0 { base } else { index };
    if target >= vol.in_use.len() {
        return;
    }
    if base == 0 {
        vol.in_use[target] = true;
        vol.is_dir[target] = flags & 0x02 != 0;
    }
    let mut a = u16_at(rec, 0x14) as usize;
    while a + 16 <= rec.len() {
        let t = u32_at(rec, a);
        let len = u32_at(rec, a + 4) as usize;
        if t == ATTR_END || len == 0 || a + len > rec.len() {
            break;
        }
        let non_resident = rec[a + 8] == 1;
        let name_len = rec[a + 9];
        match t {
            ATTR_FILE_NAME if !non_resident => {
                let c = a + u16_at(rec, a + 0x14) as usize;
                let parent = (u64_at(rec, c) & REF_MASK) as u32;
                let n = rec.get(c + 0x40).copied().unwrap_or(0) as usize;
                let ns = rec.get(c + 0x41).copied().unwrap_or(2);
                // Namespace 2 is the 8.3 DOS alias; 1/3 are the real Win32 name, 0 is POSIX.
                let rank = match ns {
                    1 | 3 => 3,
                    0 => 2,
                    _ => 1,
                };
                if rank > name_rank[target] {
                    if let Some(raw) = rec.get(c + 0x42..c + 0x42 + n * 2) {
                        let units: Vec<u16> = raw.chunks_exact(2).map(|x| u16::from_le_bytes([x[0], x[1]])).collect();
                        vol.name[target] = Some(String::from_utf16_lossy(&units).into_boxed_str());
                        vol.parent[target] = parent;
                        name_rank[target] = rank;
                    }
                }
            }
            ATTR_DATA if name_len == 0 => {
                if !non_resident {
                    vol.size[target] = u32_at(rec, a + 0x10) as u64;
                } else if u64_at(rec, a + 0x10) == 0 {
                    // First extent (starting VCN 0) holds the sizes. Compressed/sparse streams
                    // record what they really occupy separately.
                    let compression_unit = u16_at(rec, a + 0x22);
                    vol.size[target] = if compression_unit != 0 { u64_at(rec, a + 0x40) } else { u64_at(rec, a + 0x28) };
                }
            }
            _ => {}
        }
        a += len;
    }
}
