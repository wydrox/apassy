//! A small zip reader for the 1Password export (`.1pux`).
//!
//! It reads one entry into memory and nothing else. It never writes an entry to disk.
//! It reads the end of the archive, walks the central directory, and then reads the
//! local header and the data of the one entry. It supports the methods "stored" and
//! "deflate", and the data-descriptor flag (the central directory has the sizes). It
//! refuses encryption, zip64, archives on more than one disk, and an entry with the same
//! name two times.
//!
//! Limits: the size of the archive, the number of entries, the uncompressed size of the
//! entry, and the ratio between the uncompressed and the compressed size. The reader
//! checks the declared sizes before it decompresses, and it never reads more than the
//! declared size, so a false size cannot make it use more memory.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use flate2::Crc;
use flate2::bufread::DeflateDecoder;
use zeroize::Zeroizing;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD_LEN: usize = 22;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_LOCATOR_LEN: u64 = 20;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_LEN: usize = 46;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const LOCAL_LEN: usize = 30;
const MAX_COMMENT: usize = 0xFFFF;

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_AES: u16 = 99;

/// The limits of one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipLimits {
    /// The largest archive, in bytes. A 1PUX file holds the attachments too.
    pub max_archive_bytes: u64,
    /// The most entries in the central directory.
    pub max_entries: usize,
    /// The largest uncompressed entry, in bytes.
    pub max_entry_bytes: u64,
    /// The highest ratio of the uncompressed size to the compressed size.
    pub max_ratio: u64,
}

impl ZipLimits {
    /// The limits for `export.data` of a 1PUX file.
    pub const EXPORT: Self = Self {
        max_archive_bytes: 2 * 1024 * 1024 * 1024,
        max_entries: 20_000,
        max_entry_bytes: 64 * 1024 * 1024,
        max_ratio: 250,
    };
}

/// Why an archive cannot be read. The text names no entry data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// The file is larger than the archive limit.
    ArchiveTooLarge,
    /// The file is not a zip archive, or its end is missing.
    NotZip,
    /// The archive is damaged: `what` says where.
    Corrupt(&'static str),
    /// A zip64 archive. A 1PUX export does not need it.
    Zip64,
    /// An archive on more than one disk.
    MultiDisk,
    /// The entry is encrypted.
    Encrypted,
    /// The entry uses a compression method other than stored or deflate.
    UnsupportedMethod(u16),
    /// The central directory lists more entries than the limit.
    TooManyEntries,
    /// The archive has no entry with the name.
    Missing,
    /// The archive has two entries with the name.
    Duplicate,
    /// The uncompressed entry is larger than the limit.
    EntryTooLarge,
    /// The entry expands more than the ratio limit allows.
    RatioTooHigh,
    /// The data does not match the declared size or checksum.
    Mismatch,
    /// The file could not be read.
    Io,
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveTooLarge => f.write_str("The file is larger than 2 GB."),
            Self::NotZip => f.write_str("The file is not a complete zip archive."),
            Self::Corrupt(what) => write!(f, "The zip archive is damaged ({what})."),
            Self::Zip64 => f.write_str("The archive is a zip64 archive. Apassy does not read it."),
            Self::MultiDisk => f.write_str("The archive is split into parts."),
            Self::Encrypted => f.write_str("The archive entry is encrypted."),
            Self::UnsupportedMethod(method) => {
                write!(f, "The archive uses compression method {method}.")
            }
            Self::TooManyEntries => f.write_str("The archive has too many files."),
            Self::Missing => f.write_str("The archive has no export.data file."),
            Self::Duplicate => f.write_str("The archive has two export.data files."),
            Self::EntryTooLarge => f.write_str("The export.data file is larger than 64 MB."),
            Self::RatioTooHigh => {
                f.write_str("The export.data file expands too much. It looks like a zip bomb.")
            }
            Self::Mismatch => {
                f.write_str("The export.data file does not match its size or checksum.")
            }
            Self::Io => f.write_str("The file could not be read."),
        }
    }
}

impl std::error::Error for ZipError {}

fn io_err(err: io::Error) -> ZipError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        ZipError::NotZip
    } else {
        ZipError::Io
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, buf: &mut [u8]) -> Result<(), ZipError> {
    reader.seek(SeekFrom::Start(offset)).map_err(io_err)?;
    reader.read_exact(buf).map_err(io_err)
}

/// The end of the central directory.
struct End {
    /// The offset of the end record in the file.
    at: u64,
    entries: usize,
    directory_offset: u64,
    directory_size: u64,
}

fn find_end<R: Read + Seek>(reader: &mut R, len: u64) -> Result<End, ZipError> {
    if len < EOCD_LEN as u64 {
        return Err(ZipError::NotZip);
    }
    let tail_len = len.min((EOCD_LEN + MAX_COMMENT) as u64);
    let tail_start = len - tail_len;
    let mut tail = vec![0u8; usize::try_from(tail_len).map_err(|_| ZipError::NotZip)?];
    read_at(reader, tail_start, &mut tail)?;
    // The end record is the last one whose comment reaches the end of the file.
    let mut found = None;
    for pos in (0..=tail.len() - EOCD_LEN).rev() {
        if u32_at(&tail, pos) != EOCD_SIGNATURE {
            continue;
        }
        let comment = usize::from(u16_at(&tail, pos + 20));
        if pos + EOCD_LEN + comment == tail.len() {
            found = Some(pos);
            break;
        }
    }
    let pos = found.ok_or(ZipError::NotZip)?;
    let at = tail_start + pos as u64;
    let disk = u16_at(&tail, pos + 4);
    let directory_disk = u16_at(&tail, pos + 6);
    let disk_entries = u16_at(&tail, pos + 8);
    let entries = u16_at(&tail, pos + 10);
    let directory_size = u32_at(&tail, pos + 12);
    let directory_offset = u32_at(&tail, pos + 16);
    if disk == 0xFFFF
        || directory_disk == 0xFFFF
        || disk_entries == 0xFFFF
        || entries == 0xFFFF
        || directory_size == 0xFFFF_FFFF
        || directory_offset == 0xFFFF_FFFF
    {
        return Err(ZipError::Zip64);
    }
    if at >= ZIP64_LOCATOR_LEN {
        let mut locator = [0u8; 4];
        read_at(reader, at - ZIP64_LOCATOR_LEN, &mut locator)?;
        if u32::from_le_bytes(locator) == ZIP64_LOCATOR_SIGNATURE {
            return Err(ZipError::Zip64);
        }
    }
    if disk != 0 || directory_disk != 0 || disk_entries != entries {
        return Err(ZipError::MultiDisk);
    }
    let directory_offset = u64::from(directory_offset);
    let directory_size = u64::from(directory_size);
    if directory_offset
        .checked_add(directory_size)
        .is_none_or(|end| end > at)
    {
        return Err(ZipError::Corrupt("the central directory is out of bounds"));
    }
    Ok(End {
        at,
        entries: usize::from(entries),
        directory_offset,
        directory_size,
    })
}

/// One entry of the central directory.
#[derive(Clone, Copy)]
struct Entry {
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    local_offset: u64,
}

fn find_entry(directory: &[u8], entries: usize, name: &[u8]) -> Result<Entry, ZipError> {
    let mut pos = 0usize;
    let mut found = None;
    for _ in 0..entries {
        let header = directory
            .get(pos..pos + CENTRAL_LEN)
            .ok_or(ZipError::Corrupt("the central directory is short"))?;
        if u32_at(header, 0) != CENTRAL_SIGNATURE {
            return Err(ZipError::Corrupt("a central directory entry is invalid"));
        }
        let name_len = usize::from(u16_at(header, 28));
        let extra_len = usize::from(u16_at(header, 30));
        let comment_len = usize::from(u16_at(header, 32));
        let start_disk = u16_at(header, 34);
        let entry_name = directory
            .get(pos + CENTRAL_LEN..pos + CENTRAL_LEN + name_len)
            .ok_or(ZipError::Corrupt("the central directory is short"))?;
        if entry_name == name {
            if found.is_some() {
                return Err(ZipError::Duplicate);
            }
            let compressed = u32_at(header, 20);
            let uncompressed = u32_at(header, 24);
            let local_offset = u32_at(header, 42);
            if compressed == 0xFFFF_FFFF
                || uncompressed == 0xFFFF_FFFF
                || local_offset == 0xFFFF_FFFF
                || start_disk == 0xFFFF
            {
                return Err(ZipError::Zip64);
            }
            if start_disk != 0 {
                return Err(ZipError::MultiDisk);
            }
            found = Some(Entry {
                flags: u16_at(header, 8),
                method: u16_at(header, 10),
                crc: u32_at(header, 16),
                compressed: u64::from(compressed),
                uncompressed: u64::from(uncompressed),
                local_offset: u64::from(local_offset),
            });
        }
        pos += CENTRAL_LEN + name_len + extra_len + comment_len;
        if pos > directory.len() {
            return Err(ZipError::Corrupt("the central directory is short"));
        }
    }
    found.ok_or(ZipError::Missing)
}

fn check_entry(entry: &Entry, limits: &ZipLimits) -> Result<(), ZipError> {
    if entry.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 || entry.method == METHOD_AES {
        return Err(ZipError::Encrypted);
    }
    if entry.method != METHOD_STORED && entry.method != METHOD_DEFLATE {
        return Err(ZipError::UnsupportedMethod(entry.method));
    }
    if entry.uncompressed > limits.max_entry_bytes {
        return Err(ZipError::EntryTooLarge);
    }
    if entry.method == METHOD_STORED && entry.compressed != entry.uncompressed {
        return Err(ZipError::Mismatch);
    }
    if entry.uncompressed > entry.compressed.max(1).saturating_mul(limits.max_ratio) {
        return Err(ZipError::RatioTooHigh);
    }
    Ok(())
}

/// Read the entry `name` of the archive into memory. The result erases itself on drop.
pub fn read_entry<R: Read + Seek>(
    reader: &mut R,
    name: &str,
    limits: &ZipLimits,
) -> Result<Zeroizing<Vec<u8>>, ZipError> {
    let len = reader.seek(SeekFrom::End(0)).map_err(io_err)?;
    if len > limits.max_archive_bytes {
        return Err(ZipError::ArchiveTooLarge);
    }
    let end = find_end(reader, len)?;
    if end.entries > limits.max_entries {
        return Err(ZipError::TooManyEntries);
    }
    let mut directory =
        vec![0u8; usize::try_from(end.directory_size).map_err(|_| ZipError::ArchiveTooLarge)?];
    read_at(reader, end.directory_offset, &mut directory)?;
    let entry = find_entry(&directory, end.entries, name.as_bytes())?;
    drop(directory);
    check_entry(&entry, limits)?;

    // The local header must match the central directory.
    let mut local = [0u8; LOCAL_LEN];
    if entry.local_offset + LOCAL_LEN as u64 > end.directory_offset {
        return Err(ZipError::Corrupt("a local header is out of bounds"));
    }
    read_at(reader, entry.local_offset, &mut local)?;
    if u32_at(&local, 0) != LOCAL_SIGNATURE {
        return Err(ZipError::Corrupt("a local header is invalid"));
    }
    let local_flags = u16_at(&local, 6);
    if local_flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
        return Err(ZipError::Encrypted);
    }
    if u16_at(&local, 8) != entry.method {
        return Err(ZipError::Corrupt("the local header does not match"));
    }
    let name_len = u64::from(u16_at(&local, 26));
    let extra_len = u64::from(u16_at(&local, 28));
    let mut local_name = vec![0u8; usize::from(u16_at(&local, 26))];
    read_at(
        reader,
        entry.local_offset + LOCAL_LEN as u64,
        &mut local_name,
    )?;
    if local_name != name.as_bytes() {
        return Err(ZipError::Corrupt("the local header does not match"));
    }
    let data_start = entry.local_offset + LOCAL_LEN as u64 + name_len + extra_len;
    if data_start
        .checked_add(entry.compressed)
        .is_none_or(|data_end| data_end > end.directory_offset || data_end > end.at)
    {
        return Err(ZipError::Corrupt("the entry data is out of bounds"));
    }

    let size = usize::try_from(entry.uncompressed).map_err(|_| ZipError::EntryTooLarge)?;
    let mut compressed = Zeroizing::new(vec![
        0u8;
        usize::try_from(entry.compressed)
            .map_err(|_| ZipError::EntryTooLarge)?
    ]);
    read_at(reader, data_start, &mut compressed)?;
    let data = if entry.method == METHOD_STORED {
        compressed
    } else {
        // `bufread` reads the slice in place, without a second buffer of the input.
        let mut decoder = DeflateDecoder::new(&compressed[..]);
        let mut out = Zeroizing::new(vec![0u8; size]);
        decoder
            .read_exact(&mut out[..])
            .map_err(|_| ZipError::Mismatch)?;
        let mut more = [0u8; 1];
        match decoder.read(&mut more) {
            Ok(0) => {}
            _ => return Err(ZipError::Mismatch),
        }
        out
    };
    let mut crc = Crc::new();
    crc.update(&data);
    if crc.sum() != entry.crc {
        return Err(ZipError::Mismatch);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let mut crc = Crc::new();
        crc.update(data);
        let mut out = Vec::new();
        out.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        let directory = out.len() as u32;
        out.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let size = out.len() as u32 - directory;
        out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&directory.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_a_stored_entry_and_checks_the_checksum() {
        let zip = stored_zip("export.data", b"{\"accounts\":[]}");
        let data = read_entry(&mut Cursor::new(&zip), "export.data", &ZipLimits::EXPORT).unwrap();
        assert_eq!(&data[..], b"{\"accounts\":[]}");
        let mut bad = zip.clone();
        bad[30 + "export.data".len()] ^= 0x20;
        assert_eq!(
            read_entry(&mut Cursor::new(&bad), "export.data", &ZipLimits::EXPORT).unwrap_err(),
            ZipError::Mismatch
        );
        assert_eq!(
            read_entry(&mut Cursor::new(&zip), "other", &ZipLimits::EXPORT).unwrap_err(),
            ZipError::Missing
        );
    }

    #[test]
    fn short_or_foreign_input_is_not_a_zip() {
        for input in [
            &b""[..],
            b"PK",
            b"just some text that is long enough to scan",
        ] {
            assert_eq!(
                read_entry(&mut Cursor::new(input), "export.data", &ZipLimits::EXPORT).unwrap_err(),
                ZipError::NotZip
            );
        }
    }
}
