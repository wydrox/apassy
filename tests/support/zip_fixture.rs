// Zip archives for the 1Password import tests, built in memory. Synthetic data only.
// `tests/onepassword_import.rs` uses this file as a module, and the desktop import tests
// (`src/desktop/ui/import.rs`) include it.

use std::io::Write as _;

use flate2::Crc;
use flate2::write::DeflateEncoder;

/// How an entry is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflated,
}

/// One entry of a test archive.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub method: Method,
    /// Extra general-purpose flags, for example 0x0001 (encrypted).
    pub flags: u16,
    /// Write the sizes and the checksum in a data descriptor after the data (flag 0x0008).
    pub descriptor: bool,
    /// Replace the method number in both headers, for example 12 (bzip2).
    pub method_number: Option<u16>,
    /// Replace the uncompressed size in the central directory.
    pub declared_size: Option<u32>,
}

impl ZipEntry {
    pub fn new(name: &str, data: &[u8], method: Method) -> Self {
        Self {
            name: name.to_owned(),
            data: data.to_vec(),
            method,
            flags: 0,
            descriptor: false,
            method_number: None,
            declared_size: None,
        }
    }
}

fn push16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A zip archive with `entries`, in order.
pub fn build_zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let mut crc = Crc::new();
        crc.update(&entry.data);
        let crc = crc.sum();
        let (method, body) = match entry.method {
            Method::Stored => (0u16, entry.data.clone()),
            Method::Deflated => {
                let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::best());
                encoder.write_all(&entry.data).expect("deflate");
                (8u16, encoder.finish().expect("deflate"))
            }
        };
        let method = entry.method_number.unwrap_or(method);
        let flags = entry.flags | if entry.descriptor { 0x0008 } else { 0 };
        let offset = out.len() as u32;
        let size = entry.data.len() as u32;
        // Local header.
        push32(&mut out, 0x0403_4b50);
        push16(&mut out, 20);
        push16(&mut out, flags);
        push16(&mut out, method);
        push16(&mut out, 0);
        push16(&mut out, 0);
        if entry.descriptor {
            push32(&mut out, 0);
            push32(&mut out, 0);
            push32(&mut out, 0);
        } else {
            push32(&mut out, crc);
            push32(&mut out, body.len() as u32);
            push32(&mut out, size);
        }
        push16(&mut out, entry.name.len() as u16);
        push16(&mut out, 0);
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&body);
        if entry.descriptor {
            push32(&mut out, 0x0807_4b50);
            push32(&mut out, crc);
            push32(&mut out, body.len() as u32);
            push32(&mut out, size);
        }
        // Central directory entry.
        push32(&mut central, 0x0201_4b50);
        push16(&mut central, 20);
        push16(&mut central, 20);
        push16(&mut central, flags);
        push16(&mut central, method);
        push16(&mut central, 0);
        push16(&mut central, 0);
        push32(&mut central, crc);
        push32(&mut central, body.len() as u32);
        push32(&mut central, entry.declared_size.unwrap_or(size));
        push16(&mut central, entry.name.len() as u16);
        push16(&mut central, 0);
        push16(&mut central, 0);
        push16(&mut central, 0);
        push16(&mut central, 0);
        push32(&mut central, 0);
        push32(&mut central, offset);
        central.extend_from_slice(entry.name.as_bytes());
    }
    let directory = out.len() as u32;
    out.extend_from_slice(&central);
    push32(&mut out, 0x0605_4b50);
    push16(&mut out, 0);
    push16(&mut out, 0);
    push16(&mut out, entries.len() as u16);
    push16(&mut out, entries.len() as u16);
    push32(&mut out, central.len() as u32);
    push32(&mut out, directory);
    push16(&mut out, 0);
    out
}

/// A 1PUX archive: `export.attributes`, `export.data` (deflated), and one attachment.
pub fn onepux(export_data: &str) -> Vec<u8> {
    build_zip(&[
        ZipEntry::new(
            "export.attributes",
            br#"{"version":3,"description":"1Password Unencrypted Export"}"#,
            Method::Stored,
        ),
        ZipEntry::new("export.data", export_data.as_bytes(), Method::Deflated),
        ZipEntry::new(
            "files/synthetic-attachment.txt",
            b"attachment",
            Method::Stored,
        ),
    ])
}
