use std::io::{self, Read};

/// Strict inbound chunks. The upstream decoder buffers unbounded size lines and
/// treats EOF in chunk data as successful completion. Trailers remain unsupported,
/// as in upstream tiny_http 0.12.0; they are never parsed as another request.
pub struct ChunkedReader<R> {
    source: R,
    remaining: usize,
    finished: bool,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid chunk framing")
}

impl<R: Read> ChunkedReader<R> {
    pub fn new(source: R) -> Self {
        Self {
            source,
            remaining: 0,
            finished: false,
        }
    }

    fn crlf(&mut self) -> io::Result<()> {
        let mut ending = [0; 2];
        self.source.read_exact(&mut ending)?;
        if ending != *b"\r\n" {
            return Err(invalid());
        }
        Ok(())
    }

    fn size(&mut self) -> io::Result<usize> {
        let mut size = 0usize;
        let mut digits = 0usize;
        let mut extension = false;
        // Count extensions too, without allocating any metadata buffer.
        for _ in 0..8192 {
            let mut byte = [0];
            self.source.read_exact(&mut byte)?;
            let byte = byte[0];
            if byte == b'\r' {
                let mut lf = [0];
                self.source.read_exact(&mut lf)?;
                if lf != [b'\n'] || digits == 0 {
                    return Err(invalid());
                }
                return Ok(size);
            }
            if byte == b'\n' || byte == 127 || (byte < 32 && byte != b'\t') {
                return Err(invalid());
            }
            if extension {
                continue;
            }
            if byte == b';' && digits > 0 {
                extension = true;
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(invalid()),
            };
            size = size
                .checked_mul(16)
                .and_then(|n| n.checked_add(digit as usize))
                .ok_or_else(invalid)?;
            digits += 1;
        }
        Err(invalid())
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.finished {
            return Ok(0);
        }
        if self.remaining == 0 {
            self.remaining = self.size()?;
            if self.remaining == 0 {
                self.crlf()?;
                self.finished = true;
                return Ok(0);
            }
        }
        let limit = buf.len().min(self.remaining);
        let count = self.source.read(&mut buf[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete chunk",
            ));
        }
        self.remaining -= count;
        if self.remaining == 0 {
            self.crlf()?;
        }
        Ok(count)
    }
}
