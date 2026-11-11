use ascii::AsciiString;

use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Read};

use std::net::SocketAddr;
use std::str::FromStr;

use crate::common::{HTTPVersion, Method};
use crate::util::RefinedTcpStream;
use crate::util::{SequentialReader, SequentialReaderBuilder, SequentialWriterBuilder};
use crate::Request;

/// A ClientConnection is an object that will store a socket to a client
/// and return Request objects.
pub struct ClientConnection {
    // address of the client
    remote_addr: IoResult<Option<SocketAddr>>,

    // sequence of Readers to the stream, so that the data is not read in
    //  the wrong order
    source: SequentialReaderBuilder<BufReader<RefinedTcpStream>>,

    // sequence of Writers to the stream, to avoid writing response #2 before
    //  response #1
    sink: SequentialWriterBuilder<BufWriter<RefinedTcpStream>>,

    // Reader to read the next header from
    next_header_source: SequentialReader<BufReader<RefinedTcpStream>>,

    // set to true if we know that the previous request is the last one
    no_more_requests: bool,

    // Apassy (connect keep-alive): a request came on this connection already
    served: bool,

    // true if the connection goes through SSL
    secure: bool,
    deadline: Option<std::sync::Arc<crate::deadline::Deadline>>,
}

/// Error that can happen when reading a request.
#[derive(Debug)]
enum ReadError {
    WrongRequestLine,
    WrongHeader(HTTPVersion),
    /// the client sent an unrecognized `Expect` header
    ExpectationFailed(HTTPVersion),
    ReadIoError(IoError),
}

impl ClientConnection {
    /// Creates a new `ClientConnection` that takes ownership of the `TcpStream`.
    pub fn new(
        write_socket: RefinedTcpStream,
        mut read_socket: RefinedTcpStream,
    ) -> ClientConnection {
        let deadline = read_socket.deadline.clone();
        let remote_addr = read_socket.peer_addr();
        let secure = read_socket.secure();

        let mut source = SequentialReaderBuilder::new(BufReader::with_capacity(1024, read_socket));
        let first_header = source.next().unwrap();

        ClientConnection {
            source,
            sink: SequentialWriterBuilder::new(BufWriter::with_capacity(1024, write_socket)),
            remote_addr,
            next_header_source: first_header,
            no_more_requests: false,
            served: false,
            secure,
            deadline,
        }
    }

    /// true if the connection is HTTPS
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Apassy (connect keep-alive): the connection may carry sequential requests, so the
    /// server hands it the next request only after the answer of the last one.
    pub(crate) fn waits_for_answers(&self) -> bool {
        self.deadline
            .as_ref()
            .map_or(false, |deadline| deadline.keeps())
    }

    /// Reads the next line from self.next_header_source.
    ///
    /// Reads until `CRLF` is reached. The next read will start
    ///  at the first byte of the new line.
    fn read_next_line(&mut self) -> IoResult<AsciiString> {
        let mut buf = Vec::new();
        let mut prev_byte_was_cr = false;

        loop {
            let byte = self.next_header_source.by_ref().bytes().next();

            let byte = match byte {
                Some(b) => b?,
                None => return Err(IoError::new(ErrorKind::ConnectionAborted, "Unexpected EOF")),
            };

            if byte == b'\n' {
                if !prev_byte_was_cr {
                    return Err(IoError::new(
                        ErrorKind::InvalidInput,
                        "bare LF in HTTP line",
                    ));
                }
                buf.pop(); // removing the '\r'
                return AsciiString::from_ascii(buf)
                    .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Header is not in ASCII"));
            }
            if prev_byte_was_cr {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "bare CR in HTTP line",
                ));
            }

            prev_byte_was_cr = byte == b'\r';

            if buf.len() >= 8192 {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "header line too large",
                ));
            }
            buf.push(byte);
        }
    }

    /// Reads a request from the stream.
    /// Blocks until the header has been read.
    fn read(&mut self) -> Result<Request, ReadError> {
        let (method, path, version, headers) = {
            // reading the request line
            let (method, path, version) = {
                let line = self.read_next_line().map_err(ReadError::ReadIoError)?;

                parse_request_line(
                    line.as_str().trim(), // TODO: remove this conversion
                )?
            };

            // getting all headers
            let headers = {
                let mut headers = Vec::new();
                let mut header_bytes = 0usize;
                loop {
                    let line = self.read_next_line().map_err(ReadError::ReadIoError)?;

                    if line.is_empty() {
                        break;
                    };
                    header_bytes += line.len() + 2;
                    if headers.len() >= 100 || header_bytes > 64 * 1024 {
                        return Err(ReadError::WrongHeader(version));
                    }
                    // Never reinterpret obs-fold as an independent header. A proxy
                    // may unfold it into the preceding field instead.
                    if line
                        .as_bytes()
                        .first()
                        .map_or(false, |b| *b == b' ' || *b == b'\t')
                    {
                        return Err(ReadError::WrongHeader(version));
                    }
                    headers.push(match FromStr::from_str(line.as_str()) {
                        // TODO: remove this conversion
                        Ok(h) => h,
                        _ => return Err(ReadError::WrongHeader(version)),
                    });
                }

                headers
            };

            (method, path, version, headers)
        };

        // Apassy (connect-tunnel-v1): a GET upgrade without body framing headers is
        // allowed; its reader is the raw stream and nothing in it is a body. The handler
        // either answers it (one request per connection) or calls `upgrade_split`.
        let bodyless_get = method == Method::Get
            && !headers.iter().any(|h: &crate::Header| {
                h.field.equiv("Content-Length") || h.field.equiv("Transfer-Encoding")
            });
        if self.deadline.is_some() && !bodyless_get && crate::common::asks_upgrade(&headers) {
            // Relay endpoints upgrade only a body-less GET. Upstream's upgrade reader
            // ignores Content-Length and Transfer-Encoding, so never select it otherwise.
            return Err(ReadError::WrongHeader(version));
        }
        if let Some(deadline) = &self.deadline {
            deadline.body();
        }
        // building the writer for the request
        let writer = self.sink.next().unwrap();

        // follow-up for next potential request
        let mut data_source = self.source.next().unwrap();
        std::mem::swap(&mut self.next_header_source, &mut data_source);

        // building the next reader
        let mut request = crate::request::new_request(
            self.secure,
            method,
            path,
            version.clone(),
            headers,
            *self.remote_addr.as_ref().unwrap(),
            data_source,
            writer,
            self.deadline.is_none(),
        )
        .map_err(|e| {
            use crate::request;
            match e {
                request::RequestCreationError::CreationIoError(e) => ReadError::ReadIoError(e),
                request::RequestCreationError::InvalidFraming => ReadError::WrongHeader(version),
                request::RequestCreationError::ExpectationFailed => {
                    ReadError::ExpectationFailed(version)
                }
            }
        })?;

        if let Some(deadline) = &self.deadline {
            request.deadline = Some(deadline.clone());
            // One request per connection avoids a deadline/rejection of an earlier
            // request affecting a pipelined successor. Apassy (connect keep-alive): a
            // listener that allows sequential requests reads a next head only after the
            // answer of this one kept the connection open (`await_next`).
            if !deadline.keeps() {
                self.no_more_requests = true;
            }
        }
        // return the request
        Ok(request)
    }

    /// Apassy (connect keep-alive): whether a kept connection carries a next request.
    /// It waits until the request before it is dropped (its answer is then written), and
    /// goes on only when that answer kept the connection open and no byte came before it
    /// was written (a pipelined request closes the connection). Then the first byte of
    /// the next head must come within the idle wait; from that byte on the request has
    /// fresh header, body, and handle deadlines. Nothing is ever written in between: an
    /// idle or pipelined connection just closes.
    fn await_next(&mut self, deadline: &crate::deadline::Deadline) -> bool {
        let reader = self.next_header_source.inner();
        if !deadline.take_again() {
            return false;
        }
        if !reader.buffer().is_empty() {
            deadline.close(std::net::Shutdown::Both);
            return false;
        }
        deadline.idle_wait();
        loop {
            match reader.fill_buf() {
                Ok(bytes) if !bytes.is_empty() => break,
                Ok(_) => return false,
                Err(ref err)
                    if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                        && !deadline.expired() =>
                {
                    continue
                }
                Err(_) => {
                    deadline.close(std::net::Shutdown::Both);
                    return false;
                }
            }
        }
        deadline.next_request();
        true
    }
}

impl Iterator for ClientConnection {
    type Item = Request;

    /// Blocks until the next Request is available.
    /// Returns None when no new Requests will come from the client.
    fn next(&mut self) -> Option<Request> {
        use crate::{Response, StatusCode};

        // the client sent a "connection: close" header in this previous request
        //  or is using HTTP 1.0, meaning that no new request will come
        if self.no_more_requests {
            return None;
        }
        if self.served {
            if let Some(deadline) = self.deadline.clone() {
                if !self.await_next(&deadline) {
                    return None;
                }
            }
        }

        loop {
            let rq = match self.read() {
                Err(ReadError::WrongRequestLine) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::WrongHeader(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::from_string(r#"{"ok":false,"error":{"code":"invalid_request","message":"The HTTP headers or framing are not valid."}}"#)
                        .with_status_code(StatusCode(400))
                        .with_header(crate::Header::from_bytes("Content-Type", "application/json").unwrap())
                        .with_header(crate::Header::from_bytes("Cache-Control", "no-store").unwrap())
                        .with_header(crate::Header::from_bytes("Connection", "close").unwrap());
                    response.raw_print(writer, ver, &[], false, None).ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::ReadIoError(ref err)) if err.kind() == ErrorKind::TimedOut => {
                    // request timeout
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(408));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // closing the connection
                }

                Err(ReadError::ExpectationFailed(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(417));
                    response.raw_print(writer, ver, &[], true, None).ok();
                    return None; // TODO: should be recoverable, but needs handling in case of body
                }

                Err(ReadError::ReadIoError(_)) => return None,

                Ok(rq) => rq,
            };

            // checking HTTP version
            if *rq.http_version() > (1, 1) {
                let writer = self.sink.next().unwrap();
                let response = Response::from_string(
                    "This server only supports HTTP versions 1.0 and 1.1".to_owned(),
                )
                .with_status_code(StatusCode(505));
                response
                    .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                    .ok();
                continue;
            }

            // updating the status of the connection
            let connection_header = rq
                .headers()
                .iter()
                .find(|h| h.field.equiv("Connection"))
                .map(|h| h.value.as_str());

            let lowercase = connection_header.map(|h| h.to_ascii_lowercase());
            // Apassy: an upgrade is the one rule of the crate (`asks_upgrade`).
            if crate::common::asks_upgrade(rq.headers()) {
                self.no_more_requests = true;
            }

            match lowercase {
                Some(ref val) if val.contains("close") => self.no_more_requests = true,
                Some(ref val)
                    if !val.contains("keep-alive") && *rq.http_version() == HTTPVersion(1, 0) =>
                {
                    self.no_more_requests = true
                }
                None if *rq.http_version() == HTTPVersion(1, 0) => self.no_more_requests = true,
                _ => (),
            };

            // returning the request
            self.served = true;
            return Some(rq);
        }
    }
}

/// Parses a "HTTP/1.1" string.
fn parse_http_version(version: &str) -> Result<HTTPVersion, ReadError> {
    let (major, minor) = match version {
        "HTTP/0.9" => (0, 9),
        "HTTP/1.0" => (1, 0),
        "HTTP/1.1" => (1, 1),
        "HTTP/2.0" => (2, 0),
        "HTTP/3.0" => (3, 0),
        _ => return Err(ReadError::WrongRequestLine),
    };

    Ok(HTTPVersion(major, minor))
}

/// Parses the request line of the request.
/// eg. GET / HTTP/1.1
fn parse_request_line(line: &str) -> Result<(Method, String, HTTPVersion), ReadError> {
    let mut parts = line.split(' ');

    let method = parts.next().and_then(|w| w.parse().ok());
    let path = parts.next().map(ToOwned::to_owned);
    let version = parts.next().and_then(|w| parse_http_version(w).ok());

    method
        .and_then(|method| Some((method, path?, version?)))
        .ok_or(ReadError::WrongRequestLine)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_parse_request_line() {
        let (method, path, ver) = super::parse_request_line("GET /hello HTTP/1.1").unwrap();

        assert!(method == crate::Method::Get);
        assert!(path == "/hello");
        assert!(ver == crate::common::HTTPVersion(1, 1));

        assert!(super::parse_request_line("GET /hello").is_err());
        assert!(super::parse_request_line("qsd qsd qsd").is_err());
    }
}
