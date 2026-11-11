//! Apassy (connect keep-alive): sequential requests on the connections that the server
//! allows them on, and one request on every other connection. Loopback, free ports.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{KeepAlive, Response, Server};

/// A deadline server that answers each request with its path, after reading the body
/// unless the path is `/unread`. `allow` decides keep-alive; `None`: no keep-alive.
struct Served {
    addr: SocketAddr,
    paths: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(header: Duration, keep: Option<KeepAlive>) -> Served {
    let server = Server::http_with_deadlines_and_keep_alive(
        "127.0.0.1:0",
        header,
        Duration::from_secs(5),
        Duration::from_secs(30),
        keep,
    )
    .unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (log, done) = (paths.clone(), stop.clone());
    let thread = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            let mut request = match server.recv_timeout(Duration::from_millis(20)) {
                Ok(Some(request)) => request,
                _ => continue,
            };
            let path = request.url().to_owned();
            if path != "/unread" {
                let mut body = Vec::new();
                let _ = request.as_reader().read_to_end(&mut body);
            }
            log.lock().unwrap().push(path.clone());
            let _ = request.respond(Response::from_string(path));
        }
    });
    Served {
        addr,
        paths,
        stop,
        thread: Some(thread),
    }
}

fn keep_all(idle: Duration) -> Option<KeepAlive> {
    Some(KeepAlive {
        idle,
        allow: Arc::new(|_, _| true),
    })
}

/// One answer: its head and its body (by `Content-Length`). `None` at the end of the
/// stream before any byte.
fn answer(stream: &mut TcpStream) -> Option<(String, String)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => bytes.push(byte[0]),
            Ok(_) if bytes.is_empty() => return None,
            other => panic!("the answer head ended: {:?} after {:?}", other, bytes),
        }
    }
    let head = String::from_utf8(bytes).unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    Some((head, String::from_utf8(body).unwrap()))
}

fn closes(head: &str) -> bool {
    head.lines()
        .any(|line| line.eq_ignore_ascii_case("connection: close"))
}

/// The stream ends with no more byte from the server.
fn ends(stream: &mut TcpStream) -> bool {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut rest = Vec::new();
    matches!(stream.read_to_end(&mut rest), Ok(0))
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: node\r\n\r\n")
}

#[test]
fn an_allowed_connection_serves_sequential_requests_without_close() {
    let served = serve(Duration::from_secs(5), keep_all(Duration::from_secs(5)));
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream.write_all(get("/one").as_bytes()).unwrap();
    let (head, body) = answer(&mut stream).unwrap();
    assert_eq!(body, "/one");
    assert!(!closes(&head), "{}", head);
    // A body on the kept connection, then a read.
    stream
        .write_all(b"POST /two HTTP/1.1\r\nHost: node\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    let (head, body) = answer(&mut stream).unwrap();
    assert_eq!(body, "/two");
    assert!(!closes(&head), "{}", head);
    stream.write_all(get("/three").as_bytes()).unwrap();
    assert_eq!(answer(&mut stream).unwrap().1, "/three");
    // The client asks to close: the last answer says so, and the connection ends.
    stream
        .write_all(b"GET /four HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n")
        .unwrap();
    let (head, body) = answer(&mut stream).unwrap();
    assert_eq!(body, "/four");
    assert!(closes(&head), "{}", head);
    assert!(ends(&mut stream));
    assert_eq!(
        *served.paths.lock().unwrap(),
        ["/one", "/two", "/three", "/four"]
    );
}

#[test]
fn a_pipelined_request_closes_the_connection_and_is_never_served() {
    let served = serve(Duration::from_secs(5), keep_all(Duration::from_secs(5)));
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream
        .write_all(format!("{}{}", get("/first"), get("/second")).as_bytes())
        .unwrap();
    assert_eq!(answer(&mut stream).unwrap().1, "/first");
    assert!(ends(&mut stream), "nothing more after the first answer");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(*served.paths.lock().unwrap(), ["/first"]);

    // The next request's bytes while the first one's body is read: also pipelined.
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream
        .write_all(
            format!(
                "POST /third HTTP/1.1\r\nHost: node\r\nContent-Length: 2\r\n\r\nhi{}",
                get("/fourth")
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(answer(&mut stream).unwrap().1, "/third");
    assert!(ends(&mut stream));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(*served.paths.lock().unwrap(), ["/first", "/third"]);
}

#[test]
fn a_connection_that_is_not_allowed_serves_one_request_and_says_close() {
    let allowed = Arc::new(Mutex::new(None::<SocketAddr>));
    let only = allowed.clone();
    let served = serve(
        Duration::from_secs(5),
        Some(KeepAlive {
            idle: Duration::from_secs(5),
            allow: Arc::new(move |remote, _| *only.lock().unwrap() == Some(remote)),
        }),
    );
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream.write_all(get("/one").as_bytes()).unwrap();
    let (head, _) = answer(&mut stream).unwrap();
    assert!(closes(&head), "{}", head);
    assert!(ends(&mut stream));
    // The allowed connection beside it stays open.
    let mut kept = TcpStream::connect(served.addr).unwrap();
    *allowed.lock().unwrap() = Some(kept.local_addr().unwrap());
    kept.write_all(get("/two").as_bytes()).unwrap();
    assert!(!closes(&answer(&mut kept).unwrap().0));
    kept.write_all(get("/three").as_bytes()).unwrap();
    assert_eq!(answer(&mut kept).unwrap().1, "/three");
    // A server without keep-alive: one request, `Connection: close`, the end.
    let plain = serve(Duration::from_secs(5), None);
    let mut stream = TcpStream::connect(plain.addr).unwrap();
    stream.write_all(get("/one").as_bytes()).unwrap();
    let (head, _) = answer(&mut stream).unwrap();
    assert!(closes(&head), "{}", head);
    stream.write_all(get("/two").as_bytes()).unwrap_or(());
    assert!(ends(&mut stream));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(*plain.paths.lock().unwrap(), ["/one"]);
}

#[test]
fn an_unread_body_or_http_1_0_closes_after_its_answer() {
    let served = serve(Duration::from_secs(5), keep_all(Duration::from_secs(5)));
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream
        .write_all(b"POST /unread HTTP/1.1\r\nHost: node\r\nContent-Length: 3\r\n\r\nabc")
        .unwrap();
    let (head, _) = answer(&mut stream).unwrap();
    assert!(closes(&head), "{}", head);
    assert!(ends(&mut stream));
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream
        .write_all(b"GET /old HTTP/1.0\r\nHost: node\r\n\r\n")
        .unwrap();
    let (head, _) = answer(&mut stream).unwrap();
    assert!(closes(&head), "{}", head);
    assert!(ends(&mut stream));
}

#[test]
fn an_idle_kept_connection_closes_without_a_byte_and_each_request_has_fresh_deadlines() {
    // A header deadline of 400 ms and an idle wait of 1.5 s.
    let served = serve(
        Duration::from_millis(400),
        keep_all(Duration::from_millis(1500)),
    );
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream.write_all(get("/one").as_bytes()).unwrap();
    assert!(!closes(&answer(&mut stream).unwrap().0));
    // Longer than the header deadline of the first request, within the idle wait: the
    // next request is served, with its own header deadline from its first byte.
    thread::sleep(Duration::from_millis(900));
    stream.write_all(get("/two").as_bytes()).unwrap();
    assert_eq!(answer(&mut stream).unwrap().1, "/two");
    // Past the idle wait the connection ends, and the server wrote nothing (no 408).
    let started = Instant::now();
    assert!(
        ends(&mut stream),
        "the idle connection closed without a byte"
    );
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(1200) && took < Duration::from_secs(4),
        "{:?}",
        took
    );
    // A next head that starts and stalls ends at its own header deadline, long before
    // the idle wait would.
    let mut stream = TcpStream::connect(served.addr).unwrap();
    stream.write_all(get("/three").as_bytes()).unwrap();
    answer(&mut stream).unwrap();
    stream.write_all(b"GET /four HTTP/1.1\r\n").unwrap();
    let started = Instant::now();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(*served.paths.lock().unwrap(), ["/one", "/two", "/three"]);
}
