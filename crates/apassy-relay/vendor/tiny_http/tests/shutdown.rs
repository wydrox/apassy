use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tiny_http::{Response, Server};

// A broken shutdown must fail the test rather than hang the test process.
fn drop_server(server: Server) {
    let (done, stopped) = mpsc::channel();
    let closing = thread::spawn(move || {
        drop(server);
        let _ = done.send(());
    });
    stopped
        .recv_timeout(Duration::from_secs(3))
        .expect("server drop must finish without a client wakeup");
    closing.join().expect("server drop must not panic");
}

#[test]
fn drop_closes_loopback_and_wildcard_listeners_before_returning() {
    for binding in ["127.0.0.1:0", "0.0.0.0:0"] {
        let server = Server::http(binding).expect("bind a free TCP port");
        let mut address = server.server_addr().to_ip().expect("TCP address");
        if address.ip().is_unspecified() {
            address.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        drop(TcpStream::connect_timeout(&address, Duration::from_secs(1)).expect("live listener"));
        drop_server(server);
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
            "the listener must already be closed when drop returns: {}",
            binding
        );
    }
}

#[test]
fn a_request_already_received_can_be_answered_after_server_drop() {
    let server = Server::http("127.0.0.1:0").expect("bind a free TCP port");
    let address = server.server_addr().to_ip().expect("TCP address");
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(1)).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("bounded response read");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send synthetic request");
    let request = server
        .recv_timeout(Duration::from_secs(3))
        .expect("receive request")
        .expect("the request must reach the handler");
    drop_server(server);
    request
        .respond(Response::from_string("synthetic response"))
        .expect("answer an already received request");
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 200 "), "{}", response);
    assert!(response.ends_with("synthetic response"), "{}", response);
}

#[cfg(unix)]
#[test]
fn drop_finishes_after_the_unix_socket_path_is_removed() {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ath-{}-{:x}", std::process::id(), unique));
    fs::create_dir(&path).expect("create a private synthetic fixture directory");
    let directory = Directory(path);
    let socket = directory.0.join("s");
    let server = Server::http_unix(&socket).expect("bind a temporary Unix socket");
    fs::remove_file(&socket).expect("remove the wake-connect destination");
    drop_server(server);
}
