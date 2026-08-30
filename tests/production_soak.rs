use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLIENT_THREADS: usize = 16;
const REQUESTS_PER_THREAD: usize = 125;
const TOTAL_REQUESTS: usize = CLIENT_THREADS * REQUESTS_PER_THREAD;

struct ProxyProcess {
    child: Child,
    directory: PathBuf,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_proxy(proxy: SocketAddr, management: SocketAddr, upstream: SocketAddr) -> ProxyProcess {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "polyguard-production-soak-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("polyguard.toml");
    fs::write(
        &config,
        format!(
            r#"
[listener]
address = "{proxy}"
management_address = "{management}"
security_mode = "agreement"
agreement_implementations = 2
max_connections = 128
request_header_timeout_ms = 5000
request_body_timeout_ms = 5000
upstream_connect_timeout_ms = 2000
upstream_response_timeout_ms = 5000
graceful_shutdown_timeout_ms = 5000

[limits]
max_request_body_bytes = 1048576
max_response_header_bytes = 8192
max_response_body_bytes = 1048576
max_inflight_body_bytes = 16777216

[[upstreams]]
name = "app"
address = "{upstream}"

[[routes]]
host = "example.test"
path_prefix = "/"
upstream = "app"
"#
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .args(["--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(management).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "proxy did not start");
        thread::sleep(Duration::from_millis(10));
    }
    ProxyProcess { child, directory }
}

fn read_request(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut wire = Vec::new();
    let mut scratch = [0_u8; 1_024];
    loop {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature request EOF");
        wire.extend_from_slice(&scratch[..count]);
        if wire.windows(4).any(|window| window == b"\r\n\r\n") {
            return;
        }
    }
}

fn request(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(2)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
        || stream
            .write_all(b"GET /soak HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .is_err()
        || stream.shutdown(Shutdown::Write).is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).is_ok()
        && response.starts_with(b"HTTP/1.1 200 OK")
        && response.ends_with(b"\r\n\r\nok")
}

#[test]
#[ignore = "explicit production soak gate"]
fn sustained_concurrent_proxying_remains_healthy() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let management_address = free_address();
    let _proxy = start_proxy(proxy_address, management_address, upstream_address);
    let upstream_thread = thread::spawn(move || {
        for _ in 0..TOTAL_REQUESTS {
            let (mut stream, _) = upstream.accept().unwrap();
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        }
    });

    let failures = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let clients: Vec<_> = (0..CLIENT_THREADS)
        .map(|_| {
            let failures = Arc::clone(&failures);
            thread::spawn(move || {
                for _ in 0..REQUESTS_PER_THREAD {
                    if !request(proxy_address) {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    upstream_thread.join().unwrap();
    let elapsed = started.elapsed();
    eprintln!("completed {TOTAL_REQUESTS} requests in {elapsed:?}");
    assert_eq!(failures.load(Ordering::Relaxed), 0);
    assert!(
        elapsed < Duration::from_secs(60),
        "{TOTAL_REQUESTS} requests took {elapsed:?}"
    );

    let mut readiness = TcpStream::connect(management_address).unwrap();
    readiness
        .write_all(b"GET /_polyguard/ready HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    readiness.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    readiness.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
}
