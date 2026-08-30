use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

struct ProxyProcess {
    child: Child,
    directory: PathBuf,
    config: PathBuf,
    management: SocketAddr,
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

fn start_proxy(proxy: SocketAddr, upstream: SocketAddr, max_body: usize) -> ProxyProcess {
    start_proxy_with_budget(
        proxy,
        upstream,
        max_body,
        max_body.saturating_add(1_048_576),
    )
}

fn start_proxy_with_budget(
    proxy: SocketAddr,
    upstream: SocketAddr,
    max_body: usize,
    max_inflight_body: usize,
) -> ProxyProcess {
    start_proxy_with_budget_and_timeout(proxy, upstream, max_body, max_inflight_body, 1_000)
}

fn start_proxy_with_budget_and_timeout(
    proxy: SocketAddr,
    upstream: SocketAddr,
    max_body: usize,
    max_inflight_body: usize,
    body_timeout_ms: u64,
) -> ProxyProcess {
    start_proxy_with_options(
        proxy,
        upstream,
        max_body,
        max_inflight_body,
        body_timeout_ms,
        None,
    )
}

fn start_proxy_with_options(
    proxy: SocketAddr,
    upstream: SocketAddr,
    max_body: usize,
    max_inflight_body: usize,
    body_timeout_ms: u64,
    tls_pem: Option<(&str, &str)>,
) -> ProxyProcess {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "polyguard-integration-{}-{}-{nonce}",
        std::process::id(),
        proxy.port()
    ));
    fs::create_dir(&directory).unwrap();
    let management = free_address();
    let tls_section = if let Some((certificate, private_key)) = tls_pem {
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        fs::write(&certificate_path, certificate).unwrap();
        fs::write(&private_key_path, private_key).unwrap();
        format!(
            "[listener.tls]\ncertificate_chain_file = {:?}\nprivate_key_file = {:?}\n",
            certificate_path, private_key_path
        )
    } else {
        String::new()
    };
    let config = directory.join("polyguard.toml");
    fs::write(
        &config,
        format!(
            r#"
[listener]
address = "{proxy}"
management_address = "{management}"
security_mode = "agreement"
agreement_implementations = 3
max_connections = 16
request_header_timeout_ms = 1000
request_body_timeout_ms = {body_timeout_ms}
upstream_connect_timeout_ms = 1000
upstream_response_timeout_ms = 1000
graceful_shutdown_timeout_ms = 1000

{tls_section}

[limits]
max_request_body_bytes = {max_body}
max_response_header_bytes = 8192
max_response_body_bytes = 1048576
max_inflight_body_bytes = {max_inflight_body}

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
        if TcpStream::connect(proxy).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "proxy did not start");
        thread::sleep(Duration::from_millis(10));
    }
    ProxyProcess {
        child,
        directory,
        config,
        management,
    }
}

#[test]
fn aggregate_body_memory_limit_rejects_overload_and_recovers() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let proxy = start_proxy_with_budget_and_timeout(proxy_address, upstream_address, 4, 4, 5_000);

    let mut holding = TcpStream::connect(proxy_address).unwrap();
    holding
        .write_all(
            b"POST /hold HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nx",
        )
        .unwrap();
    holding
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut early = [0_u8; 256];
    if let Ok(count) = holding.read(&mut early) {
        panic!("holding request ended early: {:?}", &early[..count]);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let metrics = send(
            proxy.management,
            b"GET /_polyguard/metrics HTTP/1.1\r\nHost: example.test\r\n\r\n",
        );
        let last_metrics = String::from_utf8_lossy(&metrics);
        if last_metrics.contains("polyguard_inflight_body_bytes 4\n") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "holding request did not reserve memory: {last_metrics}"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let saturated_readiness = send(
        proxy.management,
        b"GET /_polyguard/ready HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        saturated_readiness.starts_with(b"HTTP/1.1 503"),
        "{saturated_readiness:?}"
    );

    let overloaded = send(
        proxy_address,
        b"POST /second HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\ny",
    );
    assert!(overloaded.starts_with(b"HTTP/1.1 503"), "{overloaded:?}");
    drop(holding);
    thread::sleep(Duration::from_millis(100));

    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let request = read_request(&mut stream);
        assert!(request.ends_with(b"\r\n\r\nbody"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let recovered = send(
        proxy_address,
        b"POST /recovered HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody",
    );
    assert!(recovered.starts_with(b"HTTP/1.1 200 OK"), "{recovered:?}");
    server.join().unwrap();
    let recovered_readiness = send(
        proxy.management,
        b"GET /_polyguard/ready HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        recovered_readiness.starts_with(b"HTTP/1.1 200 OK"),
        "{recovered_readiness:?}"
    );
}

fn send(address: SocketAddr, wire: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(wire).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    if let Err(error) = stream.read_to_end(&mut response) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "response read failed: {error}"
        );
    }
    response
}

#[test]
fn native_tls_proxies_https_and_marks_forwarding_metadata() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["example.test".into()]).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let _proxy = start_proxy_with_options(
        proxy_address,
        upstream_address,
        1_024,
        1_048_576,
        1_000,
        Some((&cert.pem(), &signing_key.serialize_pem())),
    );
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        request_tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
            .unwrap();
    });

    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connection = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("example.test").unwrap().to_owned(),
    )
    .unwrap();
    let socket = TcpStream::connect(proxy_address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(b"GET /secure HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
    assert!(response.ends_with(b"\r\n\r\nsecure"), "{response:?}");
    assert_eq!(tls.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));

    let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
    assert!(
        request.contains("forwarded: for=127.0.0.1;proto=https"),
        "{request}"
    );
    assert!(request.contains("x-forwarded-proto: https"), "{request}");
    server.join().unwrap();
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut wire = Vec::new();
    let mut scratch = [0_u8; 1024];
    let head_end = loop {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature request EOF");
        wire.extend_from_slice(&scratch[..count]);
        if let Some(index) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while wire.len() < head_end + length {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature body EOF");
        wire.extend_from_slice(&scratch[..count]);
    }
    wire
}

fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut scratch = [0_u8; 1024];
    let head_end = loop {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature response EOF");
        wire.extend_from_slice(&scratch[..count]);
        if let Some(index) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap();
    while wire.len() < head_end + length {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature response body EOF");
        wire.extend_from_slice(&scratch[..count]);
    }
    wire
}

#[test]
fn sequential_keep_alive_requests_are_counted_individually() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let proxy = start_proxy(proxy_address, upstream_address, 1_024);
    let server = thread::spawn(move || {
        for expected in ["/one", "/two"] {
            let (mut stream, _) = upstream.accept().unwrap();
            let request = read_request(&mut stream);
            let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(
                request_text.starts_with(&format!("get {expected} http/1.1")),
                "{request:?}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        }
    });

    let mut client = TcpStream::connect(proxy_address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let first = read_response(&mut client);
    assert!(first.starts_with(b"HTTP/1.1 200 OK"), "{first:?}");
    assert!(
        String::from_utf8_lossy(&first).contains("connection: keep-alive"),
        "{first:?}"
    );
    client
        .write_all(b"GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let second = read_response(&mut client);
    assert!(second.starts_with(b"HTTP/1.1 200 OK"), "{second:?}");
    assert!(
        String::from_utf8_lossy(&second).contains("connection: close"),
        "{second:?}"
    );
    server.join().unwrap();

    let metrics = send(
        proxy.management,
        b"GET /_polyguard/metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        String::from_utf8_lossy(&metrics)
            .contains("polyguard_requests_total{outcome=\"accepted\"} 2\n"),
        "{metrics:?}"
    );
}

#[test]
fn smuggling_is_rejected_before_upstream_and_valid_request_is_canonical() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let request = read_request(&mut stream);
        request_tx.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let _proxy = start_proxy(proxy_address, upstream_address, 1024);

    let rejected = send(proxy_address, b"POST /bad HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx");
    assert!(rejected.starts_with(b"HTTP/1.1 400"), "{rejected:?}");
    assert!(
        request_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "ambiguous request reached upstream"
    );

    let response = send(proxy_address, b"POST /safe?q=1 HTTP/1.1\r\nHost: example.test\r\nConnection: X-Secret\r\nX-Secret: never-forward\r\nContent-Length: 3\r\n\r\nabc");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{response:?}");
    assert!(response.ends_with(b"\r\n\r\nok"));
    let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
    assert!(
        text.starts_with("post /safe?q=1 http/1.1\r\nhost: example.test\r\n"),
        "{text}"
    );
    assert!(!text.contains("x-secret"), "{text}");
    assert!(!text.contains("never-forward"), "{text}");
    assert!(
        text.contains("forwarded: for=127.0.0.1;proto=http;host=\"example.test\"\r\n"),
        "{text}"
    );
    assert!(request.ends_with(b"\r\n\r\nabc"));
    server.join().unwrap();
}

#[test]
fn chunked_request_is_fully_validated_then_forwarded_with_one_length() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        request_tx.send(read_request(&mut stream)).unwrap();
        stream.write_all(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n").unwrap();
    });
    let _proxy = start_proxy(proxy_address, upstream_address, 1024);
    let response = send(proxy_address, b"POST /chunks HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTrailer: x-proof\r\n\r\n4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Proof: yes\r\n\r\n");
    assert!(
        response.starts_with(b"HTTP/1.1 201 Created\r\n"),
        "{response:?}"
    );
    assert!(response.ends_with(b"\r\n\r\nok"));
    let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
    assert!(text.contains("content-length: 9\r\n"), "{text}");
    assert!(!text.contains("transfer-encoding"), "{text}");
    assert!(request.ends_with(b"\r\n\r\nWikipedia"));
    server.join().unwrap();
}

#[test]
fn upstream_informational_response_is_not_mistaken_for_a_final_response() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let _ = read_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )
            .unwrap();
    });
    let _proxy = start_proxy(proxy_address, upstream_address, 1_024);
    let response = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with(b"HTTP/1.1 502 Bad Gateway"),
        "{response:?}"
    );
    server.join().unwrap();
}

#[test]
fn health_metrics_and_body_limit_are_operational() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = free_address();
    let proxy = start_proxy(proxy_address, upstream.local_addr().unwrap(), 4);
    let health = send(
        proxy.management,
        b"GET /_polyguard/health HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    assert!(health.starts_with(b"HTTP/1.1 200 OK"));
    assert!(health.ends_with(b"\r\n\r\nok\n"));
    let public_health = send(
        proxy_address,
        b"GET /_polyguard/health HTTP/1.1\r\nHost: management.invalid\r\n\r\n",
    );
    assert!(
        public_health.starts_with(b"HTTP/1.1 404"),
        "management endpoint leaked onto traffic listener: {public_health:?}"
    );
    let metrics = send(
        proxy.management,
        b"GET /_polyguard/metrics HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    assert!(String::from_utf8_lossy(&metrics).contains("polyguard_disagreements_total"));
    let oversized = send(
        proxy_address,
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n12345",
    );
    assert!(oversized.starts_with(b"HTTP/1.1 413"), "{oversized:?}");
    upstream.set_nonblocking(true).unwrap();
    assert!(
        upstream.accept().is_err(),
        "oversized body reached upstream"
    );
}

#[test]
fn hostile_corpus_and_slow_partial_input_never_reach_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let proxy_address = free_address();
    let _proxy = start_proxy(proxy_address, upstream.local_addr().unwrap(), 1024);
    let cases: &[&[u8]] = &[
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : example.test\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.test\r\n X-Fold: bad\r\n\r\n",
        b"GET / HTTP/1.1\nHost: example.test\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Nul: a\0b\r\n\r\n",
        b"GET http://other.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nxy",
        b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ];
    for wire in cases {
        let response = send(proxy_address, wire);
        assert!(
            response.starts_with(b"HTTP/1.1 400") || response.starts_with(b"HTTP/1.1 413"),
            "unexpected response for {wire:?}: {response:?}"
        );
    }
    assert!(
        upstream.accept().is_err(),
        "hostile corpus reached upstream"
    );

    let mut slow = TcpStream::connect(proxy_address).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
    thread::sleep(Duration::from_millis(1_200));
    let mut response = Vec::new();
    slow.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 408"), "{response:?}");
    assert!(
        upstream.accept().is_err(),
        "slow partial request reached upstream"
    );
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_listener_cleanly() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = free_address();
    let mut proxy = start_proxy(proxy_address, upstream.local_addr().unwrap(), 1024);
    unsafe extern "C" {
        fn kill(process: i32, signal: i32) -> i32;
    }
    assert_eq!(unsafe { kill(proxy.child.id() as i32, 15) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = proxy.child.try_wait().unwrap() {
            assert!(status.success(), "graceful process exit was {status}");
            break;
        }
        assert!(Instant::now() < deadline, "proxy ignored SIGTERM");
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn sighup_atomically_reloads_valid_config_and_retains_the_previous_generation_on_error() {
    unsafe extern "C" {
        fn kill(process: i32, signal: i32) -> i32;
    }

    let first_upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_address = first_upstream.local_addr().unwrap();
    let second_upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_address = second_upstream.local_addr().unwrap();
    let proxy_address = free_address();
    let proxy = start_proxy(proxy_address, first_address, 1_024);
    let first_server = thread::spawn(move || {
        let (mut stream, _) = first_upstream.accept().unwrap();
        let _ = read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
            .unwrap();
    });
    let first = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(first.ends_with(b"\r\n\r\none"), "{first:?}");
    first_server.join().unwrap();

    let original = fs::read_to_string(&proxy.config).unwrap();
    let replacement = original.replace(&first_address.to_string(), &second_address.to_string());
    fs::write(&proxy.config, &replacement).unwrap();
    assert_eq!(unsafe { kill(proxy.child.id() as i32, 1) }, 0);
    thread::sleep(Duration::from_millis(150));

    let second_server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = second_upstream.accept().unwrap();
            let _ = read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
                .unwrap();
        }
    });
    let second = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(second.ends_with(b"\r\n\r\ntwo"), "{second:?}");

    let invalid_address = free_address();
    let invalid = replacement.replace(&proxy_address.to_string(), &invalid_address.to_string());
    fs::write(&proxy.config, invalid).unwrap();
    assert_eq!(unsafe { kill(proxy.child.id() as i32, 1) }, 0);
    thread::sleep(Duration::from_millis(150));
    let retained = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(retained.ends_with(b"\r\n\r\ntwo"), "{retained:?}");
    second_server.join().unwrap();
}
