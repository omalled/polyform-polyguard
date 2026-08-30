use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

struct ProcessGuard {
    child: Child,
    directory: PathBuf,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "polyguard-nginx-integration-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    directory
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start(config: &Path, address: SocketAddr) -> ProcessGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .args(["--nginx-config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(address).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "proxy did not start");
        thread::sleep(Duration::from_millis(10));
    }
    ProcessGuard {
        child,
        directory: config.parent().unwrap().to_path_buf(),
    }
}

fn send(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut request = Vec::new();
    let mut scratch = [0_u8; 1024];
    loop {
        let count = stream.read(&mut scratch).unwrap();
        assert_ne!(count, 0, "premature request EOF");
        request.extend_from_slice(&scratch[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
    }
}

#[test]
fn nginx_config_drives_static_redirect_and_rewritten_proxy_traffic() {
    let directory = temporary_directory("traffic");
    let public = directory.join("public");
    fs::create_dir(&public).unwrap();
    let home_body = "generic home".repeat(128);
    fs::write(public.join("index.html"), &home_body).unwrap();
    #[cfg(unix)]
    {
        let outside = directory.join("outside.txt");
        fs::write(&outside, "not public").unwrap();
        std::os::unix::fs::symlink(&outside, public.join("escape.txt")).unwrap();
    }
    let proxy_address = free_address();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let config = directory.join("nginx.conf");
    fs::write(
        &config,
        format!(
            r#"
events {{ worker_connections 128; }}
http {{
    gzip on;
    gzip_types text/html;
    server {{
        listen {proxy_address};
        server_name app.example.test;
        add_header X-Content-Type-Options nosniff always;
        location = /old {{ return 308 https://$host$request_uri; }}
        location /api/ {{
            proxy_pass http://{upstream_address}/v1/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            client_max_body_size 8;
            if ($request_method = 'OPTIONS') {{
                add_header Access-Control-Allow-Origin '*';
                add_header Content-Length 0;
                return 204;
            }}
        }}
        location /private/ {{
            deny 127.0.0.1;
            proxy_pass http://{upstream_address}/private/;
            proxy_http_version 1.1;
        }}
        location / {{
            root {};
            try_files $uri $uri/ =404;
        }}
    }}
}}
"#,
            public.display()
        ),
    )
    .unwrap();

    let imported = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .args(["--import-nginx", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(imported.status.success(), "{:?}", imported.stderr);
    let imported_config = directory.join("polyguard.toml");
    fs::write(&imported_config, imported.stdout).unwrap();
    let checked = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .args(["--check-config", imported_config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(checked.status.success(), "{:?}", checked.stderr);

    let _process = start(&config, proxy_address);

    let home = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    let home_text = String::from_utf8_lossy(&home).to_ascii_lowercase();
    assert!(home.starts_with(b"HTTP/1.1 200 OK"), "{home:?}");
    assert!(home_text.contains("x-content-type-options: nosniff"));
    assert!(home.ends_with(home_body.as_bytes()), "{home:?}");

    let compressed = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: app.example.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    let split = compressed
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let compressed_head = String::from_utf8_lossy(&compressed[..split]).to_ascii_lowercase();
    assert!(compressed_head.contains("content-encoding: gzip\r\n"));
    assert!(compressed_head.contains("vary: accept-encoding\r\n"));
    let mut decoded = String::new();
    GzDecoder::new(&compressed[split..])
        .read_to_string(&mut decoded)
        .unwrap();
    assert_eq!(decoded, home_body);

    let partial = send(
        proxy_address,
        b"GET / HTTP/1.1\r\nHost: app.example.test\r\nRange: bytes=0-6\r\nConnection: close\r\n\r\n",
    );
    let partial_text = String::from_utf8_lossy(&partial).to_ascii_lowercase();
    assert!(partial.starts_with(b"HTTP/1.1 206 Partial Content"));
    assert!(partial_text.contains("content-range: bytes 0-6/1536\r\n"));
    assert!(partial.ends_with(b"\r\n\r\ngeneric"), "{partial:?}");

    #[cfg(unix)]
    {
        let escaped = send(
            proxy_address,
            b"GET /escape.txt HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
        );
        assert!(
            escaped.starts_with(b"HTTP/1.1 404 Not Found"),
            "{escaped:?}"
        );
        assert!(!escaped.windows(10).any(|window| window == b"not public"));
    }
    let traversal = send(
        proxy_address,
        b"GET /%2e%2e/outside.txt HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        traversal.starts_with(b"HTTP/1.1 400 Bad Request"),
        "{traversal:?}"
    );

    let preflight = send(
        proxy_address,
        b"OPTIONS /api/users HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    let preflight_text = String::from_utf8_lossy(&preflight).to_ascii_lowercase();
    assert!(preflight.starts_with(b"HTTP/1.1 204 No Content"));
    assert!(preflight_text.contains("access-control-allow-origin: *\r\n"));

    let blocked = send(
        proxy_address,
        b"GET /private/item HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        blocked.starts_with(b"HTTP/1.1 403 Forbidden"),
        "{blocked:?}"
    );

    let redirect = send(
        proxy_address,
        b"GET /old?q=1 HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    let redirect_text = String::from_utf8_lossy(&redirect).to_ascii_lowercase();
    assert!(redirect.starts_with(b"HTTP/1.1 308"), "{redirect:?}");
    assert!(redirect_text.contains("location: https://app.example.test/old?q=1\r\n"));

    let (request_tx, request_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        request_tx.send(read_request(&mut stream)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let proxied = send(
        proxy_address,
        b"GET /api/users?q=1 HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    assert!(proxied.starts_with(b"HTTP/1.1 200 OK"), "{proxied:?}");
    let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
    assert!(
        request.starts_with("get /v1/users?q=1 http/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("host: app.example.test\r\n"), "{request}");
    assert!(request.contains("x-real-ip: 127.0.0.1\r\n"), "{request}");
    server.join().unwrap();
}

#[test]
fn nginx_check_reports_unsupported_protocol_flags() {
    let directory = temporary_directory("check");
    let config = directory.join("nginx.conf");
    fs::write(
        &config,
        "events {} http { server { listen 127.0.0.1:8443 ssl http2; server_name app.example.test; } }",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .args(["--check-nginx", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported listen address"), "{stderr}");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn nginx_tls_servers_select_certificate_and_route_by_sni_and_host() {
    let directory = temporary_directory("sni");
    let address = free_address();
    let clear_address = free_address();
    let CertifiedKey {
        cert: first_cert,
        signing_key: first_key,
    } = generate_simple_self_signed(vec!["first.example.test".into()]).unwrap();
    let CertifiedKey {
        cert: second_cert,
        signing_key: second_key,
    } = generate_simple_self_signed(vec!["second.example.test".into()]).unwrap();
    let first_certificate = directory.join("first.pem");
    let first_private_key = directory.join("first-key.pem");
    let second_certificate = directory.join("second.pem");
    let second_private_key = directory.join("second-key.pem");
    fs::write(&first_certificate, first_cert.pem()).unwrap();
    fs::write(&first_private_key, first_key.serialize_pem()).unwrap();
    fs::write(&second_certificate, second_cert.pem()).unwrap();
    fs::write(&second_private_key, second_key.serialize_pem()).unwrap();
    let config = directory.join("nginx.conf");
    fs::write(
        &config,
        format!(
            r#"
events {{}}
http {{
    server {{
        listen {address} ssl default_server;
        server_name first.example.test;
        ssl_certificate {};
        ssl_certificate_key {};
        return 200 first;
    }}
    server {{
        listen {address} ssl;
        server_name second.example.test;
        ssl_certificate {};
        ssl_certificate_key {};
        return 200 second;
    }}
    server {{
        listen {clear_address};
        server_name first.example.test second.example.test;
        if ($host = first.example.test) {{ return 308 https://$host$request_uri; }}
        if ($host = second.example.test) {{ return 308 https://$host$request_uri; }}
        return 404;
    }}
}}
"#,
            first_certificate.display(),
            first_private_key.display(),
            second_certificate.display(),
            second_private_key.display(),
        ),
    )
    .unwrap();
    let _process = start(&config, address);

    let redirected = send(
        clear_address,
        b"GET /path?q=1 HTTP/1.1\r\nHost: second.example.test\r\nConnection: close\r\n\r\n",
    );
    let redirected_text = String::from_utf8_lossy(&redirected).to_ascii_lowercase();
    assert!(redirected.starts_with(b"HTTP/1.1 308 Permanent Redirect"));
    assert!(redirected_text.contains("location: https://second.example.test/path?q=1\r\n"));

    let mut roots = RootCertStore::empty();
    roots.add(first_cert.der().clone()).unwrap();
    roots.add(second_cert.der().clone()).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_config = Arc::new(client_config);

    for (name, body) in [
        ("first.example.test", b"first".as_slice()),
        ("second.example.test", b"second".as_slice()),
    ] {
        let connection = ClientConnection::new(
            Arc::clone(&client_config),
            ServerName::try_from(name).unwrap().to_owned(),
        )
        .unwrap();
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut tls = StreamOwned::new(connection, socket);
        tls.write_all(
            format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
        assert!(response.ends_with(body), "{response:?}");
        assert_eq!(tls.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
    }

    let connection = ClientConnection::new(
        Arc::clone(&client_config),
        ServerName::try_from("first.example.test")
            .unwrap()
            .to_owned(),
    )
    .unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: second.example.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403 Forbidden"),
        "{response:?}"
    );
}
