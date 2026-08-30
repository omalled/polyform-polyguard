use std::io::{self, Read};

use polyform_polyguard::*;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Request {
    schema_version: u64,
    operation: String,
    function: String,
    seed: Option<u64>,
    case: Option<u64>,
    input: Option<Value>,
}

fn encoded<T: serde::Serialize>(result: Result<T>) -> Value {
    match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": error}),
    }
}

fn outcome(id: &str, result: Value) -> Value {
    json!({"implementation": id, "result": result})
}

fn line(method: &str, target: &str) -> RequestLine {
    RequestLine {
        method: method.into(),
        target: target.into(),
        version: HttpVersion::Http11,
        bytes_consumed: 0,
    }
}

fn block(fields: &[(&str, &[u8])]) -> HeaderBlock {
    HeaderBlock {
        fields: fields
            .iter()
            .map(|(name, value)| HeaderField {
                name: (*name).into(),
                value: (*value).into(),
            })
            .collect(),
        bytes_consumed: 0,
    }
}

fn target(path: &str) -> NormalizedTarget {
    NormalizedTarget {
        form: TargetForm::Origin,
        scheme: None,
        authority: None,
        path_and_query: path.into(),
        routing_path: path.split('?').next().unwrap().into(),
    }
}

fn mix(seed: u64, case: u64) -> u64 {
    let mut x = seed ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn generated(function: &str, seed: u64, case: u64) -> Option<Value> {
    let choice = (case.wrapping_add(mix(seed, 0)) % 12) as usize;
    Some(match function {
        "parse_request_line" => {
            let variants: Vec<Vec<u8>> = vec![
                b"GET / HTTP/1.1\r\n".to_vec(),
                b"M-SEARCH /x?y=1 HTTP/1.1\r\nnext".to_vec(),
                b"GET  / HTTP/1.1\r\n".to_vec(),
                b"GET / HTTP/1.0\r\n".to_vec(),
                b"GET /x#y HTTP/1.1\r\n".to_vec(),
                b"GET / HTTP/1.1\n".to_vec(),
                vec![b'a'; 8192],
                vec![b'a'; 8193],
                format!("{} / HTTP/1.1\r\n", "A".repeat(32)).into_bytes(),
                format!("{} / HTTP/1.1\r\n", "A".repeat(33)).into_bytes(),
                b"GET /%2f HTTP/1.1\r\n".to_vec(),
                b"OPTIONS * HTTP/1.1\r\n".to_vec(),
            ];
            json!({"input": variants[choice].clone()})
        }
        "parse_header_section" => {
            let variants: Vec<Vec<u8>> = vec![
                b"\r\n".to_vec(),
                b"Host: x\r\nX: y\r\n\r\nbody".to_vec(),
                b"X:\t a \t\r\n\r\n".to_vec(),
                b"Host : x\r\n\r\n".to_vec(),
                b"X: a\r\n b\r\n\r\n".to_vec(),
                b"X: a\0b\r\n\r\n".to_vec(),
                vec![b'a'; 32768],
                vec![b'a'; 32769],
                ("x:\r\n".repeat(128) + "\r\n").into_bytes(),
                ("x:\r\n".repeat(129) + "\r\n").into_bytes(),
                format!("x:{}\r\n\r\n", "v".repeat(8192)).into_bytes(),
                format!("x:{}\r\n\r\n", "v".repeat(8193)).into_bytes(),
            ];
            json!({"input": variants[choice].clone()})
        }
        "determine_body_framing" => {
            let variants = [
                block(&[]),
                block(&[("content-length", b"0")]),
                block(&[("content-length", b"5")]),
                block(&[("content-length", b"05, 5")]),
                block(&[("content-length", b"4,5")]),
                block(&[("content-length", b"+1")]),
                block(&[("content-length", b"16777217")]),
                block(&[("transfer-encoding", b"chunked")]),
                block(&[("transfer-encoding", b"gzip, chunked")]),
                block(&[("transfer-encoding", b"chunked"), ("content-length", b"0")]),
                block(&[("transfer-encoding", b"bad"), ("content-length", b"bad")]),
                block(&[("content-length", b"")]),
            ];
            json!({"request": line("post", "/"), "headers": variants[choice]})
        }
        "parse_chunk_metadata" => {
            let variants: Vec<Vec<u8>> = vec![
                b"0\r\n".to_vec(),
                b"a;Foo=bar;x=\"a\\\"b\"\r\ndata".to_vec(),
                b"1000000\r\n".to_vec(),
                b"1000001\r\n".to_vec(),
                b"0x10\r\n".to_vec(),
                b"a\n".to_vec(),
                vec![b'a'; 1024],
                vec![b'a'; 1025],
                b"a; x=y\r\n".to_vec(),
                b"a;x=\"bad\r\n".to_vec(),
                format!("1{}\r\n", ";x".repeat(16)).into_bytes(),
                format!("1{}\r\n", ";x".repeat(17)).into_bytes(),
            ];
            json!({"input": variants[choice].clone()})
        }
        "parse_trailer_section" => {
            let variants: Vec<(Vec<u8>, Vec<String>)> = vec![
                (b"\r\n".to_vec(), vec![]),
                (b"Digest: x\r\n\r\nnext".to_vec(), vec!["digest".into()]),
                (b"X: y\r\n\r\n".to_vec(), vec![]),
                (b"X: a\r\nX: b\r\n\r\n".to_vec(), vec!["x".into()]),
                (b"\r\n".to_vec(), vec!["content-length".into()]),
                (b"\r\n".to_vec(), vec!["X".into()]),
                (vec![b'a'; 8192], vec![]),
                (vec![b'a'; 8193], vec![]),
                (b"X : y\r\n\r\n".to_vec(), vec!["x".into()]),
                (b"X: y\r\n z\r\n\r\n".to_vec(), vec!["x".into()]),
                (b"\r\n".to_vec(), vec!["x".into(), "x".into()]),
                (b"Set-Cookie: x\r\n\r\n".to_vec(), vec!["set-cookie".into()]),
            ];
            json!({"input": variants[choice].0, "declared_names": variants[choice].1})
        }
        "normalize_request_target" => {
            let variants = [
                line("get", "/a/%7e/b/../c?x=%2f"),
                line("get", "HTTP://Example.TEST:80/a"),
                line("connect", "example.test:443"),
                line("options", "*"),
                line("get", "*"),
                line("get", "/a%2fb"),
                line("get", "/../../x"),
                line("get", "/a//b/./c"),
                line("get", "https://example.test"),
                line("connect", "[2001:DB8::1]:443"),
                line("get", "/bad%GG"),
                line("get", &format!("/{}", "a".repeat(8192))),
            ];
            json!({"request": variants[choice]})
        }
        "reconcile_authority" => {
            let variants = [
                (target("/"), block(&[("host", b"Example.Test.:8080")])),
                (target("/"), block(&[])),
                (target("/"), block(&[("host", b"x"), ("host", b"x")])),
                (target("/"), block(&[("host", b"x,x")])),
                (target("/"), block(&[("host", b"fe80::1")])),
                (target("/"), block(&[("host", b"[2001:DB8::1]:443")])),
                (target("/"), block(&[("host", b"a:0")])),
                (target("/"), block(&[("host", b"-a.test")])),
                (target("/"), block(&[("host", b"a.test.")])),
                (target("/"), block(&[("host", b"u@a.test")])),
                (
                    NormalizedTarget {
                        form: TargetForm::Absolute,
                        scheme: Some("http".into()),
                        authority: Some("example.test:80".into()),
                        path_and_query: "/".into(),
                        routing_path: "/".into(),
                    },
                    block(&[("host", b"example.test")]),
                ),
                (
                    NormalizedTarget {
                        form: TargetForm::Absolute,
                        scheme: Some("http".into()),
                        authority: Some("example.test".into()),
                        path_and_query: "/".into(),
                        routing_path: "/".into(),
                    },
                    block(&[("host", b"evil.test")]),
                ),
            ];
            json!({"target": variants[choice].0, "headers": variants[choice].1})
        }
        "remove_hop_by_hop_headers" => {
            let variants = [
                block(&[]),
                block(&[
                    ("connection", b"x-hop"),
                    ("x-hop", b"secret"),
                    ("x-end", b"ok"),
                ]),
                block(&[("connection", b"close,,upgrade")]),
                block(&[("transfer-encoding", b"chunked")]),
                block(&[("authorization", b"x"), ("cookie", b"y")]),
                block(&[("proxy-authorization", b"x")]),
                block(&[("connection", b"missing")]),
                block(&[("connection", b"")]),
                block(&[("te", b"trailers")]),
                block(&[("forwarded", b"old")]),
                block(&[("x-forwarded-for", b"old")]),
                block(&[("host", b"x")]),
            ];
            json!({"headers": variants[choice]})
        }
        "construct_canonical_upstream_head" => {
            let framings = [
                BodyFraming::None,
                BodyFraming::ContentLength(0),
                BodyFraming::ContentLength(12),
                BodyFraming::Chunked,
            ];
            let methods = ["get", "post", "", "bad method"];
            json!({
                "method": methods[choice % methods.len()], "target": target(if choice == 4 { "" } else { "/a?x=1" }),
                "authority": EffectiveAuthority { host: if choice == 5 { "bad host".into() } else { "example.test".into() }, port: None },
                "headers": SanitizedHeaders { fields: if choice == 6 { vec![HeaderField { name: "keep-alive".into(), value: b"x".to_vec() }] } else { vec![HeaderField { name: "x-test".into(), value: b"y".to_vec() }] }, removed_names: vec![] },
                "framing": framings[choice % framings.len()],
                "forwarding": ForwardingResult { forwarded: "for=192.0.2.1;proto=https;host=\"example.test\"".into(), x_forwarded_for: "192.0.2.1".into(), x_forwarded_proto: "https".into(), x_forwarded_host: "example.test".into() }
            })
        }
        "match_route" => {
            let path = ["/", "/api", "/api/x", "/apix", "/a%2Fb"][choice % 5];
            let mut routes = vec![
                RouteRule {
                    host: "example.test".into(),
                    path_prefix: "/".into(),
                    upstream: "root".into(),
                    declaration_order: 9,
                },
                RouteRule {
                    host: "example.test".into(),
                    path_prefix: "/api".into(),
                    upstream: "api".into(),
                    declaration_order: 2,
                },
            ];
            if choice == 6 {
                routes[1].path_prefix = "/api/".into();
            }
            if choice == 7 {
                routes[1].upstream = "bad/upstream".into();
            }
            if choice == 8 {
                routes[1].declaration_order = 9;
            }
            if choice == 9 {
                routes = (0..257)
                    .map(|n| RouteRule {
                        host: "example.test".into(),
                        path_prefix: "/".into(),
                        upstream: "u".into(),
                        declaration_order: n,
                    })
                    .collect();
            }
            json!({"authority": EffectiveAuthority { host: if choice == 10 { "other.test".into() } else { "example.test".into() }, port: Some(8080) }, "target": target(path), "routes": routes})
        }
        "apply_forwarding_policy" => {
            let policy = ForwardingPolicy {
                trust_incoming: choice.is_multiple_of(2),
                client_ip: if choice == 8 {
                    "bad".into()
                } else if choice == 9 {
                    "2001:db8::1".into()
                } else {
                    "192.0.2.1".into()
                },
                proto: if choice == 10 {
                    "HTTP".into()
                } else {
                    "https".into()
                },
                host: "example.test".into(),
            };
            let headers = match choice {
                2 => block(&[("x-forwarded-for", b"old")]),
                4 => block(&[("forwarded", b"one"), ("forwarded", b"two")]),
                6 => block(&[("x-forwarded-for", b"x,,y")]),
                7 => block(&[("x-forwarded-for", &[b'a'; 1025])]),
                _ => block(&[]),
            };
            json!({"policy": policy, "headers": headers})
        }
        "decide_upgrade" => {
            let mut headers = block(&[
                ("connection", b"keep-alive, Upgrade"),
                ("upgrade", b"websocket"),
                ("sec-websocket-version", b"13"),
                ("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
            ]);
            if choice == 0 {
                headers = block(&[]);
            }
            if choice == 2 {
                headers.fields.retain(|f| f.name != "upgrade");
            }
            if choice == 3 {
                headers
                    .fields
                    .iter_mut()
                    .find(|f| f.name == "upgrade")
                    .unwrap()
                    .value = b"h2c".to_vec();
            }
            if choice == 4 {
                headers.fields.push(HeaderField {
                    name: "content-length".into(),
                    value: b"0".to_vec(),
                });
            }
            if choice == 5 {
                headers.fields.push(HeaderField {
                    name: "sec-websocket-extensions".into(),
                    value: b"x".to_vec(),
                });
            }
            if choice == 6 {
                headers.fields.push(HeaderField {
                    name: "sec-websocket-protocol".into(),
                    value: b"chat,chat".to_vec(),
                });
            }
            json!({"request": line(if choice == 7 { "post" } else { "get" }, "/"), "headers": headers, "framing": if choice == 8 { BodyFraming::Chunked } else { BodyFraming::None }})
        }
        "classify_telemetry_outcome" => {
            let codes = [
                "accepted",
                "client_syntax",
                "ambiguous_framing",
                "policy_rejected",
                "route_missing",
                "upstream_failure",
                "timeout",
                "implementation_disagreement",
                "internal_failure",
                "unknown",
                "",
                "/private",
            ];
            json!({"code": codes[choice], "upstream_reached": choice.is_multiple_of(2)})
        }
        _ => return None,
    })
}

fn member<T: for<'de> Deserialize<'de>>(
    input: &Value,
    name: &str,
) -> std::result::Result<T, String> {
    serde_json::from_value(
        input
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing {name}"))?,
    )
    .map_err(|e| e.to_string())
}

fn evaluate(function: &str, input: &Value) -> std::result::Result<Vec<Value>, String> {
    let mut outcomes = Vec::new();
    match function {
        "parse_request_line" => {
            let value: Vec<u8> = member(input, "input")?;
            for i in registered_implementations() {
                if let Some(f) = i.parse_request_line {
                    outcomes.push(outcome(i.id, encoded(f(&value))));
                }
            }
        }
        "parse_header_section" => {
            let value: Vec<u8> = member(input, "input")?;
            for i in registered_implementations() {
                if let Some(f) = i.parse_header_section {
                    outcomes.push(outcome(i.id, encoded(f(&value))));
                }
            }
        }
        "determine_body_framing" => {
            let request = member(input, "request")?;
            let headers = member(input, "headers")?;
            for i in registered_implementations() {
                if let Some(f) = i.determine_body_framing {
                    outcomes.push(outcome(i.id, encoded(f(&request, &headers))));
                }
            }
        }
        "parse_chunk_metadata" => {
            let value: Vec<u8> = member(input, "input")?;
            for i in registered_implementations() {
                if let Some(f) = i.parse_chunk_metadata {
                    outcomes.push(outcome(i.id, encoded(f(&value))));
                }
            }
        }
        "parse_trailer_section" => {
            let value: Vec<u8> = member(input, "input")?;
            let names: Vec<String> = member(input, "declared_names")?;
            for i in registered_implementations() {
                if let Some(f) = i.parse_trailer_section {
                    outcomes.push(outcome(i.id, encoded(f(&value, &names))));
                }
            }
        }
        "normalize_request_target" => {
            let request = member(input, "request")?;
            for i in registered_implementations() {
                if let Some(f) = i.normalize_request_target {
                    outcomes.push(outcome(i.id, encoded(f(&request))));
                }
            }
        }
        "reconcile_authority" => {
            let target = member(input, "target")?;
            let headers = member(input, "headers")?;
            for i in registered_implementations() {
                if let Some(f) = i.reconcile_authority {
                    outcomes.push(outcome(i.id, encoded(f(&target, &headers))));
                }
            }
        }
        "remove_hop_by_hop_headers" => {
            let headers = member(input, "headers")?;
            for i in registered_implementations() {
                if let Some(f) = i.remove_hop_by_hop_headers {
                    outcomes.push(outcome(i.id, encoded(f(&headers))));
                }
            }
        }
        "construct_canonical_upstream_head" => {
            let method: String = member(input, "method")?;
            let target = member(input, "target")?;
            let authority = member(input, "authority")?;
            let headers = member(input, "headers")?;
            let framing = member(input, "framing")?;
            let forwarding = member(input, "forwarding")?;
            for i in registered_implementations() {
                if let Some(f) = i.construct_canonical_upstream_head {
                    outcomes.push(outcome(
                        i.id,
                        encoded(f(
                            &method,
                            &target,
                            &authority,
                            &headers,
                            &framing,
                            &forwarding,
                        )),
                    ));
                }
            }
        }
        "match_route" => {
            let authority = member(input, "authority")?;
            let target = member(input, "target")?;
            let routes: Vec<RouteRule> = member(input, "routes")?;
            for i in registered_implementations() {
                if let Some(f) = i.match_route {
                    outcomes.push(outcome(i.id, encoded(f(&authority, &target, &routes))));
                }
            }
        }
        "apply_forwarding_policy" => {
            let policy = member(input, "policy")?;
            let headers = member(input, "headers")?;
            for i in registered_implementations() {
                if let Some(f) = i.apply_forwarding_policy {
                    outcomes.push(outcome(i.id, encoded(f(&policy, &headers))));
                }
            }
        }
        "decide_upgrade" => {
            let request = member(input, "request")?;
            let headers = member(input, "headers")?;
            let framing = member(input, "framing")?;
            for i in registered_implementations() {
                if let Some(f) = i.decide_upgrade {
                    outcomes.push(outcome(i.id, encoded(f(&request, &headers, &framing))));
                }
            }
        }
        "classify_telemetry_outcome" => {
            let code: String = member(input, "code")?;
            let reached = member(input, "upstream_reached")?;
            for i in registered_implementations() {
                if let Some(f) = i.classify_telemetry_outcome {
                    outcomes.push(outcome(i.id, encoded(f(&code, reached))));
                }
            }
        }
        _ => return Err("unknown function".into()),
    }
    Ok(outcomes)
}

fn response(valid: bool, input: Value, outcomes: Vec<Value>) -> Value {
    json!({"valid": valid, "input": input, "outcomes": outcomes})
}

fn run() -> std::result::Result<Value, String> {
    let mut source = String::new();
    io::stdin()
        .read_to_string(&mut source)
        .map_err(|e| e.to_string())?;
    let request: Request = serde_json::from_str(&source).map_err(|e| e.to_string())?;
    if request.schema_version != 1 {
        return Err("unsupported schema_version".into());
    }
    let input = match request.operation.as_str() {
        "generate" => generated(
            &request.function,
            request.seed.ok_or("missing seed")?,
            request.case.ok_or("missing case")?,
        )
        .ok_or("unknown function")?,
        "evaluate" => request.input.ok_or("missing input")?,
        _ => return Err("unknown operation".into()),
    };
    let outcomes = evaluate(&request.function, &input)?;
    Ok(response(true, input, outcomes))
}

fn main() {
    let value = match run() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("polyguard-fuzz: {error}");
            response(false, Value::Null, vec![])
        }
    };
    println!("{}", serde_json::to_string(&value).unwrap());
}
