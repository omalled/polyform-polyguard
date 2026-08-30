use polyform_polyguard::*;

macro_rules! each_impl {
    ($field:ident, |$function:ident, $id:ident| $body:block) => {{
        for implementation in registered_implementations() {
            if let Some($function) = implementation.$field {
                let $id = implementation.id;
                $body
            }
        }
    }};
}

fn field(name: &str, value: &[u8]) -> HeaderField {
    HeaderField {
        name: name.into(),
        value: value.into(),
    }
}

fn headers(fields: Vec<HeaderField>) -> HeaderBlock {
    HeaderBlock {
        fields,
        bytes_consumed: 0,
    }
}

fn request(method: &str, target: &str) -> RequestLine {
    RequestLine {
        method: method.into(),
        target: target.into(),
        version: HttpVersion::Http11,
        bytes_consumed: 0,
    }
}

fn origin(path: &str) -> NormalizedTarget {
    NormalizedTarget {
        form: TargetForm::Origin,
        scheme: None,
        authority: None,
        path_and_query: path.into(),
        routing_path: path.split('?').next().unwrap().into(),
    }
}

fn absolute(scheme: &str, authority: &str, path: &str) -> NormalizedTarget {
    NormalizedTarget {
        form: TargetForm::Absolute,
        scheme: Some(scheme.into()),
        authority: Some(authority.into()),
        path_and_query: path.into(),
        routing_path: path.split('?').next().unwrap().into(),
    }
}

fn invalid_reason(error: &PolyguardError) -> Option<&str> {
    match error {
        PolyguardError::InvalidRequestLine { reason }
        | PolyguardError::InvalidTarget { reason }
        | PolyguardError::InvalidChunk { reason }
        | PolyguardError::InvalidTrailer { reason }
        | PolyguardError::InvalidRoute { reason } => Some(reason),
        PolyguardError::InvalidHeader { reason, .. } => Some(reason),
        _ => None,
    }
}

fn assert_safe_reason(error: &PolyguardError) {
    if let Some(reason) = invalid_reason(error) {
        assert!(!reason.is_empty());
        assert!(
            reason.bytes().all(|b| b == b'_' || b.is_ascii_lowercase()),
            "unsafe reason: {reason:?}"
        );
    }
}

#[test]
fn public_models_have_required_serde_shape_and_traits() {
    fn traits<
        T: std::fmt::Debug
            + Clone
            + PartialEq
            + Eq
            + serde::Serialize
            + for<'de> serde::Deserialize<'de>,
    >() {
    }
    traits::<HeaderField>();
    traits::<HeaderBlock>();
    traits::<RequestLine>();
    traits::<HttpVersion>();
    traits::<BodyFraming>();
    traits::<ChunkMeta>();
    traits::<ChunkExtension>();
    traits::<TrailerBlock>();
    traits::<TargetForm>();
    traits::<NormalizedTarget>();
    traits::<EffectiveAuthority>();
    traits::<SanitizedHeaders>();
    traits::<CanonicalRequestHead>();
    traits::<RouteRule>();
    traits::<RouteMatch>();
    traits::<ForwardingPolicy>();
    traits::<ForwardingResult>();
    traits::<UpgradeDecision>();
    traits::<TelemetryOutcome>();
    traits::<OutcomeCategory>();
    traits::<PolyguardError>();

    assert_eq!(serde_json::to_value(HttpVersion::Http11).unwrap(), "http11");
    assert_eq!(
        serde_json::to_value(TargetForm::Asterisk).unwrap(),
        "asterisk"
    );
    assert_eq!(
        serde_json::to_value(UpgradeDecision::WebSocket).unwrap(),
        "web_socket"
    );
    assert_eq!(
        serde_json::to_value(OutcomeCategory::ImplementationDisagreement).unwrap(),
        "implementation_disagreement"
    );
    assert_eq!(
        serde_json::to_value(PolyguardError::InvalidMethod).unwrap(),
        "invalid_method"
    );
    assert_eq!(
        serde_json::to_value(PolyguardError::InvalidTarget {
            reason: "encoded_separator".into()
        })
        .unwrap(),
        serde_json::json!({"invalid_target":{"reason":"encoded_separator"}}),
    );
}

#[test]
fn registered_implementation_identifiers_are_stable_and_unique() {
    let mut ids = std::collections::BTreeSet::new();
    let mut counts = [0_usize; 13];
    for implementation in registered_implementations() {
        assert!(!implementation.id.is_empty());
        assert!(
            implementation
                .id
                .bytes()
                .all(|b| b == b'-' || b == b'_' || b == b'.' || b.is_ascii_alphanumeric()),
            "unsafe implementation id {:?}",
            implementation.id
        );
        assert!(
            ids.insert(implementation.id),
            "duplicate implementation id {}",
            implementation.id
        );
        let present = [
            implementation.parse_request_line.is_some(),
            implementation.parse_header_section.is_some(),
            implementation.determine_body_framing.is_some(),
            implementation.parse_chunk_metadata.is_some(),
            implementation.parse_trailer_section.is_some(),
            implementation.normalize_request_target.is_some(),
            implementation.reconcile_authority.is_some(),
            implementation.remove_hop_by_hop_headers.is_some(),
            implementation.construct_canonical_upstream_head.is_some(),
            implementation.match_route.is_some(),
            implementation.apply_forwarding_policy.is_some(),
            implementation.decide_upgrade.is_some(),
            implementation.classify_telemetry_outcome.is_some(),
        ];
        assert_eq!(
            present.iter().filter(|&&value| value).count(),
            1,
            "implementation {} must implement exactly one public function",
            implementation.id
        );
        for (count, is_present) in counts.iter_mut().zip(present) {
            *count += usize::from(is_present);
        }
    }
    assert_eq!(registered_implementations().len(), 65);
    assert_eq!(
        counts, [5; 13],
        "every public function must have exactly five independent implementations"
    );
}

#[test]
fn request_line_examples_boundary_and_canonical_method() {
    each_impl!(parse_request_line, |parse, id| {
        let got =
            parse(b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\n").unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(
            got,
            RequestLine {
                method: "get".into(),
                target: "/a?b=1".into(),
                version: HttpVersion::Http11,
                bytes_consumed: 21
            },
            "{id}"
        );
        assert_eq!(
            parse(b"M-SEARCH / HTTP/1.1\r\n").unwrap().method,
            "m-search",
            "{id}"
        );
    });
}

#[test]
fn request_line_rejects_line_endings_controls_and_spacing() {
    each_impl!(parse_request_line, |parse, id| {
        for input in [
            b"GET / HTTP/1.1\n".as_slice(),
            b"GET / HTTP/1.1\rX".as_slice(),
        ] {
            assert_eq!(
                parse(input),
                Err(PolyguardError::InvalidRequestLine {
                    reason: "bare_line_ending".into()
                }),
                "{id}: {input:?}"
            );
        }
        assert_eq!(
            parse(b"GET /\0 HTTP/1.1\r\n"),
            Err(PolyguardError::InvalidRequestLine {
                reason: "control_character".into()
            }),
            "{id}"
        );
        for input in [
            b"GET  / HTTP/1.1\r\n".as_slice(),
            b"GET\t/ HTTP/1.1\r\n",
            b" GET / HTTP/1.1\r\n",
            b"GET / HTTP/1.1 \r\n",
            b"GET /  HTTP/1.1\r\n",
        ] {
            assert_eq!(
                parse(input),
                Err(PolyguardError::InvalidRequestLine {
                    reason: "invalid_spacing".into()
                }),
                "{id}: {input:?}"
            );
        }
    });
}

#[test]
fn request_line_enforces_method_target_version_and_limits() {
    each_impl!(parse_request_line, |parse, id| {
        for input in [
            b"G@T / HTTP/1.1\r\n".as_slice(),
            format!("{} / HTTP/1.1\r\n", "A".repeat(33)).as_bytes(),
        ] {
            assert_eq!(parse(input), Err(PolyguardError::InvalidMethod), "{id}");
        }
        for input in [
            b"GET / HTTP/1.0\r\n".as_slice(),
            b"GET / HTTP/2\r\n",
            b"GET /\r\n",
        ] {
            assert_eq!(
                parse(input),
                Err(PolyguardError::UnsupportedVersion),
                "{id}: {input:?}"
            );
        }
        assert_eq!(
            parse(b"GET /x#frag HTTP/1.1\r\n"),
            Err(PolyguardError::InvalidTarget {
                reason: "fragment_not_allowed".into()
            }),
            "{id}"
        );
        assert_eq!(
            parse(b"GET /\x80 HTTP/1.1\r\n"),
            Err(PolyguardError::InvalidTarget {
                reason: "non_visible_ascii".into()
            }),
            "{id}"
        );
        assert_eq!(
            parse(&vec![b'A'; 8192]),
            Err(PolyguardError::Incomplete),
            "{id}"
        );
        assert!(
            matches!(parse(&vec![b'A'; 8193]), Err(PolyguardError::LimitExceeded { ref limit, max: 8192, actual: 8193 }) if limit == "request_line_bytes"),
            "{id}"
        );
    });
}

#[test]
fn header_examples_preserve_duplicates_values_and_boundary() {
    each_impl!(parse_header_section, |parse, id| {
        let got = parse(b"Host: example.test\r\nX-A: one\r\nX-A:\ttwo \t\r\n\r\nBODY").unwrap();
        assert_eq!(
            got.fields,
            vec![
                field("host", b"example.test"),
                field("x-a", b"one"),
                field("x-a", b"two")
            ],
            "{id}"
        );
        assert_eq!(got.bytes_consumed, 44, "{id}");
        let got = parse(b"Empty:\t \r\nBinary: \x80\xff\r\n\r\nrest").unwrap();
        assert_eq!(
            got.fields,
            vec![field("empty", b""), field("binary", b"\x80\xff")],
            "{id}"
        );
    });
}

#[test]
fn headers_reject_ambiguous_lines_and_report_byte_index() {
    each_impl!(parse_header_section, |parse, id| {
        assert_eq!(
            parse(b"Host : x\r\n\r\n"),
            Err(PolyguardError::InvalidHeader {
                index: 0,
                reason: "whitespace_before_colon".into()
            }),
            "{id}"
        );
        assert_eq!(
            parse(b"X: a\r\n b\r\n\r\n"),
            Err(PolyguardError::InvalidHeader {
                index: 6,
                reason: "obs_fold".into()
            }),
            "{id}"
        );
        assert_eq!(
            parse(b"Good: x\r\nBad: a\0b\r\n\r\n"),
            Err(PolyguardError::InvalidHeader {
                index: 9,
                reason: "invalid_value_byte".into()
            }),
            "{id}"
        );
        assert!(
            matches!(parse(b"X: a\x7fb\r\n\r\n"), Err(PolyguardError::InvalidHeader { ref reason, .. }) if reason == "invalid_value_byte"),
            "{id}"
        );
        assert!(
            matches!(parse(b"X: a\n\r\n"), Err(PolyguardError::InvalidHeader { reason, .. }) if reason == "bare_line_ending"),
            "{id}"
        );
        assert!(
            matches!(
                parse(b": x\r\n\r\n"),
                Err(PolyguardError::InvalidHeader { .. })
            ),
            "{id}"
        );
    });
}

#[test]
fn header_section_enforces_all_inclusive_limits() {
    each_impl!(parse_header_section, |parse, id| {
        assert_eq!(
            parse(&vec![b'A'; 32768]),
            Err(PolyguardError::Incomplete),
            "{id}"
        );
        assert!(
            matches!(parse(&vec![b'A'; 32769]), Err(PolyguardError::LimitExceeded { ref limit, max: 32768, actual: 32769 }) if limit == "header_section_bytes"),
            "{id}"
        );
        let name_ok = format!("{}: x\r\n\r\n", "a".repeat(128));
        assert!(parse(name_ok.as_bytes()).is_ok(), "{id}");
        let name_bad = format!("{}: x\r\n\r\n", "a".repeat(129));
        assert!(
            matches!(parse(name_bad.as_bytes()), Err(PolyguardError::LimitExceeded { ref limit, max: 128, actual: 129 }) if limit == "header_name_bytes"),
            "{id}"
        );
        let value_ok = format!("x:{}\r\n\r\n", "v".repeat(8192));
        assert!(parse(value_ok.as_bytes()).is_ok(), "{id}");
        let value_bad = format!("x:{}\r\n\r\n", "v".repeat(8193));
        assert!(
            matches!(parse(value_bad.as_bytes()), Err(PolyguardError::LimitExceeded { ref limit, max: 8192, actual: 8193 }) if limit == "header_value_bytes"),
            "{id}"
        );
        let fields_128 = "x:\r\n".repeat(128) + "\r\n";
        assert_eq!(
            parse(fields_128.as_bytes()).unwrap().fields.len(),
            128,
            "{id}"
        );
        let fields_129 = "x:\r\n".repeat(129) + "\r\n";
        assert_eq!(
            parse(fields_129.as_bytes()),
            Err(PolyguardError::TooManyHeaders),
            "{id}"
        );
    });
}

#[test]
fn body_framing_handles_identical_conflicting_and_ambiguous_metadata() {
    let req = request("post", "/");
    each_impl!(determine_body_framing, |frame, id| {
        assert_eq!(
            frame(
                &req,
                &headers(vec![
                    field("content-length", b"05"),
                    field("content-length", b" 5, 05 ")
                ])
            ),
            Ok(BodyFraming::ContentLength(5)),
            "{id}"
        );
        assert_eq!(
            frame(&req, &headers(vec![field("content-length", b"4, 5")])),
            Err(PolyguardError::ConflictingContentLength),
            "{id}"
        );
        assert_eq!(
            frame(
                &req,
                &headers(vec![
                    field("transfer-encoding", b"chunked"),
                    field("content-length", b"0")
                ])
            ),
            Err(PolyguardError::AmbiguousFraming),
            "{id}"
        );
        assert_eq!(
            frame(
                &req,
                &headers(vec![
                    field("transfer-encoding", b"bad"),
                    field("content-length", b"bad")
                ])
            ),
            Err(PolyguardError::AmbiguousFraming),
            "{id}"
        );
    });
}

#[test]
fn body_framing_strictly_validates_content_length_and_transfer_encoding() {
    let req = request("get", "/");
    each_impl!(determine_body_framing, |frame, id| {
        for value in [
            b"".as_slice(),
            b"+1",
            b"1 0",
            b"1,",
            b",1",
            b"18446744073709551616",
        ] {
            assert_eq!(
                frame(&req, &headers(vec![field("content-length", value)])),
                Err(PolyguardError::InvalidContentLength),
                "{id}: {value:?}"
            );
        }
        assert_eq!(
            frame(&req, &headers(vec![field("content-length", b"16777216")])),
            Ok(BodyFraming::ContentLength(16777216)),
            "{id}"
        );
        assert!(
            matches!(frame(&req, &headers(vec![field("content-length", b"16777217")])), Err(PolyguardError::LimitExceeded { ref limit, max: 16777216, actual: 16777217 }) if limit == "content_length"),
            "{id}"
        );
        assert_eq!(
            frame(&req, &headers(vec![field("content-length", b"0")])),
            Ok(BodyFraming::None),
            "{id}"
        );
        assert_eq!(frame(&req, &headers(vec![])), Ok(BodyFraming::None), "{id}");
        assert_eq!(
            frame(&req, &headers(vec![field("transfer-encoding", b"ChUnKeD")])),
            Ok(BodyFraming::Chunked),
            "{id}"
        );
        for value in [
            b"gzip, chunked".as_slice(),
            b"chunked, chunked",
            b"chunked;foo=bar",
            b"",
            b",chunked",
            b"chunked,",
        ] {
            assert_eq!(
                frame(&req, &headers(vec![field("transfer-encoding", value)])),
                Err(PolyguardError::InvalidTransferEncoding),
                "{id}: {value:?}"
            );
        }
    });
}

#[test]
fn chunk_metadata_examples_boundary_and_extensions() {
    each_impl!(parse_chunk_metadata, |parse, id| {
        let got = parse(b"a;Foo=bar;x=\"a\\\"b\"\r\n0123456789").unwrap();
        assert_eq!(
            got,
            ChunkMeta {
                size: 10,
                extensions: vec![
                    ChunkExtension {
                        name: "foo".into(),
                        value: Some("bar".into())
                    },
                    ChunkExtension {
                        name: "x".into(),
                        value: Some("a\"b".into())
                    }
                ],
                bytes_consumed: 20
            },
            "{id}"
        );
        assert_eq!(parse(b"0000000000000000\r\ndata").unwrap().size, 0, "{id}");
    });
}

#[test]
fn chunk_metadata_rejects_bad_size_lines_and_extensions() {
    each_impl!(parse_chunk_metadata, |parse, id| {
        for input in [
            b"0x10\r\n".as_slice(),
            b"+10\r\n",
            b" a\r\n",
            b"12345678901234567\r\n",
        ] {
            assert!(
                matches!(parse(input), Err(PolyguardError::InvalidChunk { ref reason }) if reason == "invalid_size"),
                "{id}: {input:?}"
            );
        }
        for input in [b"a\n".as_slice(), b"a\rX", b"a\0\r\n"] {
            assert_eq!(
                parse(input),
                Err(PolyguardError::InvalidChunk {
                    reason: "invalid_line_ending_or_control".into()
                }),
                "{id}"
            );
        }
        assert_eq!(
            parse(&vec![b'a'; 1024]),
            Err(PolyguardError::Incomplete),
            "{id}"
        );
        assert!(
            matches!(parse(&vec![b'a'; 1025]), Err(PolyguardError::LimitExceeded { ref limit, max: 1024, actual: 1025 }) if limit == "chunk_line_bytes"),
            "{id}"
        );
        assert!(
            matches!(parse(b"1000001\r\n"), Err(PolyguardError::LimitExceeded { ref limit, max: 16777216, actual: 16777217 }) if limit == "chunk_size"),
            "{id}"
        );
        for input in [
            b"a; foo=bar\r\n".as_slice(),
            b"a;foo =bar\r\n",
            b"a;foo= bar\r\n",
            b"a;\r\n",
            b"a;foo=\"unterminated\r\n",
            b"a;foo=bad value\r\n",
        ] {
            let error = parse(input).unwrap_err();
            assert!(
                matches!(error, PolyguardError::InvalidChunk { .. }),
                "{id}: {input:?} -> {error:?}"
            );
            assert_safe_reason(&error);
        }
        let sixteen = format!("1{}\r\n", ";x".repeat(16));
        assert_eq!(
            parse(sixteen.as_bytes()).unwrap().extensions.len(),
            16,
            "{id}"
        );
        let seventeen = format!("1{}\r\n", ";x".repeat(17));
        assert!(
            matches!(parse(seventeen.as_bytes()), Err(PolyguardError::LimitExceeded { ref limit, max: 16, actual: 17 }) if limit == "chunk_extensions"),
            "{id}"
        );
        let duplicate = parse(b"1;x=one;X=two\r\n").unwrap();
        assert_eq!(
            duplicate.extensions,
            vec![
                ChunkExtension {
                    name: "x".into(),
                    value: Some("one".into())
                },
                ChunkExtension {
                    name: "x".into(),
                    value: Some("two".into())
                },
            ],
            "{id}"
        );
        let name_64 = format!("1;{}\r\n", "x".repeat(64));
        assert!(parse(name_64.as_bytes()).is_ok(), "{id}");
        let name_65 = format!("1;{}\r\n", "x".repeat(65));
        assert!(
            matches!(
                parse(name_65.as_bytes()),
                Err(PolyguardError::InvalidChunk { .. })
            ),
            "{id}"
        );
    });
}

#[test]
fn trailers_enforce_declarations_forbidden_names_duplicates_and_boundary() {
    each_impl!(parse_trailer_section, |parse, id| {
        let got = parse(b"Digest: sha-256=x\r\n\r\nNEXT", &["digest".into()]).unwrap();
        assert_eq!(
            got,
            TrailerBlock {
                fields: vec![field("digest", b"sha-256=x")],
                bytes_consumed: 21
            },
            "{id}"
        );
        assert_eq!(
            parse(b"\r\nNEXT", &["digest".into()]).unwrap(),
            TrailerBlock {
                fields: vec![],
                bytes_consumed: 2
            },
            "{id}"
        );
        assert_eq!(
            parse(b"X: y\r\n\r\n", &[]),
            Err(PolyguardError::InvalidTrailer {
                reason: "undeclared_field".into()
            }),
            "{id}"
        );
        assert_eq!(
            parse(b"X: a\r\nX: b\r\n\r\n", &["x".into()]),
            Err(PolyguardError::InvalidTrailer {
                reason: "duplicate_field".into()
            }),
            "{id}"
        );
        for forbidden in [
            "content-length",
            "transfer-encoding",
            "host",
            "connection",
            "trailer",
            "upgrade",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ] {
            let declarations = vec![forbidden.into()];
            assert_eq!(
                parse(b"\r\n", &declarations),
                Err(PolyguardError::InvalidTrailer {
                    reason: "forbidden_field".into()
                }),
                "{id}: {declarations:?}"
            );
        }
        for declarations in [
            vec!["X".into()],
            vec!["bad name".into()],
            vec!["x".into(), "x".into()],
        ] {
            assert!(
                matches!(
                    parse(b"\r\n", &declarations),
                    Err(PolyguardError::InvalidTrailer { .. })
                ),
                "{id}: {declarations:?}"
            );
        }
    });
}

#[test]
fn trailers_reuse_strict_header_grammar_and_have_smaller_limits() {
    each_impl!(parse_trailer_section, |parse, id| {
        assert!(
            matches!(
                parse(b"X : y\r\n\r\n", &["x".into()]),
                Err(PolyguardError::InvalidTrailer { .. })
            ),
            "{id}"
        );
        assert!(
            matches!(
                parse(b"X: y\r\n z\r\n\r\n", &["x".into()]),
                Err(PolyguardError::InvalidTrailer { .. })
            ),
            "{id}"
        );
        assert_eq!(
            parse(&vec![b'A'; 8192], &[]),
            Err(PolyguardError::Incomplete),
            "{id}"
        );
        assert!(
            matches!(parse(&vec![b'A'; 8193], &[]), Err(PolyguardError::LimitExceeded { ref limit, max: 8192, actual: 8193 }) if limit == "trailer_bytes"),
            "{id}"
        );
        let names: Vec<String> = (0..32).map(|n| format!("x{n}")).collect();
        let section = names
            .iter()
            .map(|n| format!("{n}: y\r\n"))
            .collect::<String>()
            + "\r\n";
        assert_eq!(
            parse(section.as_bytes(), &names).unwrap().fields.len(),
            32,
            "{id}"
        );
        let names: Vec<String> = (0..33).map(|n| format!("x{n}")).collect();
        let section = names
            .iter()
            .map(|n| format!("{n}: y\r\n"))
            .collect::<String>()
            + "\r\n";
        assert!(
            matches!(
                parse(section.as_bytes(), &names),
                Err(PolyguardError::InvalidTrailer { .. })
            ),
            "{id}"
        );
    });
}

#[test]
fn target_normalization_covers_all_four_forms_and_examples() {
    each_impl!(normalize_request_target, |normalize, id| {
        assert_eq!(
            normalize(&request("get", "/a/%7e/b/../c?x=%2f")),
            Ok(NormalizedTarget {
                form: TargetForm::Origin,
                scheme: None,
                authority: None,
                path_and_query: "/a/~/c?x=%2F".into(),
                routing_path: "/a/~/c".into()
            }),
            "{id}"
        );
        assert_eq!(
            normalize(&request("get", "HTTP://Example.TEST:80/a")),
            Ok(NormalizedTarget {
                form: TargetForm::Absolute,
                scheme: Some("http".into()),
                authority: Some("example.test:80".into()),
                path_and_query: "/a".into(),
                routing_path: "/a".into()
            }),
            "{id}"
        );
        assert_eq!(
            normalize(&request("connect", "example.test:443")),
            Ok(NormalizedTarget {
                form: TargetForm::Authority,
                scheme: None,
                authority: Some("example.test:443".into()),
                path_and_query: "example.test:443".into(),
                routing_path: "example.test:443".into()
            }),
            "{id}"
        );
        assert_eq!(
            normalize(&request("options", "*")),
            Ok(NormalizedTarget {
                form: TargetForm::Asterisk,
                scheme: None,
                authority: None,
                path_and_query: "*".into(),
                routing_path: "*".into()
            }),
            "{id}"
        );
        assert_eq!(
            normalize(&request("get", "https://EXAMPLE.test"))
                .unwrap()
                .path_and_query,
            "/",
            "{id}"
        );
    });
}

#[test]
fn target_form_method_rules_and_authority_validation_are_strict() {
    each_impl!(normalize_request_target, |normalize, id| {
        assert_eq!(
            normalize(&request("get", "*")),
            Err(PolyguardError::InvalidTarget {
                reason: "asterisk_method".into()
            }),
            "{id}"
        );
        assert!(
            matches!(
                normalize(&request("connect", "/path")),
                Err(PolyguardError::InvalidTarget { .. })
            ),
            "{id}"
        );
        assert!(
            matches!(
                normalize(&request("get", "example.test:443")),
                Err(PolyguardError::InvalidTarget { .. })
            ),
            "{id}"
        );
        for target in [
            "ftp://example.test/a",
            "http:///a",
            "http://user@example.test/a",
            "http://example.test/a#x",
            "example.test:0",
            "example.test:65536",
            "example.test",
            "example.test:abc",
        ] {
            let result = normalize(&request(
                if target.starts_with("example") {
                    "connect"
                } else {
                    "get"
                },
                target,
            ));
            assert!(
                matches!(
                    result,
                    Err(PolyguardError::InvalidTarget { .. } | PolyguardError::InvalidAuthority)
                ),
                "{id}: {target} -> {result:?}"
            );
        }
        let v6 = normalize(&request("connect", "[2001:DB8::A]:443")).unwrap();
        assert_eq!(v6.authority.as_deref(), Some("[2001:db8::a]:443"), "{id}");
    });
}

#[test]
fn target_percent_dot_and_separator_rules_do_not_hide_ambiguity() {
    each_impl!(normalize_request_target, |normalize, id| {
        assert_eq!(
            normalize(&request("get", "/a%2fb")),
            Err(PolyguardError::InvalidTarget {
                reason: "encoded_separator".into()
            }),
            "{id}"
        );
        for target in ["/a%5Cb", "/a%00b", "/a%1Fb"] {
            assert!(
                matches!(
                    normalize(&request("get", target)),
                    Err(PolyguardError::InvalidTarget { .. })
                ),
                "{id}: {target}"
            );
        }
        for target in ["/bad%", "/bad%0", "/bad%GG"] {
            assert_eq!(
                normalize(&request("get", target)),
                Err(PolyguardError::InvalidTarget {
                    reason: "invalid_percent_encoding".into()
                }),
                "{id}: {target}"
            );
        }
        assert_eq!(
            normalize(&request("get", "/a//b/./c"))
                .unwrap()
                .routing_path,
            "/a//b/c",
            "{id}"
        );
        assert_eq!(
            normalize(&request("get", "/a/%2E%2E/b"))
                .unwrap()
                .routing_path,
            "/b",
            "{id}"
        );
        assert!(
            matches!(
                normalize(&request("get", "/../../secret")),
                Err(PolyguardError::InvalidTarget { .. })
            ),
            "{id}"
        );
        assert_eq!(
            normalize(&request("get", "/%41?x=%7e&y=%3f"))
                .unwrap()
                .path_and_query,
            "/A?x=~&y=%3F",
            "{id}"
        );
        for target in ["/a\\b", "/a b", "/a#b"] {
            assert!(
                matches!(
                    normalize(&request("get", target)),
                    Err(PolyguardError::InvalidTarget { .. })
                ),
                "{id}: {target}"
            );
        }
        for target in ["/a\0b", "/a\u{1f}b", "/a\u{7f}b"] {
            assert!(
                matches!(
                    normalize(&request("get", target)),
                    Err(PolyguardError::InvalidTarget { .. })
                ),
                "{id}: {target:?}"
            );
        }
        let too_long = format!("/{}", "a".repeat(8192));
        assert!(
            matches!(normalize(&request("get", &too_long)), Err(PolyguardError::LimitExceeded { ref limit, max: 8192, actual: 8193 }) if limit == "target_bytes"),
            "{id}"
        );
    });
}

#[test]
fn target_rejects_malformed_percent_triplet_regression_b1e516b4b8a5f43e() {
    each_impl!(normalize_request_target, |normalize, id| {
        assert_eq!(
            normalize(&request("get", "/bad%GG")),
            Err(PolyguardError::InvalidTarget {
                reason: "invalid_percent_encoding".into()
            }),
            "{id}"
        );
    });
}

#[test]
fn reconcile_authority_examples_host_counts_and_default_ports() {
    each_impl!(reconcile_authority, |reconcile, id| {
        assert_eq!(
            reconcile(
                &origin("/"),
                &headers(vec![field("host", b"Example.Test.:8080")])
            ),
            Ok(EffectiveAuthority {
                host: "example.test".into(),
                port: Some(8080)
            }),
            "{id}"
        );
        assert_eq!(
            reconcile(
                &absolute("http", "example.test:80", "/"),
                &headers(vec![field("host", b"example.test")])
            ),
            Ok(EffectiveAuthority {
                host: "example.test".into(),
                port: None
            }),
            "{id}"
        );
        assert_eq!(
            reconcile(&origin("/"), &headers(vec![])),
            Err(PolyguardError::MissingHost),
            "{id}"
        );
        assert_eq!(
            reconcile(
                &origin("/"),
                &headers(vec![field("host", b"x"), field("host", b"x")])
            ),
            Err(PolyguardError::MultipleHost),
            "{id}"
        );
        assert_eq!(
            reconcile(
                &absolute("http", "example.test", "/"),
                &headers(vec![field("host", b"evil.test")])
            ),
            Err(PolyguardError::AuthorityMismatch),
            "{id}"
        );
        assert_eq!(
            reconcile(
                &absolute("https", "example.test:443", "/"),
                &headers(vec![])
            )
            .unwrap()
            .port,
            None,
            "{id}"
        );
        assert_eq!(
            reconcile(
                &absolute("https", "example.test:8443", "/"),
                &headers(vec![])
            )
            .unwrap()
            .port,
            Some(8443),
            "{id}"
        );
    });
}

#[test]
fn reconcile_authority_rejects_smuggling_and_invalid_hosts() {
    each_impl!(reconcile_authority, |reconcile, id| {
        for host in [
            "",
            "a,b",
            " a",
            "a ",
            "u@a",
            "a/path",
            "a?x",
            "a#x",
            "fe80::1",
            "[fe80::1%25eth0]",
            "-a.test",
            "a-.test",
            "a..test",
            "a:0",
            "a:65536",
            "a:+80",
        ] {
            assert_eq!(
                reconcile(&origin("/"), &headers(vec![field("host", host.as_bytes())])),
                Err(PolyguardError::InvalidAuthority),
                "{id}: {host:?}"
            );
        }
        assert_eq!(
            reconcile(
                &origin("/"),
                &headers(vec![field("host", b"[2001:DB8::A]:8443")])
            ),
            Ok(EffectiveAuthority {
                host: "[2001:db8::a]".into(),
                port: Some(8443)
            }),
            "{id}"
        );
        let long_label = format!("{}.test", "a".repeat(64));
        assert_eq!(
            reconcile(
                &origin("/"),
                &headers(vec![field("host", long_label.as_bytes())])
            ),
            Err(PolyguardError::InvalidAuthority),
            "{id}"
        );
        let overlong_dns = (0..43).map(|_| "aaaaa").collect::<Vec<_>>().join(".");
        assert!(overlong_dns.len() > 253);
        assert_eq!(
            reconcile(
                &origin("/"),
                &headers(vec![field("host", overlong_dns.as_bytes())])
            ),
            Err(PolyguardError::InvalidAuthority),
            "{id}"
        );
        let comma_combined = headers(vec![field("host", b"x,x")]);
        assert_eq!(
            reconcile(&origin("/"), &comma_combined),
            Err(PolyguardError::MultipleHost),
            "{id}"
        );
    });
}

#[test]
fn hop_by_hop_removal_is_dynamic_ordered_and_complete() {
    each_impl!(remove_hop_by_hop_headers, |remove, id| {
        let input = headers(vec![
            field("host", b"example.test"),
            field("connection", b"X-Hop, keep-alive"),
            field("x-hop", b"secret"),
            field("keep-alive", b"timeout=5"),
            field("x-end", b"one"),
            field("authorization", b"secret"),
            field("cookie", b"a=b"),
            field("content-length", b"3"),
            field("forwarded", b"for=old"),
            field("x-forwarded-for", b"old"),
            field("x-end", b"two"),
        ]);
        let got = remove(&input).unwrap();
        assert_eq!(
            got.fields,
            vec![
                field("host", b"example.test"),
                field("x-end", b"one"),
                field("authorization", b"secret"),
                field("cookie", b"a=b"),
                field("content-length", b"3"),
                field("forwarded", b"for=old"),
                field("x-forwarded-for", b"old"),
                field("x-end", b"two")
            ],
            "{id}"
        );
        assert_eq!(
            got.removed_names,
            vec!["connection", "keep-alive", "x-hop"],
            "{id}"
        );
    });
}

#[test]
fn hop_by_hop_removal_handles_all_fixed_names_and_bad_connection_lists() {
    each_impl!(remove_hop_by_hop_headers, |remove, id| {
        let fixed = [
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authenticate",
            "proxy-authorization",
        ];
        let input = headers(fixed.iter().map(|name| field(name, b"x")).collect());
        let got = remove(&input).unwrap();
        assert!(got.fields.is_empty(), "{id}");
        let mut expected: Vec<String> = fixed.iter().map(|s| (*s).into()).collect();
        expected.push("x".into());
        expected.sort();
        assert_eq!(got.removed_names, expected, "{id}");
        let got = remove(&headers(vec![
            field("connection", b" Missing, MISSING "),
            field("x", b"y"),
        ]))
        .unwrap();
        assert_eq!(got.removed_names, vec!["connection", "missing"], "{id}");
        for value in [
            b"close,,upgrade".as_slice(),
            b"",
            b",close",
            b"close,",
            b"bad name",
            b"close, @",
        ] {
            let result = remove(&headers(vec![field("connection", value)]));
            assert!(
                matches!(result, Err(PolyguardError::InvalidHeader { ref reason, .. }) if reason == "invalid_connection_token"),
                "{id}: {value:?} -> {result:?}"
            );
        }
    });
}

fn forwarding() -> ForwardingResult {
    ForwardingResult {
        forwarded: "for=192.0.2.1;proto=https;host=\"example.test\"".into(),
        x_forwarded_for: "192.0.2.1".into(),
        x_forwarded_proto: "https".into(),
        x_forwarded_host: "example.test".into(),
    }
}

#[test]
fn canonical_head_has_one_deterministic_safe_interpretation() {
    each_impl!(construct_canonical_upstream_head, |construct, id| {
        let sanitized = SanitizedHeaders {
            fields: vec![field("x-test", b"y")],
            removed_names: vec![],
        };
        let got = construct(
            "get",
            &origin("/a?x=1"),
            &EffectiveAuthority {
                host: "example.test".into(),
                port: None,
            },
            &sanitized,
            &BodyFraming::None,
            &forwarding(),
        )
        .unwrap();
        let expected = b"GET /a?x=1 HTTP/1.1\r\nHost: example.test\r\nx-test: y\r\nForwarded: for=192.0.2.1;proto=https;host=\"example.test\"\r\nX-Forwarded-For: 192.0.2.1\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: example.test\r\nConnection: close\r\n\r\n";
        assert_eq!(got.bytes, expected, "{id}");
        assert_eq!(got.body_framing, BodyFraming::None, "{id}");
    });
}

#[test]
fn canonical_head_replaces_metadata_and_emits_exact_framing() {
    each_impl!(construct_canonical_upstream_head, |construct, id| {
        let dirty = SanitizedHeaders {
            fields: vec![
                field("host", b"evil"),
                field("host", b"also-evil"),
                field("content-length", b"999"),
                field("transfer-encoding", b"evil"),
                field("connection", b"keep-alive"),
                field("forwarded", b"for=evil"),
                field("x-forwarded-for", b"evil"),
                field("x-ok", b"v"),
            ],
            removed_names: vec![],
        };
        let authority = EffectiveAuthority {
            host: "2001:db8::1".into(),
            port: Some(8443),
        };
        let got = construct(
            "post",
            &origin("/"),
            &authority,
            &dirty,
            &BodyFraming::ContentLength(12),
            &forwarding(),
        )
        .unwrap();
        let text = String::from_utf8(got.bytes).unwrap();
        assert!(
            text.starts_with("POST / HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nx-ok: v\r\n"),
            "{id}: {text:?}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("Host:"))
                .count(),
            1,
            "{id}"
        );
        assert_eq!(text.matches("Content-Length:").count(), 1, "{id}");
        assert!(
            text.ends_with("Content-Length: 12\r\nConnection: close\r\n\r\n"),
            "{id}: {text:?}"
        );
        let chunked = construct(
            "post",
            &origin("/"),
            &EffectiveAuthority {
                host: "x.test".into(),
                port: None,
            },
            &SanitizedHeaders {
                fields: vec![],
                removed_names: vec![],
            },
            &BodyFraming::Chunked,
            &forwarding(),
        )
        .unwrap();
        assert!(
            String::from_utf8(chunked.bytes)
                .unwrap()
                .ends_with("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"),
            "{id}"
        );
    });
}

#[test]
fn canonical_head_revalidates_every_model_and_size() {
    each_impl!(construct_canonical_upstream_head, |construct, id| {
        let auth = EffectiveAuthority {
            host: "example.test".into(),
            port: None,
        };
        let empty = SanitizedHeaders {
            fields: vec![],
            removed_names: vec![],
        };
        for target in [
            NormalizedTarget {
                form: TargetForm::Authority,
                scheme: None,
                authority: Some("x:443".into()),
                path_and_query: "x:443".into(),
                routing_path: "x:443".into(),
            },
            NormalizedTarget {
                form: TargetForm::Asterisk,
                scheme: None,
                authority: None,
                path_and_query: "*".into(),
                routing_path: "*".into(),
            },
        ] {
            assert_eq!(
                construct(
                    "get",
                    &target,
                    &auth,
                    &empty,
                    &BodyFraming::None,
                    &forwarding()
                ),
                Err(PolyguardError::SerializationInvariant),
                "{id}"
            );
        }
        let too_long_method = "a".repeat(33);
        for method in ["", "bad method", "GET", "g\r\nInjected", &too_long_method] {
            assert_eq!(
                construct(
                    method,
                    &origin("/"),
                    &auth,
                    &empty,
                    &BodyFraming::None,
                    &forwarding()
                ),
                Err(PolyguardError::SerializationInvariant),
                "{id}: {method:?}"
            );
        }
        for bad in [
            field("bad name", b"v"),
            field("x", b"bad\r\nInjected: yes"),
            field("keep-alive", b"x"),
            field("te", b"trailers"),
            field("proxy-authorization", b"secret"),
        ] {
            let fields = SanitizedHeaders {
                fields: vec![bad],
                removed_names: vec![],
            };
            assert_eq!(
                construct(
                    "get",
                    &origin("/"),
                    &auth,
                    &fields,
                    &BodyFraming::None,
                    &forwarding()
                ),
                Err(PolyguardError::SerializationInvariant),
                "{id}"
            );
        }
        let unsafe_forwarding = ForwardingResult {
            forwarded: "for=x\r\nInjected: yes".into(),
            ..forwarding()
        };
        assert_eq!(
            construct(
                "get",
                &origin("/"),
                &auth,
                &empty,
                &BodyFraming::None,
                &unsafe_forwarding
            ),
            Err(PolyguardError::SerializationInvariant),
            "{id}"
        );
        let huge = SanitizedHeaders {
            fields: (0..7).map(|_| field("x", &vec![b'a'; 8192])).collect(),
            removed_names: vec![],
        };
        assert!(
            matches!(construct("get", &origin("/"), &auth, &huge, &BodyFraming::None, &forwarding()), Err(PolyguardError::LimitExceeded { ref limit, max: 49152, .. }) if limit == "canonical_head_bytes"),
            "{id}"
        );
    });
}

#[test]
fn canonical_head_round_trips_through_every_registered_parser() {
    for serializer in registered_implementations() {
        let Some(construct) = serializer.construct_canonical_upstream_head else {
            continue;
        };
        let output = construct(
            "post",
            &origin("/round?x=1"),
            &EffectiveAuthority {
                host: "example.test".into(),
                port: Some(8080),
            },
            &SanitizedHeaders {
                fields: vec![field("x-end", b"a  b")],
                removed_names: vec![],
            },
            &BodyFraming::ContentLength(3),
            &forwarding(),
        )
        .unwrap();
        for line_parser in registered_implementations() {
            let Some(parse_line) = line_parser.parse_request_line else {
                continue;
            };
            let parsed = parse_line(&output.bytes).unwrap();
            assert_eq!(
                (parsed.method.as_str(), parsed.target.as_str()),
                ("post", "/round?x=1"),
                "{} -> {}",
                serializer.id,
                line_parser.id
            );
            for header_parser in registered_implementations() {
                let Some(parse_headers) = header_parser.parse_header_section else {
                    continue;
                };
                let parsed_headers = parse_headers(&output.bytes[parsed.bytes_consumed..]).unwrap();
                assert_eq!(
                    parsed_headers.fields.first(),
                    Some(&field("host", b"example.test:8080")),
                    "{} -> {}",
                    serializer.id,
                    header_parser.id
                );
                assert!(
                    parsed_headers.fields.contains(&field("x-end", b"a  b")),
                    "{} -> {}",
                    serializer.id,
                    header_parser.id
                );
                for policy in registered_implementations() {
                    if let Some(frame) = policy.determine_body_framing {
                        assert_eq!(
                            frame(&parsed, &parsed_headers),
                            Ok(BodyFraming::ContentLength(3)),
                            "{} -> {}",
                            serializer.id,
                            policy.id
                        );
                    }
                    if let Some(reconcile) = policy.reconcile_authority {
                        assert_eq!(
                            reconcile(&origin("/round?x=1"), &parsed_headers),
                            Ok(EffectiveAuthority {
                                host: "example.test".into(),
                                port: Some(8080)
                            }),
                            "{} -> {}",
                            serializer.id,
                            policy.id
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn route_matching_is_longest_boundary_aware_and_order_independent() {
    each_impl!(match_route, |match_route, id| {
        let authority = EffectiveAuthority {
            host: "example.test".into(),
            port: Some(8443),
        };
        let rules = vec![
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/api/v1".into(),
                upstream: "v1".into(),
                declaration_order: 9,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "root".into(),
                declaration_order: 1,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/api".into(),
                upstream: "api".into(),
                declaration_order: 3,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/api/v1".into(),
                upstream: "v1-first".into(),
                declaration_order: 2,
            },
        ];
        assert_eq!(
            match_route(&authority, &origin("/api/v1/x"), &rules),
            Ok(RouteMatch {
                upstream: "v1-first".into(),
                declaration_order: 2
            }),
            "{id}"
        );
        let mut reversed = rules.clone();
        reversed.reverse();
        assert_eq!(
            match_route(&authority, &origin("/api/v1/x"), &reversed),
            Ok(RouteMatch {
                upstream: "v1-first".into(),
                declaration_order: 2
            }),
            "{id}"
        );
        assert_eq!(
            match_route(
                &authority,
                &origin("/apix"),
                &[RouteRule {
                    host: "example.test".into(),
                    path_prefix: "/api".into(),
                    upstream: "api".into(),
                    declaration_order: 0
                }]
            ),
            Err(PolyguardError::NoRoute),
            "{id}"
        );
    });
}

#[test]
fn route_matching_validates_all_rules_limits_and_target_form() {
    each_impl!(match_route, |match_route, id| {
        let authority = EffectiveAuthority {
            host: "example.test".into(),
            port: None,
        };
        let valid = RouteRule {
            host: "example.test".into(),
            path_prefix: "/a%2Fb".into(),
            upstream: "upstream-1.a".into(),
            declaration_order: 1,
        };
        assert_eq!(
            match_route(&authority, &origin("/a%2Fb"), &[valid]),
            Ok(RouteMatch {
                upstream: "upstream-1.a".into(),
                declaration_order: 1
            }),
            "{id}"
        );
        for bad in [
            RouteRule {
                host: "example.test:80".into(),
                path_prefix: "/".into(),
                upstream: "u".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "bad host".into(),
                path_prefix: "/".into(),
                upstream: "u".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "api".into(),
                upstream: "u".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/api/".into(),
                upstream: "u".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "bad/upstream".into(),
                declaration_order: 0,
            },
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "u".repeat(65),
                declaration_order: 0,
            },
        ] {
            let error = match_route(&authority, &origin("/"), &[bad]).unwrap_err();
            assert!(
                matches!(error, PolyguardError::InvalidRoute { .. }),
                "{id}: {error:?}"
            );
            assert_safe_reason(&error);
        }
        let duplicate_order = vec![
            RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "a".into(),
                declaration_order: 1,
            },
            RouteRule {
                host: "other.test".into(),
                path_prefix: "/".into(),
                upstream: "b".into(),
                declaration_order: 1,
            },
        ];
        assert!(
            matches!(
                match_route(&authority, &origin("/"), &duplicate_order),
                Err(PolyguardError::InvalidRoute { .. })
            ),
            "{id}"
        );
        let many: Vec<RouteRule> = (0..257)
            .map(|n| RouteRule {
                host: "example.test".into(),
                path_prefix: "/".into(),
                upstream: "u".into(),
                declaration_order: n,
            })
            .collect();
        assert!(
            matches!(match_route(&authority, &origin("/"), &many), Err(PolyguardError::LimitExceeded { ref limit, max: 256, actual: 257 }) if limit == "route_count"),
            "{id}"
        );
        let authority_target = NormalizedTarget {
            form: TargetForm::Authority,
            scheme: None,
            authority: Some("x:1".into()),
            path_and_query: "x:1".into(),
            routing_path: "x:1".into(),
        };
        assert!(
            matches!(
                match_route(&authority, &authority_target, &[]),
                Err(PolyguardError::InvalidRoute { .. })
            ),
            "{id}"
        );
    });
}

#[test]
fn forwarding_policy_replaces_untrusted_and_appends_trusted_values() {
    each_impl!(apply_forwarding_policy, |apply, id| {
        let spoofed = headers(vec![
            field("forwarded", b"for=evil"),
            field("x-forwarded-for", b"evil"),
            field("x-forwarded-proto", b"ftp"),
            field("x-forwarded-host", b"evil"),
        ]);
        let policy = ForwardingPolicy {
            trust_incoming: false,
            client_ip: "192.0.2.1".into(),
            proto: "https".into(),
            host: "example.test".into(),
        };
        let got = apply(&policy, &spoofed).unwrap();
        assert_eq!(
            got,
            ForwardingResult {
                forwarded: "for=192.0.2.1;proto=https;host=\"example.test\"".into(),
                x_forwarded_for: "192.0.2.1".into(),
                x_forwarded_proto: "https".into(),
                x_forwarded_host: "example.test".into()
            },
            "{id}"
        );

        let trusted = ForwardingPolicy {
            trust_incoming: true,
            ..policy.clone()
        };
        let incoming = headers(vec![
            field("forwarded", b"for=198.51.100.2"),
            field("x-forwarded-for", b"198.51.100.2"),
            field("x-forwarded-proto", b"http"),
            field("x-forwarded-host", b"old.test"),
        ]);
        let got = apply(&trusted, &incoming).unwrap();
        assert_eq!(got.x_forwarded_for, "198.51.100.2, 192.0.2.1", "{id}");
        assert_eq!(got.x_forwarded_proto, "http, https", "{id}");
        assert_eq!(got.x_forwarded_host, "old.test, example.test", "{id}");
        assert_eq!(
            got.forwarded, "for=198.51.100.2, for=192.0.2.1;proto=https;host=\"example.test\"",
            "{id}"
        );
    });
}

#[test]
fn forwarding_policy_formats_ipv6_and_validates_listener_inputs() {
    each_impl!(apply_forwarding_policy, |apply, id| {
        let policy = ForwardingPolicy {
            trust_incoming: false,
            client_ip: "2001:db8::1".into(),
            proto: "http".into(),
            host: "[2001:db8::2]:8080".into(),
        };
        let got = apply(&policy, &headers(vec![])).unwrap();
        assert_eq!(
            got.forwarded, "for=\"[2001:db8::1]\";proto=http;host=\"[2001:db8::2]:8080\"",
            "{id}"
        );
        assert_eq!(got.x_forwarded_for, "2001:db8::1", "{id}");
        for bad in [
            ForwardingPolicy {
                client_ip: "192.168.001.1".into(),
                ..policy.clone()
            },
            ForwardingPolicy {
                client_ip: "[2001:db8::1]".into(),
                ..policy.clone()
            },
            ForwardingPolicy {
                client_ip: "fe80::1%eth0".into(),
                ..policy.clone()
            },
            ForwardingPolicy {
                proto: "HTTP".into(),
                ..policy.clone()
            },
            ForwardingPolicy {
                proto: "ftp".into(),
                ..policy.clone()
            },
            ForwardingPolicy {
                host: "user@example.test".into(),
                ..policy.clone()
            },
        ] {
            assert_eq!(
                apply(&bad, &headers(vec![])),
                Err(PolyguardError::InvalidForwardingInput),
                "{id}: {bad:?}"
            );
        }
    });
}

#[test]
fn trusted_forwarding_rejects_duplicates_unsafe_lists_and_limits() {
    let policy = ForwardingPolicy {
        trust_incoming: true,
        client_ip: "192.0.2.1".into(),
        proto: "https".into(),
        host: "example.test".into(),
    };
    each_impl!(apply_forwarding_policy, |apply, id| {
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
        ] {
            assert_eq!(
                apply(
                    &policy,
                    &headers(vec![field(name, b"one"), field(name, b"two")])
                ),
                Err(PolyguardError::InvalidForwardingInput),
                "{id}: {name}"
            );
        }
        for value in [b"".as_slice(), b",x", b"x,", b"x,,y", b"x\r\ny", b"x\x80"] {
            assert_eq!(
                apply(&policy, &headers(vec![field("x-forwarded-for", value)])),
                Err(PolyguardError::InvalidForwardingInput),
                "{id}: {value:?}"
            );
        }
        let max_existing = vec![b'a'; 1014];
        let result = apply(
            &policy,
            &headers(vec![field("x-forwarded-for", &max_existing)]),
        );
        assert!(
            matches!(result, Err(PolyguardError::LimitExceeded { ref limit, max: 1024, .. }) if limit == "forwarding_value_bytes"),
            "{id}: {result:?}"
        );
        assert_eq!(
            apply(
                &policy,
                &headers(vec![field("forwarded", &vec![b'a'; 1025])])
            ),
            Err(PolyguardError::LimitExceeded {
                limit: "forwarding_value_bytes".into(),
                max: 1024,
                actual: 1025
            }),
            "{id}"
        );
    });
}

fn websocket_headers() -> HeaderBlock {
    headers(vec![
        field("connection", b"keep-alive, Upgrade"),
        field("upgrade", b"websocket"),
        field("sec-websocket-version", b"13"),
        field("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    ])
}

#[test]
fn upgrade_decision_distinguishes_no_intent_and_complete_websocket() {
    each_impl!(decide_upgrade, |decide, id| {
        assert_eq!(
            decide(&request("get", "/"), &headers(vec![]), &BodyFraming::None),
            Ok(UpgradeDecision::None),
            "{id}"
        );
        assert_eq!(
            decide(
                &request("get", "/"),
                &websocket_headers(),
                &BodyFraming::None
            ),
            Ok(UpgradeDecision::WebSocket),
            "{id}"
        );
        assert_eq!(
            decide(
                &request("get", "http://example.test/"),
                &websocket_headers(),
                &BodyFraming::None
            ),
            Ok(UpgradeDecision::WebSocket),
            "{id}"
        );
        let h2c = headers(vec![
            field("connection", b"Upgrade"),
            field("upgrade", b"h2c"),
        ]);
        assert_eq!(
            decide(&request("get", "/"), &h2c, &BodyFraming::None),
            Err(PolyguardError::UnsupportedUpgrade),
            "{id}"
        );
    });
}

#[test]
fn upgrade_requires_both_intent_sides_and_all_unique_handshake_fields() {
    each_impl!(decide_upgrade, |decide, id| {
        for one_sided in [
            headers(vec![field("upgrade", b"websocket")]),
            headers(vec![field("connection", b"upgrade")]),
        ] {
            assert_eq!(
                decide(&request("get", "/"), &one_sided, &BodyFraming::None),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}"
            );
        }
        for extra in [
            field("upgrade", b"websocket"),
            field("sec-websocket-version", b"13"),
            field("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
            field("connection", b"upgrade"),
        ] {
            let mut block = websocket_headers();
            block.fields.push(extra);
            assert_eq!(
                decide(&request("get", "/"), &block, &BodyFraming::None),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}"
            );
        }
        for (name, bad) in [
            ("upgrade", b"h2c".as_slice()),
            ("sec-websocket-version", b"12"),
            ("sec-websocket-key", b"not-base64"),
            ("sec-websocket-key", b"c2hvcnQ="),
            ("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZR=="),
        ] {
            let mut block = websocket_headers();
            block
                .fields
                .iter_mut()
                .find(|f| f.name == name)
                .unwrap()
                .value = bad.into();
            assert_eq!(
                decide(&request("get", "/"), &block, &BodyFraming::None),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}: {name}"
            );
        }
    });
}

#[test]
fn upgrade_rejects_bodies_extensions_bad_methods_targets_and_protocol_lists() {
    each_impl!(decide_upgrade, |decide, id| {
        for framing in [BodyFraming::ContentLength(1), BodyFraming::Chunked] {
            assert_eq!(
                decide(&request("get", "/"), &websocket_headers(), &framing),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}"
            );
        }
        for extra in [
            field("content-length", b"0"),
            field("transfer-encoding", b"chunked"),
            field("sec-websocket-extensions", b"permessage-deflate"),
        ] {
            let mut block = websocket_headers();
            block.fields.push(extra);
            assert_eq!(
                decide(&request("get", "/"), &block, &BodyFraming::None),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}"
            );
        }
        let mut ambiguous = websocket_headers();
        ambiguous.fields.push(field("content-length", b"0"));
        ambiguous
            .fields
            .push(field("transfer-encoding", b"chunked"));
        assert_eq!(
            decide(&request("get", "/"), &ambiguous, &BodyFraming::None),
            Err(PolyguardError::AmbiguousFraming),
            "{id}"
        );
        assert_eq!(
            decide(
                &request("post", "/"),
                &websocket_headers(),
                &BodyFraming::None
            ),
            Err(PolyguardError::UnsupportedUpgrade),
            "{id}"
        );
        assert_eq!(
            decide(
                &request("get", "*"),
                &websocket_headers(),
                &BodyFraming::None
            ),
            Err(PolyguardError::UnsupportedUpgrade),
            "{id}"
        );
        let mut valid_protocols = websocket_headers();
        valid_protocols
            .fields
            .push(field("sec-websocket-protocol", b"chat, superchat"));
        assert_eq!(
            decide(&request("get", "/"), &valid_protocols, &BodyFraming::None),
            Ok(UpgradeDecision::WebSocket),
            "{id}"
        );
        for protocols in [
            b"chat,chat".as_slice(),
            b"",
            b"chat,,super",
            b"bad protocol",
        ] {
            let mut block = websocket_headers();
            block
                .fields
                .push(field("sec-websocket-protocol", protocols));
            assert_eq!(
                decide(&request("get", "/"), &block, &BodyFraming::None),
                Err(PolyguardError::UnsupportedUpgrade),
                "{id}: {protocols:?}"
            );
        }
    });
}

#[test]
fn telemetry_mapping_is_fixed_private_and_checks_contradictions() {
    let mappings = [
        ("accepted", OutcomeCategory::Accepted, true),
        ("client_syntax", OutcomeCategory::ClientSyntax, false),
        (
            "ambiguous_framing",
            OutcomeCategory::AmbiguousFraming,
            false,
        ),
        ("policy_rejected", OutcomeCategory::PolicyRejected, false),
        ("route_missing", OutcomeCategory::RouteMissing, false),
        ("upstream_failure", OutcomeCategory::UpstreamFailure, false),
        ("timeout", OutcomeCategory::Timeout, false),
        (
            "implementation_disagreement",
            OutcomeCategory::ImplementationDisagreement,
            false,
        ),
        ("internal_failure", OutcomeCategory::InternalFailure, false),
    ];
    each_impl!(classify_telemetry_outcome, |classify, id| {
        for (code, category, success) in &mappings {
            assert_eq!(
                classify(code, false),
                Ok(TelemetryOutcome {
                    category: category.clone(),
                    success: *success
                }),
                "{id}: {code}"
            );
        }
        for code in [
            "client_syntax",
            "ambiguous_framing",
            "policy_rejected",
            "route_missing",
            "implementation_disagreement",
        ] {
            assert_eq!(
                classify(code, true),
                Err(PolyguardError::SerializationInvariant),
                "{id}: {code}"
            );
        }
        for code in [
            "accepted",
            "upstream_failure",
            "timeout",
            "internal_failure",
        ] {
            assert!(classify(code, true).is_ok(), "{id}: {code}");
        }
        for code in [
            "",
            "unknown",
            "/private/path",
            "client_syntax: user input",
            "ACCEPTED",
        ] {
            assert_eq!(
                classify(code, false),
                Err(PolyguardError::SerializationInvariant),
                "{id}: {code:?}"
            );
        }
    });
}

#[test]
fn every_documented_error_reason_is_privacy_safe() {
    for implementation in registered_implementations() {
        if let Some(parse) = implementation.parse_request_line {
            assert_safe_reason(&parse(b"GET /secret#credential HTTP/1.1\r\n").unwrap_err());
        }
        if let Some(parse) = implementation.parse_header_section {
            assert_safe_reason(&parse(b"Authorization : top-secret\r\n\r\n").unwrap_err());
        }
    }
}
