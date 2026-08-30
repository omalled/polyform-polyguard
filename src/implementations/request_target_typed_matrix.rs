use std::net::Ipv6Addr;

use crate::{NormalizedTarget, PolyguardError, RequestLine, Result, TargetForm};

const TARGET_LIMIT: usize = 8192;

#[derive(Clone, Copy)]
enum MethodKind {
    Connect,
    Options,
    Other,
}

#[derive(Clone, Copy)]
enum TargetKind<'a> {
    Asterisk,
    Origin(&'a str),
    Absolute { scheme: Scheme, remainder: &'a str },
    Unclassified(&'a str),
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn text(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

struct Boundary<'a> {
    method: MethodKind,
    target: TargetKind<'a>,
}

struct CanonicalPath {
    path_and_query: String,
    routing_path: String,
}

struct CanonicalAuthority(String);

enum AuthorityPort {
    Required,
    Optional,
}

#[derive(Clone, Copy)]
enum EscapeContext {
    Path,
    Query,
}

/// Normalize a request target through a typed method/form rule matrix.
pub fn normalize_request_target(request: &RequestLine) -> Result<NormalizedTarget> {
    let boundary = Boundary::check(request)?;

    match (boundary.method, boundary.target) {
        (MethodKind::Options, TargetKind::Asterisk) => Ok(NormalizedTarget {
            form: TargetForm::Asterisk,
            scheme: None,
            authority: None,
            path_and_query: "*".into(),
            routing_path: "*".into(),
        }),
        (MethodKind::Connect | MethodKind::Other, TargetKind::Asterisk) => {
            Err(invalid_target("asterisk_method"))
        }
        (MethodKind::Connect, TargetKind::Unclassified(raw)) => authority_result(raw),
        (MethodKind::Connect, TargetKind::Origin(_))
        | (MethodKind::Connect, TargetKind::Absolute { .. }) => Err(invalid_target("connect_form")),
        (MethodKind::Options | MethodKind::Other, TargetKind::Origin(raw)) => origin_result(raw),
        (MethodKind::Options | MethodKind::Other, TargetKind::Absolute { scheme, remainder }) => {
            absolute_result(scheme, remainder)
        }
        (MethodKind::Options | MethodKind::Other, TargetKind::Unclassified(_)) => {
            Err(invalid_target("invalid_form"))
        }
    }
}

impl<'a> Boundary<'a> {
    fn check(request: &'a RequestLine) -> Result<Self> {
        let actual = request.target.len();
        if actual > TARGET_LIMIT {
            return Err(PolyguardError::LimitExceeded {
                limit: "target_bytes".into(),
                max: TARGET_LIMIT,
                actual,
            });
        }

        let method = if request.method.eq_ignore_ascii_case("CONNECT") {
            MethodKind::Connect
        } else if request.method.eq_ignore_ascii_case("OPTIONS") {
            MethodKind::Options
        } else {
            MethodKind::Other
        };

        let raw = request.target.as_str();
        let target = match raw {
            "*" => TargetKind::Asterisk,
            value if value.starts_with('/') => TargetKind::Origin(value),
            value if ascii_prefix(value, b"http://") => TargetKind::Absolute {
                scheme: Scheme::Http,
                remainder: &value[7..],
            },
            value if ascii_prefix(value, b"https://") => TargetKind::Absolute {
                scheme: Scheme::Https,
                remainder: &value[8..],
            },
            value => TargetKind::Unclassified(value),
        };

        Ok(Self { method, target })
    }
}

fn origin_result(raw: &str) -> Result<NormalizedTarget> {
    let canonical = canonical_path_query(raw)?;
    Ok(NormalizedTarget {
        form: TargetForm::Origin,
        scheme: None,
        authority: None,
        path_and_query: canonical.path_and_query,
        routing_path: canonical.routing_path,
    })
}

fn absolute_result(scheme: Scheme, remainder: &str) -> Result<NormalizedTarget> {
    if remainder.contains('#') {
        return Err(invalid_target("fragment"));
    }

    let authority_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let (raw_authority, tail) = remainder.split_at(authority_end);
    let authority = CanonicalAuthority::parse(raw_authority, AuthorityPort::Optional)?;

    let owned_path;
    let path = match tail.as_bytes().first() {
        None => "/",
        Some(b'?') => {
            owned_path = format!("/{tail}");
            &owned_path
        }
        Some(b'/') => tail,
        Some(_) => return Err(invalid_target("invalid_form")),
    };
    let canonical = canonical_path_query(path)?;

    Ok(NormalizedTarget {
        form: TargetForm::Absolute,
        scheme: Some(scheme.text().into()),
        authority: Some(authority.0),
        path_and_query: canonical.path_and_query,
        routing_path: canonical.routing_path,
    })
}

fn authority_result(raw: &str) -> Result<NormalizedTarget> {
    let authority = CanonicalAuthority::parse(raw, AuthorityPort::Required)?.0;
    Ok(NormalizedTarget {
        form: TargetForm::Authority,
        scheme: None,
        authority: Some(authority.clone()),
        path_and_query: authority.clone(),
        routing_path: authority,
    })
}

impl CanonicalAuthority {
    fn parse(raw: &str, port_rule: AuthorityPort) -> Result<Self> {
        if raw.is_empty() || !raw.is_ascii() {
            return Err(PolyguardError::InvalidAuthority);
        }

        let (host, port) = match raw.as_bytes().first() {
            Some(b'[') => bracketed_host(raw)?,
            Some(_) => named_host(raw)?,
            None => return Err(PolyguardError::InvalidAuthority),
        };

        match (port_rule, port) {
            (AuthorityPort::Required, None) => return Err(PolyguardError::InvalidAuthority),
            (AuthorityPort::Required | AuthorityPort::Optional, Some(value)) => {
                validate_port(value)?
            }
            (AuthorityPort::Optional, None) => {}
        }

        let mut rendered = String::with_capacity(raw.len());
        rendered.push_str(&host.to_ascii_lowercase());
        if let Some(value) = port {
            rendered.push(':');
            rendered.push_str(value);
        }
        Ok(Self(rendered))
    }
}

fn bracketed_host(raw: &str) -> Result<(&str, Option<&str>)> {
    let closing = raw.find(']').ok_or(PolyguardError::InvalidAuthority)?;
    let literal = &raw[1..closing];
    if literal.is_empty() || literal.contains('%') || literal.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }

    let suffix = &raw[closing + 1..];
    let port = match suffix {
        "" => None,
        value if value.starts_with(':') => Some(&value[1..]),
        _ => return Err(PolyguardError::InvalidAuthority),
    };
    Ok((&raw[..=closing], port))
}

fn named_host(raw: &str) -> Result<(&str, Option<&str>)> {
    let (host_with_dot, port) = match raw.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        Some(_) => return Err(PolyguardError::InvalidAuthority),
        None => (raw, None),
    };
    let host = host_with_dot.strip_suffix('.').unwrap_or(host_with_dot);

    if host.is_empty()
        || host.len() > 253
        || !host.split('.').all(valid_dns_label)
        || host_with_dot.ends_with("..")
    {
        return Err(PolyguardError::InvalidAuthority);
    }
    Ok((host, port))
}

fn valid_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_port(raw: &str) -> Result<()> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    match raw.parse::<u32>() {
        Ok(1..=65535) => Ok(()),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn canonical_path_query(raw: &str) -> Result<CanonicalPath> {
    if !raw.starts_with('/') {
        return Err(invalid_target("invalid_form"));
    }
    if raw.contains('#') {
        return Err(invalid_target("fragment"));
    }

    let (path, query) = match raw.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (raw, None),
    };
    let decoded_path = canonical_escapes(path, EscapeContext::Path)?;
    let routing_path = reduce_dot_segments(&decoded_path)?;

    let path_and_query = match query {
        Some(value) => {
            let query = canonical_escapes(value, EscapeContext::Query)?;
            let mut combined = String::with_capacity(routing_path.len() + query.len() + 1);
            combined.push_str(&routing_path);
            combined.push('?');
            combined.push_str(&query);
            combined
        }
        None => routing_path.clone(),
    };

    if path_and_query.len() > TARGET_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_LIMIT,
            actual: path_and_query.len(),
        });
    }
    Ok(CanonicalPath {
        path_and_query,
        routing_path,
    })
}

fn canonical_escapes(raw: &str, context: EscapeContext) -> Result<String> {
    let source = raw.as_bytes();
    let mut output = Vec::with_capacity(source.len());
    let mut cursor = 0;

    while cursor < source.len() {
        match source[cursor] {
            b'\\' | b' ' | 0..=31 | 127 => return Err(invalid_target("forbidden_character")),
            b'%' => {
                let high = source.get(cursor + 1).and_then(|byte| hex_value(*byte));
                let low = source.get(cursor + 2).and_then(|byte| hex_value(*byte));
                let decoded = match (high, low) {
                    (Some(high), Some(low)) => (high << 4) | low,
                    _ => return Err(invalid_target("invalid_percent_encoding")),
                };

                match (context, decoded) {
                    (EscapeContext::Path, b'/' | b'\\') => {
                        return Err(invalid_target("encoded_separator"));
                    }
                    (_, 0..=31 | 127) => return Err(invalid_target("encoded_control")),
                    (_, value) if is_unreserved(value) => output.push(value),
                    (_, value) => {
                        output.push(b'%');
                        output.push(upper_hex(value >> 4));
                        output.push(upper_hex(value & 0x0f));
                    }
                }
                cursor += 3;
            }
            byte => {
                output.push(byte);
                cursor += 1;
            }
        }
    }

    String::from_utf8(output).map_err(|_| invalid_target("invalid_encoding"))
}

fn reduce_dot_segments(path: &str) -> Result<String> {
    let mut kept = Vec::new();
    kept.push("");
    let segments: Vec<&str> = path.split('/').skip(1).collect();

    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        match *segment {
            "." => {
                if last {
                    kept.push("");
                }
            }
            ".." => {
                if kept.len() == 1 {
                    return Err(invalid_target("path_traversal"));
                }
                kept.pop();
                if last && kept.last().copied() != Some("") {
                    kept.push("");
                }
            }
            ordinary => kept.push(ordinary),
        }
    }

    let mut result = kept.join("/");
    if result.is_empty() {
        result.push('/');
    }
    Ok(result)
}

fn ascii_prefix(value: &str, prefix: &[u8]) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn upper_hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'A' + value - 10,
        _ => unreachable!("hex nibble"),
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn invalid_target(reason: &str) -> PolyguardError {
    PolyguardError::InvalidTarget {
        reason: reason.into(),
    }
}
