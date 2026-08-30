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
enum TargetSyntax<'a> {
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
    fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Clone, Copy)]
enum PortRule {
    Optional,
    Required,
}

#[derive(Clone, Copy)]
enum PercentContext {
    Path,
    Query,
}

struct CanonicalPath {
    path_and_query: String,
    routing_path: String,
}

struct CanonicalAuthority {
    spelling: String,
}

/// Normalize a preserved HTTP/1.1 request target using an explicit method/form rule table.
pub fn normalize_request_target(request: &RequestLine) -> Result<NormalizedTarget> {
    let target = checked_boundary(&request.target)?;
    let method = match request.method.as_str() {
        "connect" => MethodKind::Connect,
        "options" => MethodKind::Options,
        _ => MethodKind::Other,
    };
    let syntax = classify_syntax(target);

    match (method, syntax) {
        (MethodKind::Options, TargetSyntax::Asterisk) => Ok(fixed_target(
            TargetForm::Asterisk,
            None,
            None,
            "*".to_owned(),
        )),
        (MethodKind::Connect | MethodKind::Other, TargetSyntax::Asterisk) => {
            invalid_target("asterisk_method")
        }
        (MethodKind::Connect, TargetSyntax::Unclassified(authority)) => {
            let authority = canonical_authority(authority, PortRule::Required)?;
            Ok(fixed_target(
                TargetForm::Authority,
                None,
                Some(authority.spelling.clone()),
                authority.spelling,
            ))
        }
        (MethodKind::Connect, TargetSyntax::Origin(_))
        | (MethodKind::Connect, TargetSyntax::Absolute { .. }) => {
            invalid_target("connect_requires_authority")
        }
        (MethodKind::Options | MethodKind::Other, TargetSyntax::Origin(value)) => {
            let path = canonical_path(value)?;
            Ok(NormalizedTarget {
                form: TargetForm::Origin,
                scheme: None,
                authority: None,
                path_and_query: path.path_and_query,
                routing_path: path.routing_path,
            })
        }
        (MethodKind::Options | MethodKind::Other, TargetSyntax::Absolute { scheme, remainder }) => {
            normalize_absolute(scheme, remainder)
        }
        (MethodKind::Options | MethodKind::Other, TargetSyntax::Unclassified(_)) => {
            invalid_target("authority_method")
        }
    }
}

fn checked_boundary(target: &str) -> Result<&str> {
    let actual = target.len();
    if actual > TARGET_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_LIMIT,
            actual,
        });
    }
    if target.is_empty() {
        return invalid_target("empty_target");
    }

    for byte in target.bytes() {
        match byte {
            b'#' => return invalid_target("fragment_not_allowed"),
            b'\\' => return invalid_target("backslash_not_allowed"),
            b'!'..=b'~' => {}
            _ => return invalid_target("invalid_target_byte"),
        }
    }
    Ok(target)
}

fn classify_syntax(target: &str) -> TargetSyntax<'_> {
    if target == "*" {
        TargetSyntax::Asterisk
    } else if target.starts_with('/') {
        TargetSyntax::Origin(target)
    } else if starts_ascii_case_insensitive(target, "http://") {
        TargetSyntax::Absolute {
            scheme: Scheme::Http,
            remainder: &target[7..],
        }
    } else if starts_ascii_case_insensitive(target, "https://") {
        TargetSyntax::Absolute {
            scheme: Scheme::Https,
            remainder: &target[8..],
        }
    } else {
        TargetSyntax::Unclassified(target)
    }
}

fn normalize_absolute(scheme: Scheme, remainder: &str) -> Result<NormalizedTarget> {
    let authority_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let authority = canonical_authority(&remainder[..authority_end], PortRule::Optional)?;
    let suffix = &remainder[authority_end..];
    let path_input = match suffix.as_bytes().first() {
        None => "/".to_owned(),
        Some(b'?') => format!("/{suffix}"),
        Some(b'/') => suffix.to_owned(),
        Some(_) => unreachable!("authority delimiter was selected from a closed byte set"),
    };
    let path = canonical_path(&path_input)?;

    Ok(NormalizedTarget {
        form: TargetForm::Absolute,
        scheme: Some(scheme.name().into()),
        authority: Some(authority.spelling),
        path_and_query: path.path_and_query,
        routing_path: path.routing_path,
    })
}

fn canonical_path(input: &str) -> Result<CanonicalPath> {
    let (raw_path, raw_query) = match input.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (input, None),
    };
    if raw_path.is_empty() || !raw_path.starts_with('/') {
        return invalid_target("invalid_path");
    }

    let decoded_path = normalize_percent_encoding(raw_path, PercentContext::Path)?;
    let routing_path = remove_dot_segments(&decoded_path)?;
    let path_and_query = match raw_query {
        Some(query) => {
            let query = normalize_percent_encoding(query, PercentContext::Query)?;
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

fn normalize_percent_encoding(value: &str, context: PercentContext) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = bytes.get(index + 1).and_then(|byte| hex_value(*byte));
                let low = bytes.get(index + 2).and_then(|byte| hex_value(*byte));
                let decoded = match (high, low) {
                    (Some(high), Some(low)) => (high << 4) | low,
                    _ => return invalid_target("invalid_percent_encoding"),
                };
                match decoded {
                    b'/' | b'\\' if matches!(context, PercentContext::Path) => {
                        return invalid_target("encoded_separator");
                    }
                    0..=31 | 127 => return invalid_target("encoded_control"),
                    byte if is_unreserved(byte) => output.push(char::from(byte)),
                    byte => {
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        output.push('%');
                        output.push(char::from(HEX[(byte >> 4) as usize]));
                        output.push(char::from(HEX[(byte & 0x0f) as usize]));
                    }
                }
                index += 3;
            }
            byte => {
                output.push(char::from(byte));
                index += 1;
            }
        }
    }
    Ok(output)
}

fn remove_dot_segments(path: &str) -> Result<String> {
    let segments: Vec<&str> = path[1..].split('/').collect();
    let mut kept: Vec<&str> = Vec::with_capacity(segments.len());

    for (index, segment) in segments.iter().copied().enumerate() {
        let final_segment = index + 1 == segments.len();
        match segment {
            "." => {
                if final_segment {
                    kept.push("");
                }
            }
            ".." => {
                if kept.pop().is_none() {
                    return invalid_target("path_traversal");
                }
                if final_segment {
                    kept.push("");
                }
            }
            ordinary => kept.push(ordinary),
        }
    }

    let mut output = String::with_capacity(path.len());
    output.push('/');
    output.push_str(&kept.join("/"));
    Ok(output)
}

fn canonical_authority(value: &str, port_rule: PortRule) -> Result<CanonicalAuthority> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'@' | b'/' | b'?' | b'#' | b'%' | b'\\'))
    {
        return Err(PolyguardError::InvalidAuthority);
    }

    let (host, port) = match value.strip_prefix('[') {
        Some(bracketed) => bracketed_authority(bracketed, port_rule)?,
        None => dns_authority(value, port_rule)?,
    };
    let spelling = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok(CanonicalAuthority { spelling })
}

fn bracketed_authority(
    value_after_bracket: &str,
    port_rule: PortRule,
) -> Result<(String, Option<u16>)> {
    let close = value_after_bracket
        .find(']')
        .ok_or(PolyguardError::InvalidAuthority)?;
    let address = &value_after_bracket[..close];
    if address.parse::<Ipv6Addr>().is_err() || address.contains('%') {
        return Err(PolyguardError::InvalidAuthority);
    }
    let suffix = &value_after_bracket[close + 1..];
    let port = port_from_suffix(suffix, port_rule)?;
    Ok((format!("[{}]", address.to_ascii_lowercase()), port))
}

fn dns_authority(value: &str, port_rule: PortRule) -> Result<(String, Option<u16>)> {
    let (raw_host, suffix) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if raw_host.contains(':') {
        return Err(PolyguardError::InvalidAuthority);
    }
    let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(PolyguardError::InvalidAuthority);
    }
    if !host.split('.').all(valid_dns_label) {
        return Err(PolyguardError::InvalidAuthority);
    }

    let port = match suffix {
        Some(raw_port) => Some(parse_port(raw_port)?),
        None => match port_rule {
            PortRule::Optional => None,
            PortRule::Required => return Err(PolyguardError::InvalidAuthority),
        },
    };
    Ok((host.to_ascii_lowercase(), port))
}

fn port_from_suffix(suffix: &str, rule: PortRule) -> Result<Option<u16>> {
    match (suffix, rule) {
        ("", PortRule::Optional) => Ok(None),
        ("", PortRule::Required) => Err(PolyguardError::InvalidAuthority),
        (value, _) => {
            let port = value
                .strip_prefix(':')
                .ok_or(PolyguardError::InvalidAuthority)?;
            Ok(Some(parse_port(port)?))
        }
    }
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| PolyguardError::InvalidAuthority)?;
    match port {
        1..=u16::MAX => Ok(port),
        0 => Err(PolyguardError::InvalidAuthority),
    }
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn fixed_target(
    form: TargetForm,
    scheme: Option<String>,
    authority: Option<String>,
    spelling: String,
) -> NormalizedTarget {
    NormalizedTarget {
        form,
        scheme,
        authority,
        path_and_query: spelling.clone(),
        routing_path: spelling,
    }
}

fn starts_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn invalid_target<T>(reason: &'static str) -> Result<T> {
    Err(PolyguardError::InvalidTarget {
        reason: reason.into(),
    })
}
