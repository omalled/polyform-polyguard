use std::net::Ipv6Addr;
use std::str::FromStr;

use crate::{
    BodyFraming, CanonicalRequestHead, EffectiveAuthority, ForwardingResult, NormalizedTarget,
    PolyguardError, Result, SanitizedHeaders, TargetForm,
};

const HEAD_LIMIT: usize = 49_152;
const TARGET_LIMIT: usize = 8_192;
const METHOD_LIMIT: usize = 32;
const FIELD_COUNT_LIMIT: usize = 128;
const FIELD_NAME_LIMIT: usize = 128;
const FIELD_VALUE_LIMIT: usize = 8_192;
const FORWARDING_LIMIT: usize = 1_024;
const BODY_LIMIT: u64 = 16_777_216;

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderRule {
    Keep,
    Replace,
    Forbidden,
}

// Exact-name rules are deliberately data, rather than branches spread through serialization.
const HEADER_RULES: &[(&str, HeaderRule)] = &[
    ("host", HeaderRule::Replace),
    ("content-length", HeaderRule::Replace),
    ("transfer-encoding", HeaderRule::Replace),
    ("connection", HeaderRule::Replace),
    ("forwarded", HeaderRule::Replace),
    ("proxy-connection", HeaderRule::Forbidden),
    ("keep-alive", HeaderRule::Forbidden),
    ("te", HeaderRule::Forbidden),
    ("trailer", HeaderRule::Forbidden),
    ("upgrade", HeaderRule::Forbidden),
    ("proxy-authenticate", HeaderRule::Forbidden),
    ("proxy-authorization", HeaderRule::Forbidden),
];

struct TrustedView<'a> {
    method: &'a [u8],
    path: &'a [u8],
    authority_host: &'a [u8],
    bracket_host: bool,
}

trait HeadSink {
    fn bytes(&mut self, bytes: &[u8]) -> Option<()>;

    fn upper_ascii(&mut self, bytes: &[u8]) -> Option<()> {
        for byte in bytes {
            self.bytes(&[byte.to_ascii_uppercase()])?;
        }
        Some(())
    }

    fn decimal(&mut self, number: u64) -> Option<()> {
        let mut digits = [0_u8; 20];
        let mut cursor = digits.len();
        let mut remaining = number;
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.bytes(&digits[cursor..])
    }
}

struct Counter(usize);

impl HeadSink for Counter {
    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.0 = self.0.checked_add(bytes.len())?;
        Some(())
    }

    fn upper_ascii(&mut self, bytes: &[u8]) -> Option<()> {
        self.bytes(bytes)
    }
}

impl HeadSink for Vec<u8> {
    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.extend_from_slice(bytes);
        Some(())
    }
}

pub fn construct_canonical_upstream_head(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<CanonicalRequestHead> {
    // Phase 1: turn the public models into a small trusted view. No output is allocated here.
    let trusted = validate_boundary(method, target, authority, headers, framing, forwarding)?;

    // Phase 2: execute the emission rules against a counting sink for an exact size preflight.
    let mut counter = Counter(0);
    if emit_head(
        &mut counter,
        &trusted,
        authority,
        headers,
        framing,
        forwarding,
    )
    .is_none()
    {
        return Err(PolyguardError::LimitExceeded {
            limit: "canonical_head_bytes".into(),
            max: HEAD_LIMIT,
            actual: usize::MAX,
        });
    }
    if counter.0 > HEAD_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "canonical_head_bytes".into(),
            max: HEAD_LIMIT,
            actual: counter.0,
        });
    }

    // Phase 3: run the same rules into the one proportionally sized allocation.
    let mut bytes = Vec::with_capacity(counter.0);
    emit_head(
        &mut bytes, &trusted, authority, headers, framing, forwarding,
    )
    .ok_or(PolyguardError::SerializationInvariant)?;
    debug_assert_eq!(bytes.len(), counter.0);

    Ok(CanonicalRequestHead {
        bytes,
        body_framing: framing.clone(),
    })
}

fn validate_boundary<'a>(
    method: &'a str,
    target: &'a NormalizedTarget,
    authority: &'a EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<TrustedView<'a>> {
    let method = method.as_bytes();
    if method.is_empty()
        || method.len() > METHOD_LIMIT
        || !method.iter().copied().all(is_lower_token_byte)
    {
        return Err(PolyguardError::SerializationInvariant);
    }

    validate_target(target)?;
    let (authority_host, bracket_host) = validate_effective_authority(authority)?;

    if headers.fields.len() > FIELD_COUNT_LIMIT {
        return Err(PolyguardError::SerializationInvariant);
    }
    for field in &headers.fields {
        if field.name.is_empty()
            || field.name.len() > FIELD_NAME_LIMIT
            || !field.name.bytes().all(is_lower_token_byte)
            || field.value.len() > FIELD_VALUE_LIMIT
            || !field.value.iter().copied().all(is_field_value_byte)
            || has_edge_ows(&field.value)
        {
            return Err(PolyguardError::SerializationInvariant);
        }
        if header_rule(&field.name) == HeaderRule::Forbidden {
            return Err(PolyguardError::SerializationInvariant);
        }
    }
    let mut previous: Option<&str> = None;
    for removed in &headers.removed_names {
        if removed.is_empty()
            || removed.len() > FIELD_NAME_LIMIT
            || !removed.bytes().all(is_lower_token_byte)
            || previous.is_some_and(|name| name >= removed.as_str())
        {
            return Err(PolyguardError::SerializationInvariant);
        }
        previous = Some(removed);
    }

    if matches!(framing, BodyFraming::ContentLength(length) if *length > BODY_LIMIT) {
        return Err(PolyguardError::SerializationInvariant);
    }

    for value in [
        &forwarding.forwarded,
        &forwarding.x_forwarded_for,
        &forwarding.x_forwarded_proto,
        &forwarding.x_forwarded_host,
    ] {
        if !valid_forwarding_value(value) {
            return Err(PolyguardError::SerializationInvariant);
        }
    }

    Ok(TrustedView {
        method,
        path: target.path_and_query.as_bytes(),
        authority_host,
        bracket_host,
    })
}

fn emit_head<S: HeadSink>(
    sink: &mut S,
    trusted: &TrustedView<'_>,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Option<()> {
    sink.upper_ascii(trusted.method)?;
    sink.bytes(b" ")?;
    sink.bytes(trusted.path)?;
    sink.bytes(b" HTTP/1.1\r\nHost: ")?;
    if trusted.bracket_host {
        sink.bytes(b"[")?;
    }
    sink.bytes(trusted.authority_host)?;
    if trusted.bracket_host {
        sink.bytes(b"]")?;
    }
    if let Some(port) = authority.port {
        sink.bytes(b":")?;
        sink.decimal(u64::from(port))?;
    }
    sink.bytes(b"\r\n")?;

    for field in &headers.fields {
        if header_rule(&field.name) == HeaderRule::Keep {
            sink.bytes(field.name.as_bytes())?;
            sink.bytes(b": ")?;
            sink.bytes(&field.value)?;
            sink.bytes(b"\r\n")?;
        }
    }

    for (name, value) in [
        ("Forwarded", forwarding.forwarded.as_bytes()),
        ("X-Forwarded-For", forwarding.x_forwarded_for.as_bytes()),
        ("X-Forwarded-Proto", forwarding.x_forwarded_proto.as_bytes()),
        ("X-Forwarded-Host", forwarding.x_forwarded_host.as_bytes()),
    ] {
        sink.bytes(name.as_bytes())?;
        sink.bytes(b": ")?;
        sink.bytes(value)?;
        sink.bytes(b"\r\n")?;
    }

    match framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(length) => {
            sink.bytes(b"Content-Length: ")?;
            sink.decimal(*length)?;
            sink.bytes(b"\r\n")?;
        }
        BodyFraming::Chunked => sink.bytes(b"Transfer-Encoding: chunked\r\n")?,
    }
    sink.bytes(b"Connection: close\r\n\r\n")
}

fn header_rule(name: &str) -> HeaderRule {
    if name.starts_with("x-forwarded-") {
        return HeaderRule::Replace;
    }
    HEADER_RULES
        .iter()
        .find_map(|(candidate, rule)| (*candidate == name).then_some(*rule))
        .unwrap_or(HeaderRule::Keep)
}

fn validate_target(target: &NormalizedTarget) -> Result<()> {
    match target.form {
        TargetForm::Origin => {
            if target.scheme.is_some() || target.authority.is_some() {
                return Err(PolyguardError::SerializationInvariant);
            }
        }
        TargetForm::Absolute => {
            if !matches!(target.scheme.as_deref(), Some("http" | "https"))
                || !target
                    .authority
                    .as_deref()
                    .is_some_and(valid_canonical_authority)
            {
                return Err(PolyguardError::SerializationInvariant);
            }
        }
        TargetForm::Authority | TargetForm::Asterisk => {
            return Err(PolyguardError::SerializationInvariant);
        }
    }

    let path = target.path_and_query.as_bytes();
    if path.is_empty() || path.len() > TARGET_LIMIT || path[0] != b'/' {
        return Err(PolyguardError::SerializationInvariant);
    }
    let query_at = path
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(path.len());
    if target.routing_path.as_bytes() != &path[..query_at]
        || !valid_canonical_target_bytes(path)
        || target
            .routing_path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(PolyguardError::SerializationInvariant);
    }
    Ok(())
}

fn valid_canonical_target_bytes(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte == b'%' {
            if cursor + 2 >= bytes.len() {
                return false;
            }
            let high = bytes[cursor + 1];
            let low = bytes[cursor + 2];
            if !is_upper_hex(high) || !is_upper_hex(low) {
                return false;
            }
            let decoded = (hex_value(high) << 4) | hex_value(low);
            if is_unreserved(decoded) || matches!(decoded, b'/' | b'\\' | 0..=31 | 127) {
                return false;
            }
            cursor += 3;
            continue;
        }
        if !(0x21..=0x7e).contains(&byte) || matches!(byte, b'\\' | b'#') {
            return false;
        }
        cursor += 1;
    }
    true
}

fn validate_effective_authority(authority: &EffectiveAuthority) -> Result<(&[u8], bool)> {
    if authority.port == Some(0) {
        return Err(PolyguardError::SerializationInvariant);
    }
    let host = authority.host.as_str();
    if host.starts_with('[') || host.ends_with(']') {
        let Some(inner) = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        else {
            return Err(PolyguardError::SerializationInvariant);
        };
        if !valid_canonical_ipv6(inner) {
            return Err(PolyguardError::SerializationInvariant);
        }
        return Ok((inner.as_bytes(), true));
    }
    if host.contains(':') {
        if !valid_canonical_ipv6(host) {
            return Err(PolyguardError::SerializationInvariant);
        }
        return Ok((host.as_bytes(), true));
    }
    if !valid_canonical_dns(host) {
        return Err(PolyguardError::SerializationInvariant);
    }
    Ok((host.as_bytes(), false))
}

fn valid_canonical_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        if !valid_canonical_ipv6(&rest[..close]) {
            return false;
        }
        let suffix = &rest[close + 1..];
        return suffix.is_empty() || valid_port_suffix(suffix);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    valid_canonical_dns(host) && port.is_none_or(valid_port)
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port
            .parse::<u16>()
            .is_ok_and(|number| (1..=u16::MAX).contains(&number))
}

fn valid_canonical_dns(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_canonical_ipv6(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('%')
        && !host.bytes().any(|byte| byte.is_ascii_uppercase())
        && Ipv6Addr::from_str(host).is_ok()
}

fn valid_forwarding_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > FORWARDING_LIMIT
        || !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
        || has_edge_ows(bytes)
    {
        return false;
    }

    let mut quoted = false;
    let mut escaped = false;
    let mut member_start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b',' {
            if bytes[member_start..index]
                .iter()
                .all(|byte| matches!(byte, b' ' | b'\t'))
            {
                return false;
            }
            member_start = index + 1;
        }
    }
    !quoted
        && !escaped
        && !bytes[member_start..]
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t'))
}

fn has_edge_ows(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        || bytes
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
}

fn is_lower_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80
}

fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn hex_value(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte - b'A' + 10
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
