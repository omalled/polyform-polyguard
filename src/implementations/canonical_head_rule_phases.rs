use std::net::Ipv6Addr;

use crate::{
    BodyFraming, CanonicalRequestHead, EffectiveAuthority, ForwardingResult, NormalizedTarget,
    PolyguardError, Result, SanitizedHeaders, TargetForm,
};

const METHOD_LIMIT: usize = 32;
const TARGET_LIMIT: usize = 8_192;
const FIELD_LIMIT: usize = 128;
const NAME_LIMIT: usize = 128;
const VALUE_LIMIT: usize = 8_192;
const FORWARDING_LIMIT: usize = 1_024;
const CONTENT_LENGTH_LIMIT: u64 = 16_777_216;
const HEAD_LIMIT: usize = 49_152;

const REPLACED_FIELDS: [&str; 6] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "forwarded",
    "x-forwarded-for",
];

const FORBIDDEN_SURVIVORS: [&str; 7] = [
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldAction {
    Preserve,
    Replace,
    Reject,
}

#[derive(Clone, Copy)]
enum HostKind<'a> {
    Dns(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct AuthorityParts<'a> {
    host: HostKind<'a>,
    port: Option<u16>,
}

struct SizeBudget {
    total: usize,
}

impl SizeBudget {
    fn new() -> Self {
        Self { total: 0 }
    }

    fn add(&mut self, amount: usize) {
        self.total = self.total.saturating_add(amount);
    }

    fn finish(self) -> Result<usize> {
        if self.total > HEAD_LIMIT {
            Err(PolyguardError::LimitExceeded {
                limit: "canonical_head_bytes".into(),
                max: HEAD_LIMIT,
                actual: self.total,
            })
        } else {
            Ok(self.total)
        }
    }
}

/// Validate, size, and serialize a canonical request head in independent phases.
pub(crate) fn construct_canonical_upstream_head(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<CanonicalRequestHead> {
    // Phase 1: make the entire public boundary trusted before allocating output.
    validate_method(method)?;
    validate_target(target, authority)?;
    let host = validate_effective_authority(authority)?;
    validate_headers(headers)?;
    validate_framing(framing)?;
    validate_forwarding(forwarding)?;

    // Phase 2: compute the exact serialized size and enforce the inclusive limit.
    let output_size = serialized_size(
        method, target, authority, host, headers, framing, forwarding,
    )?;

    // Phase 3: emit once into exactly-sized storage using the same closed rule table.
    let mut bytes = Vec::with_capacity(output_size);
    emit_request_line(&mut bytes, method, &target.path_and_query);
    emit_host(&mut bytes, authority, host);
    for field in &headers.fields {
        if field_action(&field.name) == FieldAction::Preserve {
            emit_field(&mut bytes, field.name.as_bytes(), &field.value);
        }
    }
    emit_field(&mut bytes, b"Forwarded", forwarding.forwarded.as_bytes());
    emit_field(
        &mut bytes,
        b"X-Forwarded-For",
        forwarding.x_forwarded_for.as_bytes(),
    );
    emit_field(
        &mut bytes,
        b"X-Forwarded-Proto",
        forwarding.x_forwarded_proto.as_bytes(),
    );
    emit_field(
        &mut bytes,
        b"X-Forwarded-Host",
        forwarding.x_forwarded_host.as_bytes(),
    );
    match framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(length) => {
            bytes.extend_from_slice(b"Content-Length: ");
            append_decimal(&mut bytes, *length);
            bytes.extend_from_slice(b"\r\n");
        }
        BodyFraming::Chunked => bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    debug_assert_eq!(bytes.len(), output_size);

    Ok(CanonicalRequestHead {
        bytes,
        body_framing: framing.clone(),
    })
}

fn validate_method(method: &str) -> Result<()> {
    if method.is_empty()
        || method.len() > METHOD_LIMIT
        || !method.bytes().all(is_token)
        || method.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return invariant();
    }
    Ok(())
}

fn validate_target(target: &NormalizedTarget, effective: &EffectiveAuthority) -> Result<()> {
    match target.form {
        TargetForm::Origin if target.scheme.is_none() && target.authority.is_none() => {}
        TargetForm::Absolute => {
            let default_port = match target.scheme.as_deref() {
                Some("http") => 80,
                Some("https") => 443,
                _ => return invariant(),
            };
            let raw = target
                .authority
                .as_deref()
                .ok_or(PolyguardError::SerializationInvariant)?;
            let from_target = parse_target_authority(raw)?;
            let from_effective = validate_effective_authority(effective)?;
            if effective.port == Some(default_port)
                || !same_host(from_target.host, from_effective)
                || from_target.port.unwrap_or(default_port)
                    != effective.port.unwrap_or(default_port)
            {
                return invariant();
            }
        }
        _ => return invariant(),
    }

    let value = target.path_and_query.as_bytes();
    if value.is_empty() || value.len() > TARGET_LIMIT || value[0] != b'/' {
        return invariant();
    }
    if !value
        .iter()
        .all(|byte| matches!(*byte, b'!'..=b'~') && !matches!(*byte, b'#' | b'\\'))
    {
        return invariant();
    }

    let query_at = value
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(value.len());
    let path = &value[..query_at];
    if target.routing_path.as_bytes() != path || !canonical_percent_encoding(value, query_at) {
        return invariant();
    }
    if path[1..]
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b"..")
    {
        return invariant();
    }
    Ok(())
}

fn canonical_percent_encoding(value: &[u8], query_at: usize) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        let Some((&high, &low)) = value.get(index + 1).zip(value.get(index + 2)) else {
            return false;
        };
        if !matches!(high, b'0'..=b'9' | b'A'..=b'F') || !matches!(low, b'0'..=b'9' | b'A'..=b'F') {
            return false;
        }
        let decoded = (hex(high) << 4) | hex(low);
        if decoded <= 31
            || decoded == 127
            || is_unreserved(decoded)
            || (index < query_at && matches!(decoded, b'/' | b'\\'))
        {
            return false;
        }
        index += 3;
    }
    true
}

fn validate_effective_authority(authority: &EffectiveAuthority) -> Result<HostKind<'_>> {
    if authority.port == Some(0) {
        return invariant();
    }
    let host = authority.host.as_str();
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        validate_ipv6(inner)?;
        Ok(HostKind::Ipv6(inner))
    } else if host.contains(':') {
        validate_ipv6(host)?;
        Ok(HostKind::Ipv6(host))
    } else {
        validate_dns(host)?;
        Ok(HostKind::Dns(host))
    }
}

fn parse_target_authority(value: &str) -> Result<AuthorityParts<'_>> {
    if let Some(after_open) = value.strip_prefix('[') {
        let close = after_open
            .find(']')
            .ok_or(PolyguardError::SerializationInvariant)?;
        let address = &after_open[..close];
        validate_ipv6(address)?;
        let suffix = &after_open[close + 1..];
        let port = parse_optional_port(suffix)?;
        return Ok(AuthorityParts {
            host: HostKind::Ipv6(address),
            port,
        });
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
        Some(_) => return invariant(),
        None => (value, None),
    };
    validate_dns(host)?;
    Ok(AuthorityParts {
        host: HostKind::Dns(host),
        port,
    })
}

fn parse_optional_port(suffix: &str) -> Result<Option<u16>> {
    if suffix.is_empty() {
        Ok(None)
    } else {
        suffix
            .strip_prefix(':')
            .ok_or(PolyguardError::SerializationInvariant)
            .and_then(parse_port)
            .map(Some)
    }
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return invariant();
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(PolyguardError::SerializationInvariant)
}

fn validate_ipv6(value: &str) -> Result<()> {
    if value.is_empty()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.contains('%')
        || value.parse::<Ipv6Addr>().is_err()
    {
        return invariant();
    }
    Ok(())
}

fn validate_dns(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.ends_with('.')
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes().first() != Some(&b'-')
                && label.as_bytes().last() != Some(&b'-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return invariant();
    }
    Ok(())
}

fn same_host(left: HostKind<'_>, right: HostKind<'_>) -> bool {
    match (left, right) {
        (HostKind::Dns(a), HostKind::Dns(b)) | (HostKind::Ipv6(a), HostKind::Ipv6(b)) => a == b,
        _ => false,
    }
}

fn validate_headers(headers: &SanitizedHeaders) -> Result<()> {
    if headers.fields.len() > FIELD_LIMIT {
        return invariant();
    }
    for field in &headers.fields {
        if field.name.is_empty()
            || field.name.len() > NAME_LIMIT
            || !field.name.bytes().all(is_token)
            || field.name.bytes().any(|byte| byte.is_ascii_uppercase())
            || field.value.len() > VALUE_LIMIT
            || !field.value.iter().copied().all(is_field_value)
            || field.value.first().is_some_and(|byte| is_ows(*byte))
            || field.value.last().is_some_and(|byte| is_ows(*byte))
            || field_action(&field.name) == FieldAction::Reject
        {
            return invariant();
        }
    }

    let mut previous: Option<&str> = None;
    for name in &headers.removed_names {
        if name.is_empty()
            || name.len() > NAME_LIMIT
            || !name.bytes().all(is_token)
            || name.bytes().any(|byte| byte.is_ascii_uppercase())
            || previous.is_some_and(|prior| prior >= name.as_str())
        {
            return invariant();
        }
        previous = Some(name);
    }
    Ok(())
}

fn field_action(name: &str) -> FieldAction {
    if REPLACED_FIELDS.contains(&name) || name.starts_with("x-forwarded-") {
        FieldAction::Replace
    } else if FORBIDDEN_SURVIVORS.contains(&name) {
        FieldAction::Reject
    } else {
        FieldAction::Preserve
    }
}

fn validate_framing(framing: &BodyFraming) -> Result<()> {
    if matches!(framing, BodyFraming::ContentLength(length) if *length > CONTENT_LENGTH_LIMIT) {
        return invariant();
    }
    Ok(())
}

fn validate_forwarding(forwarding: &ForwardingResult) -> Result<()> {
    for value in [
        &forwarding.forwarded,
        &forwarding.x_forwarded_for,
        &forwarding.x_forwarded_proto,
        &forwarding.x_forwarded_host,
    ] {
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > FORWARDING_LIMIT
            || !bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
            || bytes.first() == Some(&b' ')
            || bytes.last() == Some(&b' ')
            || bytes
                .split(|byte| *byte == b',')
                .any(|member| member.iter().all(|byte| *byte == b' '))
        {
            return invariant();
        }
    }
    Ok(())
}

fn serialized_size(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    host: HostKind<'_>,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<usize> {
    let mut size = SizeBudget::new();
    size.add(method.len() + 1 + target.path_and_query.len() + b" HTTP/1.1\r\n".len());
    size.add(b"Host: ".len() + rendered_host_len(host) + rendered_port_len(authority.port) + 2);
    for field in &headers.fields {
        if field_action(&field.name) == FieldAction::Preserve {
            size.add(field.name.len() + 2 + field.value.len() + 2);
        }
    }
    for (name, value) in [
        (b"Forwarded".as_slice(), forwarding.forwarded.as_bytes()),
        (
            b"X-Forwarded-For".as_slice(),
            forwarding.x_forwarded_for.as_bytes(),
        ),
        (
            b"X-Forwarded-Proto".as_slice(),
            forwarding.x_forwarded_proto.as_bytes(),
        ),
        (
            b"X-Forwarded-Host".as_slice(),
            forwarding.x_forwarded_host.as_bytes(),
        ),
    ] {
        size.add(name.len() + 2 + value.len() + 2);
    }
    match framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(length) => {
            size.add(b"Content-Length: \r\n".len() + decimal_len(*length));
        }
        BodyFraming::Chunked => size.add(b"Transfer-Encoding: chunked\r\n".len()),
    }
    size.add(b"Connection: close\r\n\r\n".len());
    size.finish()
}

fn rendered_host_len(host: HostKind<'_>) -> usize {
    match host {
        HostKind::Dns(value) => value.len(),
        HostKind::Ipv6(value) => value.len() + 2,
    }
}

fn rendered_port_len(port: Option<u16>) -> usize {
    port.map_or(0, |value| 1 + decimal_len(u64::from(value)))
}

fn emit_request_line(output: &mut Vec<u8>, method: &str, target: &str) {
    output.extend(method.bytes().map(|byte| byte.to_ascii_uppercase()));
    output.push(b' ');
    output.extend_from_slice(target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\n");
}

fn emit_host(output: &mut Vec<u8>, authority: &EffectiveAuthority, host: HostKind<'_>) {
    output.extend_from_slice(b"Host: ");
    match host {
        HostKind::Dns(value) => output.extend_from_slice(value.as_bytes()),
        HostKind::Ipv6(value) => {
            output.push(b'[');
            output.extend_from_slice(value.as_bytes());
            output.push(b']');
        }
    }
    if let Some(port) = authority.port {
        output.push(b':');
        append_decimal(output, u64::from(port));
    }
    output.extend_from_slice(b"\r\n");
}

fn emit_field(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    output.extend_from_slice(name);
    output.extend_from_slice(b": ");
    output.extend_from_slice(value);
    output.extend_from_slice(b"\r\n");
}

fn decimal_len(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn append_decimal(output: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[start..]);
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_field_value(byte: u8) -> bool {
    byte == b'\t' || matches!(byte, b' '..=b'~') || byte >= 0x80
}

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn invariant<T>() -> Result<T> {
    Err(PolyguardError::SerializationInvariant)
}
