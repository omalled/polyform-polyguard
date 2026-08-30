use std::net::Ipv6Addr;

use crate::{
    BodyFraming, CanonicalRequestHead, EffectiveAuthority, ForwardingResult, NormalizedTarget,
    PolyguardError, Result, SanitizedHeaders, TargetForm,
};

const METHOD_MAX: usize = 32;
const TARGET_MAX: usize = 8_192;
const HEADER_COUNT_MAX: usize = 128;
const HEADER_NAME_MAX: usize = 128;
const HEADER_VALUE_MAX: usize = 8_192;
const FORWARDING_VALUE_MAX: usize = 1_024;
const BODY_MAX: u64 = 16_777_216;
const CANONICAL_HEAD_MAX: usize = 49_152;

const BYTE_TOKEN: u8 = 1 << 0;
const BYTE_FIELD_VALUE: u8 = 1 << 1;
const BYTE_UPPER_HEX: u8 = 1 << 2;
const BYTE_UNRESERVED: u8 = 1 << 3;
const BYTE_DNS: u8 = 1 << 4;

const KEEP: u8 = 0;
const DISCARD: u8 = 1;
const FORBID: u8 = 2;

// Exact-name rules are intentionally data: adding a hop-by-hop field cannot silently
// become an emission-control-flow change.
const HEADER_RULES: [(&str, u8); 12] = [
    ("host", DISCARD),
    ("content-length", DISCARD),
    ("transfer-encoding", DISCARD),
    ("connection", DISCARD),
    ("forwarded", DISCARD),
    ("proxy-connection", FORBID),
    ("keep-alive", FORBID),
    ("te", FORBID),
    ("trailer", FORBID),
    ("upgrade", FORBID),
    ("proxy-authenticate", FORBID),
    ("proxy-authorization", FORBID),
];

const FORWARDING_NAMES: [&[u8]; 4] = [
    b"Forwarded",
    b"X-Forwarded-For",
    b"X-Forwarded-Proto",
    b"X-Forwarded-Host",
];

const BYTE_RULES: [u8; 256] = build_byte_rules();

struct ParsedAuthority<'a> {
    host: &'a str,
    ipv6: bool,
    port: Option<u16>,
}

// A u128 is both the validation result and the emission plan for the bounded input fields.
// No retained-name collection or second classification pass is needed.
struct WirePlan<'a> {
    retained_fields: u128,
    host: &'a str,
    host_is_ipv6: bool,
    encoded_len: usize,
}

/// Compile trusted model values into a compact wire plan, then emit that plan once.
pub(crate) fn construct_canonical_upstream_head(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<CanonicalRequestHead> {
    // Phase one validates the entire public boundary and computes the exact bounded size.
    let plan = compile_wire_plan(method, target, authority, headers, framing, forwarding)?;

    // Phase two only consumes trusted values and primitive decisions from the plan.
    let mut bytes = Vec::with_capacity(plan.encoded_len);
    for byte in method.bytes() {
        bytes.push(byte.to_ascii_uppercase());
    }
    bytes.push(b' ');
    bytes.extend_from_slice(target.path_and_query.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\nHost: ");

    if plan.host_is_ipv6 {
        bytes.push(b'[');
    }
    bytes.extend_from_slice(plan.host.as_bytes());
    if plan.host_is_ipv6 {
        bytes.push(b']');
    }
    if let Some(port) = authority.port {
        bytes.push(b':');
        append_u64(&mut bytes, u64::from(port));
    }
    bytes.extend_from_slice(b"\r\n");

    for (index, field) in headers.fields.iter().enumerate() {
        if plan.retained_fields & (1_u128 << index) != 0 {
            append_header(&mut bytes, field.name.as_bytes(), &field.value);
        }
    }

    let forwarding_values = [
        forwarding.forwarded.as_bytes(),
        forwarding.x_forwarded_for.as_bytes(),
        forwarding.x_forwarded_proto.as_bytes(),
        forwarding.x_forwarded_host.as_bytes(),
    ];
    for index in 0..FORWARDING_NAMES.len() {
        append_header(
            &mut bytes,
            FORWARDING_NAMES[index],
            forwarding_values[index],
        );
    }

    match framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(length) => {
            bytes.extend_from_slice(b"Content-Length: ");
            append_u64(&mut bytes, *length);
            bytes.extend_from_slice(b"\r\n");
        }
        BodyFraming::Chunked => bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    debug_assert_eq!(bytes.len(), plan.encoded_len);

    Ok(CanonicalRequestHead {
        bytes,
        body_framing: framing.clone(),
    })
}

fn compile_wire_plan<'a>(
    method: &str,
    target: &NormalizedTarget,
    authority: &'a EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<WirePlan<'a>> {
    if !(1..=METHOD_MAX).contains(&method.len())
        || method
            .bytes()
            .any(|byte| byte_rule(byte) & BYTE_TOKEN == 0 || byte.is_ascii_uppercase())
    {
        return invariant();
    }

    let parsed_authority = parse_effective_authority(authority)?;
    validate_target(target, &parsed_authority)?;

    if headers.fields.len() > HEADER_COUNT_MAX {
        return invariant();
    }

    let mut retained_fields = 0_u128;
    let mut encoded_len = 0_usize;
    add_size(
        &mut encoded_len,
        method.len() + 1 + target.path_and_query.len() + b" HTTP/1.1\r\n".len(),
    );
    let rendered_host_len = parsed_authority.host.len()
        + usize::from(parsed_authority.ipv6) * 2
        + parsed_authority
            .port
            .map_or(0, |port| 1 + decimal_digits(u64::from(port)));
    add_size(&mut encoded_len, b"Host: \r\n".len() + rendered_host_len);

    for (index, field) in headers.fields.iter().enumerate() {
        if !canonical_name(&field.name)
            || field.value.len() > HEADER_VALUE_MAX
            || field
                .value
                .iter()
                .any(|byte| byte_rule(*byte) & BYTE_FIELD_VALUE == 0)
            || field.value.first().is_some_and(|byte| is_ows(*byte))
            || field.value.last().is_some_and(|byte| is_ows(*byte))
        {
            return invariant();
        }

        match header_rule(&field.name) {
            FORBID => return invariant(),
            DISCARD => {}
            KEEP => {
                retained_fields |= 1_u128 << index;
                add_size(
                    &mut encoded_len,
                    field.name.len() + 2 + field.value.len() + 2,
                );
            }
            _ => unreachable!(),
        }
    }

    let mut previous_removed: Option<&str> = None;
    for name in &headers.removed_names {
        if !canonical_name(name)
            || previous_removed.is_some_and(|previous| previous >= name.as_str())
        {
            return invariant();
        }
        previous_removed = Some(name);
    }

    let forwarding_values = [
        forwarding.forwarded.as_str(),
        forwarding.x_forwarded_for.as_str(),
        forwarding.x_forwarded_proto.as_str(),
        forwarding.x_forwarded_host.as_str(),
    ];
    for index in 0..FORWARDING_NAMES.len() {
        let value = forwarding_values[index];
        if !valid_forwarding_value(value) {
            return invariant();
        }
        add_size(
            &mut encoded_len,
            FORWARDING_NAMES[index].len() + 2 + value.len() + 2,
        );
    }

    match framing {
        BodyFraming::None => {}
        BodyFraming::ContentLength(length) if *length <= BODY_MAX => add_size(
            &mut encoded_len,
            b"Content-Length: \r\n".len() + decimal_digits(*length),
        ),
        BodyFraming::ContentLength(_) => return invariant(),
        BodyFraming::Chunked => add_size(&mut encoded_len, b"Transfer-Encoding: chunked\r\n".len()),
    }
    add_size(&mut encoded_len, b"Connection: close\r\n\r\n".len());

    if encoded_len > CANONICAL_HEAD_MAX {
        return Err(PolyguardError::LimitExceeded {
            limit: "canonical_head_bytes".into(),
            max: CANONICAL_HEAD_MAX,
            actual: encoded_len,
        });
    }

    Ok(WirePlan {
        retained_fields,
        host: parsed_authority.host,
        host_is_ipv6: parsed_authority.ipv6,
        encoded_len,
    })
}

fn validate_target(target: &NormalizedTarget, effective: &ParsedAuthority<'_>) -> Result<()> {
    match (
        &target.form,
        target.scheme.as_deref(),
        target.authority.as_deref(),
    ) {
        (TargetForm::Origin, None, None) => {}
        (TargetForm::Absolute, Some(scheme @ ("http" | "https")), Some(raw_authority)) => {
            let target_authority = parse_target_authority(raw_authority)?;
            let default_port = if scheme == "http" { 80 } else { 443 };
            if effective.port == Some(default_port)
                || effective.ipv6 != target_authority.ipv6
                || effective.host != target_authority.host
                || effective.port.unwrap_or(default_port)
                    != target_authority.port.unwrap_or(default_port)
            {
                return invariant();
            }
        }
        _ => return invariant(),
    }

    let bytes = target.path_and_query.as_bytes();
    if bytes.is_empty()
        || bytes.len() > TARGET_MAX
        || bytes[0] != b'/'
        || bytes
            .iter()
            .any(|byte| !matches!(*byte, b'!'..=b'~') || matches!(*byte, b'#' | b'\\'))
    {
        return invariant();
    }

    let query_at = bytes
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(bytes.len());
    if target.routing_path.as_bytes() != &bytes[..query_at]
        || bytes[1..query_at]
            .split(|byte| *byte == b'/')
            .any(|segment| segment == b"." || segment == b"..")
    {
        return invariant();
    }

    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'%' {
            cursor += 1;
            continue;
        }
        let Some(encoded) = bytes.get(cursor + 1..cursor + 3) else {
            return invariant();
        };
        if encoded
            .iter()
            .any(|byte| byte_rule(*byte) & BYTE_UPPER_HEX == 0)
        {
            return invariant();
        }
        let decoded = (hex_value(encoded[0]) << 4) | hex_value(encoded[1]);
        if decoded <= 31
            || decoded == 127
            || byte_rule(decoded) & BYTE_UNRESERVED != 0
            || (cursor < query_at && matches!(decoded, b'/' | b'\\'))
        {
            return invariant();
        }
        cursor += 3;
    }
    Ok(())
}

fn parse_effective_authority(value: &EffectiveAuthority) -> Result<ParsedAuthority<'_>> {
    if value.port == Some(0) {
        return invariant();
    }
    if let Some(unbracketed) = value
        .host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        validate_ipv6(unbracketed)?;
        return Ok(ParsedAuthority {
            host: unbracketed,
            ipv6: true,
            port: value.port,
        });
    }
    if value.host.contains(':') {
        validate_ipv6(&value.host)?;
        return Ok(ParsedAuthority {
            host: &value.host,
            ipv6: true,
            port: value.port,
        });
    }
    validate_dns(&value.host)?;
    Ok(ParsedAuthority {
        host: &value.host,
        ipv6: false,
        port: value.port,
    })
}

fn parse_target_authority(value: &str) -> Result<ParsedAuthority<'_>> {
    if let Some(remainder) = value.strip_prefix('[') {
        let closing = remainder
            .find(']')
            .ok_or(PolyguardError::SerializationInvariant)?;
        let host = &remainder[..closing];
        validate_ipv6(host)?;
        let suffix = &remainder[closing + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(
                suffix
                    .strip_prefix(':')
                    .ok_or(PolyguardError::SerializationInvariant)?,
            )?)
        };
        return Ok(ParsedAuthority {
            host,
            ipv6: true,
            port,
        });
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, raw_port)) if !host.contains(':') => (host, Some(parse_port(raw_port)?)),
        Some(_) => return invariant(),
        None => (value, None),
    };
    validate_dns(host)?;
    Ok(ParsedAuthority {
        host,
        ipv6: false,
        port,
    })
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
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
        || value.contains('%')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.parse::<Ipv6Addr>().is_err()
    {
        return invariant();
    }
    Ok(())
}

fn validate_dns(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label.bytes().any(|byte| byte_rule(byte) & BYTE_DNS == 0)
        })
    {
        return invariant();
    }
    Ok(())
}

fn canonical_name(value: &str) -> bool {
    (1..=HEADER_NAME_MAX).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte_rule(byte) & BYTE_TOKEN != 0 && !byte.is_ascii_uppercase())
}

fn header_rule(name: &str) -> u8 {
    if name.starts_with("x-forwarded-") {
        return DISCARD;
    }
    HEADER_RULES
        .iter()
        .find_map(|(candidate, rule)| (*candidate == name).then_some(*rule))
        .unwrap_or(KEEP)
}

fn valid_forwarding_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= FORWARDING_VALUE_MAX
        && bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
        && bytes.first() != Some(&b' ')
        && bytes.last() != Some(&b' ')
        && !bytes
            .split(|byte| *byte == b',')
            .any(|member| member.iter().all(|byte| *byte == b' '))
}

fn append_header(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    output.extend_from_slice(name);
    output.extend_from_slice(b": ");
    output.extend_from_slice(value);
    output.extend_from_slice(b"\r\n");
}

fn append_u64(output: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut first = digits.len();
    loop {
        first -= 1;
        digits[first] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            output.extend_from_slice(&digits[first..]);
            return;
        }
    }
}

fn decimal_digits(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

fn add_size(total: &mut usize, amount: usize) {
    *total = total.saturating_add(amount);
}

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn byte_rule(byte: u8) -> u8 {
    BYTE_RULES[usize::from(byte)]
}

const fn build_byte_rules() -> [u8; 256] {
    let mut table = [0_u8; 256];
    let mut value = 0_usize;
    while value < table.len() {
        let byte = value as u8;
        let alphanumeric = (byte >= b'0' && byte <= b'9')
            || (byte >= b'A' && byte <= b'Z')
            || (byte >= b'a' && byte <= b'z');
        let token_punctuation = matches!(
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
        );
        if alphanumeric || token_punctuation {
            table[value] |= BYTE_TOKEN;
        }
        if byte == b'\t' || (byte >= b' ' && byte <= b'~') || byte >= 0x80 {
            table[value] |= BYTE_FIELD_VALUE;
        }
        if (byte >= b'0' && byte <= b'9') || (byte >= b'A' && byte <= b'F') {
            table[value] |= BYTE_UPPER_HEX;
        }
        if alphanumeric || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            table[value] |= BYTE_UNRESERVED;
        }
        if (byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9') || byte == b'-' {
            table[value] |= BYTE_DNS;
        }
        value += 1;
    }
    table
}

fn invariant<T>() -> Result<T> {
    Err(PolyguardError::SerializationInvariant)
}
