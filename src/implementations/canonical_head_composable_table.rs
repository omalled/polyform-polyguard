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

const FORWARDING_LINES: [&[u8]; 4] = [
    b"Forwarded",
    b"X-Forwarded-For",
    b"X-Forwarded-Proto",
    b"X-Forwarded-Host",
];

#[derive(Clone, Copy)]
struct CanonicalMethod<'a>(&'a str);

#[derive(Clone, Copy)]
struct OriginTarget<'a>(&'a str);

#[derive(Clone, Copy)]
enum CanonicalHost<'a> {
    Name(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct CanonicalAuthority<'a> {
    host: CanonicalHost<'a>,
    port: Option<u16>,
}

#[derive(Clone, Copy)]
struct EndToEndFields<'a>(&'a SanitizedHeaders);

#[derive(Clone, Copy)]
struct ForwardingValues<'a>([&'a str; 4]);

#[derive(Clone, Copy)]
enum FramingLine {
    Absent,
    Length(u64),
    Chunked,
}

struct ValidatedHead<'a> {
    method: CanonicalMethod<'a>,
    target: OriginTarget<'a>,
    authority: CanonicalAuthority<'a>,
    fields: EndToEndFields<'a>,
    forwarding: ForwardingValues<'a>,
    framing: FramingLine,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputFieldDecision {
    Discard,
    Forward,
    Invalid,
}

enum WireLine<'a> {
    Request(CanonicalMethod<'a>, OriginTarget<'a>),
    Host(CanonicalAuthority<'a>),
    Bytes(&'a [u8], &'a [u8]),
    Decimal(&'static [u8], u64),
    Empty,
}

/// Construct a canonical head from fully validated wrapper values and one line recipe.
pub(crate) fn construct_canonical_upstream_head(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<CanonicalRequestHead> {
    let head = ValidatedHead::new(method, target, authority, headers, framing, forwarding)?;

    let mut serialized_len = 0usize;
    head.visit_lines(|line| {
        serialized_len = serialized_len.saturating_add(line.encoded_len());
    });
    if serialized_len > HEAD_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "canonical_head_bytes".into(),
            max: HEAD_LIMIT,
            actual: serialized_len,
        });
    }

    let mut bytes = Vec::with_capacity(serialized_len);
    head.visit_lines(|line| line.append_to(&mut bytes));
    debug_assert_eq!(bytes.len(), serialized_len);

    Ok(CanonicalRequestHead {
        bytes,
        body_framing: framing.clone(),
    })
}

impl<'a> ValidatedHead<'a> {
    fn new(
        method: &'a str,
        target: &'a NormalizedTarget,
        authority: &'a EffectiveAuthority,
        headers: &'a SanitizedHeaders,
        framing: &'a BodyFraming,
        forwarding: &'a ForwardingResult,
    ) -> Result<Self> {
        let method = CanonicalMethod::new(method)?;
        let authority = CanonicalAuthority::new(authority)?;
        let target = OriginTarget::new(target, authority)?;
        let fields = EndToEndFields::new(headers)?;
        let forwarding = ForwardingValues::new(forwarding)?;
        let framing = FramingLine::new(framing)?;

        Ok(Self {
            method,
            target,
            authority,
            fields,
            forwarding,
            framing,
        })
    }

    // This is the sole ordering table for both sizing and serialization.
    fn visit_lines(&self, mut visit: impl FnMut(WireLine<'a>)) {
        visit(WireLine::Request(self.method, self.target));
        visit(WireLine::Host(self.authority));

        for field in &self.fields.0.fields {
            if input_field_decision(&field.name) == InputFieldDecision::Forward {
                visit(WireLine::Bytes(field.name.as_bytes(), &field.value));
            }
        }

        for (name, value) in FORWARDING_LINES.into_iter().zip(self.forwarding.0) {
            visit(WireLine::Bytes(name, value.as_bytes()));
        }

        match self.framing {
            FramingLine::Absent => {}
            FramingLine::Length(value) => visit(WireLine::Decimal(b"Content-Length", value)),
            FramingLine::Chunked => visit(WireLine::Bytes(b"Transfer-Encoding", b"chunked")),
        }
        visit(WireLine::Bytes(b"Connection", b"close"));
        visit(WireLine::Empty);
    }
}

impl<'a> CanonicalMethod<'a> {
    fn new(value: &'a str) -> Result<Self> {
        let valid = (1..=METHOD_LIMIT).contains(&value.len())
            && value.bytes().all(is_token)
            && !value.bytes().any(|byte| byte.is_ascii_uppercase());
        valid.then_some(Self(value)).ok_or(invariant())
    }
}

impl<'a> OriginTarget<'a> {
    fn new(target: &'a NormalizedTarget, effective: CanonicalAuthority<'_>) -> Result<Self> {
        match (
            &target.form,
            target.scheme.as_deref(),
            target.authority.as_deref(),
        ) {
            (TargetForm::Origin, None, None) => {}
            (TargetForm::Absolute, Some(scheme @ ("http" | "https")), Some(raw_authority)) => {
                let default_port = if scheme == "http" { 80 } else { 443 };
                let source = CanonicalAuthority::from_target(raw_authority)?;
                if effective.port == Some(default_port)
                    || !source.host.same_spelling(effective.host)
                    || source.port.unwrap_or(default_port) != effective.port.unwrap_or(default_port)
                {
                    return Err(invariant());
                }
            }
            _ => return Err(invariant()),
        }

        validate_path_model(&target.path_and_query, &target.routing_path)?;
        Ok(Self(&target.path_and_query))
    }
}

impl<'a> CanonicalAuthority<'a> {
    fn new(value: &'a EffectiveAuthority) -> Result<Self> {
        if value.port == Some(0) {
            return Err(invariant());
        }

        let host = if let Some(inner) = value
            .host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
        {
            validate_ipv6(inner)?;
            CanonicalHost::Ipv6(inner)
        } else if value.host.contains(':') {
            validate_ipv6(&value.host)?;
            CanonicalHost::Ipv6(&value.host)
        } else {
            validate_dns(&value.host)?;
            CanonicalHost::Name(&value.host)
        };

        Ok(Self {
            host,
            port: value.port,
        })
    }

    fn from_target(value: &'a str) -> Result<Self> {
        if let Some(after_open) = value.strip_prefix('[') {
            let close = after_open.find(']').ok_or(invariant())?;
            let address = &after_open[..close];
            validate_ipv6(address)?;
            let suffix = &after_open[close + 1..];
            let port = if suffix.is_empty() {
                None
            } else {
                Some(parse_port(suffix.strip_prefix(':').ok_or(invariant())?)?)
            };
            return Ok(Self {
                host: CanonicalHost::Ipv6(address),
                port,
            });
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
            Some(_) => return Err(invariant()),
            None => (value, None),
        };
        validate_dns(host)?;
        Ok(Self {
            host: CanonicalHost::Name(host),
            port,
        })
    }

    fn rendered_len(self) -> usize {
        let host_len = match self.host {
            CanonicalHost::Name(value) => value.len(),
            CanonicalHost::Ipv6(value) => value.len() + 2,
        };
        host_len + self.port.map_or(0, |port| decimal_len(u64::from(port)) + 1)
    }

    fn append(self, output: &mut Vec<u8>) {
        match self.host {
            CanonicalHost::Name(value) => output.extend_from_slice(value.as_bytes()),
            CanonicalHost::Ipv6(value) => {
                output.push(b'[');
                output.extend_from_slice(value.as_bytes());
                output.push(b']');
            }
        }
        if let Some(port) = self.port {
            output.push(b':');
            append_decimal(output, u64::from(port));
        }
    }
}

impl CanonicalHost<'_> {
    fn same_spelling(self, other: Self) -> bool {
        match (self, other) {
            (Self::Name(left), Self::Name(right)) | (Self::Ipv6(left), Self::Ipv6(right)) => {
                left == right
            }
            _ => false,
        }
    }
}

impl<'a> EndToEndFields<'a> {
    fn new(headers: &'a SanitizedHeaders) -> Result<Self> {
        if headers.fields.len() > FIELD_LIMIT {
            return Err(invariant());
        }
        for field in &headers.fields {
            if !valid_canonical_name(&field.name)
                || field.value.len() > VALUE_LIMIT
                || !field.value.iter().copied().all(is_field_value)
                || field.value.first().is_some_and(|byte| is_ows(*byte))
                || field.value.last().is_some_and(|byte| is_ows(*byte))
                || input_field_decision(&field.name) == InputFieldDecision::Invalid
            {
                return Err(invariant());
            }
        }

        let mut previous = None;
        for name in &headers.removed_names {
            if !valid_canonical_name(name)
                || previous.is_some_and(|prior: &str| prior >= name.as_str())
            {
                return Err(invariant());
            }
            previous = Some(name.as_str());
        }
        Ok(Self(headers))
    }
}

impl<'a> ForwardingValues<'a> {
    fn new(value: &'a ForwardingResult) -> Result<Self> {
        let values = [
            value.forwarded.as_str(),
            value.x_forwarded_for.as_str(),
            value.x_forwarded_proto.as_str(),
            value.x_forwarded_host.as_str(),
        ];
        if values.iter().any(|value| !valid_forwarding_value(value)) {
            return Err(invariant());
        }
        Ok(Self(values))
    }
}

impl FramingLine {
    fn new(value: &BodyFraming) -> Result<Self> {
        match value {
            BodyFraming::None => Ok(Self::Absent),
            BodyFraming::ContentLength(length) if *length <= CONTENT_LENGTH_LIMIT => {
                Ok(Self::Length(*length))
            }
            BodyFraming::ContentLength(_) => Err(invariant()),
            BodyFraming::Chunked => Ok(Self::Chunked),
        }
    }
}

impl WireLine<'_> {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Request(method, target) => {
                method.0.len() + 1 + target.0.len() + b" HTTP/1.1\r\n".len()
            }
            Self::Host(authority) => b"Host: \r\n".len() + authority.rendered_len(),
            Self::Bytes(name, value) => name.len() + 2 + value.len() + 2,
            Self::Decimal(name, value) => name.len() + 2 + decimal_len(*value) + 2,
            Self::Empty => 2,
        }
    }

    fn append_to(self, output: &mut Vec<u8>) {
        match self {
            Self::Request(method, target) => {
                output.extend(method.0.bytes().map(|byte| byte.to_ascii_uppercase()));
                output.push(b' ');
                output.extend_from_slice(target.0.as_bytes());
                output.extend_from_slice(b" HTTP/1.1\r\n");
            }
            Self::Host(authority) => {
                output.extend_from_slice(b"Host: ");
                authority.append(output);
                output.extend_from_slice(b"\r\n");
            }
            Self::Bytes(name, value) => append_field(output, name, value),
            Self::Decimal(name, value) => {
                output.extend_from_slice(name);
                output.extend_from_slice(b": ");
                append_decimal(output, value);
                output.extend_from_slice(b"\r\n");
            }
            Self::Empty => output.extend_from_slice(b"\r\n"),
        }
    }
}

// Central defensive decision table for unexpected sanitized-header survivors.
fn input_field_decision(name: &str) -> InputFieldDecision {
    match name {
        "host" | "content-length" | "transfer-encoding" | "connection" | "forwarded" => {
            InputFieldDecision::Discard
        }
        "proxy-connection"
        | "keep-alive"
        | "te"
        | "trailer"
        | "upgrade"
        | "proxy-authenticate"
        | "proxy-authorization" => InputFieldDecision::Invalid,
        name if name.starts_with("x-forwarded-") => InputFieldDecision::Discard,
        _ => InputFieldDecision::Forward,
    }
}

fn validate_path_model(path_and_query: &str, routing_path: &str) -> Result<()> {
    let bytes = path_and_query.as_bytes();
    if bytes.is_empty()
        || bytes.len() > TARGET_LIMIT
        || bytes.first() != Some(&b'/')
        || !bytes
            .iter()
            .all(|byte| matches!(*byte, b'!'..=b'~') && !matches!(*byte, b'#' | b'\\'))
    {
        return Err(invariant());
    }

    let query_start = bytes
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(bytes.len());
    if routing_path.as_bytes() != &bytes[..query_start] {
        return Err(invariant());
    }
    if bytes[1..query_start]
        .split(|byte| *byte == b'/')
        .any(|segment| matches!(segment, b"." | b".."))
    {
        return Err(invariant());
    }

    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let encoded = bytes
            .get(index + 1..index + 3)
            .filter(|digits| {
                digits
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
            })
            .ok_or(invariant())?;
        let decoded = (hex(encoded[0]) << 4) | hex(encoded[1]);
        if decoded <= 31
            || decoded == 127
            || is_unreserved(decoded)
            || (index < query_start && matches!(decoded, b'/' | b'\\'))
        {
            return Err(invariant());
        }
        index += 3;
    }
    Ok(())
}

fn validate_dns(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if valid { Ok(()) } else { Err(invariant()) }
}

fn validate_ipv6(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && !value.contains('%')
        && !value.bytes().any(|byte| byte.is_ascii_uppercase())
        && value.parse::<Ipv6Addr>().is_ok();
    if valid { Ok(()) } else { Err(invariant()) }
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invariant());
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(invariant())
}

fn valid_canonical_name(value: &str) -> bool {
    (1..=NAME_LIMIT).contains(&value.len())
        && value.bytes().all(is_token)
        && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn valid_forwarding_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= FORWARDING_LIMIT
        && bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
        && bytes.first() != Some(&b' ')
        && bytes.last() != Some(&b' ')
        && !bytes
            .split(|byte| *byte == b',')
            .any(|member| member.iter().all(|byte| *byte == b' '))
}

fn append_field(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    output.extend_from_slice(name);
    output.extend_from_slice(b": ");
    output.extend_from_slice(value);
    output.extend_from_slice(b"\r\n");
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

fn decimal_len(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
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

fn invariant() -> PolyguardError {
    PolyguardError::SerializationInvariant
}
