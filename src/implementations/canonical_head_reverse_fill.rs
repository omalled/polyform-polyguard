use std::net::Ipv6Addr;

use crate::{
    BodyFraming, CanonicalRequestHead, EffectiveAuthority, ForwardingResult, NormalizedTarget,
    PolyguardError, Result, SanitizedHeaders, TargetForm,
};

const METHOD_MAX: usize = 32;
const TARGET_MAX: usize = 8_192;
const FIELD_COUNT_MAX: usize = 128;
const FIELD_NAME_MAX: usize = 128;
const FIELD_VALUE_MAX: usize = 8_192;
const FORWARDING_VALUE_MAX: usize = 1_024;
const BODY_MAX: u64 = 16_777_216;
const HEAD_MAX: usize = 49_152;

#[derive(Clone, Copy)]
struct Method<'a>(&'a str);

#[derive(Clone, Copy)]
struct OriginRoute<'a>(&'a str);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Host<'a> {
    Name(&'a str),
    Ipv6(&'a str),
}

#[derive(Clone, Copy)]
struct Authority<'a> {
    host: Host<'a>,
    port: Option<u16>,
}

struct EndToEnd<'a> {
    source: &'a SanitizedHeaders,
    retained: u128,
}

#[derive(Clone, Copy)]
struct Forwarding<'a>([&'a str; 4]);

#[derive(Clone, Copy)]
enum Framing {
    None,
    Length(u64),
    Chunked,
}

struct Validated<'a> {
    method: Method<'a>,
    route: OriginRoute<'a>,
    authority: Authority<'a>,
    fields: EndToEnd<'a>,
    forwarding: Forwarding<'a>,
    framing: Framing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SurvivorDecision {
    Retain,
    Replace,
    Reject,
}

const SURVIVOR_TABLE: [(&str, SurvivorDecision); 12] = [
    ("host", SurvivorDecision::Replace),
    ("content-length", SurvivorDecision::Replace),
    ("transfer-encoding", SurvivorDecision::Replace),
    ("connection", SurvivorDecision::Replace),
    ("forwarded", SurvivorDecision::Replace),
    ("proxy-connection", SurvivorDecision::Reject),
    ("keep-alive", SurvivorDecision::Reject),
    ("te", SurvivorDecision::Reject),
    ("trailer", SurvivorDecision::Reject),
    ("upgrade", SurvivorDecision::Reject),
    ("proxy-authenticate", SurvivorDecision::Reject),
    ("proxy-authorization", SurvivorDecision::Reject),
];

const FORWARDING_NAMES: [&[u8]; 4] = [
    b"Forwarded",
    b"X-Forwarded-For",
    b"X-Forwarded-Proto",
    b"X-Forwarded-Host",
];

/// Validate every model, then fill one exact-size wire image from tail to head.
pub(crate) fn construct_canonical_upstream_head(
    method: &str,
    target: &NormalizedTarget,
    authority: &EffectiveAuthority,
    headers: &SanitizedHeaders,
    framing: &BodyFraming,
    forwarding: &ForwardingResult,
) -> Result<CanonicalRequestHead> {
    let trusted = Validated::from_models(method, target, authority, headers, framing, forwarding)?;
    let output_len = trusted.wire_len();
    if output_len > HEAD_MAX {
        return Err(PolyguardError::LimitExceeded {
            limit: "canonical_head_bytes".into(),
            max: HEAD_MAX,
            actual: output_len,
        });
    }

    let mut writer = ReverseWriter::new(output_len);
    writer.prepend(b"\r\n");
    writer.prepend_field(b"Connection", b"close");

    match trusted.framing {
        Framing::None => {}
        Framing::Length(value) => writer.prepend_decimal_field(b"Content-Length", value),
        Framing::Chunked => writer.prepend_field(b"Transfer-Encoding", b"chunked"),
    }

    for index in (0..FORWARDING_NAMES.len()).rev() {
        writer.prepend_field(
            FORWARDING_NAMES[index],
            trusted.forwarding.0[index].as_bytes(),
        );
    }

    for index in (0..trusted.fields.source.fields.len()).rev() {
        if trusted.fields.retained & (1_u128 << index) != 0 {
            let field = &trusted.fields.source.fields[index];
            writer.prepend_field(field.name.as_bytes(), &field.value);
        }
    }

    writer.prepend_host(trusted.authority);
    writer.prepend_request(trusted.method, trusted.route);
    let bytes = writer.finish();

    Ok(CanonicalRequestHead {
        bytes,
        body_framing: framing.clone(),
    })
}

impl<'a> Validated<'a> {
    fn from_models(
        method: &'a str,
        target: &'a NormalizedTarget,
        authority: &'a EffectiveAuthority,
        headers: &'a SanitizedHeaders,
        framing: &'a BodyFraming,
        forwarding: &'a ForwardingResult,
    ) -> Result<Self> {
        let method = Method::validate(method)?;
        let authority = Authority::validate_effective(authority)?;
        let route = OriginRoute::validate(target, authority)?;
        let fields = EndToEnd::validate(headers)?;
        let forwarding = Forwarding::validate(forwarding)?;
        let framing = Framing::validate(framing)?;
        Ok(Self {
            method,
            route,
            authority,
            fields,
            forwarding,
            framing,
        })
    }

    fn wire_len(&self) -> usize {
        let request = self.method.0.len() + 1 + self.route.0.len() + b" HTTP/1.1\r\n".len();
        let host = b"Host: \r\n".len() + self.authority.rendered_len();
        let retained = self
            .fields
            .source
            .fields
            .iter()
            .enumerate()
            .filter(|(index, _)| self.fields.retained & (1_u128 << index) != 0)
            .fold(0usize, |total, (_, field)| {
                total.saturating_add(field_line_len(field.name.len(), field.value.len()))
            });
        let forwarding = FORWARDING_NAMES
            .iter()
            .zip(self.forwarding.0)
            .fold(0usize, |total, (name, value)| {
                total.saturating_add(field_line_len(name.len(), value.len()))
            });
        let framing = match self.framing {
            Framing::None => 0,
            Framing::Length(value) => field_line_len(b"Content-Length".len(), decimal_len(value)),
            Framing::Chunked => field_line_len(b"Transfer-Encoding".len(), b"chunked".len()),
        };

        [
            request,
            host,
            retained,
            forwarding,
            framing,
            b"Connection: close\r\n\r\n".len(),
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add)
    }
}

impl<'a> Method<'a> {
    fn validate(value: &'a str) -> Result<Self> {
        if !(1..=METHOD_MAX).contains(&value.len())
            || !value.bytes().all(is_token)
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return invariant();
        }
        Ok(Self(value))
    }
}

impl<'a> OriginRoute<'a> {
    fn validate(target: &'a NormalizedTarget, effective: Authority<'_>) -> Result<Self> {
        match (
            &target.form,
            target.scheme.as_deref(),
            target.authority.as_deref(),
        ) {
            (TargetForm::Origin, None, None) => {}
            (TargetForm::Absolute, Some(scheme @ ("http" | "https")), Some(raw)) => {
                let default_port = if scheme == "http" { 80 } else { 443 };
                let source = Authority::parse_absolute(raw)?;
                if effective.port == Some(default_port)
                    || source.host != effective.host
                    || source.port.unwrap_or(default_port) != effective.port.unwrap_or(default_port)
                {
                    return invariant();
                }
            }
            _ => return invariant(),
        }

        validate_path(&target.path_and_query, &target.routing_path)?;
        Ok(Self(&target.path_and_query))
    }
}

impl<'a> Authority<'a> {
    fn validate_effective(value: &'a EffectiveAuthority) -> Result<Self> {
        if value.port == Some(0) {
            return invariant();
        }
        let host = parse_host(&value.host, true)?;
        Ok(Self {
            host,
            port: value.port,
        })
    }

    fn parse_absolute(value: &'a str) -> Result<Self> {
        if let Some(rest) = value.strip_prefix('[') {
            let close = rest
                .find(']')
                .ok_or(PolyguardError::SerializationInvariant)?;
            let host = &rest[..close];
            validate_ipv6(host)?;
            let suffix = &rest[close + 1..];
            let port = if suffix.is_empty() {
                None
            } else {
                Some(parse_port(
                    suffix
                        .strip_prefix(':')
                        .ok_or(PolyguardError::SerializationInvariant)?,
                )?)
            };
            return Ok(Self {
                host: Host::Ipv6(host),
                port,
            });
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
            Some(_) => return invariant(),
            None => (value, None),
        };
        validate_dns(host)?;
        Ok(Self {
            host: Host::Name(host),
            port,
        })
    }

    fn rendered_len(self) -> usize {
        let host = match self.host {
            Host::Name(value) => value.len(),
            Host::Ipv6(value) => value.len() + 2,
        };
        host + self.port.map_or(0, |port| 1 + decimal_len(u64::from(port)))
    }
}

impl<'a> EndToEnd<'a> {
    fn validate(value: &'a SanitizedHeaders) -> Result<Self> {
        if value.fields.len() > FIELD_COUNT_MAX {
            return invariant();
        }
        let mut retained = 0_u128;
        for (index, field) in value.fields.iter().enumerate() {
            if !canonical_name(&field.name)
                || field.value.len() > FIELD_VALUE_MAX
                || !field.value.iter().copied().all(is_field_value)
                || has_edge_ows(&field.value)
            {
                return invariant();
            }
            match survivor_decision(&field.name) {
                SurvivorDecision::Retain => retained |= 1_u128 << index,
                SurvivorDecision::Replace => {}
                SurvivorDecision::Reject => return invariant(),
            }
        }

        let mut previous: Option<&str> = None;
        for name in &value.removed_names {
            if !canonical_name(name) || previous.is_some_and(|prior| prior >= name.as_str()) {
                return invariant();
            }
            previous = Some(name);
        }
        Ok(Self {
            source: value,
            retained,
        })
    }
}

impl<'a> Forwarding<'a> {
    fn validate(value: &'a ForwardingResult) -> Result<Self> {
        let values = [
            value.forwarded.as_str(),
            value.x_forwarded_for.as_str(),
            value.x_forwarded_proto.as_str(),
            value.x_forwarded_host.as_str(),
        ];
        if values.iter().any(|value| !valid_forwarding(value)) {
            return invariant();
        }
        Ok(Self(values))
    }
}

impl Framing {
    fn validate(value: &BodyFraming) -> Result<Self> {
        match value {
            BodyFraming::None => Ok(Self::None),
            BodyFraming::ContentLength(length) if *length <= BODY_MAX => Ok(Self::Length(*length)),
            BodyFraming::ContentLength(_) => invariant(),
            BodyFraming::Chunked => Ok(Self::Chunked),
        }
    }
}

struct ReverseWriter {
    bytes: Vec<u8>,
    cursor: usize,
}

impl ReverseWriter {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            cursor: size,
        }
    }

    fn prepend(&mut self, value: &[u8]) {
        self.cursor -= value.len();
        self.bytes[self.cursor..self.cursor + value.len()].copy_from_slice(value);
    }

    fn prepend_field(&mut self, name: &[u8], value: &[u8]) {
        self.prepend(b"\r\n");
        self.prepend(value);
        self.prepend(b": ");
        self.prepend(name);
    }

    fn prepend_decimal_field(&mut self, name: &[u8], value: u64) {
        let mut digits = [0_u8; 20];
        let rendered = render_decimal(value, &mut digits);
        self.prepend_field(name, rendered);
    }

    fn prepend_host(&mut self, authority: Authority<'_>) {
        self.prepend(b"\r\n");
        if let Some(port) = authority.port {
            let mut digits = [0_u8; 20];
            self.prepend(render_decimal(u64::from(port), &mut digits));
            self.prepend(b":");
        }
        match authority.host {
            Host::Name(value) => self.prepend(value.as_bytes()),
            Host::Ipv6(value) => {
                self.prepend(b"]");
                self.prepend(value.as_bytes());
                self.prepend(b"[");
            }
        }
        self.prepend(b"Host: ");
    }

    fn prepend_request(&mut self, method: Method<'_>, route: OriginRoute<'_>) {
        self.prepend(b" HTTP/1.1\r\n");
        self.prepend(route.0.as_bytes());
        self.prepend(b" ");
        self.cursor -= method.0.len();
        for (destination, source) in self.bytes[self.cursor..self.cursor + method.0.len()]
            .iter_mut()
            .zip(method.0.bytes())
        {
            *destination = source.to_ascii_uppercase();
        }
    }

    fn finish(self) -> Vec<u8> {
        debug_assert_eq!(self.cursor, 0);
        self.bytes
    }
}

fn survivor_decision(name: &str) -> SurvivorDecision {
    if name.starts_with("x-forwarded-") {
        return SurvivorDecision::Replace;
    }
    SURVIVOR_TABLE
        .iter()
        .find_map(|(candidate, decision)| (*candidate == name).then_some(*decision))
        .unwrap_or(SurvivorDecision::Retain)
}

fn parse_host(value: &str, allow_bare_ipv6: bool) -> Result<Host<'_>> {
    if let Some(inner) = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        validate_ipv6(inner)?;
        Ok(Host::Ipv6(inner))
    } else if allow_bare_ipv6 && value.contains(':') {
        validate_ipv6(value)?;
        Ok(Host::Ipv6(value))
    } else {
        validate_dns(value)?;
        Ok(Host::Name(value))
    }
}

fn validate_path(path_and_query: &str, routing_path: &str) -> Result<()> {
    let bytes = path_and_query.as_bytes();
    if bytes.is_empty()
        || bytes.len() > TARGET_MAX
        || bytes.first() != Some(&b'/')
        || !bytes
            .iter()
            .all(|byte| matches!(*byte, b'!'..=b'~') && !matches!(*byte, b'#' | b'\\'))
    {
        return invariant();
    }
    let query = bytes
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(bytes.len());
    if routing_path.as_bytes() != &bytes[..query]
        || bytes[1..query]
            .split(|byte| *byte == b'/')
            .any(|part| matches!(part, b"." | b".."))
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
        if !encoded
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        {
            return invariant();
        }
        let decoded = (hex(encoded[0]) << 4) | hex(encoded[1]);
        if decoded <= 31
            || decoded == 127
            || is_unreserved(decoded)
            || (cursor < query && matches!(decoded, b'/' | b'\\'))
        {
            return invariant();
        }
        cursor += 3;
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
    if valid { Ok(()) } else { invariant() }
}

fn validate_ipv6(value: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('%')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.parse::<Ipv6Addr>().is_err()
    {
        invariant()
    } else {
        Ok(())
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

fn canonical_name(value: &str) -> bool {
    (1..=FIELD_NAME_MAX).contains(&value.len())
        && value.bytes().all(is_token)
        && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn valid_forwarding(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= FORWARDING_VALUE_MAX
        && bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
        && !has_edge_ows(bytes)
        && !bytes
            .split(|byte| *byte == b',')
            .any(|member| member.iter().all(|byte| *byte == b' '))
}

fn has_edge_ows(value: &[u8]) -> bool {
    value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        || value
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_field_value(byte: u8) -> bool {
    byte == b'\t' || matches!(byte, b' '..=b'~') || byte >= 0x80
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

fn field_line_len(name: usize, value: usize) -> usize {
    name.saturating_add(2)
        .saturating_add(value)
        .saturating_add(2)
}

fn decimal_len(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

fn render_decimal(mut value: u64, digits: &mut [u8; 20]) -> &[u8] {
    let mut cursor = digits.len();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &digits[cursor..];
        }
    }
}

fn invariant<T>() -> Result<T> {
    Err(PolyguardError::SerializationInvariant)
}
