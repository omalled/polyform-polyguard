use std::net::Ipv6Addr;

use crate::{NormalizedTarget, PolyguardError, RequestLine, Result, TargetForm};

const MAX_TARGET_BYTES: usize = 8192;
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
const ABSOLUTE_SCHEMES: [(&str, &str); 2] = [("http://", "http"), ("https://", "https")];

enum ValidatedTarget<'a> {
    Asterisk,
    Authority(ValidatedAuthority<'a>),
    Origin(ValidatedPath<'a>),
    Absolute {
        scheme: &'static str,
        authority: ValidatedAuthority<'a>,
        path: ValidatedPath<'a>,
    },
}

enum ValidatedAuthority<'a> {
    Dns { host: &'a str, port: Option<u16> },
    Ipv6 { address: &'a str, port: Option<u16> },
}

struct ValidatedPath<'a> {
    path: Option<&'a str>,
    query: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum PercentToken {
    Literal(u8),
    Encoded(u8),
}

struct PercentTokens<'a> {
    remaining: &'a [u8],
}

impl<'a> PercentTokens<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            remaining: value.as_bytes(),
        }
    }
}

impl Iterator for PercentTokens<'_> {
    type Item = PercentToken;

    fn next(&mut self) -> Option<Self::Item> {
        let (&first, tail) = self.remaining.split_first()?;
        if first == b'%' {
            let value = (hex_value(tail[0]) << 4) | hex_value(tail[1]);
            self.remaining = &tail[2..];
            Some(PercentToken::Encoded(value))
        } else {
            self.remaining = tail;
            Some(PercentToken::Literal(first))
        }
    }
}

/// Normalize a request target through a validate-then-transform pipeline.
pub fn normalize_request_target(request: &RequestLine) -> Result<NormalizedTarget> {
    validated_plan(request).map(materialize)
}

fn validated_plan(request: &RequestLine) -> Result<ValidatedTarget<'_>> {
    validate_target_boundary(&request.target)?;

    if request.target == "*" {
        return if request.method == "options" {
            Ok(ValidatedTarget::Asterisk)
        } else {
            invalid_target("asterisk_method")
        };
    }

    if request.method == "connect" {
        if request.target.starts_with('/') || absolute_scheme(&request.target).is_some() {
            return invalid_target("connect_requires_authority");
        }
        return validate_authority(&request.target, true).map(ValidatedTarget::Authority);
    }

    if request.target.starts_with('/') {
        return validate_path(&request.target).map(ValidatedTarget::Origin);
    }

    let Some((scheme_prefix, scheme_name)) = absolute_scheme(&request.target) else {
        return invalid_target("authority_method");
    };
    validate_absolute(&request.target[scheme_prefix.len()..], scheme_name)
}

fn validate_target_boundary(target: &str) -> Result<()> {
    if target.len() > MAX_TARGET_BYTES {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: MAX_TARGET_BYTES,
            actual: target.len(),
        });
    }
    if target.is_empty() {
        return invalid_target("empty_target");
    }

    target.bytes().try_for_each(|byte| match byte {
        b'#' => invalid_target("fragment_not_allowed"),
        b'\\' => invalid_target("backslash_not_allowed"),
        b'!'..=b'~' => Ok(()),
        _ => invalid_target("invalid_target_byte"),
    })
}

fn absolute_scheme(target: &str) -> Option<(&'static str, &'static str)> {
    ABSOLUTE_SCHEMES.iter().copied().find(|(prefix, _)| {
        target
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
    })
}

fn validate_absolute<'a>(remainder: &'a str, scheme: &'static str) -> Result<ValidatedTarget<'a>> {
    let authority_length = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let authority = validate_authority(&remainder[..authority_length], false)?;
    let suffix = &remainder[authority_length..];
    let path = match suffix.strip_prefix('?') {
        Some(query) => validate_path_parts(None, Some(query))?,
        None if suffix.is_empty() => validate_path_parts(None, None)?,
        None => validate_path(suffix)?,
    };

    Ok(ValidatedTarget::Absolute {
        scheme,
        authority,
        path,
    })
}

fn validate_path(value: &str) -> Result<ValidatedPath<'_>> {
    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(path, query)| (path, Some(query)));
    validate_path_parts(Some(path), query)
}

fn validate_path_parts<'a>(
    path: Option<&'a str>,
    query: Option<&'a str>,
) -> Result<ValidatedPath<'a>> {
    if path.is_some_and(|value| value.is_empty() || !value.starts_with('/')) {
        return invalid_target("invalid_path");
    }

    if let Some(value) = path {
        validate_percent_encoding(value, true)?;
        validate_no_root_escape(value)?;
    }
    if let Some(value) = query {
        validate_percent_encoding(value, false)?;
    }

    Ok(ValidatedPath { path, query })
}

fn validate_percent_encoding(value: &str, reject_separators: bool) -> Result<()> {
    let mut remaining = value.as_bytes();
    while let Some((&byte, tail)) = remaining.split_first() {
        if byte != b'%' {
            remaining = tail;
            continue;
        }
        let Some((&high, after_high)) = tail.split_first() else {
            return invalid_target("invalid_percent_encoding");
        };
        let Some((&low, after_low)) = after_high.split_first() else {
            return invalid_target("invalid_percent_encoding");
        };
        if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
            return invalid_target("invalid_percent_encoding");
        }
        let decoded = (hex_value(high) << 4) | hex_value(low);
        if reject_separators && matches!(decoded, b'/' | b'\\') {
            return invalid_target("encoded_separator");
        }
        if decoded.is_ascii_control() {
            return invalid_target("encoded_control");
        }
        remaining = after_low;
    }
    Ok(())
}

fn validate_no_root_escape(path: &str) -> Result<()> {
    path[1..]
        .split('/')
        .try_fold(0usize, |depth, segment| match decoded_dot_kind(segment) {
            Some(1) => Ok(depth),
            Some(2) if depth == 0 => invalid_target("path_traversal"),
            Some(2) => Ok(depth - 1),
            _ => Ok(depth + 1),
        })
        .map(|_| ())
}

fn decoded_dot_kind(segment: &str) -> Option<u8> {
    let mut tokens = PercentTokens::new(segment).map(decoded_unreserved);
    match (tokens.next(), tokens.next(), tokens.next()) {
        (Some(b'.'), None, None) => Some(1),
        (Some(b'.'), Some(b'.'), None) => Some(2),
        _ => None,
    }
}

fn validate_authority(value: &str, port_required: bool) -> Result<ValidatedAuthority<'_>> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'@' | b'/' | b'?' | b'#' | b'%' | b'\\'))
    {
        return Err(PolyguardError::InvalidAuthority);
    }

    if let Some(after_open) = value.strip_prefix('[') {
        validate_ipv6_authority(after_open, port_required)
    } else {
        validate_dns_authority(value, port_required)
    }
}

fn validate_ipv6_authority(
    after_open: &str,
    port_required: bool,
) -> Result<ValidatedAuthority<'_>> {
    let close = after_open
        .find(']')
        .ok_or(PolyguardError::InvalidAuthority)?;
    let address = &after_open[..close];
    if address.contains('%') || address.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }
    let port = validate_port_suffix(&after_open[close + 1..], port_required)?;
    Ok(ValidatedAuthority::Ipv6 { address, port })
}

fn validate_dns_authority(value: &str, port_required: bool) -> Result<ValidatedAuthority<'_>> {
    let (raw_host, raw_port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if raw_host.contains(':') {
        return Err(PolyguardError::InvalidAuthority);
    }
    let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
    let labels_valid = !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !labels_valid {
        return Err(PolyguardError::InvalidAuthority);
    }

    let port = match raw_port {
        Some(value) => Some(validate_port(value)?),
        None if port_required => return Err(PolyguardError::InvalidAuthority),
        None => None,
    };
    Ok(ValidatedAuthority::Dns { host, port })
}

fn validate_port_suffix(suffix: &str, required: bool) -> Result<Option<u16>> {
    if suffix.is_empty() && !required {
        return Ok(None);
    }
    let raw_port = suffix
        .strip_prefix(':')
        .ok_or(PolyguardError::InvalidAuthority)?;
    validate_port(raw_port).map(Some)
}

fn validate_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    match value.parse::<u16>() {
        Ok(port @ 1..=u16::MAX) => Ok(port),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn materialize(plan: ValidatedTarget<'_>) -> NormalizedTarget {
    match plan {
        ValidatedTarget::Asterisk => fixed_target(TargetForm::Asterisk, None, None, "*".into()),
        ValidatedTarget::Authority(authority) => {
            let authority = canonical_authority(authority);
            fixed_target(
                TargetForm::Authority,
                None,
                Some(authority.clone()),
                authority,
            )
        }
        ValidatedTarget::Origin(path) => {
            let (path_and_query, routing_path) = canonical_path(path);
            NormalizedTarget {
                form: TargetForm::Origin,
                scheme: None,
                authority: None,
                path_and_query,
                routing_path,
            }
        }
        ValidatedTarget::Absolute {
            scheme,
            authority,
            path,
        } => {
            let (path_and_query, routing_path) = canonical_path(path);
            NormalizedTarget {
                form: TargetForm::Absolute,
                scheme: Some(scheme.into()),
                authority: Some(canonical_authority(authority)),
                path_and_query,
                routing_path,
            }
        }
    }
}

fn canonical_authority(authority: ValidatedAuthority<'_>) -> String {
    let (mut host, port) = match authority {
        ValidatedAuthority::Dns { host, port } => (host.to_ascii_lowercase(), port),
        ValidatedAuthority::Ipv6 { address, port } => {
            (format!("[{}]", address.to_ascii_lowercase()), port)
        }
    };
    if let Some(port) = port {
        host.push(':');
        host.push_str(&port.to_string());
    }
    host
}

fn canonical_path(path: ValidatedPath<'_>) -> (String, String) {
    let raw_path = path.path.unwrap_or("/");
    let last_index = raw_path[1..].split('/').count() - 1;
    let segments = raw_path[1..]
        .split('/')
        .map(canonical_component)
        .enumerate()
        .fold(Vec::new(), |mut kept, (index, segment)| {
            match segment.as_str() {
                "." if index == last_index => kept.push(String::new()),
                "." => {}
                ".." => {
                    kept.pop();
                    if index == last_index {
                        kept.push(String::new());
                    }
                }
                _ => kept.push(segment),
            }
            kept
        });
    let routing_path = format!("/{}", segments.join("/"));
    let path_and_query = path.query.map_or_else(
        || routing_path.clone(),
        |query| format!("{routing_path}?{}", canonical_component(query)),
    );
    (path_and_query, routing_path)
}

fn canonical_component(value: &str) -> String {
    PercentTokens::new(value).fold(String::with_capacity(value.len()), |mut output, token| {
        match token {
            PercentToken::Literal(byte) => output.push(char::from(byte)),
            PercentToken::Encoded(byte) if is_unreserved(byte) => output.push(char::from(byte)),
            PercentToken::Encoded(byte) => {
                output.push('%');
                output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
                output.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
            }
        }
        output
    })
}

fn decoded_unreserved(token: PercentToken) -> u8 {
    match token {
        PercentToken::Encoded(byte) if is_unreserved(byte) => byte,
        PercentToken::Literal(byte) => byte,
        PercentToken::Encoded(_) => b'%',
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("percent encoding was validated before transformation"),
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
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

fn invalid_target<T>(reason: &'static str) -> Result<T> {
    Err(PolyguardError::InvalidTarget {
        reason: reason.into(),
    })
}
