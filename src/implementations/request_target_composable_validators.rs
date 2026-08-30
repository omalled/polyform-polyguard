use std::net::Ipv6Addr;

use crate::{NormalizedTarget, PolyguardError, RequestLine, Result, TargetForm};

const TARGET_MAX: usize = 8192;
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
const SCHEME_TABLE: [(&[u8], &str); 2] = [(b"http://", "http"), (b"https://", "https")];
const ENVELOPE_VALIDATORS: [fn(&str) -> Result<()>; 4] = [
    require_nonempty,
    require_visible_ascii,
    reject_fragment,
    reject_backslash,
];

#[derive(Clone, Copy)]
enum Authority<'a> {
    Dns { host: &'a str, port: Option<u16> },
    Ipv6 { literal: &'a str, port: Option<u16> },
}

struct ValidatedParts<'a> {
    form: TargetForm,
    scheme: Option<&'static str>,
    authority: Option<Authority<'a>>,
    path: Option<&'a str>,
    query: Option<&'a str>,
    fixed: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum ComponentKind {
    Path,
    Query,
}

#[derive(Clone, Copy)]
enum ComponentToken {
    Literal(u8),
    Encoded(u8),
}

struct ComponentTokens<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ComponentTokens<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            bytes: value.as_bytes(),
            offset: 0,
        }
    }
}

impl Iterator for ComponentTokens<'_> {
    type Item = Result<ComponentToken>;

    fn next(&mut self) -> Option<Self::Item> {
        let byte = *self.bytes.get(self.offset)?;
        if byte != b'%' {
            self.offset += 1;
            return Some(Ok(ComponentToken::Literal(byte)));
        }

        let decoded = self
            .bytes
            .get(self.offset + 1..self.offset + 3)
            .and_then(|pair| Some((hex(pair[0])? << 4) | hex(pair[1])?));
        match decoded {
            Some(value) => {
                self.offset += 3;
                Some(Ok(ComponentToken::Encoded(value)))
            }
            None => {
                self.offset = self.bytes.len();
                Some(invalid_target("invalid_percent_encoding"))
            }
        }
    }
}

/// Normalize through composable validation passes followed by allocation-only rendering.
pub fn normalize_request_target(request: &RequestLine) -> Result<NormalizedTarget> {
    validate_envelope(&request.target)?;
    let parts = validate_and_decompose(request)?;
    render(parts)
}

fn validate_envelope(target: &str) -> Result<()> {
    if target.len() > TARGET_MAX {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_MAX,
            actual: target.len(),
        });
    }
    ENVELOPE_VALIDATORS
        .iter()
        .try_for_each(|validator| validator(target))
}

fn require_nonempty(target: &str) -> Result<()> {
    if target.is_empty() {
        invalid_target("empty_target")
    } else {
        Ok(())
    }
}

fn require_visible_ascii(target: &str) -> Result<()> {
    if target.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        Ok(())
    } else {
        invalid_target("invalid_target_byte")
    }
}

fn reject_fragment(target: &str) -> Result<()> {
    if target.contains('#') {
        invalid_target("fragment_not_allowed")
    } else {
        Ok(())
    }
}

fn reject_backslash(target: &str) -> Result<()> {
    if target.contains('\\') {
        invalid_target("backslash_not_allowed")
    } else {
        Ok(())
    }
}

fn validate_and_decompose(request: &RequestLine) -> Result<ValidatedParts<'_>> {
    let raw = request.target.as_str();
    if raw == "*" {
        return if request.method == "options" {
            Ok(fixed_parts(TargetForm::Asterisk, raw))
        } else {
            invalid_target("asterisk_method")
        };
    }

    if request.method == "connect" {
        if raw.starts_with('/') || recognized_scheme(raw).is_some() {
            return invalid_target("connect_requires_authority");
        }
        return Ok(ValidatedParts {
            form: TargetForm::Authority,
            scheme: None,
            authority: Some(validate_authority(raw, true)?),
            path: None,
            query: None,
            fixed: None,
        });
    }

    if raw.starts_with('/') {
        let (path, query) = split_query(raw);
        validate_path(path)?;
        validate_query(query)?;
        return Ok(ValidatedParts {
            form: TargetForm::Origin,
            scheme: None,
            authority: None,
            path: Some(path),
            query,
            fixed: None,
        });
    }

    let Some((prefix_length, scheme)) = recognized_scheme(raw) else {
        return invalid_target("authority_method");
    };
    validate_absolute(&raw[prefix_length..], scheme)
}

fn validate_absolute<'a>(remainder: &'a str, scheme: &'static str) -> Result<ValidatedParts<'a>> {
    let authority_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let authority = validate_authority(&remainder[..authority_end], false)?;
    let tail = &remainder[authority_end..];
    let (path, query) = if let Some(query) = tail.strip_prefix('?') {
        (None, Some(query))
    } else if tail.is_empty() {
        (None, None)
    } else {
        let (path, query) = split_query(tail);
        (Some(path), query)
    };

    if let Some(path) = path {
        validate_path(path)?;
    }
    validate_query(query)?;
    Ok(ValidatedParts {
        form: TargetForm::Absolute,
        scheme: Some(scheme),
        authority: Some(authority),
        path,
        query,
        fixed: None,
    })
}

fn split_query(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('?')
        .map_or((value, None), |(path, query)| (path, Some(query)))
}

fn recognized_scheme(target: &str) -> Option<(usize, &'static str)> {
    SCHEME_TABLE.iter().find_map(|(prefix, name)| {
        target
            .as_bytes()
            .get(..prefix.len())
            .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
            .map(|_| (prefix.len(), *name))
    })
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || !path.starts_with('/') {
        return invalid_target("invalid_path");
    }
    validate_component(path, ComponentKind::Path)?;
    validate_root_boundary(path)
}

fn validate_query(query: Option<&str>) -> Result<()> {
    query.map_or(Ok(()), |value| {
        validate_component(value, ComponentKind::Query)
    })
}

fn validate_component(value: &str, kind: ComponentKind) -> Result<()> {
    ComponentTokens::new(value).try_for_each(|token| match token? {
        ComponentToken::Encoded(b'/' | b'\\') if matches!(kind, ComponentKind::Path) => {
            invalid_target("encoded_separator")
        }
        ComponentToken::Encoded(0..=31 | 127) => invalid_target("encoded_control"),
        ComponentToken::Literal(_) | ComponentToken::Encoded(_) => Ok(()),
    })
}

fn validate_root_boundary(path: &str) -> Result<()> {
    path[1..]
        .split('/')
        .try_fold(0usize, |depth, segment| match dot_segment(segment)? {
            1 => Ok(depth),
            2 if depth == 0 => invalid_target("path_traversal"),
            2 => Ok(depth - 1),
            _ => Ok(depth + 1),
        })
        .map(|_| ())
}

fn dot_segment(segment: &str) -> Result<u8> {
    let mut canonical = ComponentTokens::new(segment).map(|token| {
        token.map(|token| match token {
            ComponentToken::Literal(byte) => Some(byte),
            ComponentToken::Encoded(byte) if is_unreserved(byte) => Some(byte),
            ComponentToken::Encoded(_) => None,
        })
    });
    match (
        canonical.next().transpose()?,
        canonical.next().transpose()?,
        canonical.next(),
    ) {
        (Some(Some(b'.')), None, None) => Ok(1),
        (Some(Some(b'.')), Some(Some(b'.')), None) => Ok(2),
        _ => Ok(0),
    }
}

fn validate_authority(raw: &str, port_required: bool) -> Result<Authority<'_>> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|byte| matches!(byte, b'@' | b'/' | b'?' | b'#' | b'%' | b'\\'))
    {
        return Err(PolyguardError::InvalidAuthority);
    }
    if let Some(after_open) = raw.strip_prefix('[') {
        validate_ipv6(after_open, port_required)
    } else {
        validate_dns(raw, port_required)
    }
}

fn validate_ipv6(after_open: &str, port_required: bool) -> Result<Authority<'_>> {
    let closing = after_open
        .find(']')
        .ok_or(PolyguardError::InvalidAuthority)?;
    let literal = &after_open[..closing];
    if literal.is_empty() || literal.contains('%') || literal.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }
    let port = validate_port_suffix(&after_open[closing + 1..], port_required)?;
    Ok(Authority::Ipv6 { literal, port })
}

fn validate_dns(raw: &str, port_required: bool) -> Result<Authority<'_>> {
    let (host_with_dot, port_text) = raw
        .rsplit_once(':')
        .map_or((raw, None), |(host, port)| (host, Some(port)));
    if host_with_dot.contains(':') {
        return Err(PolyguardError::InvalidAuthority);
    }
    let host = host_with_dot.strip_suffix('.').unwrap_or(host_with_dot);
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || !host.split('.').all(valid_dns_label)
    {
        return Err(PolyguardError::InvalidAuthority);
    }
    let port = match port_text {
        Some(value) => Some(validate_port(value)?),
        None if port_required => return Err(PolyguardError::InvalidAuthority),
        None => None,
    };
    Ok(Authority::Dns { host, port })
}

fn valid_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn validate_port_suffix(suffix: &str, required: bool) -> Result<Option<u16>> {
    match suffix {
        "" if !required => Ok(None),
        value => value
            .strip_prefix(':')
            .ok_or(PolyguardError::InvalidAuthority)
            .and_then(validate_port)
            .map(Some),
    }
}

fn validate_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(PolyguardError::InvalidAuthority)
}

fn render(parts: ValidatedParts<'_>) -> Result<NormalizedTarget> {
    if let Some(fixed) = parts.fixed {
        return Ok(NormalizedTarget {
            form: parts.form,
            scheme: None,
            authority: None,
            path_and_query: fixed.into(),
            routing_path: fixed.into(),
        });
    }

    if matches!(parts.form, TargetForm::Authority) {
        let authority = render_authority(parts.authority.expect("validated authority form"));
        return Ok(NormalizedTarget {
            form: parts.form,
            scheme: None,
            authority: Some(authority.clone()),
            path_and_query: authority.clone(),
            routing_path: authority,
        });
    }

    let routing_path = render_path(parts.path.unwrap_or("/"));
    let path_and_query = parts.query.map_or_else(
        || routing_path.clone(),
        |query| {
            let mut result = String::with_capacity(routing_path.len() + query.len() + 1);
            result.push_str(&routing_path);
            result.push('?');
            render_component_into(&mut result, query);
            result
        },
    );
    if path_and_query.len() > TARGET_MAX {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_MAX,
            actual: path_and_query.len(),
        });
    }
    Ok(NormalizedTarget {
        form: parts.form,
        scheme: parts.scheme.map(str::to_owned),
        authority: parts.authority.map(render_authority),
        path_and_query,
        routing_path,
    })
}

fn render_authority(authority: Authority<'_>) -> String {
    let (host, port, bracketed) = match authority {
        Authority::Dns { host, port } => (host, port, false),
        Authority::Ipv6 { literal, port } => (literal, port, true),
    };
    let mut output = String::with_capacity(host.len() + 8);
    if bracketed {
        output.push('[');
    }
    output.extend(host.chars().map(|character| character.to_ascii_lowercase()));
    if bracketed {
        output.push(']');
    }
    if let Some(port) = port {
        output.push(':');
        output.push_str(&port.to_string());
    }
    output
}

fn render_path(path: &str) -> String {
    let last = path[1..].split('/').count() - 1;
    let segments = path[1..].split('/').map(render_component).enumerate().fold(
        Vec::new(),
        |mut output, (index, segment)| {
            match segment.as_str() {
                "." if index == last => output.push(String::new()),
                "." => {}
                ".." => {
                    output.pop();
                    if index == last {
                        output.push(String::new());
                    }
                }
                _ => output.push(segment),
            }
            output
        },
    );
    format!("/{}", segments.join("/"))
}

fn render_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    render_component_into(&mut output, value);
    output
}

fn render_component_into(output: &mut String, value: &str) {
    ComponentTokens::new(value).for_each(|token| match token.expect("validated component") {
        ComponentToken::Literal(byte) => output.push(char::from(byte)),
        ComponentToken::Encoded(byte) if is_unreserved(byte) => output.push(char::from(byte)),
        ComponentToken::Encoded(byte) => {
            output.push('%');
            output.push(char::from(UPPER_HEX[usize::from(byte >> 4)]));
            output.push(char::from(UPPER_HEX[usize::from(byte & 0x0f)]));
        }
    });
}

fn fixed_parts(form: TargetForm, value: &str) -> ValidatedParts<'_> {
    ValidatedParts {
        form,
        scheme: None,
        authority: None,
        path: None,
        query: None,
        fixed: Some(value),
    }
}

fn hex(byte: u8) -> Option<u8> {
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
