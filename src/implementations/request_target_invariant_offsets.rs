use std::net::Ipv6Addr;

use crate::{NormalizedTarget, PolyguardError, RequestLine, Result, TargetForm};

const TARGET_BYTES: usize = 8192;
const HTTP_PREFIX: &[u8] = b"http://";
const HTTPS_PREFIX: &[u8] = b"https://";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Normalize by proving the target's invariants before constructing any output.
///
/// Classification uses guard decisions and byte offsets rather than a typed
/// syntax tree. Path transformation keeps offsets into the output string;
/// popping an offset is exactly the inverse of appending one path segment.
pub fn normalize_request_target(request: &RequestLine) -> Result<NormalizedTarget> {
    validate_target_envelope(&request.target)?;

    if request.target == "*" {
        if request.method != "options" {
            return invalid_target("asterisk_method");
        }
        return Ok(non_path_target(TargetForm::Asterisk, None, "*".into()));
    }

    if request.method == "connect" {
        if request.target.starts_with('/') || scheme_prefix(&request.target).is_some() {
            return invalid_target("connect_requires_authority");
        }
        let authority = normalize_authority(&request.target, true)?;
        return Ok(non_path_target(
            TargetForm::Authority,
            Some(authority.clone()),
            authority,
        ));
    }

    if request.target.starts_with('/') {
        validate_path_and_query(&request.target)?;
        let (path_and_query, routing_path) = transform_path_and_query(&request.target);
        return finish_path_target(TargetForm::Origin, None, None, path_and_query, routing_path);
    }

    let Some((prefix_len, scheme)) = scheme_prefix(&request.target) else {
        return invalid_target("authority_method");
    };
    normalize_absolute(&request.target[prefix_len..], scheme)
}

fn validate_target_envelope(target: &str) -> Result<()> {
    if target.len() > TARGET_BYTES {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_BYTES,
            actual: target.len(),
        });
    }
    if target.is_empty() {
        return invalid_target("empty_target");
    }

    for byte in target.bytes() {
        if byte == b'#' {
            return invalid_target("fragment_not_allowed");
        }
        if byte == b'\\' {
            return invalid_target("backslash_not_allowed");
        }
        if !(b'!'..=b'~').contains(&byte) {
            return invalid_target("invalid_target_byte");
        }
    }
    Ok(())
}

fn scheme_prefix(target: &str) -> Option<(usize, &'static str)> {
    let bytes = target.as_bytes();
    if bytes
        .get(..HTTP_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(HTTP_PREFIX))
    {
        return Some((HTTP_PREFIX.len(), "http"));
    }
    if bytes
        .get(..HTTPS_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(HTTPS_PREFIX))
    {
        return Some((HTTPS_PREFIX.len(), "https"));
    }
    None
}

fn normalize_absolute(remainder: &str, scheme: &'static str) -> Result<NormalizedTarget> {
    let boundary = remainder
        .bytes()
        .position(|byte| byte == b'/' || byte == b'?')
        .unwrap_or(remainder.len());
    let authority = normalize_authority(&remainder[..boundary], false)?;
    let suffix = &remainder[boundary..];

    if suffix.starts_with('/') {
        validate_path_and_query(suffix)?;
        let (path_and_query, routing_path) = transform_path_and_query(suffix);
        return finish_path_target(
            TargetForm::Absolute,
            Some(scheme.into()),
            Some(authority),
            path_and_query,
            routing_path,
        );
    }

    let synthetic;
    let path = if suffix.is_empty() {
        "/"
    } else {
        synthetic = format!("/{suffix}");
        synthetic.as_str()
    };
    validate_path_and_query(path)?;
    let (path_and_query, routing_path) = transform_path_and_query(path);
    finish_path_target(
        TargetForm::Absolute,
        Some(scheme.into()),
        Some(authority),
        path_and_query,
        routing_path,
    )
}

fn validate_path_and_query(value: &str) -> Result<()> {
    let question = value.bytes().position(|byte| byte == b'?');
    let path_end = question.unwrap_or(value.len());
    if path_end == 0 || value.as_bytes()[0] != b'/' {
        return invalid_target("invalid_path");
    }

    validate_percent_triplets(&value[..path_end], true)?;
    if let Some(index) = question {
        validate_percent_triplets(&value[index + 1..], false)?;
    }
    validate_root_balance(&value[..path_end])
}

fn validate_percent_triplets(value: &str, path: bool) -> Result<()> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return invalid_target("invalid_percent_encoding");
        }
        let Some(high) = hex_value(bytes[index + 1]) else {
            return invalid_target("invalid_percent_encoding");
        };
        let Some(low) = hex_value(bytes[index + 2]) else {
            return invalid_target("invalid_percent_encoding");
        };
        let decoded = (high << 4) | low;
        if path && (decoded == b'/' || decoded == b'\\') {
            return invalid_target("encoded_separator");
        }
        if decoded <= 31 || decoded == 127 {
            return invalid_target("encoded_control");
        }
        index += 3;
    }
    Ok(())
}

// Depth is the invariant needed to prove that dot removal cannot escape root.
fn validate_root_balance(path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    let mut depth = 0usize;
    let mut start = 1usize;
    loop {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(bytes.len(), |offset| start + offset);
        let dots = decoded_dot_count(&path[start..end]);
        if dots == 2 {
            if depth == 0 {
                return invalid_target("path_traversal");
            }
            depth -= 1;
        } else if dots != 1 {
            depth += 1;
        }
        if end == bytes.len() {
            return Ok(());
        }
        start = end + 1;
    }
}

fn decoded_dot_count(segment: &str) -> u8 {
    let bytes = segment.as_bytes();
    let mut index = 0usize;
    let mut count = 0u8;
    while index < bytes.len() {
        let (byte, width) = if bytes[index] == b'%' {
            (
                ((hex_value(bytes[index + 1]).unwrap() << 4)
                    | hex_value(bytes[index + 2]).unwrap()),
                3,
            )
        } else {
            (bytes[index], 1)
        };
        if byte != b'.' || count == 2 {
            return 0;
        }
        count += 1;
        index += width;
    }
    count
}

fn transform_path_and_query(value: &str) -> (String, String) {
    let question = value.bytes().position(|byte| byte == b'?');
    let path_end = question.unwrap_or(value.len());
    let raw_path = &value[..path_end];
    let mut output = String::with_capacity(value.len());
    let mut segment_offsets = Vec::with_capacity(raw_path.len() / 2 + 1);
    let mut start = 1usize;

    loop {
        let end = raw_path.as_bytes()[start..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(raw_path.len(), |offset| start + offset);
        let final_segment = end == raw_path.len();
        let output_offset = output.len();
        output.push('/');
        append_canonical(&mut output, &raw_path[start..end]);
        let segment = &output[output_offset + 1..];

        if segment == "." {
            output.truncate(output_offset);
            if final_segment {
                output.push('/');
            }
        } else if segment == ".." {
            output.truncate(output_offset);
            let previous = segment_offsets.pop().expect("root balance was validated");
            output.truncate(previous);
            if final_segment {
                output.push('/');
            }
        } else {
            segment_offsets.push(output_offset);
        }

        if final_segment {
            break;
        }
        start = end + 1;
    }

    let routing_path = output.clone();
    if let Some(index) = question {
        output.push('?');
        append_canonical(&mut output, &value[index + 1..]);
    }
    (output, routing_path)
}

fn append_canonical(output: &mut String, input: &str) {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        let decoded =
            (hex_value(bytes[index + 1]).unwrap() << 4) | hex_value(bytes[index + 2]).unwrap();
        if is_unreserved(decoded) {
            output.push(char::from(decoded));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(decoded >> 4)]));
            output.push(char::from(HEX[usize::from(decoded & 15)]));
        }
        index += 3;
    }
}

fn normalize_authority(value: &str, port_required: bool) -> Result<String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'@' | b'/' | b'?' | b'#' | b'%' | b'\\'))
    {
        return Err(PolyguardError::InvalidAuthority);
    }
    if value.starts_with('[') {
        return normalize_ipv6_authority(value, port_required);
    }
    normalize_dns_authority(value, port_required)
}

fn normalize_ipv6_authority(value: &str, port_required: bool) -> Result<String> {
    let close = value.find(']').ok_or(PolyguardError::InvalidAuthority)?;
    let address = &value[1..close];
    if address.is_empty() || address.contains('%') || address.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }
    let suffix = &value[close + 1..];
    let port = normalize_port_suffix(suffix, port_required)?;
    let mut result = String::with_capacity(value.len());
    result.push('[');
    result.push_str(&address.to_ascii_lowercase());
    result.push(']');
    if let Some(port) = port {
        result.push(':');
        result.push_str(&port.to_string());
    }
    Ok(result)
}

fn normalize_dns_authority(value: &str, port_required: bool) -> Result<String> {
    let (raw_host, raw_port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if raw_host.contains(':') {
        return Err(PolyguardError::InvalidAuthority);
    }
    let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(PolyguardError::InvalidAuthority);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PolyguardError::InvalidAuthority);
        }
    }
    let port = match raw_port {
        Some(port) => Some(parse_port(port)?),
        None if port_required => return Err(PolyguardError::InvalidAuthority),
        None => None,
    };
    let mut result = host.to_ascii_lowercase();
    if let Some(port) = port {
        result.push(':');
        result.push_str(&port.to_string());
    }
    Ok(result)
}

fn normalize_port_suffix(suffix: &str, required: bool) -> Result<Option<u16>> {
    if suffix.is_empty() {
        if required {
            return Err(PolyguardError::InvalidAuthority);
        }
        return Ok(None);
    }
    let raw = suffix
        .strip_prefix(':')
        .ok_or(PolyguardError::InvalidAuthority)?;
    parse_port(raw).map(Some)
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }
    match value.parse::<u16>() {
        Ok(port @ 1..=u16::MAX) => Ok(port),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn finish_path_target(
    form: TargetForm,
    scheme: Option<String>,
    authority: Option<String>,
    path_and_query: String,
    routing_path: String,
) -> Result<NormalizedTarget> {
    if path_and_query.len() > TARGET_BYTES {
        return Err(PolyguardError::LimitExceeded {
            limit: "target_bytes".into(),
            max: TARGET_BYTES,
            actual: path_and_query.len(),
        });
    }
    Ok(NormalizedTarget {
        form,
        scheme,
        authority,
        path_and_query,
        routing_path,
    })
}

fn non_path_target(
    form: TargetForm,
    authority: Option<String>,
    spelling: String,
) -> NormalizedTarget {
    NormalizedTarget {
        form,
        scheme: None,
        authority,
        path_and_query: spelling.clone(),
        routing_path: spelling,
    }
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
