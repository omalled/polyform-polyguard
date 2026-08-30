use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ForwardingPolicy, ForwardingResult, HeaderBlock, PolyguardError, Result};

const FORWARDING_VALUE_LIMIT: usize = 1024;
const FORWARDING_LIMIT_NAME: &str = "forwarding_value_bytes";

#[derive(Clone, Copy)]
struct FieldRule {
    name: &'static str,
    slot: usize,
}

const FORWARDED: usize = 0;
const X_FORWARDED_FOR: usize = 1;
const X_FORWARDED_PROTO: usize = 2;
const X_FORWARDED_HOST: usize = 3;

const FIELD_RULES: [FieldRule; 4] = [
    FieldRule {
        name: "forwarded",
        slot: FORWARDED,
    },
    FieldRule {
        name: "x-forwarded-for",
        slot: X_FORWARDED_FOR,
    },
    FieldRule {
        name: "x-forwarded-proto",
        slot: X_FORWARDED_PROTO,
    },
    FieldRule {
        name: "x-forwarded-host",
        slot: X_FORWARDED_HOST,
    },
];

enum Address {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

#[derive(Clone, Copy)]
enum Transition {
    Replace,
    Extend,
}

/// Apply the trusted-boundary forwarding policy through one field decision table.
pub fn apply_forwarding_policy(
    policy: &ForwardingPolicy,
    headers: &HeaderBlock,
) -> Result<ForwardingResult> {
    let address = validate_client_address(&policy.client_ip)?;
    validate_proto(&policy.proto)?;
    validate_host_authority(&policy.host)?;

    let previous = if policy.trust_incoming {
        collect_trusted_values(headers)?
    } else {
        [None; FIELD_RULES.len()]
    };

    let canonical_ip = match address {
        Address::V4(value) => value.to_string(),
        Address::V6(value) => value.to_string(),
    };
    let canonical_forwarded = render_forwarded_hop(&address, &policy.proto, &policy.host)?;
    let additions = [
        canonical_forwarded.as_str(),
        canonical_ip.as_str(),
        policy.proto.as_str(),
        policy.host.as_str(),
    ];
    let transition = if policy.trust_incoming {
        Transition::Extend
    } else {
        Transition::Replace
    };

    let mut outputs: [String; FIELD_RULES.len()] = std::array::from_fn(|_| String::new());
    for rule in FIELD_RULES {
        outputs[rule.slot] =
            transition_value(transition, previous[rule.slot], additions[rule.slot])?;
    }

    let [
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    ] = outputs;
    Ok(ForwardingResult {
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    })
}

fn validate_client_address(input: &str) -> Result<Address> {
    if input.is_empty() || input.contains('%') || input.starts_with('[') || input.ends_with(']') {
        return invalid();
    }

    match input.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) if address.to_string() == input => Ok(Address::V4(address)),
        Ok(IpAddr::V6(address)) => Ok(Address::V6(address)),
        _ => invalid(),
    }
}

fn validate_proto(proto: &str) -> Result<()> {
    if matches!(proto, "http" | "https") {
        Ok(())
    } else {
        invalid()
    }
}

fn validate_host_authority(authority: &str) -> Result<()> {
    if authority.is_empty()
        || !authority.is_ascii()
        || authority.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b',' | b'@' | b'/' | b'?' | b'#' | b'%')
        })
    {
        return invalid();
    }

    if authority.starts_with('[') {
        validate_bracketed_host(authority)
    } else {
        validate_named_host(authority)
    }
}

fn validate_bracketed_host(authority: &str) -> Result<()> {
    let closing = authority
        .find(']')
        .ok_or(PolyguardError::InvalidForwardingInput)?;
    let literal = &authority[1..closing];
    if literal.is_empty() || literal.parse::<Ipv6Addr>().is_err() {
        return invalid();
    }

    let suffix = &authority[closing + 1..];
    if suffix.is_empty() {
        Ok(())
    } else {
        validate_port(
            suffix
                .strip_prefix(':')
                .ok_or(PolyguardError::InvalidForwardingInput)?,
        )
    }
}

fn validate_named_host(authority: &str) -> Result<()> {
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        Some(_) => return invalid(),
        None => (authority, None),
    };

    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return invalid();
    }
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return invalid();
        }
    }

    if let Some(port) = port {
        validate_port(port)?;
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<()> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid();
    }
    match port.parse::<u16>() {
        Ok(1..=u16::MAX) => Ok(()),
        _ => invalid(),
    }
}

fn collect_trusted_values<'a>(headers: &'a HeaderBlock) -> Result<[Option<&'a [u8]>; 4]> {
    let mut values: [Option<&'a [u8]>; FIELD_RULES.len()] = [None; FIELD_RULES.len()];

    for field in &headers.fields {
        let Some(rule) = FIELD_RULES.iter().find(|rule| field.name == rule.name) else {
            continue;
        };
        if values[rule.slot].is_some() {
            return invalid();
        }
        validate_trusted_value(&field.value)?;
        values[rule.slot] = Some(field.value.as_slice());
    }
    Ok(values)
}

fn validate_trusted_value(value: &[u8]) -> Result<()> {
    enforce_limit(value.len())?;
    if value.is_empty() || !value.iter().all(|byte| matches!(*byte, b' '..=b'~')) {
        return invalid();
    }
    if value
        .split(|byte| *byte == b',')
        .any(|member| member.iter().all(|byte| *byte == b' '))
    {
        return invalid();
    }
    Ok(())
}

fn render_forwarded_hop(address: &Address, proto: &str, host: &str) -> Result<String> {
    let address_text = match address {
        Address::V4(value) => value.to_string(),
        Address::V6(value) => format!("\"[{value}]\""),
    };
    let escaped_host_bytes = host
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    let length = b"for=;proto=;host=\"\"".len()
        + address_text.len()
        + proto.len()
        + host.len()
        + escaped_host_bytes;
    enforce_limit(length)?;

    let mut hop = String::with_capacity(length);
    hop.push_str("for=");
    hop.push_str(&address_text);
    hop.push_str(";proto=");
    hop.push_str(proto);
    hop.push_str(";host=\"");
    for character in host.chars() {
        if matches!(character, '"' | '\\') {
            hop.push('\\');
        }
        hop.push(character);
    }
    hop.push('"');
    Ok(hop)
}

fn transition_value(
    transition: Transition,
    previous: Option<&[u8]>,
    addition: &str,
) -> Result<String> {
    let prefix = match transition {
        Transition::Replace => None,
        Transition::Extend => previous,
    };
    let length = prefix.map_or(addition.len(), |value| {
        value.len() + b", ".len() + addition.len()
    });
    enforce_limit(length)?;

    let mut result = String::with_capacity(length);
    if let Some(value) = prefix {
        // Trusted values were restricted to visible ASCII immediately on collection.
        result.push_str(
            std::str::from_utf8(value).map_err(|_| PolyguardError::InvalidForwardingInput)?,
        );
        result.push_str(", ");
    }
    result.push_str(addition);
    Ok(result)
}

fn enforce_limit(actual: usize) -> Result<()> {
    if actual > FORWARDING_VALUE_LIMIT {
        Err(PolyguardError::LimitExceeded {
            limit: FORWARDING_LIMIT_NAME.into(),
            max: FORWARDING_VALUE_LIMIT,
            actual,
        })
    } else {
        Ok(())
    }
}

fn invalid<T>() -> Result<T> {
    Err(PolyguardError::InvalidForwardingInput)
}
