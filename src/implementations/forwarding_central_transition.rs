use std::net::{IpAddr, Ipv6Addr};

use crate::{ForwardingPolicy, ForwardingResult, HeaderBlock, PolyguardError, Result};

const VALUE_LIMIT: usize = 1024;
const LIMIT_NAME: &str = "forwarding_value_bytes";
const SEPARATOR: &str = ", ";

#[derive(Clone, Copy)]
enum OutputSlot {
    Forwarded = 0,
    For = 1,
    Proto = 2,
    Host = 3,
}

struct HeaderRule {
    name: &'static str,
    slot: OutputSlot,
}

const FORWARDING_HEADERS: [HeaderRule; 4] = [
    HeaderRule {
        name: "forwarded",
        slot: OutputSlot::Forwarded,
    },
    HeaderRule {
        name: "x-forwarded-for",
        slot: OutputSlot::For,
    },
    HeaderRule {
        name: "x-forwarded-proto",
        slot: OutputSlot::Proto,
    },
    HeaderRule {
        name: "x-forwarded-host",
        slot: OutputSlot::Host,
    },
];

enum BoundaryState<'a> {
    Replace,
    Extend([Option<&'a str>; 4]),
}

pub fn apply_forwarding_policy(
    policy: &ForwardingPolicy,
    headers: &HeaderBlock,
) -> Result<ForwardingResult> {
    let client = canonical_client(&policy.client_ip)?;
    let canonical_for = match client {
        IpAddr::V4(_) => format!("for={}", policy.client_ip),
        IpAddr::V6(_) => format!("for=\"[{}]\"", policy.client_ip),
    };

    validate_proto(&policy.proto)?;

    validate_authority(&policy.host)?;
    let escaped_host = quote_host(&policy.host);
    let canonical_forwarded = format!("{canonical_for};proto={};host={escaped_host}", policy.proto);

    let state = if policy.trust_incoming {
        BoundaryState::Extend(collect_forwarding_headers(headers)?)
    } else {
        BoundaryState::Replace
    };

    let canonical = [
        canonical_forwarded.as_str(),
        policy.client_ip.as_str(),
        policy.proto.as_str(),
        policy.host.as_str(),
    ];
    let outputs = match state {
        BoundaryState::Replace => canonical
            .map(bounded_copy)
            .into_iter()
            .collect::<Result<Vec<_>>>()?,
        BoundaryState::Extend(previous) => previous
            .into_iter()
            .zip(canonical)
            .map(|(old, new)| transition_value(old, new))
            .collect::<Result<Vec<_>>>()?,
    };

    let [
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    ]: [String; 4] = outputs
        .try_into()
        .map_err(|_| PolyguardError::InvalidForwardingInput)?;

    Ok(ForwardingResult {
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    })
}

fn canonical_client(value: &str) -> Result<IpAddr> {
    if value.contains(['[', ']', '%']) {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| PolyguardError::InvalidForwardingInput)?;
    if address.to_string() != value {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    Ok(address)
}

fn validate_proto(value: &str) -> Result<()> {
    match value {
        "http" | "https" => Ok(()),
        _ => Err(PolyguardError::InvalidForwardingInput),
    }
}

fn validate_authority(value: &str) -> Result<()> {
    if value.is_empty() || !value.is_ascii() {
        return Err(PolyguardError::InvalidForwardingInput);
    }

    if let Some(after_open) = value.strip_prefix('[') {
        let close = after_open
            .find(']')
            .ok_or(PolyguardError::InvalidForwardingInput)?;
        let address_text = &after_open[..close];
        address_text
            .parse::<Ipv6Addr>()
            .map_err(|_| PolyguardError::InvalidForwardingInput)?;
        let remainder = &after_open[close + 1..];
        if remainder.is_empty() {
            return Ok(());
        }
        return validate_port(
            remainder
                .strip_prefix(':')
                .ok_or(PolyguardError::InvalidForwardingInput)?,
        );
    }

    if value.contains(['[', ']', '@', '/', '?', '#', ',', '\\', '"']) {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        Some(_) => return Err(PolyguardError::InvalidForwardingInput),
        None => (value, None),
    };
    validate_dns_name(host)?;
    if let Some(port) = port {
        validate_port(port)?;
    }
    Ok(())
}

fn validate_dns_name(host: &str) -> Result<()> {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PolyguardError::InvalidForwardingInput);
        }
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<()> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    let number = port
        .parse::<u16>()
        .map_err(|_| PolyguardError::InvalidForwardingInput)?;
    if number == 0 {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    Ok(())
}

fn quote_host(host: &str) -> String {
    let extra = host
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    let mut quoted = String::with_capacity(host.len() + extra + 2);
    quoted.push('"');
    for character in host.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

fn collect_forwarding_headers(headers: &HeaderBlock) -> Result<[Option<&str>; 4]> {
    let mut values = [None; 4];
    for field in &headers.fields {
        let Some(rule) = FORWARDING_HEADERS
            .iter()
            .find(|rule| field.name == rule.name)
        else {
            continue;
        };
        validate_incoming_value(&field.value)?;
        let slot = rule.slot as usize;
        if values[slot].is_some() {
            return Err(PolyguardError::InvalidForwardingInput);
        }
        values[slot] = Some(
            std::str::from_utf8(&field.value)
                .map_err(|_| PolyguardError::InvalidForwardingInput)?,
        );
    }
    Ok(values)
}

fn validate_incoming_value(value: &[u8]) -> Result<()> {
    check_limit(value.len())?;
    if value
        .iter()
        .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
        || value
            .split(|byte| *byte == b',')
            .any(|member| member.iter().all(|byte| *byte == b' '))
    {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    Ok(())
}

fn bounded_copy(value: &str) -> Result<String> {
    check_limit(value.len())?;
    Ok(value.to_owned())
}

fn transition_value(previous: Option<&str>, canonical: &str) -> Result<String> {
    let length = previous.map_or(canonical.len(), |value| {
        value.len() + SEPARATOR.len() + canonical.len()
    });
    check_limit(length)?;

    let mut output = String::with_capacity(length);
    if let Some(value) = previous {
        output.push_str(value);
        output.push_str(SEPARATOR);
    }
    output.push_str(canonical);
    Ok(output)
}

fn check_limit(actual: usize) -> Result<()> {
    if actual > VALUE_LIMIT {
        Err(PolyguardError::LimitExceeded {
            limit: LIMIT_NAME.into(),
            max: VALUE_LIMIT,
            actual,
        })
    } else {
        Ok(())
    }
}
