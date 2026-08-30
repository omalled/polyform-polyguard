use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{ForwardingPolicy, ForwardingResult, HeaderBlock, PolyguardError, Result};

const VALUE_MAX: usize = 1024;
const ABSENT: usize = usize::MAX;

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

/// Applies the forwarding boundary after reducing all external input to bounded primitive facts.
pub fn apply_forwarding_policy(
    policy: &ForwardingPolicy,
    headers: &HeaderBlock,
) -> Result<ForwardingResult> {
    let family = validate_policy(policy)?;
    let old_fields = match policy.trust_incoming {
        false => [ABSENT; 4],
        true => validate_trusted_headers(headers)?,
    };

    let hop = make_hop(policy, family)?;
    let additions = [
        hop.as_str(),
        policy.client_ip.as_str(),
        policy.proto.as_str(),
        policy.host.as_str(),
    ];

    // Prove every final bound before allocating any final output buffer.
    let mut sizes = [0usize; 4];
    for index in 0..4 {
        sizes[index] = output_size(old_fields[index], additions[index].len(), headers)?;
    }

    Ok(ForwardingResult {
        forwarded: write_output(old_fields[0], additions[0], sizes[0], headers)?,
        x_forwarded_for: write_output(old_fields[1], additions[1], sizes[1], headers)?,
        x_forwarded_proto: write_output(old_fields[2], additions[2], sizes[2], headers)?,
        x_forwarded_host: write_output(old_fields[3], additions[3], sizes[3], headers)?,
    })
}

fn validate_policy(policy: &ForwardingPolicy) -> Result<IpFamily> {
    let family = match (
        policy.client_ip.parse::<Ipv4Addr>(),
        policy.client_ip.parse::<Ipv6Addr>(),
    ) {
        (Ok(address), _) if address.to_string() == policy.client_ip => IpFamily::V4,
        (Err(_), Ok(_))
            if !policy.client_ip.contains(['[', ']', '%']) && !policy.client_ip.is_empty() =>
        {
            IpFamily::V6
        }
        _ => return invalid(),
    };

    match policy.proto.as_str() {
        "http" | "https" => {}
        _ => return invalid(),
    }

    validate_host_authority(&policy.host)?;
    Ok(family)
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

    match authority.as_bytes().first() {
        Some(b'[') => validate_ipv6_authority(authority),
        Some(_) => validate_dns_authority(authority),
        None => invalid(),
    }
}

fn validate_ipv6_authority(authority: &str) -> Result<()> {
    let close = authority
        .find(']')
        .ok_or(PolyguardError::InvalidForwardingInput)?;
    let literal = &authority[1..close];
    if literal.is_empty() || literal.contains('%') || literal.parse::<Ipv6Addr>().is_err() {
        return invalid();
    }

    match &authority[close + 1..] {
        "" => Ok(()),
        suffix => match suffix.strip_prefix(':') {
            Some(port) => validate_port(port),
            None => invalid(),
        },
    }
}

fn validate_dns_authority(authority: &str) -> Result<()> {
    let (host, port) = match authority.split_once(':') {
        None => (authority, None),
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        Some(_) => return invalid(),
    };

    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return invalid();
    }
    for label in name.split('.') {
        let edge = match (label.as_bytes().first(), label.as_bytes().last()) {
            (Some(first), Some(last)) => {
                first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
            }
            _ => false,
        };
        if label.len() > 63
            || !edge
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return invalid();
        }
    }

    match port {
        Some(value) => validate_port(value),
        None => Ok(()),
    }
}

fn validate_port(port: &str) -> Result<()> {
    match port.parse::<u16>() {
        Ok(1..=u16::MAX) if port.bytes().all(|byte| byte.is_ascii_digit()) => Ok(()),
        _ => invalid(),
    }
}

fn validate_trusted_headers(headers: &HeaderBlock) -> Result<[usize; 4]> {
    let mut positions = [ABSENT; 4];
    for (position, field) in headers.fields.iter().enumerate() {
        let slot = match field.name.as_str() {
            "forwarded" => 0,
            "x-forwarded-for" => 1,
            "x-forwarded-proto" => 2,
            "x-forwarded-host" => 3,
            _ => continue,
        };

        validate_old_value(&field.value)?;
        match positions[slot] {
            ABSENT => positions[slot] = position,
            _ => return invalid(),
        }
    }
    Ok(positions)
}

fn validate_old_value(value: &[u8]) -> Result<()> {
    enforce_bound(value.len())?;

    let mut member_content = false;
    for byte in value {
        match *byte {
            b',' if member_content => member_content = false,
            b',' => return invalid(),
            b' ' => {}
            b'!'..=b'~' => member_content = true,
            _ => return invalid(),
        }
    }
    match member_content {
        true => Ok(()),
        false => invalid(),
    }
}

fn make_hop(policy: &ForwardingPolicy, family: IpFamily) -> Result<String> {
    let family_extra = match family {
        IpFamily::V4 => 0,
        IpFamily::V6 => 4,
    };
    let escaping = policy
        .host
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    let size = 19usize
        .checked_add(family_extra)
        .and_then(|size| size.checked_add(policy.client_ip.len()))
        .and_then(|size| size.checked_add(policy.proto.len()))
        .and_then(|size| size.checked_add(policy.host.len()))
        .and_then(|size| size.checked_add(escaping))
        .unwrap_or(usize::MAX);
    enforce_bound(size)?;

    let mut output = String::with_capacity(size);
    output.push_str("for=");
    match family {
        IpFamily::V4 => output.push_str(&policy.client_ip),
        IpFamily::V6 => {
            output.push_str("\"[");
            output.push_str(&policy.client_ip);
            output.push_str("]\"");
        }
    }
    output.push_str(";proto=");
    output.push_str(&policy.proto);
    output.push_str(";host=\"");
    for byte in policy.host.bytes() {
        match byte {
            b'"' | b'\\' => {
                output.push('\\');
                output.push(char::from(byte));
            }
            _ => output.push(char::from(byte)),
        }
    }
    output.push('"');
    Ok(output)
}

fn output_size(old_position: usize, addition_size: usize, headers: &HeaderBlock) -> Result<usize> {
    let size = match old_position {
        ABSENT => addition_size,
        position => headers.fields[position]
            .value
            .len()
            .checked_add(2)
            .and_then(|size| size.checked_add(addition_size))
            .unwrap_or(usize::MAX),
    };
    enforce_bound(size)?;
    Ok(size)
}

fn write_output(
    old_position: usize,
    addition: &str,
    capacity: usize,
    headers: &HeaderBlock,
) -> Result<String> {
    let mut output = String::with_capacity(capacity);
    match old_position {
        ABSENT => {}
        position => {
            let old = std::str::from_utf8(&headers.fields[position].value)
                .map_err(|_| PolyguardError::InvalidForwardingInput)?;
            output.push_str(old);
            output.push_str(", ");
        }
    }
    output.push_str(addition);
    Ok(output)
}

fn enforce_bound(actual: usize) -> Result<()> {
    match actual {
        0..=VALUE_MAX => Ok(()),
        _ => Err(PolyguardError::LimitExceeded {
            limit: "forwarding_value_bytes".into(),
            max: VALUE_MAX,
            actual,
        }),
    }
}

fn invalid<T>() -> Result<T> {
    Err(PolyguardError::InvalidForwardingInput)
}
