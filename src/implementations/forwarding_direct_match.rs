use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{ForwardingPolicy, ForwardingResult, HeaderBlock, PolyguardError, Result};

const VALUE_LIMIT: usize = 1024;
const LIMIT_NAME: &str = "forwarding_value_bytes";

#[derive(Clone, Copy)]
enum ClientFamily {
    V4,
    V6,
}

#[derive(Default)]
struct PriorValues<'a> {
    forwarded: Option<&'a [u8]>,
    x_for: Option<&'a [u8]>,
    x_proto: Option<&'a [u8]>,
    x_host: Option<&'a [u8]>,
}

/// Apply forwarding metadata with direct validation and exhaustive boundary decisions.
pub fn apply_forwarding_policy(
    policy: &ForwardingPolicy,
    headers: &HeaderBlock,
) -> Result<ForwardingResult> {
    let family = validate_listener_values(policy)?;
    let prior = match policy.trust_incoming {
        false => PriorValues::default(),
        true => inspect_prior_values(headers)?,
    };

    let new_forwarded = canonical_hop(policy, family)?;
    let forwarded_len = combined_len(prior.forwarded, new_forwarded.len())?;
    let x_for_len = combined_len(prior.x_for, policy.client_ip.len())?;
    let x_proto_len = combined_len(prior.x_proto, policy.proto.len())?;
    let x_host_len = combined_len(prior.x_host, policy.host.len())?;

    Ok(ForwardingResult {
        forwarded: combine(prior.forwarded, &new_forwarded, forwarded_len)?,
        x_forwarded_for: combine(prior.x_for, &policy.client_ip, x_for_len)?,
        x_forwarded_proto: combine(prior.x_proto, &policy.proto, x_proto_len)?,
        x_forwarded_host: combine(prior.x_host, &policy.host, x_host_len)?,
    })
}

fn validate_listener_values(policy: &ForwardingPolicy) -> Result<ClientFamily> {
    let family = match (
        policy.client_ip.parse::<Ipv4Addr>(),
        policy.client_ip.parse::<Ipv6Addr>(),
    ) {
        (Ok(address), _) if address.to_string() == policy.client_ip => ClientFamily::V4,
        (_, Ok(address)) if address.to_string() == policy.client_ip => ClientFamily::V6,
        _ => return Err(PolyguardError::InvalidForwardingInput),
    };

    match policy.proto.as_str() {
        "http" | "https" => {}
        _ => return Err(PolyguardError::InvalidForwardingInput),
    }

    validate_host(&policy.host)?;
    Ok(family)
}

fn validate_host(authority: &str) -> Result<()> {
    if authority.is_empty()
        || !authority.is_ascii()
        || authority.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b',' | b'@' | b'/' | b'?' | b'#' | b'%')
        })
    {
        return Err(PolyguardError::InvalidForwardingInput);
    }

    match authority.strip_prefix('[') {
        Some(remainder) => match remainder.split_once(']') {
            Some((literal, suffix))
                if !literal.is_empty()
                    && !literal.contains('%')
                    && literal.parse::<Ipv6Addr>().is_ok() =>
            {
                match suffix {
                    "" => Ok(()),
                    value if value.starts_with(':') => validate_port(&value[1..]),
                    _ => Err(PolyguardError::InvalidForwardingInput),
                }
            }
            _ => Err(PolyguardError::InvalidForwardingInput),
        },
        None => {
            let (name, port) = match authority.split_once(':') {
                None => (authority, None),
                Some((name, port)) if !port.contains(':') => (name, Some(port)),
                Some(_) => return Err(PolyguardError::InvalidForwardingInput),
            };
            let name = name.strip_suffix('.').unwrap_or(name);
            if name.is_empty() || name.len() > 253 {
                return Err(PolyguardError::InvalidForwardingInput);
            }
            if name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }) {
                return Err(PolyguardError::InvalidForwardingInput);
            }
            match port {
                None => Ok(()),
                Some(value) => validate_port(value),
            }
        }
    }
}

fn validate_port(port: &str) -> Result<()> {
    match port.parse::<u16>() {
        Ok(1..=u16::MAX) if port.bytes().all(|byte| byte.is_ascii_digit()) => Ok(()),
        _ => Err(PolyguardError::InvalidForwardingInput),
    }
}

fn inspect_prior_values(headers: &HeaderBlock) -> Result<PriorValues<'_>> {
    let mut prior = PriorValues::default();
    for field in &headers.fields {
        let destination = match field.name.as_str() {
            "forwarded" => Some(&mut prior.forwarded),
            "x-forwarded-for" => Some(&mut prior.x_for),
            "x-forwarded-proto" => Some(&mut prior.x_proto),
            "x-forwarded-host" => Some(&mut prior.x_host),
            _ => None,
        };
        match destination {
            Some(slot) if slot.is_none() => {
                validate_prior_value(&field.value)?;
                *slot = Some(&field.value);
            }
            Some(_) => return Err(PolyguardError::InvalidForwardingInput),
            None => {}
        }
    }
    Ok(prior)
}

fn validate_prior_value(value: &[u8]) -> Result<()> {
    check_limit(value.len())?;
    if value.is_empty() || value.iter().any(|byte| !(b' '..=b'~').contains(byte)) {
        return Err(PolyguardError::InvalidForwardingInput);
    }

    let mut member_has_content = false;
    for byte in value {
        match *byte {
            b',' if member_has_content => member_has_content = false,
            b',' => return Err(PolyguardError::InvalidForwardingInput),
            b' ' => {}
            _ => member_has_content = true,
        }
    }
    match member_has_content {
        true => Ok(()),
        false => Err(PolyguardError::InvalidForwardingInput),
    }
}

fn canonical_hop(policy: &ForwardingPolicy, family: ClientFamily) -> Result<String> {
    let address_overhead = match family {
        ClientFamily::V4 => 0,
        ClientFamily::V6 => 4,
    };
    let escaped = policy
        .host
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    let length = 19usize
        .saturating_add(address_overhead)
        .saturating_add(policy.client_ip.len())
        .saturating_add(policy.proto.len())
        .saturating_add(policy.host.len())
        .saturating_add(escaped);
    check_limit(length)?;

    let mut output = String::with_capacity(length);
    output.push_str("for=");
    match family {
        ClientFamily::V4 => output.push_str(&policy.client_ip),
        ClientFamily::V6 => {
            output.push_str("\"[");
            output.push_str(&policy.client_ip);
            output.push_str("]\"");
        }
    }
    output.push_str(";proto=");
    output.push_str(&policy.proto);
    output.push_str(";host=\"");
    for character in policy.host.chars() {
        match character {
            '"' | '\\' => {
                output.push('\\');
                output.push(character);
            }
            _ => output.push(character),
        }
    }
    output.push('"');
    Ok(output)
}

fn combined_len(previous: Option<&[u8]>, addition_len: usize) -> Result<usize> {
    let actual = match previous {
        None => addition_len,
        Some(value) => value
            .len()
            .checked_add(2)
            .and_then(|length| length.checked_add(addition_len))
            .unwrap_or(usize::MAX),
    };
    check_limit(actual)?;
    Ok(actual)
}

fn combine(previous: Option<&[u8]>, addition: &str, length: usize) -> Result<String> {
    let mut output = String::with_capacity(length);
    match previous {
        None => {}
        Some(value) => {
            let value =
                std::str::from_utf8(value).map_err(|_| PolyguardError::InvalidForwardingInput)?;
            output.push_str(value);
            output.push_str(", ");
        }
    }
    output.push_str(addition);
    Ok(output)
}

fn check_limit(actual: usize) -> Result<()> {
    match actual {
        0..=VALUE_LIMIT => Ok(()),
        _ => Err(PolyguardError::LimitExceeded {
            limit: LIMIT_NAME.into(),
            max: VALUE_LIMIT,
            actual,
        }),
    }
}
