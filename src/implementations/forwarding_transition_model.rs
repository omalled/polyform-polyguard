use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ForwardingPolicy, ForwardingResult, HeaderBlock, PolyguardError, Result};

const VALUE_LIMIT: usize = 1024;
const APPEND_SEPARATOR: &str = ", ";

#[derive(Clone, Copy)]
enum FieldSlot {
    Forwarded = 0,
    For = 1,
    Proto = 2,
    Host = 3,
}

const FIELD_SLOTS: [(&str, FieldSlot); 4] = [
    ("forwarded", FieldSlot::Forwarded),
    ("x-forwarded-for", FieldSlot::For),
    ("x-forwarded-proto", FieldSlot::Proto),
    ("x-forwarded-host", FieldSlot::Host),
];

#[derive(Clone, Copy)]
enum Occupancy {
    Vacant = 0,
    Occupied = 1,
}

#[derive(Clone, Copy)]
enum Transition {
    Store,
    RejectDuplicate,
}

// Every recognized header drives this single state transition.  Keeping the duplicate
// policy data-driven makes the scan independent of the formatting path below.
const HEADER_TRANSITIONS: [Transition; 2] = [Transition::Store, Transition::RejectDuplicate];

enum ClientAddress<'a> {
    V4(&'a str),
    V6(&'a str),
}

pub fn apply_forwarding_policy(
    policy: &ForwardingPolicy,
    headers: &HeaderBlock,
) -> Result<ForwardingResult> {
    let client = validate_client_address(&policy.client_ip)?;
    validate_proto(&policy.proto)?;
    validate_authority(&policy.host)?;

    let current = [
        format_forwarded_hop(client, &policy.proto, &policy.host),
        policy.client_ip.clone(),
        policy.proto.clone(),
        policy.host.clone(),
    ];

    if !policy.trust_incoming {
        return result_from_values(current);
    }

    let mut incoming: [Option<&[u8]>; 4] = [None; 4];
    for field in &headers.fields {
        let Some(slot) = lookup_slot(&field.name) else {
            continue;
        };
        validate_incoming_value(&field.value)?;

        let index = slot as usize;
        let occupancy = if incoming[index].is_some() {
            Occupancy::Occupied
        } else {
            Occupancy::Vacant
        };
        match HEADER_TRANSITIONS[occupancy as usize] {
            Transition::Store => incoming[index] = Some(&field.value),
            Transition::RejectDuplicate => return Err(PolyguardError::InvalidForwardingInput),
        }
    }

    let mut output = current;
    for index in 0..output.len() {
        if let Some(prefix) = incoming[index] {
            output[index] = append_value(prefix, &output[index])?;
        } else {
            enforce_limit(output[index].len())?;
        }
    }
    result_from_values(output)
}

fn lookup_slot(name: &str) -> Option<FieldSlot> {
    FIELD_SLOTS
        .iter()
        .find(|(candidate, _)| name.eq_ignore_ascii_case(candidate))
        .map(|(_, slot)| *slot)
}

fn validate_client_address(input: &str) -> Result<ClientAddress<'_>> {
    if input.contains(['[', ']', '%']) {
        return Err(PolyguardError::InvalidForwardingInput);
    }

    match input.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) if canonical_ipv4(input, address) => Ok(ClientAddress::V4(input)),
        Ok(IpAddr::V6(_)) => Ok(ClientAddress::V6(input)),
        _ => Err(PolyguardError::InvalidForwardingInput),
    }
}

fn canonical_ipv4(input: &str, address: Ipv4Addr) -> bool {
    address.to_string() == input
}

fn validate_proto(proto: &str) -> Result<()> {
    if matches!(proto, "http" | "https") {
        Ok(())
    } else {
        Err(PolyguardError::InvalidForwardingInput)
    }
}

fn validate_authority(authority: &str) -> Result<()> {
    if authority.is_empty() || !authority.is_ascii() {
        return Err(PolyguardError::InvalidForwardingInput);
    }

    if let Some(literal) = authority.strip_prefix('[') {
        let Some(close) = literal.find(']') else {
            return Err(PolyguardError::InvalidForwardingInput);
        };
        let (address, suffix) = literal.split_at(close);
        if address.is_empty()
            || address.contains('%')
            || address.parse::<Ipv6Addr>().is_err()
            || !valid_port_suffix(&suffix[1..])
        {
            return Err(PolyguardError::InvalidForwardingInput);
        }
        return Ok(());
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        Some(_) => return Err(PolyguardError::InvalidForwardingInput),
        None => (authority, None),
    };
    if !valid_dns_name(host) || port.is_some_and(|value| !valid_port(value)) {
        return Err(PolyguardError::InvalidForwardingInput);
    }
    Ok(())
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|number| number != 0)
}

fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn format_forwarded_hop(client: ClientAddress<'_>, proto: &str, host: &str) -> String {
    let node = match client {
        ClientAddress::V4(address) => format!("for={address}"),
        ClientAddress::V6(address) => format!("for=\"[{address}]\""),
    };
    format!("{node};proto={proto};host=\"{}\"", escape_quoted(host))
}

fn escape_quoted(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn validate_incoming_value(value: &[u8]) -> Result<()> {
    enforce_limit(value.len())?;
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

fn append_value(prefix: &[u8], current: &str) -> Result<String> {
    let actual = prefix.len() + APPEND_SEPARATOR.len() + current.len();
    enforce_limit(actual)?;

    let prefix = std::str::from_utf8(prefix).map_err(|_| PolyguardError::InvalidForwardingInput)?;
    let mut combined = String::with_capacity(actual);
    combined.push_str(prefix);
    combined.push_str(APPEND_SEPARATOR);
    combined.push_str(current);
    Ok(combined)
}

fn enforce_limit(actual: usize) -> Result<()> {
    if actual > VALUE_LIMIT {
        Err(PolyguardError::LimitExceeded {
            limit: "forwarding_value_bytes".into(),
            max: VALUE_LIMIT,
            actual,
        })
    } else {
        Ok(())
    }
}

fn result_from_values(values: [String; 4]) -> Result<ForwardingResult> {
    for value in &values {
        enforce_limit(value.len())?;
    }
    let [
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    ] = values;
    Ok(ForwardingResult {
        forwarded,
        x_forwarded_for,
        x_forwarded_proto,
        x_forwarded_host,
    })
}
