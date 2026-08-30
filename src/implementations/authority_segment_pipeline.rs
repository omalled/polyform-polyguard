use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, HeaderBlock, NormalizedTarget, PolyguardError, Result, TargetForm,
};

const TARGET_SOURCE: usize = 0;
const HEADER_SOURCE: usize = 1;

struct Boundary<'a> {
    sources: [Option<&'a [u8]>; 2],
    default_port: Option<u16>,
}

#[derive(Clone, Copy)]
struct Endpoint<'a> {
    canonical_host: &'a [u8],
    explicit_port: Option<u16>,
}

/// Reconcile authority through a fixed two-source pipeline: validate the public
/// boundary, decode both spellings into compact slices and integers, establish
/// agreement, and only then allocate the result.
pub fn reconcile_authority(
    target: &NormalizedTarget,
    headers: &HeaderBlock,
) -> Result<EffectiveAuthority> {
    let boundary = validate_boundary(target, headers)?;
    let endpoints = decode_sources(&boundary)?;

    require_agreement(&endpoints, boundary.default_port)?;
    materialize_preferred(endpoints, boundary.default_port)
}

fn validate_boundary<'a>(
    target: &'a NormalizedTarget,
    headers: &'a HeaderBlock,
) -> Result<Boundary<'a>> {
    let header = validate_host_cardinality(headers)?;

    let (target_authority, default_port, host_required) = match (
        &target.form,
        target.scheme.as_deref(),
        target.authority.as_deref(),
    ) {
        (TargetForm::Origin | TargetForm::Asterisk, None, None) => (None, None, true),
        (TargetForm::Absolute, Some("http"), Some(value)) => {
            (Some(value.as_bytes()), Some(80), false)
        }
        (TargetForm::Absolute, Some("https"), Some(value)) => {
            (Some(value.as_bytes()), Some(443), false)
        }
        (TargetForm::Authority, None, Some(value)) => (Some(value.as_bytes()), None, false),
        _ => return Err(PolyguardError::InvalidAuthority),
    };

    if host_required && header.is_none() {
        return Err(PolyguardError::MissingHost);
    }

    Ok(Boundary {
        sources: [target_authority, header],
        default_port,
    })
}

fn validate_host_cardinality(headers: &HeaderBlock) -> Result<Option<&[u8]>> {
    let mut host = None;

    for field in &headers.fields {
        if field.name != "host" {
            continue;
        }
        if host.is_some() {
            return Err(PolyguardError::MultipleHost);
        }
        host = Some(field.value.as_slice());
    }

    if let Some(value) = host
        && value.contains(&b',')
    {
        return Err(classify_list_shaped_host(value));
    }
    Ok(host)
}

fn classify_list_shaped_host(value: &[u8]) -> PolyguardError {
    let mut members = value.split(|byte| *byte == b',');
    let first = members.next().unwrap_or_default();
    if !first.is_empty() && members.all(|member| member == first) {
        PolyguardError::MultipleHost
    } else {
        PolyguardError::InvalidAuthority
    }
}

fn decode_sources<'a>(boundary: &Boundary<'a>) -> Result<[Option<Endpoint<'a>>; 2]> {
    let mut decoded = [None, None];
    for index in [TARGET_SOURCE, HEADER_SOURCE] {
        decoded[index] = boundary.sources[index].map(decode_authority).transpose()?;
    }
    Ok(decoded)
}

fn decode_authority(input: &[u8]) -> Result<Endpoint<'_>> {
    validate_authority_alphabet(input)?;

    if input.first() == Some(&b'[') {
        decode_bracketed_ipv6(input)
    } else {
        decode_dns_authority(input)
    }
}

fn validate_authority_alphabet(input: &[u8]) -> Result<()> {
    let forbidden = input.is_empty()
        || !input.is_ascii()
        || input.iter().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b',' | b'@' | b'/' | b'\\' | b'?' | b'#' | b'%')
        });

    if forbidden {
        Err(PolyguardError::InvalidAuthority)
    } else {
        Ok(())
    }
}

fn decode_bracketed_ipv6(input: &[u8]) -> Result<Endpoint<'_>> {
    let close = input
        .iter()
        .position(|byte| *byte == b']')
        .ok_or(PolyguardError::InvalidAuthority)?;
    let host = &input[..=close];
    let literal =
        std::str::from_utf8(&input[1..close]).map_err(|_| PolyguardError::InvalidAuthority)?;
    if literal.is_empty() || literal.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }

    let explicit_port = decode_suffix_port(&input[close + 1..])?;
    Ok(Endpoint {
        canonical_host: host,
        explicit_port,
    })
}

fn decode_dns_authority(input: &[u8]) -> Result<Endpoint<'_>> {
    let colon = input.iter().position(|byte| *byte == b':');
    let (spelled_host, explicit_port) = match colon {
        Some(index) => {
            if input[index + 1..].contains(&b':') {
                return Err(PolyguardError::InvalidAuthority);
            }
            (&input[..index], Some(decode_port(&input[index + 1..])?))
        }
        None => (input, None),
    };

    let canonical_host = spelled_host.strip_suffix(b".").unwrap_or(spelled_host);
    validate_dns_name(canonical_host)?;
    Ok(Endpoint {
        canonical_host,
        explicit_port,
    })
}

fn decode_suffix_port(suffix: &[u8]) -> Result<Option<u16>> {
    if suffix.is_empty() {
        return Ok(None);
    }
    let digits = suffix
        .strip_prefix(b":")
        .ok_or(PolyguardError::InvalidAuthority)?;
    decode_port(digits).map(Some)
}

fn validate_dns_name(host: &[u8]) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return Err(PolyguardError::InvalidAuthority);
    }

    for label in host.split(|byte| *byte == b'.') {
        let valid_edges = label.first().is_some_and(|byte| *byte != b'-')
            && label.last().is_some_and(|byte| *byte != b'-');
        let valid_body = label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        if label.len() > 63 || !valid_edges || !valid_body {
            return Err(PolyguardError::InvalidAuthority);
        }
    }
    Ok(())
}

fn decode_port(digits: &[u8]) -> Result<u16> {
    if digits.is_empty() {
        return Err(PolyguardError::InvalidAuthority);
    }

    let mut port = 0_u32;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return Err(PolyguardError::InvalidAuthority);
        }
        port = port
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(*digit - b'0')))
            .ok_or(PolyguardError::InvalidAuthority)?;
        if port > u32::from(u16::MAX) {
            return Err(PolyguardError::InvalidAuthority);
        }
    }

    u16::try_from(port)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(PolyguardError::InvalidAuthority)
}

fn require_agreement(endpoints: &[Option<Endpoint<'_>>; 2], default: Option<u16>) -> Result<()> {
    let (Some(target), Some(header)) = (endpoints[TARGET_SOURCE], endpoints[HEADER_SOURCE]) else {
        return Ok(());
    };

    let same_host = target
        .canonical_host
        .eq_ignore_ascii_case(header.canonical_host);
    let same_port = target.explicit_port.or(default) == header.explicit_port.or(default);
    if same_host && same_port {
        Ok(())
    } else {
        Err(PolyguardError::AuthorityMismatch)
    }
}

fn materialize_preferred(
    endpoints: [Option<Endpoint<'_>>; 2],
    default: Option<u16>,
) -> Result<EffectiveAuthority> {
    let selected = endpoints[TARGET_SOURCE]
        .or(endpoints[HEADER_SOURCE])
        .ok_or(PolyguardError::MissingHost)?;
    let host = selected
        .canonical_host
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(char::from)
        .collect();

    Ok(EffectiveAuthority {
        host,
        port: selected.explicit_port.filter(|port| Some(*port) != default),
    })
}
