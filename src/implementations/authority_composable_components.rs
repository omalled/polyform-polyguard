use std::net::Ipv6Addr;

use crate::{
    EffectiveAuthority, HeaderBlock, NormalizedTarget, PolyguardError, Result, TargetForm,
};

struct Authority {
    host: String,
    port: Option<u16>,
}

enum HostSyntax<'a> {
    Dns(&'a str),
    Ipv6(&'a str),
}

pub fn reconcile_authority(
    target: &NormalizedTarget,
    headers: &HeaderBlock,
) -> Result<EffectiveAuthority> {
    // Phase 1: establish Host cardinality before interpreting any field value. This makes a
    // repeated or list-shaped Host unambiguously a multiplicity error, even when one member
    // would independently be malformed.
    let host_value = single_host_value(headers)?;
    require_host_for_form(&target.form, host_value)?;

    // Phase 2: validate both external authority spellings at the public boundary. Later phases
    // only receive canonical hosts and bounded numeric ports.
    let header_authority = host_value.map(parse_authority).transpose()?;
    let target_authority = target
        .authority
        .as_deref()
        .map(|value| parse_authority(value.as_bytes()))
        .transpose()?;
    let default_port = default_port(target);

    // Phase 3: compare semantic endpoints, then render the preferred target spelling while
    // suppressing a scheme-default port.
    let disagreement = target_authority
        .as_ref()
        .zip(header_authority.as_ref())
        .is_some_and(|(from_target, from_header)| {
            from_target.host != from_header.host
                || comparable_port(from_target.port, default_port)
                    != comparable_port(from_header.port, default_port)
        });
    if disagreement {
        return Err(PolyguardError::AuthorityMismatch);
    }

    let selected = target_authority
        .or(header_authority)
        .ok_or(PolyguardError::MissingHost)?;
    Ok(EffectiveAuthority {
        host: selected.host,
        port: selected.port.filter(|port| Some(*port) != default_port),
    })
}

fn single_host_value(headers: &HeaderBlock) -> Result<Option<&[u8]>> {
    let mut found = None;

    for field in &headers.fields {
        if !field.name.eq_ignore_ascii_case("host") {
            continue;
        }
        if found.is_some() || is_repeated_comma_value(&field.value) {
            return Err(PolyguardError::MultipleHost);
        }
        found = Some(field.value.as_slice());
    }

    Ok(found)
}

fn is_repeated_comma_value(value: &[u8]) -> bool {
    let mut members = value.split(|byte| *byte == b',');
    let Some(first) = members.next() else {
        return false;
    };
    let mut count = 1_usize;
    for member in members {
        count += 1;
        if member != first {
            return false;
        }
    }
    count > 1
}

fn require_host_for_form(form: &TargetForm, host: Option<&[u8]>) -> Result<()> {
    if matches!(form, TargetForm::Origin | TargetForm::Asterisk) && host.is_none() {
        return Err(PolyguardError::MissingHost);
    }
    Ok(())
}

fn parse_authority(input: &[u8]) -> Result<Authority> {
    if input.is_empty() || !input.is_ascii() {
        return Err(PolyguardError::InvalidAuthority);
    }
    let text = std::str::from_utf8(input).map_err(|_| PolyguardError::InvalidAuthority)?;
    let (syntax, port_text) = separate_host_and_port(text)?;
    let host = match syntax {
        HostSyntax::Dns(value) => canonical_dns(value)?,
        HostSyntax::Ipv6(value) => canonical_ipv6(value)?,
    };
    let port = port_text.map(parse_port).transpose()?;

    Ok(Authority { host, port })
}

fn separate_host_and_port(text: &str) -> Result<(HostSyntax<'_>, Option<&str>)> {
    if let Some(after_open) = text.strip_prefix('[') {
        let close = after_open
            .find(']')
            .ok_or(PolyguardError::InvalidAuthority)?;
        let literal = &after_open[..close];
        let suffix = &after_open[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .filter(|value| !value.is_empty())
                    .ok_or(PolyguardError::InvalidAuthority)?,
            )
        };
        return Ok((HostSyntax::Ipv6(literal), port));
    }

    let colon_count = text.bytes().filter(|byte| *byte == b':').count();
    match colon_count {
        0 => Ok((HostSyntax::Dns(text), None)),
        1 => {
            let (host, port) = text
                .split_once(':')
                .ok_or(PolyguardError::InvalidAuthority)?;
            if host.is_empty() || port.is_empty() {
                return Err(PolyguardError::InvalidAuthority);
            }
            Ok((HostSyntax::Dns(host), Some(port)))
        }
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn canonical_dns(text: &str) -> Result<String> {
    let without_final_dot = text.strip_suffix('.').unwrap_or(text);
    if without_final_dot.is_empty() || without_final_dot.len() > 253 {
        return Err(PolyguardError::InvalidAuthority);
    }

    for label in without_final_dot.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(PolyguardError::InvalidAuthority);
        }
    }

    Ok(without_final_dot.to_ascii_lowercase())
}

fn canonical_ipv6(text: &str) -> Result<String> {
    if text.is_empty() || text.contains('%') || text.parse::<Ipv6Addr>().is_err() {
        return Err(PolyguardError::InvalidAuthority);
    }
    Ok(format!("[{}]", text.to_ascii_lowercase()))
}

fn parse_port(text: &str) -> Result<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolyguardError::InvalidAuthority);
    }

    let value = text.bytes().try_fold(0_u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(u32::from(byte - b'0')))
    });
    match value {
        Some(value @ 1..=65_535) => Ok(value as u16),
        _ => Err(PolyguardError::InvalidAuthority),
    }
}

fn default_port(target: &NormalizedTarget) -> Option<u16> {
    if !matches!(target.form, TargetForm::Absolute) {
        return None;
    }
    match target.scheme.as_deref() {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

fn comparable_port(port: Option<u16>, default: Option<u16>) -> Option<u16> {
    port.or(default)
}
