use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::BuildHasherDefault,
};

use crate::{HeaderBlock, HeaderField, PolyguardError, Result, SanitizedHeaders};

const CONNECTION: &str = "connection";

// Kept sorted so membership does not require allocating or hashing a probe.
const FIXED_HOP_BY_HOP_NAMES: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const TOKEN_PUNCTUATION: &[u8] = b"!#$%&'*+-.^_`|~";

type RemovalSet = HashSet<String, BuildHasherDefault<DefaultHasher>>;

/// Remove fixed and Connection-nominated hop-by-hop fields while retaining the
/// exact order and representation of end-to-end fields.
pub(crate) fn remove_hop_by_hop_headers(headers: &HeaderBlock) -> Result<SanitizedHeaders> {
    let removals = discover_removals(headers)?;
    let fields = copy_survivors(&headers.fields, &removals);
    let mut removed_names: Vec<String> = removals.into_iter().collect();
    removed_names.sort_unstable();

    Ok(SanitizedHeaders {
        fields,
        removed_names,
    })
}

fn discover_removals(headers: &HeaderBlock) -> Result<RemovalSet> {
    let mut removals = RemovalSet::default();

    for (index, field) in headers.fields.iter().enumerate() {
        if is_fixed_hop_by_hop(&field.name) {
            removals.insert(field.name.clone());
        }

        if field.name != CONNECTION {
            continue;
        }

        add_connection_value(&field.value, index, &mut removals)?;
    }

    Ok(removals)
}

fn add_connection_value(value: &[u8], field_index: usize, removals: &mut RemovalSet) -> Result<()> {
    let mut member_start = 0;

    loop {
        let comma = value[member_start..]
            .iter()
            .position(|byte| *byte == b',')
            .map(|offset| member_start + offset);
        let member_end = comma.unwrap_or(value.len());
        let member = strip_optional_whitespace(&value[member_start..member_end]);
        let Some(name) = validated_canonical_token(member) else {
            return Err(invalid_connection_token(field_index));
        };
        removals.insert(name);

        let Some(comma_index) = comma else {
            return Ok(());
        };
        member_start = comma_index + 1;
    }
}

fn strip_optional_whitespace(mut member: &[u8]) -> &[u8] {
    while matches!(member.first(), Some(b' ' | b'\t')) {
        member = &member[1..];
    }
    while matches!(member.last(), Some(b' ' | b'\t')) {
        member = &member[..member.len() - 1];
    }
    member
}

fn validated_canonical_token(member: &[u8]) -> Option<String> {
    if member.is_empty() {
        return None;
    }
    if member
        .iter()
        .any(|byte| !byte.is_ascii_alphanumeric() && !TOKEN_PUNCTUATION.contains(byte))
    {
        return None;
    }

    let mut canonical = String::with_capacity(member.len());
    for byte in member {
        canonical.push(byte.to_ascii_lowercase() as char);
    }
    Some(canonical)
}

fn is_fixed_hop_by_hop(name: &str) -> bool {
    FIXED_HOP_BY_HOP_NAMES.binary_search(&name).is_ok()
}

fn copy_survivors(fields: &[HeaderField], removals: &RemovalSet) -> Vec<HeaderField> {
    let survivor_count = fields
        .iter()
        .filter(|field| !removals.contains(field.name.as_str()))
        .count();
    let mut survivors = Vec::with_capacity(survivor_count);

    for field in fields {
        if removals.contains(field.name.as_str()) {
            continue;
        }
        survivors.push(field.clone());
    }

    survivors
}

fn invalid_connection_token(index: usize) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: "invalid_connection_token".into(),
    }
}
