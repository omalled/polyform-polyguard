use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result};

const CONTENT_LENGTH_LIMIT: u64 = 16_777_216;

#[derive(Clone, Copy, PartialEq, Eq)]
struct PresenceKey {
    content_length: bool,
    transfer_encoding: bool,
}

#[derive(Clone, Copy)]
struct HeaderInventory {
    key: PresenceKey,
    content_length_fields: usize,
    transfer_encoding_fields: usize,
}

#[derive(Clone, Copy)]
enum ValidationRule {
    NoMetadata,
    ContentLength,
    TransferEncoding,
    Ambiguous,
}

struct RuleRow {
    key: PresenceKey,
    validation: ValidationRule,
}

const RULE_MATRIX: [RuleRow; 4] = [
    RuleRow {
        key: PresenceKey {
            content_length: false,
            transfer_encoding: false,
        },
        validation: ValidationRule::NoMetadata,
    },
    RuleRow {
        key: PresenceKey {
            content_length: true,
            transfer_encoding: false,
        },
        validation: ValidationRule::ContentLength,
    },
    RuleRow {
        key: PresenceKey {
            content_length: false,
            transfer_encoding: true,
        },
        validation: ValidationRule::TransferEncoding,
    },
    RuleRow {
        key: PresenceKey {
            content_length: true,
            transfer_encoding: true,
        },
        validation: ValidationRule::Ambiguous,
    },
];

enum ValidatedFraming {
    NoBody,
    Fixed(u64),
    Chunked,
}

pub(crate) fn determine_body_framing(
    _request: &RequestLine,
    headers: &HeaderBlock,
) -> Result<BodyFraming> {
    // Phase 1 records only field presence. This makes the CL+TE rejection independent of
    // either field's value, as required for ambiguity precedence.
    let inventory = inventory(headers);
    let rule = lookup_rule(inventory.key);

    // Phase 2 validates all framing metadata selected by the rule before constructing the
    // public result in phase 3.
    let validated = validate_rule(rule, inventory, headers)?;
    Ok(render(validated))
}

fn inventory(headers: &HeaderBlock) -> HeaderInventory {
    let (content_length_fields, transfer_encoding_fields) =
        headers
            .fields
            .iter()
            .fold((0_usize, 0_usize), |counts, field| {
                let (content_lengths, transfer_encodings) = counts;
                match field.name.as_str() {
                    "content-length" => (content_lengths + 1, transfer_encodings),
                    "transfer-encoding" => (content_lengths, transfer_encodings + 1),
                    _ => counts,
                }
            });

    HeaderInventory {
        key: PresenceKey {
            content_length: content_length_fields != 0,
            transfer_encoding: transfer_encoding_fields != 0,
        },
        content_length_fields,
        transfer_encoding_fields,
    }
}

fn lookup_rule(key: PresenceKey) -> ValidationRule {
    RULE_MATRIX
        .iter()
        .find(|row| row.key == key)
        .map(|row| row.validation)
        .expect("rule matrix covers every presence key")
}

fn validate_rule(
    rule: ValidationRule,
    inventory: HeaderInventory,
    headers: &HeaderBlock,
) -> Result<ValidatedFraming> {
    match rule {
        ValidationRule::NoMetadata => Ok(ValidatedFraming::NoBody),
        ValidationRule::Ambiguous => Err(PolyguardError::AmbiguousFraming),
        ValidationRule::ContentLength => {
            debug_assert!(inventory.content_length_fields > 0);
            let length = validate_content_lengths(headers)?;
            if length == 0 {
                Ok(ValidatedFraming::NoBody)
            } else {
                Ok(ValidatedFraming::Fixed(length))
            }
        }
        ValidationRule::TransferEncoding => {
            validate_transfer_encoding(inventory, headers)?;
            Ok(ValidatedFraming::Chunked)
        }
    }
}

fn validate_content_lengths(headers: &HeaderBlock) -> Result<u64> {
    let mut agreed = None;

    for field in &headers.fields {
        if field.name != "content-length" {
            continue;
        }

        agreed = Some(validate_content_length_field(&field.value, agreed)?);
    }

    agreed.ok_or(PolyguardError::InvalidContentLength)
}

fn validate_content_length_field(raw: &[u8], mut agreed: Option<u64>) -> Result<u64> {
    let mut member_start = 0_usize;

    for boundary in 0..=raw.len() {
        if boundary != raw.len() && raw[boundary] != b',' {
            continue;
        }

        let value = parse_decimal_member(&raw[member_start..boundary])?;
        if agreed.is_some_and(|prior| prior != value) {
            return Err(PolyguardError::ConflictingContentLength);
        }
        agreed = Some(value);
        member_start = boundary + 1;
    }

    agreed.ok_or(PolyguardError::InvalidContentLength)
}

fn parse_decimal_member(raw: &[u8]) -> Result<u64> {
    let member = trim_ows(raw);
    if member.is_empty() {
        return Err(PolyguardError::InvalidContentLength);
    }

    let mut value = 0_u64;
    for &byte in member {
        if !byte.is_ascii_digit() {
            return Err(PolyguardError::InvalidContentLength);
        }
        value = value
            .checked_mul(10)
            .and_then(|prefix| prefix.checked_add(u64::from(byte - b'0')))
            .ok_or(PolyguardError::InvalidContentLength)?;
    }

    if value > CONTENT_LENGTH_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "content_length".to_owned(),
            max: CONTENT_LENGTH_LIMIT as usize,
            actual: usize::try_from(value).unwrap_or(usize::MAX),
        });
    }

    Ok(value)
}

fn validate_transfer_encoding(inventory: HeaderInventory, headers: &HeaderBlock) -> Result<()> {
    // A combined list containing exactly one member can originate from exactly one field.
    // Comparing that entire field after OWS trimming rejects commas, parameters, empty
    // members, repeated codings, and additional codings with one auditable condition.
    if inventory.transfer_encoding_fields != 1 {
        return Err(PolyguardError::InvalidTransferEncoding);
    }

    let value = headers
        .fields
        .iter()
        .find(|field| field.name == "transfer-encoding")
        .map(|field| trim_ows(&field.value))
        .ok_or(PolyguardError::InvalidTransferEncoding)?;

    if value.eq_ignore_ascii_case(b"chunked") {
        Ok(())
    } else {
        Err(PolyguardError::InvalidTransferEncoding)
    }
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let leading = bytes
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();
    let trailing = bytes[leading..]
        .iter()
        .rev()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();
    &bytes[leading..bytes.len() - trailing]
}

fn render(validated: ValidatedFraming) -> BodyFraming {
    match validated {
        ValidatedFraming::NoBody => BodyFraming::None,
        ValidatedFraming::Fixed(length) => BodyFraming::ContentLength(length),
        ValidatedFraming::Chunked => BodyFraming::Chunked,
    }
}
