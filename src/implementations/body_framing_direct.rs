use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result};

const CONTENT_LENGTH_LIMIT: u64 = 16_777_216;

struct ContentLengthFields<'a>(&'a HeaderBlock);
struct TransferEncodingFields<'a>(&'a HeaderBlock);

enum FramingMetadata<'a> {
    Absent,
    ContentLength(ContentLengthFields<'a>),
    TransferEncoding(TransferEncodingFields<'a>),
    Ambiguous,
}

struct DecimalLength(u64);

pub(crate) fn determine_body_framing(
    _request: &RequestLine,
    headers: &HeaderBlock,
) -> Result<BodyFraming> {
    let metadata = classify_metadata(headers);

    if matches!(&metadata, FramingMetadata::Ambiguous) {
        return Err(PolyguardError::AmbiguousFraming);
    }

    match metadata {
        FramingMetadata::TransferEncoding(fields) => {
            fields.validate_chunked()?;
            Ok(BodyFraming::Chunked)
        }
        FramingMetadata::ContentLength(fields) => {
            let length = fields.validate_consistent()?.0;
            if length == 0 {
                return Ok(BodyFraming::None);
            }
            Ok(BodyFraming::ContentLength(length))
        }
        FramingMetadata::Absent => Ok(BodyFraming::None),
        FramingMetadata::Ambiguous => Err(PolyguardError::AmbiguousFraming),
    }
}

fn classify_metadata(headers: &HeaderBlock) -> FramingMetadata<'_> {
    let mut content_length_present = false;
    let mut transfer_encoding_present = false;

    for field in &headers.fields {
        if field.name == "content-length" {
            content_length_present = true;
        } else if field.name == "transfer-encoding" {
            transfer_encoding_present = true;
        }

        if content_length_present && transfer_encoding_present {
            return FramingMetadata::Ambiguous;
        }
    }

    if content_length_present {
        return FramingMetadata::ContentLength(ContentLengthFields(headers));
    }
    if transfer_encoding_present {
        return FramingMetadata::TransferEncoding(TransferEncodingFields(headers));
    }
    FramingMetadata::Absent
}

impl ContentLengthFields<'_> {
    fn validate_consistent(&self) -> Result<DecimalLength> {
        let mut accepted = None;

        for field in &self.0.fields {
            if field.name != "content-length" {
                continue;
            }

            let mut member_start = 0;
            loop {
                let member_end = field.value[member_start..]
                    .iter()
                    .position(|byte| *byte == b',')
                    .map_or(field.value.len(), |offset| member_start + offset);
                let parsed = parse_decimal_length(&field.value[member_start..member_end])?;

                if let Some(previous) = accepted
                    && previous != parsed.0
                {
                    return Err(PolyguardError::ConflictingContentLength);
                }
                accepted = Some(parsed.0);

                if member_end == field.value.len() {
                    break;
                }
                member_start = member_end + 1;
            }
        }

        accepted
            .map(DecimalLength)
            .ok_or(PolyguardError::InvalidContentLength)
    }
}

fn parse_decimal_length(raw: &[u8]) -> Result<DecimalLength> {
    let member = without_ows(raw);
    if member.is_empty() {
        return Err(PolyguardError::InvalidContentLength);
    }

    let mut value = 0_u64;
    for byte in member {
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
            limit: "content_length".into(),
            max: CONTENT_LENGTH_LIMIT as usize,
            actual: usize::try_from(value).unwrap_or(usize::MAX),
        });
    }

    Ok(DecimalLength(value))
}

impl TransferEncodingFields<'_> {
    fn validate_chunked(&self) -> Result<()> {
        let mut members_seen = 0_usize;

        for field in &self.0.fields {
            if field.name != "transfer-encoding" {
                continue;
            }

            let mut member_start = 0;
            loop {
                let member_end = field.value[member_start..]
                    .iter()
                    .position(|byte| *byte == b',')
                    .map_or(field.value.len(), |offset| member_start + offset);
                let member = without_ows(&field.value[member_start..member_end]);

                members_seen += 1;
                if members_seen != 1 || !member.eq_ignore_ascii_case(b"chunked") {
                    return Err(PolyguardError::InvalidTransferEncoding);
                }

                if member_end == field.value.len() {
                    break;
                }
                member_start = member_end + 1;
            }
        }

        if members_seen != 1 {
            return Err(PolyguardError::InvalidTransferEncoding);
        }
        Ok(())
    }
}

fn without_ows(bytes: &[u8]) -> &[u8] {
    let mut first = 0;
    while first < bytes.len() && matches!(bytes[first], b' ' | b'\t') {
        first += 1;
    }

    let mut end = bytes.len();
    while end > first && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }

    &bytes[first..end]
}
