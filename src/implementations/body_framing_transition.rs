use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result};

const HAS_CONTENT_LENGTH: u8 = 0b01;
const HAS_TRANSFER_ENCODING: u8 = 0b10;
const HAS_BOTH: u8 = HAS_CONTENT_LENGTH | HAS_TRANSFER_ENCODING;
const CONTENT_LENGTH_LIMIT: u64 = 16_777_216;

pub(crate) fn determine_body_framing(
    _request: &RequestLine,
    headers: &HeaderBlock,
) -> Result<BodyFraming> {
    let metadata_state = headers.fields.iter().fold(0, |state, field| {
        state
            | match field.name.as_str() {
                "content-length" => HAS_CONTENT_LENGTH,
                "transfer-encoding" => HAS_TRANSFER_ENCODING,
                _ => 0,
            }
    });

    match metadata_state {
        HAS_BOTH => Err(PolyguardError::AmbiguousFraming),
        HAS_TRANSFER_ENCODING => validate_transfer_encoding(headers).map(|()| BodyFraming::Chunked),
        HAS_CONTENT_LENGTH => content_length_members(headers)
            .try_fold(None, accept_content_length)?
            .map_or(Ok(BodyFraming::None), |length| {
                if length == 0 {
                    Ok(BodyFraming::None)
                } else {
                    Ok(BodyFraming::ContentLength(length))
                }
            }),
        _ => Ok(BodyFraming::None),
    }
}

fn content_length_members(headers: &HeaderBlock) -> impl Iterator<Item = &[u8]> {
    headers
        .fields
        .iter()
        .filter(|field| field.name == "content-length")
        .flat_map(|field| field.value.split(|byte| *byte == b','))
}

fn accept_content_length(accepted: Option<u64>, raw: &[u8]) -> Result<Option<u64>> {
    let member = trim_ows(raw);
    if member.is_empty() || !member.iter().all(u8::is_ascii_digit) {
        return Err(PolyguardError::InvalidContentLength);
    }

    let value = member.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or(PolyguardError::InvalidContentLength)
    })?;

    if value > CONTENT_LENGTH_LIMIT {
        return Err(PolyguardError::LimitExceeded {
            limit: "content_length".into(),
            max: CONTENT_LENGTH_LIMIT as usize,
            actual: usize::try_from(value).unwrap_or(usize::MAX),
        });
    }
    if accepted.is_some_and(|previous| previous != value) {
        return Err(PolyguardError::ConflictingContentLength);
    }

    Ok(Some(value))
}

fn validate_transfer_encoding(headers: &HeaderBlock) -> Result<()> {
    let member_count = headers
        .fields
        .iter()
        .filter(|field| field.name == "transfer-encoding")
        .flat_map(|field| field.value.split(|byte| *byte == b','))
        .try_fold(0_u8, |count, raw| {
            let member = trim_ows(raw);
            if !member.eq_ignore_ascii_case(b"chunked") || count != 0 {
                return Err(PolyguardError::InvalidTransferEncoding);
            }
            Ok(count + 1)
        })?;

    if member_count == 1 {
        Ok(())
    } else {
        Err(PolyguardError::InvalidTransferEncoding)
    }
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}
