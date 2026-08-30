use crate::{BodyFraming, HeaderBlock, PolyguardError, RequestLine, Result};

const MAX_CONTENT_LENGTH: u64 = 16_777_216;

#[derive(Clone, Copy)]
struct BoundedLength(u64);

#[derive(Default)]
struct LengthConsensus {
    agreed: Option<BoundedLength>,
}

struct CommaMembers<'a> {
    remainder: Option<&'a [u8]>,
}

enum ValidatedMetadata {
    NoBody,
    Fixed(BoundedLength),
    Chunked,
}

pub(crate) fn determine_body_framing(
    _request: &RequestLine,
    headers: &HeaderBlock,
) -> Result<BodyFraming> {
    let metadata = validate_boundary(headers)?;

    Ok(match metadata {
        ValidatedMetadata::NoBody => BodyFraming::None,
        ValidatedMetadata::Fixed(length) => BodyFraming::ContentLength(length.0),
        ValidatedMetadata::Chunked => BodyFraming::Chunked,
    })
}

fn validate_boundary(headers: &HeaderBlock) -> Result<ValidatedMetadata> {
    let mut content_length_fields = 0_usize;
    let mut transfer_encoding_fields = 0_usize;

    for field in &headers.fields {
        if field.name == "content-length" {
            content_length_fields += 1;
        }
        if field.name == "transfer-encoding" {
            transfer_encoding_fields += 1;
        }
    }

    if content_length_fields != 0 && transfer_encoding_fields != 0 {
        return Err(PolyguardError::AmbiguousFraming);
    }
    if transfer_encoding_fields != 0 {
        return validate_chunked(headers, transfer_encoding_fields);
    }
    if content_length_fields == 0 {
        return Ok(ValidatedMetadata::NoBody);
    }

    validate_content_lengths(headers)
}

fn validate_chunked(
    headers: &HeaderBlock,
    transfer_encoding_fields: usize,
) -> Result<ValidatedMetadata> {
    if transfer_encoding_fields != 1 {
        return Err(PolyguardError::InvalidTransferEncoding);
    }

    let field = headers
        .fields
        .iter()
        .find(|field| field.name == "transfer-encoding")
        .ok_or(PolyguardError::InvalidTransferEncoding)?;

    if !trim_ows(&field.value).eq_ignore_ascii_case(b"chunked") {
        return Err(PolyguardError::InvalidTransferEncoding);
    }

    Ok(ValidatedMetadata::Chunked)
}

fn validate_content_lengths(headers: &HeaderBlock) -> Result<ValidatedMetadata> {
    let mut consensus = LengthConsensus::default();

    for field in &headers.fields {
        if field.name != "content-length" {
            continue;
        }

        for raw_member in CommaMembers::new(&field.value) {
            consensus.accept(BoundedLength::parse(raw_member)?)?;
        }
    }

    let length = consensus
        .agreed
        .ok_or(PolyguardError::InvalidContentLength)?;
    if length.0 == 0 {
        return Ok(ValidatedMetadata::NoBody);
    }

    Ok(ValidatedMetadata::Fixed(length))
}

impl BoundedLength {
    fn parse(raw: &[u8]) -> Result<Self> {
        let digits = trim_ows(raw);
        if digits.is_empty() {
            return Err(PolyguardError::InvalidContentLength);
        }

        let mut value = 0_u64;
        for &digit in digits {
            if !digit.is_ascii_digit() {
                return Err(PolyguardError::InvalidContentLength);
            }
            value = value
                .checked_mul(10)
                .and_then(|prefix| prefix.checked_add(u64::from(digit - b'0')))
                .ok_or(PolyguardError::InvalidContentLength)?;
        }

        if value > MAX_CONTENT_LENGTH {
            return Err(PolyguardError::LimitExceeded {
                limit: "content_length".to_owned(),
                max: MAX_CONTENT_LENGTH as usize,
                actual: usize::try_from(value).unwrap_or(usize::MAX),
            });
        }

        Ok(Self(value))
    }
}

impl LengthConsensus {
    fn accept(&mut self, candidate: BoundedLength) -> Result<()> {
        if let Some(accepted) = self.agreed
            && accepted.0 != candidate.0
        {
            return Err(PolyguardError::ConflictingContentLength);
        }

        self.agreed = Some(candidate);
        Ok(())
    }
}

impl<'a> CommaMembers<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self {
            remainder: Some(value),
        }
    }
}

impl<'a> Iterator for CommaMembers<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remainder.take()?;
        if let Some(comma) = remaining.iter().position(|byte| *byte == b',') {
            self.remainder = Some(&remaining[comma + 1..]);
            return Some(&remaining[..comma]);
        }

        Some(remaining)
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
        .map_or(start, |index| index + 1);

    &bytes[start..end]
}
