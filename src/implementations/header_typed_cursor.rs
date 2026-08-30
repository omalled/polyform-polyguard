use crate::{HeaderBlock, HeaderField, PolyguardError, Result};

const HEADER_SECTION_BYTES: usize = 32_768;
const HEADER_FIELDS: usize = 128;
const HEADER_NAME_BYTES: usize = 128;
const HEADER_VALUE_BYTES: usize = 8_192;

#[derive(Clone, Copy)]
struct Cursor(usize);

struct CanonicalName(String);

struct TrimmedValue(Vec<u8>);

enum FramedLine<'a> {
    Field { bytes: &'a [u8], next: Cursor },
    Terminator { next: Cursor },
}

pub(crate) fn parse_header_section(input: &[u8]) -> Result<HeaderBlock> {
    let mut cursor = Cursor(0);
    let mut fields = Vec::new();

    loop {
        let line_start = cursor.0;
        let (bytes, next) = match frame_next_line(input, cursor)? {
            FramedLine::Terminator { next } => {
                return Ok(HeaderBlock {
                    fields,
                    bytes_consumed: next.0,
                });
            }
            FramedLine::Field { bytes, next } => (bytes, next),
        };

        if fields.len() == HEADER_FIELDS {
            return Err(PolyguardError::TooManyHeaders);
        }
        if matches!(bytes.first(), Some(b' ' | b'\t')) {
            return Err(invalid_header(line_start, "obs_fold"));
        }

        let colon = match bytes.iter().position(|byte| *byte == b':') {
            Some(index) => index,
            None => return Err(invalid_header(line_start, "invalid_name")),
        };
        let name = CanonicalName::from_bytes(&bytes[..colon], line_start)?;
        let value = TrimmedValue::from_bytes(&bytes[colon + 1..], line_start)?;

        fields.push(HeaderField {
            name: name.0,
            value: value.0,
        });
        cursor = next;
    }
}

fn frame_next_line(input: &[u8], cursor: Cursor) -> Result<FramedLine<'_>> {
    let start = cursor.0;
    let mut position = start;

    loop {
        if position == HEADER_SECTION_BYTES {
            if position < input.len() {
                return Err(limit_exceeded(
                    "header_section_bytes",
                    HEADER_SECTION_BYTES,
                    HEADER_SECTION_BYTES + 1,
                ));
            }
            return Err(PolyguardError::Incomplete);
        }

        let byte = match input.get(position) {
            Some(byte) => *byte,
            None => return Err(PolyguardError::Incomplete),
        };

        if byte == b'\n' {
            return Err(invalid_header(start, "bare_line_ending"));
        }
        if byte != b'\r' {
            position += 1;
            continue;
        }
        if input.get(position + 1) != Some(&b'\n') {
            return Err(invalid_header(start, "bare_line_ending"));
        }

        let next = Cursor(position + 2);
        if next.0 > HEADER_SECTION_BYTES {
            return Err(limit_exceeded(
                "header_section_bytes",
                HEADER_SECTION_BYTES,
                next.0,
            ));
        }
        if position == start {
            return Ok(FramedLine::Terminator { next });
        }
        return Ok(FramedLine::Field {
            bytes: &input[start..position],
            next,
        });
    }
}

impl CanonicalName {
    fn from_bytes(bytes: &[u8], line_start: usize) -> Result<Self> {
        if bytes.is_empty() {
            return Err(invalid_header(line_start, "invalid_name"));
        }
        if bytes.len() > HEADER_NAME_BYTES {
            return Err(limit_exceeded(
                "header_name_bytes",
                HEADER_NAME_BYTES,
                bytes.len(),
            ));
        }
        if bytes.iter().any(|byte| matches!(byte, b' ' | b'\t')) {
            return Err(invalid_header(line_start, "whitespace_before_colon"));
        }
        if bytes.iter().any(|byte| !is_token(*byte)) {
            return Err(invalid_header(line_start, "invalid_name"));
        }

        let canonical = bytes
            .iter()
            .map(|byte| char::from(byte.to_ascii_lowercase()))
            .collect();
        Ok(Self(canonical))
    }
}

impl TrimmedValue {
    fn from_bytes(bytes: &[u8], line_start: usize) -> Result<Self> {
        if bytes.iter().any(|byte| !is_value_byte(*byte)) {
            return Err(invalid_header(line_start, "invalid_value_byte"));
        }

        let leading = bytes.iter().take_while(|byte| is_ows(**byte)).count();
        let trailing = bytes.iter().rev().take_while(|byte| is_ows(**byte)).count();
        let trimmed_len = bytes.len().saturating_sub(leading + trailing);
        if trimmed_len > HEADER_VALUE_BYTES {
            return Err(limit_exceeded(
                "header_value_bytes",
                HEADER_VALUE_BYTES,
                trimmed_len,
            ));
        }

        Ok(Self(bytes[leading..leading + trimmed_len].to_vec()))
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 0x80
}

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn invalid_header(index: usize, reason: &str) -> PolyguardError {
    PolyguardError::InvalidHeader {
        index,
        reason: reason.into(),
    }
}

fn limit_exceeded(limit: &str, max: usize, actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: limit.into(),
        max,
        actual,
    }
}
