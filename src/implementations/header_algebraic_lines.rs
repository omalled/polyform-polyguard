use crate::{HeaderBlock, HeaderField, PolyguardError, Result};

const SECTION_MAX: usize = 32_768;
const FIELD_MAX: usize = 128;
const NAME_MAX: usize = 128;
const VALUE_MAX: usize = 8_192;

/// The unconsumed suffix, paired with its byte offset in the original input.
struct SectionTail<'a> {
    offset: usize,
    bytes: &'a [u8],
}

/// A line whose terminating CRLF and lack of embedded line endings are proven.
struct CompleteLine<'a> {
    offset: usize,
    bytes: &'a [u8],
}

struct LowercaseName(String);
struct TrimmedValue(Vec<u8>);

enum NextLine<'a> {
    Field {
        line: CompleteLine<'a>,
        tail: SectionTail<'a>,
    },
    End {
        bytes_consumed: usize,
    },
}

pub(crate) fn parse_header_section(input: &[u8]) -> Result<HeaderBlock> {
    let mut tail = SectionTail {
        offset: 0,
        bytes: input,
    };
    let mut fields = Vec::new();

    loop {
        let (line, next_tail) = match take_complete_line(tail)? {
            NextLine::End { bytes_consumed } => {
                return Ok(HeaderBlock {
                    fields,
                    bytes_consumed,
                });
            }
            NextLine::Field { line, tail } => (line, tail),
        };

        if fields.len() == FIELD_MAX {
            return Err(PolyguardError::TooManyHeaders);
        }
        fields.push(parse_field(line)?);
        tail = next_tail;
    }
}

fn take_complete_line(tail: SectionTail<'_>) -> Result<NextLine<'_>> {
    let delimiter = tail.bytes.windows(2).position(|pair| pair == b"\r\n");

    let Some(line_len) = delimiter else {
        if let Some(control) = tail
            .bytes
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
        {
            let absolute = tail.offset + control;
            if absolute < SECTION_MAX {
                return Err(invalid_header(tail.offset, "bare_line_ending"));
            }
        }
        if tail.offset + tail.bytes.len() > SECTION_MAX {
            return Err(limit_exceeded(
                "header_section_bytes",
                SECTION_MAX,
                SECTION_MAX + 1,
            ));
        }
        return Err(PolyguardError::Incomplete);
    };

    if let Some(embedded) = tail.bytes[..line_len]
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        && tail.offset + embedded < SECTION_MAX
    {
        return Err(invalid_header(tail.offset, "bare_line_ending"));
    }

    let next_offset = tail.offset + line_len + 2;
    if next_offset > SECTION_MAX {
        return Err(limit_exceeded(
            "header_section_bytes",
            SECTION_MAX,
            SECTION_MAX + 1,
        ));
    }
    if line_len == 0 {
        return Ok(NextLine::End {
            bytes_consumed: next_offset,
        });
    }

    Ok(NextLine::Field {
        line: CompleteLine {
            offset: tail.offset,
            bytes: &tail.bytes[..line_len],
        },
        tail: SectionTail {
            offset: next_offset,
            bytes: &tail.bytes[line_len + 2..],
        },
    })
}

fn parse_field(line: CompleteLine<'_>) -> Result<HeaderField> {
    if matches!(line.bytes.first(), Some(b' ' | b'\t')) {
        return Err(invalid_header(line.offset, "obs_fold"));
    }

    let Some(colon) = line.bytes.iter().position(|byte| *byte == b':') else {
        return Err(invalid_header(line.offset, "invalid_name"));
    };
    let name = LowercaseName::new(&line.bytes[..colon], line.offset)?;
    let value = TrimmedValue::new(&line.bytes[colon + 1..], line.offset)?;

    Ok(HeaderField {
        name: name.0,
        value: value.0,
    })
}

impl LowercaseName {
    fn new(bytes: &[u8], line_offset: usize) -> Result<Self> {
        if bytes.is_empty() {
            return Err(invalid_header(line_offset, "invalid_name"));
        }
        if bytes.len() > NAME_MAX {
            return Err(limit_exceeded("header_name_bytes", NAME_MAX, bytes.len()));
        }
        if bytes.iter().any(|byte| matches!(byte, b' ' | b'\t')) {
            return Err(invalid_header(line_offset, "whitespace_before_colon"));
        }
        if !bytes.iter().all(|byte| is_token(*byte)) {
            return Err(invalid_header(line_offset, "invalid_name"));
        }

        Ok(Self(
            bytes
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
        ))
    }
}

impl TrimmedValue {
    fn new(bytes: &[u8], line_offset: usize) -> Result<Self> {
        if !bytes.iter().all(|byte| is_value_byte(*byte)) {
            return Err(invalid_header(line_offset, "invalid_value_byte"));
        }

        let first = bytes.iter().position(|byte| !is_ows(*byte));
        let trimmed = match first {
            None => &bytes[0..0],
            Some(start) => {
                let last = bytes
                    .iter()
                    .rposition(|byte| !is_ows(*byte))
                    .expect("a first non-OWS byte implies a last non-OWS byte");
                &bytes[start..=last]
            }
        };
        if trimmed.len() > VALUE_MAX {
            return Err(limit_exceeded(
                "header_value_bytes",
                VALUE_MAX,
                trimmed.len(),
            ));
        }

        Ok(Self(trimmed.to_vec()))
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
