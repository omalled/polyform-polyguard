use crate::{ChunkExtension, ChunkMeta, PolyguardError, Result};

const MAX_LINE_CONTENT: usize = 1_024;
const MAX_SIZE: u64 = 16_777_216;
const MAX_EXTENSION_COUNT: usize = 16;
const MAX_EXTENSION_NAME: usize = 64;
const TOKEN_MARKS: &[u8] = b"!#$%&'*+-.^_`|~";

struct LineLayout {
    separators: [usize; MAX_EXTENSION_COUNT],
    extension_count: usize,
}

pub(crate) fn parse_chunk_metadata(input: &[u8]) -> Result<ChunkMeta> {
    let (line, bytes_consumed) = bounded_line(input)?;
    let first_separator = line.iter().position(|&byte| byte == b';');
    let size_end = first_separator.unwrap_or(line.len());
    let size = parse_size(&line[..size_end])?;
    let layout = map_extension_separators(line, first_separator)?;
    let extensions = transform_extensions(line, &layout)?;

    Ok(ChunkMeta {
        size,
        extensions,
        bytes_consumed,
    })
}

fn bounded_line(input: &[u8]) -> Result<(&[u8], usize)> {
    for (offset, &byte) in input.iter().enumerate() {
        if byte == b'\r' && input.get(offset + 1) == Some(&b'\n') {
            return Ok((&input[..offset], offset + 2));
        }
        if byte.is_ascii_control() {
            return Err(invalid("invalid_line_ending_or_control"));
        }
        if offset == MAX_LINE_CONTENT {
            return Err(limit(
                "chunk_line_bytes",
                MAX_LINE_CONTENT,
                MAX_LINE_CONTENT + 1,
            ));
        }
    }

    Err(PolyguardError::Incomplete)
}

/// Records only semicolons that separate extensions. Semicolons protected by a
/// syntactically possible quoted value remain ordinary value bytes.
fn map_extension_separators(line: &[u8], first_separator: Option<usize>) -> Result<LineLayout> {
    let mut layout = LineLayout {
        separators: [0; MAX_EXTENSION_COUNT],
        extension_count: 0,
    };
    let Some(first_separator) = first_separator else {
        return Ok(layout);
    };

    layout.separators[0] = first_separator;
    layout.extension_count = 1;
    let mut segment_start = first_separator + 1;
    let mut quoted = false;
    let mut escaped = false;

    for (offset, &byte) in line.iter().enumerate().skip(segment_start) {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }

        if byte == b'"'
            && offset > segment_start
            && line[offset - 1] == b'='
            && valid_name(&line[segment_start..offset - 1])
        {
            quoted = true;
            continue;
        }

        if byte != b';' {
            continue;
        }
        if layout.extension_count == MAX_EXTENSION_COUNT {
            return Err(limit(
                "chunk_extensions",
                MAX_EXTENSION_COUNT,
                MAX_EXTENSION_COUNT + 1,
            ));
        }
        layout.separators[layout.extension_count] = offset;
        layout.extension_count += 1;
        segment_start = offset + 1;
    }

    Ok(layout)
}

fn parse_size(digits: &[u8]) -> Result<u64> {
    if !(1..=16).contains(&digits.len()) || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("invalid_size"));
    }

    let text = std::str::from_utf8(digits).expect("ASCII hex was validated");
    let size = u64::from_str_radix(text, 16).expect("one to sixteen hex digits fit u64");
    if size > MAX_SIZE {
        return Err(limit(
            "chunk_size",
            MAX_SIZE as usize,
            usize::try_from(size).unwrap_or(usize::MAX),
        ));
    }
    Ok(size)
}

fn transform_extensions(line: &[u8], layout: &LineLayout) -> Result<Vec<ChunkExtension>> {
    let mut extensions = Vec::with_capacity(layout.extension_count);
    for ordinal in 0..layout.extension_count {
        let start = layout.separators[ordinal] + 1;
        let end = layout
            .separators
            .get(ordinal + 1)
            .copied()
            .filter(|_| ordinal + 1 < layout.extension_count)
            .unwrap_or(line.len());
        extensions.push(transform_extension(&line[start..end])?);
    }
    Ok(extensions)
}

fn transform_extension(segment: &[u8]) -> Result<ChunkExtension> {
    let equals = segment.iter().position(|&byte| byte == b'=');
    let name_bytes = equals.map_or(segment, |offset| &segment[..offset]);
    if !valid_name(name_bytes) {
        return Err(invalid("invalid_extension_name"));
    }

    let name = lowercase_ascii(name_bytes);
    let value = match equals {
        None => None,
        Some(offset) => Some(transform_value(&segment[offset + 1..])?),
    };
    Ok(ChunkExtension { name, value })
}

fn transform_value(value: &[u8]) -> Result<String> {
    if value.first() == Some(&b'"') {
        return unquote(value);
    }
    if value.is_empty() || !value.iter().all(|&byte| is_token(byte)) {
        return Err(invalid("invalid_extension_value"));
    }
    Ok(String::from_utf8(value.to_vec()).expect("tokens contain only ASCII"))
}

fn unquote(value: &[u8]) -> Result<String> {
    let mut decoded = Vec::with_capacity(value.len().saturating_sub(2));
    let mut offset = 1;

    while offset < value.len() {
        match value[offset] {
            b'\\' => {
                let escaped = value
                    .get(offset + 1)
                    .copied()
                    .ok_or_else(|| invalid("invalid_quoted_string"))?;
                decoded.push(escaped);
                offset += 2;
            }
            b'"' if offset + 1 == value.len() => {
                return String::from_utf8(decoded).map_err(|_| invalid("invalid_quoted_string"));
            }
            b'"' => return Err(invalid("invalid_extension_value")),
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }

    Err(invalid("invalid_quoted_string"))
}

fn valid_name(name: &[u8]) -> bool {
    (1..=MAX_EXTENSION_NAME).contains(&name.len()) && name.iter().all(|&byte| is_token(byte))
}

fn lowercase_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || TOKEN_MARKS.contains(&byte)
}

fn invalid(reason: &str) -> PolyguardError {
    PolyguardError::InvalidChunk {
        reason: reason.into(),
    }
}

fn limit(name: &str, max: usize, actual: usize) -> PolyguardError {
    PolyguardError::LimitExceeded {
        limit: name.into(),
        max,
        actual,
    }
}
