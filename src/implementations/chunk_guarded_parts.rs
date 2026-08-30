use crate::{ChunkExtension, ChunkMeta, PolyguardError, Result};

const MAX_LINE_CONTENT_BYTES: usize = 1_024;
const MAX_CHUNK_SIZE: u64 = 16_777_216;
const MAX_EXTENSIONS: usize = 16;
const MAX_EXTENSION_NAME_BYTES: usize = 64;
const TOKEN_PUNCTUATION: &[u8] = b"!#$%&'*+-.^_`|~";

pub(crate) fn parse_chunk_metadata(input: &[u8]) -> Result<ChunkMeta> {
    let (line, bytes_consumed) = validated_line(input)?;
    let (size_text, extension_text) = separate_size(line);
    let size = checked_size(size_text)?;
    let extensions = match extension_text {
        Some(text) => parse_extensions(text)?,
        None => Vec::new(),
    };

    Ok(ChunkMeta {
        size,
        extensions,
        bytes_consumed,
    })
}

/// Establishes the public-boundary invariants used by every later transformation:
/// the returned slice is bounded, complete, and contains no line/control bytes.
fn validated_line(input: &[u8]) -> Result<(&[u8], usize)> {
    for (offset, &byte) in input.iter().enumerate() {
        if offset > MAX_LINE_CONTENT_BYTES {
            return Err(limit(
                "chunk_line_bytes",
                MAX_LINE_CONTENT_BYTES,
                offset + 1,
            ));
        }

        if byte == b'\r' && input.get(offset + 1) == Some(&b'\n') {
            return Ok((&input[..offset], offset + 2));
        }

        if byte == b'\r' || byte == b'\n' || byte.is_ascii_control() {
            return Err(invalid("invalid_line_ending_or_control"));
        }

        if offset == MAX_LINE_CONTENT_BYTES {
            return Err(limit(
                "chunk_line_bytes",
                MAX_LINE_CONTENT_BYTES,
                offset + 1,
            ));
        }
    }

    Err(PolyguardError::Incomplete)
}

fn separate_size(line: &[u8]) -> (&[u8], Option<&[u8]>) {
    match line.iter().position(|&byte| byte == b';') {
        Some(delimiter) => (&line[..delimiter], Some(&line[delimiter + 1..])),
        None => (line, None),
    }
}

fn checked_size(text: &[u8]) -> Result<u64> {
    if text.is_empty() || text.len() > 16 || !text.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("invalid_size"));
    }

    let size = text.iter().fold(0_u64, |value, byte| {
        value * 16 + u64::from(hex_digit(*byte))
    });
    if size > MAX_CHUNK_SIZE {
        return Err(limit(
            "chunk_size",
            MAX_CHUNK_SIZE as usize,
            usize::try_from(size).unwrap_or(usize::MAX),
        ));
    }

    Ok(size)
}

fn parse_extensions(mut text: &[u8]) -> Result<Vec<ChunkExtension>> {
    let mut extensions = Vec::new();
    loop {
        if extensions.len() == MAX_EXTENSIONS {
            return Err(limit(
                "chunk_extensions",
                MAX_EXTENSIONS,
                MAX_EXTENSIONS + 1,
            ));
        }

        let (extension, remainder) = parse_extension(text)?;
        extensions.push(extension);
        match remainder {
            Some(next) => text = next,
            None => return Ok(extensions),
        }
    }
}

fn parse_extension(text: &[u8]) -> Result<(ChunkExtension, Option<&[u8]>)> {
    let name_end = text
        .iter()
        .position(|byte| !is_token(*byte))
        .unwrap_or(text.len());
    if name_end == 0 || name_end > MAX_EXTENSION_NAME_BYTES {
        return Err(invalid("invalid_extension_name"));
    }

    let name = ascii_lowercase(&text[..name_end]);
    match text.get(name_end) {
        None => Ok((ChunkExtension { name, value: None }, None)),
        Some(b';') => Ok((
            ChunkExtension { name, value: None },
            Some(&text[name_end + 1..]),
        )),
        Some(b'=') => {
            let (value, remainder) = parse_value(&text[name_end + 1..])?;
            Ok((
                ChunkExtension {
                    name,
                    value: Some(value),
                },
                remainder,
            ))
        }
        Some(_) => Err(invalid("invalid_extension_name")),
    }
}

fn parse_value(text: &[u8]) -> Result<(String, Option<&[u8]>)> {
    if text.first() == Some(&b'"') {
        return parse_quoted_value(text);
    }

    let value_end = text
        .iter()
        .position(|byte| !is_token(*byte))
        .unwrap_or(text.len());
    if value_end == 0 {
        return Err(invalid("invalid_extension_value"));
    }

    let value = String::from_utf8(text[..value_end].to_vec())
        .expect("validated token values contain only ASCII");
    match text.get(value_end) {
        None => Ok((value, None)),
        Some(b';') => Ok((value, Some(&text[value_end + 1..]))),
        Some(_) => Err(invalid("invalid_extension_value")),
    }
}

fn parse_quoted_value(text: &[u8]) -> Result<(String, Option<&[u8]>)> {
    let mut unescaped = Vec::with_capacity(text.len().saturating_sub(2));
    let mut offset = 1;

    while let Some(&byte) = text.get(offset) {
        if byte == b'\\' {
            let escaped = text
                .get(offset + 1)
                .copied()
                .ok_or_else(|| invalid("invalid_quoted_string"))?;
            unescaped.push(escaped);
            offset += 2;
            continue;
        }

        if byte == b'"' {
            let value =
                String::from_utf8(unescaped).map_err(|_| invalid("invalid_quoted_string"))?;
            return match text.get(offset + 1) {
                None => Ok((value, None)),
                Some(b';') => Ok((value, Some(&text[offset + 2..]))),
                Some(_) => Err(invalid("invalid_extension_value")),
            };
        }

        unescaped.push(byte);
        offset += 1;
    }

    Err(invalid("invalid_quoted_string"))
}

fn ascii_lowercase(text: &[u8]) -> String {
    text.iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(&byte)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("hex syntax was validated at the boundary"),
    }
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
