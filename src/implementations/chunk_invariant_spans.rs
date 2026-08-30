use crate::{ChunkExtension, ChunkMeta, PolyguardError, Result};

const MAX_LINE_BYTES: usize = 1_024;
const MAX_SIZE: u64 = 16_777_216;
const MAX_EXTENSIONS: usize = 16;
const MAX_NAME_BYTES: usize = 64;

// A descriptor packs four line offsets and two flags into one primitive value. Line offsets
// are at most 1024, so eleven bits per offset are sufficient.
const OFFSET_BITS: u32 = 11;
const OFFSET_MASK: u64 = (1 << OFFSET_BITS) - 1;
const HAS_VALUE_BIT: u32 = OFFSET_BITS * 4;
const QUOTED_BIT: u32 = HAS_VALUE_BIT + 1;

struct Preflight {
    size: u64,
    extension_count: usize,
    spans: [u64; MAX_EXTENSIONS],
}

pub(crate) fn parse_chunk_metadata(input: &[u8]) -> Result<ChunkMeta> {
    let (line, bytes_consumed) = isolate_line(input)?;
    let checked = validate_line_grammar(line)?;
    let extensions = materialize_extensions(line, &checked.spans[..checked.extension_count]);

    Ok(ChunkMeta {
        size: checked.size,
        extensions,
        bytes_consumed,
    })
}

/// Phase one establishes a bounded, control-free line without inspecting bytes after its CRLF.
fn isolate_line(input: &[u8]) -> Result<(&[u8], usize)> {
    let mut offset = 0;
    while offset < input.len() {
        let byte = input[offset];
        if byte == b'\r' && input.get(offset + 1) == Some(&b'\n') {
            if offset <= MAX_LINE_BYTES {
                return Ok((&input[..offset], offset + 2));
            }
            return Err(limit("chunk_line_bytes", MAX_LINE_BYTES, offset + 1));
        }
        if byte.is_ascii_control() {
            return Err(invalid("invalid_line_ending_or_control"));
        }
        if offset == MAX_LINE_BYTES {
            return Err(limit(
                "chunk_line_bytes",
                MAX_LINE_BYTES,
                MAX_LINE_BYTES + 1,
            ));
        }
        offset += 1;
    }
    Err(PolyguardError::Incomplete)
}

/// Phase two proves all syntax and limits before any result-sized allocation is performed.
fn validate_line_grammar(line: &[u8]) -> Result<Preflight> {
    let size_end = line
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(line.len());
    let size = validate_size(&line[..size_end])?;

    let mut checked = Preflight {
        size,
        extension_count: 0,
        spans: [0; MAX_EXTENSIONS],
    };
    let mut cursor = size_end;

    while cursor < line.len() {
        debug_assert_eq!(line[cursor], b';');
        let ordinal = checked.extension_count + 1;
        if ordinal > MAX_EXTENSIONS {
            return Err(limit("chunk_extensions", MAX_EXTENSIONS, ordinal));
        }

        cursor += 1;
        let name_start = cursor;
        while cursor < line.len() && is_token(line[cursor]) {
            cursor += 1;
        }
        let name_end = cursor;
        if !(1..=MAX_NAME_BYTES).contains(&(name_end - name_start)) {
            return Err(invalid("invalid_extension_name"));
        }

        let descriptor = match line.get(cursor).copied() {
            None | Some(b';') => pack_span(name_start, name_end, 0, 0, false, false),
            Some(b'=') => {
                cursor += 1;
                validate_value(line, &mut cursor, name_start, name_end)?
            }
            Some(_) => return Err(invalid("invalid_extension_name")),
        };

        checked.spans[checked.extension_count] = descriptor;
        checked.extension_count = ordinal;
    }

    Ok(checked)
}

fn validate_size(text: &[u8]) -> Result<u64> {
    if !(1..=16).contains(&text.len()) {
        return Err(invalid("invalid_size"));
    }

    let mut size = 0_u64;
    for &byte in text {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(invalid("invalid_size")),
        };
        size = (size << 4) | u64::from(digit);
    }

    if size > MAX_SIZE {
        return Err(limit(
            "chunk_size",
            MAX_SIZE as usize,
            usize::try_from(size).unwrap_or(usize::MAX),
        ));
    }
    Ok(size)
}

fn validate_value(
    line: &[u8],
    cursor: &mut usize,
    name_start: usize,
    name_end: usize,
) -> Result<u64> {
    if line.get(*cursor) != Some(&b'"') {
        let value_start = *cursor;
        while *cursor < line.len() && is_token(line[*cursor]) {
            *cursor += 1;
        }
        if *cursor == value_start {
            return Err(invalid("invalid_extension_value"));
        }
        if *cursor < line.len() && line[*cursor] != b';' {
            return Err(invalid("invalid_extension_value"));
        }
        return Ok(pack_span(
            name_start,
            name_end,
            value_start,
            *cursor,
            true,
            false,
        ));
    }

    *cursor += 1;
    let value_start = *cursor;
    let mut escaped = false;
    while *cursor < line.len() {
        match (escaped, line[*cursor]) {
            (true, _) => escaped = false,
            (false, b'\\') => escaped = true,
            (false, b'"') => {
                let value_end = *cursor;
                if !valid_unescaped_utf8(&line[value_start..value_end]) {
                    return Err(invalid("invalid_quoted_string"));
                }
                *cursor += 1;
                if *cursor < line.len() && line[*cursor] != b';' {
                    return Err(invalid("invalid_extension_value"));
                }
                return Ok(pack_span(
                    name_start,
                    name_end,
                    value_start,
                    value_end,
                    true,
                    true,
                ));
            }
            (false, _) => {}
        }
        *cursor += 1;
    }

    Err(invalid("invalid_quoted_string"))
}

/// Checks UTF-8 over the algebraic projection produced by deleting each quoted-pair slash.
fn valid_unescaped_utf8(raw: &[u8]) -> bool {
    let mut projected = ProjectedBytes { raw, offset: 0 };
    while let Some(first) = projected.next() {
        let ranges: &[(u8, u8)] = match first {
            0x00..=0x7f => continue,
            0xc2..=0xdf => &[(0x80, 0xbf)],
            0xe0 => &[(0xa0, 0xbf), (0x80, 0xbf)],
            0xe1..=0xec | 0xee..=0xef => &[(0x80, 0xbf), (0x80, 0xbf)],
            0xed => &[(0x80, 0x9f), (0x80, 0xbf)],
            0xf0 => &[(0x90, 0xbf), (0x80, 0xbf), (0x80, 0xbf)],
            0xf1..=0xf3 => &[(0x80, 0xbf), (0x80, 0xbf), (0x80, 0xbf)],
            0xf4 => &[(0x80, 0x8f), (0x80, 0xbf), (0x80, 0xbf)],
            _ => return false,
        };
        for &(low, high) in ranges {
            if !matches!(projected.next(), Some(byte) if (low..=high).contains(&byte)) {
                return false;
            }
        }
    }
    true
}

struct ProjectedBytes<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl Iterator for ProjectedBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let byte = *self.raw.get(self.offset)?;
        self.offset += if byte == b'\\' { 2 } else { 1 };
        if byte == b'\\' {
            self.raw.get(self.offset - 1).copied()
        } else {
            Some(byte)
        }
    }
}

/// Phase three transforms only descriptors whose complete input was already proven valid.
fn materialize_extensions(line: &[u8], spans: &[u64]) -> Vec<ChunkExtension> {
    let mut extensions = Vec::with_capacity(spans.len());
    for &span in spans {
        let name_start = unpack_offset(span, 0);
        let name_end = unpack_offset(span, 1);
        let name = line[name_start..name_end]
            .iter()
            .map(|byte| char::from(byte.to_ascii_lowercase()))
            .collect();

        let value = if span & (1 << HAS_VALUE_BIT) == 0 {
            None
        } else {
            let value_start = unpack_offset(span, 2);
            let value_end = unpack_offset(span, 3);
            if span & (1 << QUOTED_BIT) == 0 {
                Some(
                    std::str::from_utf8(&line[value_start..value_end])
                        .expect("validated token is ASCII")
                        .to_owned(),
                )
            } else {
                let bytes = ProjectedBytes {
                    raw: &line[value_start..value_end],
                    offset: 0,
                }
                .collect::<Vec<_>>();
                Some(String::from_utf8(bytes).expect("projected UTF-8 was preflighted"))
            }
        };
        extensions.push(ChunkExtension { name, value });
    }
    extensions
}

fn pack_span(
    name_start: usize,
    name_end: usize,
    value_start: usize,
    value_end: usize,
    has_value: bool,
    quoted: bool,
) -> u64 {
    (name_start as u64)
        | ((name_end as u64) << OFFSET_BITS)
        | ((value_start as u64) << (OFFSET_BITS * 2))
        | ((value_end as u64) << (OFFSET_BITS * 3))
        | ((has_value as u64) << HAS_VALUE_BIT)
        | ((quoted as u64) << QUOTED_BIT)
}

fn unpack_offset(span: u64, ordinal: u32) -> usize {
    ((span >> (OFFSET_BITS * ordinal)) & OFFSET_MASK) as usize
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
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
