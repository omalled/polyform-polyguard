use crate::{ChunkExtension, ChunkMeta, PolyguardError, Result};

const CHUNK_LINE_BYTES: usize = 1_024;
const CHUNK_SIZE: u64 = 16_777_216;
const CHUNK_EXTENSIONS: usize = 16;
const EXTENSION_NAME_BYTES: usize = 64;

#[derive(Clone, Copy)]
struct FramedLine<'a> {
    content: &'a [u8],
    bytes_consumed: usize,
}

enum Boundary {
    Complete(usize),
    Invalid,
    OverLimit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Symbol {
    Token,
    Equals,
    Semicolon,
    Quote,
    Escape,
    Other,
}

enum RawValue<'a> {
    Token(&'a [u8]),
    Quoted(&'a [u8]),
}

struct RawExtension<'a> {
    name: &'a [u8],
    value: Option<RawValue<'a>>,
}

struct ExtensionPipeline<'a> {
    remaining: &'a [u8],
    failed: bool,
}

pub(crate) fn parse_chunk_metadata(input: &[u8]) -> Result<ChunkMeta> {
    let line = frame_line(input)?;
    let split = line
        .content
        .iter()
        .position(|byte| classify(*byte) == Symbol::Semicolon)
        .unwrap_or(line.content.len());
    let size = parse_size(&line.content[..split])?;

    let extensions = ExtensionPipeline::new(&line.content[split..])
        .enumerate()
        .map(|(index, extension)| {
            if index == CHUNK_EXTENSIONS {
                return Err(limit_exceeded(
                    "chunk_extensions",
                    CHUNK_EXTENSIONS,
                    index + 1,
                ));
            }
            extension.and_then(normalize_extension)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ChunkMeta {
        size,
        extensions,
        bytes_consumed: line.bytes_consumed,
    })
}

fn frame_line(input: &[u8]) -> Result<FramedLine<'_>> {
    let boundary = input
        .iter()
        .copied()
        .enumerate()
        .take(CHUNK_LINE_BYTES + 1)
        .find_map(|(index, byte)| {
            if index == CHUNK_LINE_BYTES {
                return Some(match byte {
                    b'\r' if input.get(index + 1) == Some(&b'\n') => Boundary::Complete(index),
                    b'\r' | b'\n' | 0..=31 | 127 => Boundary::Invalid,
                    _ => Boundary::OverLimit,
                });
            }

            match byte {
                b'\r' if input.get(index + 1) == Some(&b'\n') => Some(Boundary::Complete(index)),
                b'\r' | b'\n' | 0..=31 | 127 => Some(Boundary::Invalid),
                _ => None,
            }
        });

    match boundary {
        Some(Boundary::Complete(end)) => Ok(FramedLine {
            content: &input[..end],
            bytes_consumed: end + 2,
        }),
        Some(Boundary::Invalid) => Err(invalid_chunk("invalid_line_ending_or_control")),
        Some(Boundary::OverLimit) => Err(limit_exceeded(
            "chunk_line_bytes",
            CHUNK_LINE_BYTES,
            CHUNK_LINE_BYTES + 1,
        )),
        None => Err(PolyguardError::Incomplete),
    }
}

fn parse_size(bytes: &[u8]) -> Result<u64> {
    if !(1..=16).contains(&bytes.len())
        || !bytes.iter().copied().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_chunk("invalid_size"));
    }

    let value = bytes.iter().copied().try_fold(0_u64, |value, byte| {
        let digit = u64::from(hex_value(byte).expect("hex syntax validated"));
        value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
    });
    let value = value.ok_or_else(|| invalid_chunk("invalid_size"))?;

    if value > CHUNK_SIZE {
        return Err(limit_exceeded(
            "chunk_size",
            CHUNK_SIZE as usize,
            usize::try_from(value).unwrap_or(usize::MAX),
        ));
    }
    Ok(value)
}

impl<'a> ExtensionPipeline<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self {
            remaining,
            failed: false,
        }
    }

    fn parse_next(&mut self) -> Result<RawExtension<'a>> {
        let body = self
            .remaining
            .strip_prefix(b";")
            .expect("pipeline only retains extension delimiters");
        let name_end = body
            .iter()
            .position(|byte| classify(*byte) != Symbol::Token)
            .unwrap_or(body.len());
        let name = &body[..name_end];

        if !(1..=EXTENSION_NAME_BYTES).contains(&name.len()) {
            return Err(invalid_chunk("invalid_extension_name"));
        }

        match body.get(name_end).copied().map(classify) {
            None => {
                self.remaining = &[];
                Ok(RawExtension { name, value: None })
            }
            Some(Symbol::Semicolon) => {
                self.remaining = &body[name_end..];
                Ok(RawExtension { name, value: None })
            }
            Some(Symbol::Equals) => self.parse_value(name, &body[name_end + 1..]),
            _ => Err(invalid_chunk("invalid_extension_name")),
        }
    }

    fn parse_value(&mut self, name: &'a [u8], bytes: &'a [u8]) -> Result<RawExtension<'a>> {
        if bytes.first() == Some(&b'"') {
            return self.parse_quoted(name, &bytes[1..]);
        }

        let value_end = bytes
            .iter()
            .position(|byte| classify(*byte) != Symbol::Token)
            .unwrap_or(bytes.len());
        if value_end == 0 {
            return Err(invalid_chunk("invalid_extension_value"));
        }

        match bytes.get(value_end).copied().map(classify) {
            None => self.remaining = &[],
            Some(Symbol::Semicolon) => self.remaining = &bytes[value_end..],
            _ => return Err(invalid_chunk("invalid_extension_value")),
        }

        Ok(RawExtension {
            name,
            value: Some(RawValue::Token(&bytes[..value_end])),
        })
    }

    fn parse_quoted(&mut self, name: &'a [u8], bytes: &'a [u8]) -> Result<RawExtension<'a>> {
        let mut escaped = false;
        let closing = bytes.iter().copied().enumerate().find_map(|(index, byte)| {
            if escaped {
                escaped = false;
                return None;
            }
            match classify(byte) {
                Symbol::Escape => {
                    escaped = true;
                    None
                }
                Symbol::Quote => Some(index),
                _ => None,
            }
        });
        let closing = closing.ok_or_else(|| invalid_chunk("invalid_quoted_string"))?;
        let after_quote = &bytes[closing + 1..];

        match after_quote.first().copied().map(classify) {
            None => self.remaining = &[],
            Some(Symbol::Semicolon) => self.remaining = after_quote,
            _ => return Err(invalid_chunk("invalid_extension_value")),
        }

        Ok(RawExtension {
            name,
            value: Some(RawValue::Quoted(&bytes[..closing])),
        })
    }
}

impl<'a> Iterator for ExtensionPipeline<'a> {
    type Item = Result<RawExtension<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() || self.failed {
            return None;
        }
        let result = self.parse_next();
        self.failed = result.is_err();
        Some(result)
    }
}

fn normalize_extension(raw: RawExtension<'_>) -> Result<ChunkExtension> {
    let name = raw
        .name
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    let value = match raw.value {
        None => None,
        Some(RawValue::Token(bytes)) => Some(
            std::str::from_utf8(bytes)
                .expect("token bytes are ASCII")
                .to_owned(),
        ),
        Some(RawValue::Quoted(bytes)) => Some(unescape_quoted(bytes)?),
    };
    Ok(ChunkExtension { name, value })
}

fn unescape_quoted(bytes: &[u8]) -> Result<String> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut pipeline = bytes.iter().copied();
    while let Some(byte) = pipeline.next() {
        if classify(byte) == Symbol::Escape {
            let escaped = pipeline
                .next()
                .ok_or_else(|| invalid_chunk("invalid_quoted_string"))?;
            output.push(escaped);
        } else {
            output.push(byte);
        }
    }
    String::from_utf8(output).map_err(|_| invalid_chunk("invalid_quoted_string"))
}

fn classify(byte: u8) -> Symbol {
    match byte {
        b'=' => Symbol::Equals,
        b';' => Symbol::Semicolon,
        b'"' => Symbol::Quote,
        b'\\' => Symbol::Escape,
        byte if byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte) => Symbol::Token,
        _ => Symbol::Other,
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_chunk(reason: &str) -> PolyguardError {
    PolyguardError::InvalidChunk {
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
