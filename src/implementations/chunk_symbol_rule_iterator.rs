use std::ops::ControlFlow;

use crate::{ChunkExtension, ChunkMeta, PolyguardError, Result};

const MAX_LINE_BYTES: usize = 1024;
const MAX_CHUNK_SIZE: u64 = 16_777_216;
const MAX_EXTENSIONS: usize = 16;
const MAX_EXTENSION_NAME: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum GrammarClass {
    HexDigit,
    Token,
    QuotedUnit,
}

struct SymbolRule {
    class: GrammarClass,
    accepts: fn(u8) -> bool,
}

const SYMBOL_RULES: [SymbolRule; 3] = [
    SymbolRule {
        class: GrammarClass::HexDigit,
        accepts: |byte| byte.is_ascii_hexdigit(),
    },
    SymbolRule {
        class: GrammarClass::Token,
        accepts: |byte| {
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
        },
    },
    SymbolRule {
        class: GrammarClass::QuotedUnit,
        accepts: |byte| (b' '..=b'~').contains(&byte),
    },
];

fn accepts(class: GrammarClass, byte: u8) -> bool {
    SYMBOL_RULES
        .iter()
        .find(|rule| rule.class == class)
        .is_some_and(|rule| (rule.accepts)(byte))
}

fn invalid(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidChunk {
        reason: reason.into(),
    }
}

enum LineEvent {
    Complete(usize),
    InvalidControl,
    TooLong(usize),
}

fn bounded_line(input: &[u8]) -> Result<&[u8]> {
    let event = input.iter().enumerate().find_map(|(offset, byte)| {
        if *byte == b'\r' {
            return Some(if input.get(offset + 1) == Some(&b'\n') {
                LineEvent::Complete(offset)
            } else {
                LineEvent::InvalidControl
            });
        }
        if *byte == b'\n' || byte.is_ascii_control() {
            return Some(LineEvent::InvalidControl);
        }
        (offset == MAX_LINE_BYTES).then_some(LineEvent::TooLong(offset + 1))
    });

    match event {
        Some(LineEvent::Complete(length)) => Ok(&input[..length]),
        Some(LineEvent::InvalidControl) => Err(invalid("invalid_line_ending_or_control")),
        Some(LineEvent::TooLong(actual)) => Err(PolyguardError::LimitExceeded {
            limit: "chunk_line_bytes".into(),
            max: MAX_LINE_BYTES,
            actual,
        }),
        None => Err(PolyguardError::Incomplete),
    }
}

fn parse_size(bytes: &[u8]) -> Result<u64> {
    if !(1..=16).contains(&bytes.len()) {
        return Err(invalid("invalid_size"));
    }

    let size = bytes.iter().try_fold(0_u64, |value, byte| {
        if !accepts(GrammarClass::HexDigit, *byte) {
            return Err(invalid("invalid_size"));
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => unreachable!("hex rule and conversion table disagree"),
        };
        Ok(value * 16 + u64::from(digit))
    })?;

    if size > MAX_CHUNK_SIZE {
        return Err(PolyguardError::LimitExceeded {
            limit: "chunk_size".into(),
            max: MAX_CHUNK_SIZE as usize,
            actual: size as usize,
        });
    }
    Ok(size)
}

enum ExtensionValue<'a> {
    Token(&'a [u8]),
    Quoted(&'a [u8]),
}

struct ParsedExtension<'a> {
    name: &'a [u8],
    value: Option<ExtensionValue<'a>>,
}

#[derive(Default)]
struct QuoteScan {
    escaped: bool,
    closing: Option<usize>,
}

fn quoted_contents(bytes: &[u8]) -> Result<(&[u8], usize)> {
    let state =
        bytes
            .iter()
            .enumerate()
            .try_fold(QuoteScan::default(), |mut state, (offset, byte)| {
                if state.closing.is_some() {
                    return ControlFlow::Continue(state);
                }
                if state.escaped {
                    if !accepts(GrammarClass::QuotedUnit, *byte) {
                        return ControlFlow::Break(invalid("invalid_quoted_string"));
                    }
                    state.escaped = false;
                } else {
                    match byte {
                        b'\\' => state.escaped = true,
                        b'"' => state.closing = Some(offset),
                        byte if accepts(GrammarClass::QuotedUnit, *byte) => {}
                        _ => return ControlFlow::Break(invalid("invalid_quoted_string")),
                    }
                }
                ControlFlow::Continue(state)
            });

    let state = match state {
        ControlFlow::Continue(state) => state,
        ControlFlow::Break(error) => return Err(error),
    };
    let closing = state
        .closing
        .filter(|_| !state.escaped)
        .ok_or_else(|| invalid("invalid_quoted_string"))?;
    Ok((&bytes[..closing], closing + 1))
}

struct ExtensionIterator<'a> {
    remaining: &'a [u8],
}

impl<'a> ExtensionIterator<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }
}

impl<'a> Iterator for ExtensionIterator<'a> {
    type Item = Result<ParsedExtension<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        if self.remaining.first() != Some(&b';') {
            self.remaining = &[];
            return Some(Err(invalid("invalid_extension_name")));
        }

        let after_separator = &self.remaining[1..];
        let name_length = after_separator
            .iter()
            .take_while(|byte| accepts(GrammarClass::Token, **byte))
            .count();
        if !(1..=MAX_EXTENSION_NAME).contains(&name_length) {
            self.remaining = &[];
            return Some(Err(invalid("invalid_extension_name")));
        }

        let name = &after_separator[..name_length];
        let suffix = &after_separator[name_length..];
        let (value, consumed) = match suffix.first() {
            None | Some(b';') => (None, 0),
            Some(b'=') => {
                let source = &suffix[1..];
                if source.first() == Some(&b'"') {
                    match quoted_contents(&source[1..]) {
                        Ok((contents, used)) => (Some(ExtensionValue::Quoted(contents)), used + 2),
                        Err(error) => {
                            self.remaining = &[];
                            return Some(Err(error));
                        }
                    }
                } else {
                    let length = source
                        .iter()
                        .take_while(|byte| accepts(GrammarClass::Token, **byte))
                        .count();
                    if length == 0 {
                        self.remaining = &[];
                        return Some(Err(invalid("invalid_extension_value")));
                    }
                    (Some(ExtensionValue::Token(&source[..length])), length + 1)
                }
            }
            _ => {
                self.remaining = &[];
                return Some(Err(invalid("invalid_extension_name")));
            }
        };

        let rest = &suffix[consumed..];
        if !rest.is_empty() && rest.first() != Some(&b';') {
            self.remaining = &[];
            return Some(Err(invalid("invalid_extension_value")));
        }
        self.remaining = rest;
        Some(Ok(ParsedExtension { name, value }))
    }
}

fn normalize(extension: ParsedExtension<'_>) -> ChunkExtension {
    let name = extension
        .name
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(char::from)
        .collect();
    let value = extension.value.map(|value| match value {
        ExtensionValue::Token(bytes) => bytes.iter().copied().map(char::from).collect(),
        ExtensionValue::Quoted(bytes) => {
            let mut escaped = false;
            bytes
                .iter()
                .filter_map(|byte| {
                    if escaped {
                        escaped = false;
                        return Some(char::from(*byte));
                    }
                    if *byte == b'\\' {
                        escaped = true;
                        None
                    } else {
                        Some(char::from(*byte))
                    }
                })
                .collect()
        }
    });
    ChunkExtension { name, value }
}

pub fn parse_chunk_metadata(input: &[u8]) -> Result<ChunkMeta> {
    let line = bounded_line(input)?;
    let size_end = line
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(line.len());
    let size = parse_size(&line[..size_end])?;

    let extensions = ExtensionIterator::new(&line[size_end..])
        .enumerate()
        .map(|(index, extension)| {
            if index >= MAX_EXTENSIONS {
                return Err(PolyguardError::LimitExceeded {
                    limit: "chunk_extensions".into(),
                    max: MAX_EXTENSIONS,
                    actual: index + 1,
                });
            }
            extension.map(normalize)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ChunkMeta {
        size,
        extensions,
        bytes_consumed: line.len() + 2,
    })
}
