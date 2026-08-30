use std::ops::Range;

use crate::{HeaderBlock, HeaderField, PolyguardError, Result};

const SECTION_LIMIT: usize = 32_768;
const FIELD_LIMIT: usize = 128;
const NAME_LIMIT: usize = 128;
const VALUE_LIMIT: usize = 8_192;

#[derive(Clone, Copy)]
enum FramingState {
    LineStart { offset: usize },
    LineData { offset: usize },
    AfterCarriageReturn { offset: usize, empty: bool },
}

enum FramingTransition {
    Continue(FramingState),
    Complete,
}

#[derive(Clone, Copy)]
struct SectionEnvelope {
    bytes_consumed: usize,
    field_count: usize,
}

#[derive(Clone, Copy)]
struct NameFacts {
    length: usize,
    has_whitespace: bool,
    has_invalid: bool,
}

#[derive(Clone, Copy)]
struct ValueFacts {
    name: NameFacts,
    colon: usize,
    first_content: Option<usize>,
    content_end: usize,
    has_invalid: bool,
}

#[derive(Clone, Copy)]
enum FieldState {
    Name(NameFacts),
    Value(ValueFacts),
}

#[derive(Clone)]
struct FieldPlan {
    name: Range<usize>,
    value: Range<usize>,
}

pub(crate) fn parse_header_section(input: &[u8]) -> Result<HeaderBlock> {
    let envelope = validate_framing(input)?;
    let plans = validate_fields(input, envelope)?;
    Ok(materialize(input, envelope.bytes_consumed, plans))
}

/// Establish the complete, bounded CRLF envelope without allocating from untrusted input.
fn validate_framing(input: &[u8]) -> Result<SectionEnvelope> {
    let mut state = FramingState::LineStart { offset: 0 };
    let mut cursor = 0;
    let mut field_count = 0;

    loop {
        if cursor == SECTION_LIMIT {
            if cursor < input.len() {
                return Err(limit_exceeded(
                    "header_section_bytes",
                    SECTION_LIMIT,
                    SECTION_LIMIT + 1,
                ));
            }
            return match state {
                FramingState::AfterCarriageReturn { offset, .. } => {
                    Err(invalid_header(offset, "bare_line_ending"))
                }
                _ => Err(PolyguardError::Incomplete),
            };
        }

        let Some(&byte) = input.get(cursor) else {
            return match state {
                FramingState::AfterCarriageReturn { offset, .. } => {
                    Err(invalid_header(offset, "bare_line_ending"))
                }
                _ => Err(PolyguardError::Incomplete),
            };
        };

        match framing_step(state, cursor, byte) {
            Ok(FramingTransition::Continue(next)) => {
                if matches!(
                    (state, next),
                    (
                        FramingState::AfterCarriageReturn { empty: false, .. },
                        FramingState::LineStart { .. }
                    )
                ) {
                    field_count += 1;
                }
                state = next;
                cursor += 1;
            }
            Ok(FramingTransition::Complete) => {
                let bytes_consumed = cursor + 1;
                return Ok(SectionEnvelope {
                    bytes_consumed,
                    field_count,
                });
            }
            Err(reason) => return Err(invalid_header(line_offset(state), reason)),
        }
    }
}

fn framing_step(
    state: FramingState,
    index: usize,
    byte: u8,
) -> std::result::Result<FramingTransition, &'static str> {
    match (state, byte) {
        (FramingState::LineStart { offset }, b'\r') => Ok(FramingTransition::Continue(
            FramingState::AfterCarriageReturn {
                offset,
                empty: true,
            },
        )),
        (FramingState::LineStart { .. }, b'\n') => Err("bare_line_ending"),
        (FramingState::LineStart { offset }, _) => {
            Ok(FramingTransition::Continue(FramingState::LineData {
                offset,
            }))
        }
        (FramingState::LineData { offset }, b'\r') => Ok(FramingTransition::Continue(
            FramingState::AfterCarriageReturn {
                offset,
                empty: false,
            },
        )),
        (FramingState::LineData { .. }, b'\n') => Err("bare_line_ending"),
        (FramingState::LineData { offset }, _) => {
            Ok(FramingTransition::Continue(FramingState::LineData {
                offset,
            }))
        }
        (FramingState::AfterCarriageReturn { empty: true, .. }, b'\n') => {
            Ok(FramingTransition::Complete)
        }
        (FramingState::AfterCarriageReturn { empty: false, .. }, b'\n') => {
            Ok(FramingTransition::Continue(FramingState::LineStart {
                offset: index + 1,
            }))
        }
        (FramingState::AfterCarriageReturn { .. }, _) => Err("bare_line_ending"),
    }
}

fn line_offset(state: FramingState) -> usize {
    match state {
        FramingState::LineStart { offset }
        | FramingState::LineData { offset }
        | FramingState::AfterCarriageReturn { offset, .. } => offset,
    }
}

/// Reduce each already-framed line to immutable source spans before creating owned output.
fn validate_fields(input: &[u8], envelope: SectionEnvelope) -> Result<Vec<FieldPlan>> {
    let field_bytes = &input[..envelope.bytes_consumed - 2];
    let mut line_start = 0;

    field_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(ordinal, framed)| {
            if ordinal == FIELD_LIMIT {
                return Err(PolyguardError::TooManyHeaders);
            }

            debug_assert!(framed.ends_with(b"\r\n"));
            let line = &framed[..framed.len() - 2];
            let plan = reduce_field(line, line_start)?;
            line_start += framed.len();
            Ok(plan)
        })
        .collect::<Result<Vec<_>>>()
        .inspect(|plans| {
            debug_assert_eq!(plans.len(), envelope.field_count);
        })
}

fn reduce_field(line: &[u8], line_start: usize) -> Result<FieldPlan> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(invalid_header(line_start, "obs_fold"));
    }

    let initial = FieldState::Name(NameFacts {
        length: 0,
        has_whitespace: false,
        has_invalid: false,
    });
    let final_state = line.iter().copied().enumerate().fold(initial, field_step);

    decide_field(final_state, line_start, line.len())
}

fn field_step(state: FieldState, (index, byte): (usize, u8)) -> FieldState {
    match state {
        FieldState::Name(facts) if byte == b':' => FieldState::Value(ValueFacts {
            name: facts,
            colon: index,
            first_content: None,
            content_end: index + 1,
            has_invalid: false,
        }),
        FieldState::Name(facts) => FieldState::Name(NameFacts {
            length: facts.length + 1,
            has_whitespace: facts.has_whitespace || matches!(byte, b' ' | b'\t'),
            has_invalid: facts.has_invalid || !is_token(byte),
        }),
        FieldState::Value(facts) => {
            let content = !matches!(byte, b' ' | b'\t');
            FieldState::Value(ValueFacts {
                name: facts.name,
                colon: facts.colon,
                first_content: facts.first_content.or(content.then_some(index)),
                content_end: if content {
                    index + 1
                } else {
                    facts.content_end
                },
                has_invalid: facts.has_invalid || !is_value_byte(byte),
            })
        }
    }
}

fn decide_field(state: FieldState, line_start: usize, line_len: usize) -> Result<FieldPlan> {
    let FieldState::Value(value) = state else {
        return Err(invalid_header(line_start, "invalid_name"));
    };

    if value.colon == 0 {
        return Err(invalid_header(line_start, "invalid_name"));
    }
    if value.name.length > NAME_LIMIT {
        return Err(limit_exceeded(
            "header_name_bytes",
            NAME_LIMIT,
            value.name.length,
        ));
    }

    if value.name.has_whitespace {
        return Err(invalid_header(line_start, "whitespace_before_colon"));
    }
    if value.name.has_invalid {
        return Err(invalid_header(line_start, "invalid_name"));
    }
    if value.has_invalid {
        return Err(invalid_header(line_start, "invalid_value_byte"));
    }

    let value_start = value.first_content.unwrap_or(line_len);
    let value_end = value.first_content.map_or(line_len, |_| value.content_end);
    let value_length = value_end - value_start;
    if value_length > VALUE_LIMIT {
        return Err(limit_exceeded(
            "header_value_bytes",
            VALUE_LIMIT,
            value_length,
        ));
    }

    Ok(FieldPlan {
        name: line_start..line_start + value.colon,
        value: line_start + value_start..line_start + value_end,
    })
}

fn materialize(input: &[u8], bytes_consumed: usize, plans: Vec<FieldPlan>) -> HeaderBlock {
    let fields = plans
        .into_iter()
        .map(|plan| HeaderField {
            name: input[plan.name]
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
            value: input[plan.value].to_vec(),
        })
        .collect();

    HeaderBlock {
        fields,
        bytes_consumed,
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
