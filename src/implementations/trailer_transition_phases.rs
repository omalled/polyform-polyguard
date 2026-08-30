use crate::{HeaderField, PolyguardError, Result, TrailerBlock};

const MAX_SECTION_BYTES: usize = 8192;
const MAX_FIELDS: usize = 32;
const MAX_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Default)]
struct LineSpan {
    start: usize,
    end: usize,
}

struct SectionFrame {
    lines: [LineSpan; MAX_FIELDS + 1],
    retained_lines: usize,
    bytes_consumed: usize,
}

#[derive(Clone, Copy)]
enum ScanState {
    LineStart { offset: usize },
    LineBytes { start: usize, offset: usize },
}

struct DeclarationCatalog<'a> {
    names: Vec<&'a str>,
}

enum FieldDecision {
    Permit,
    Reject(&'static str),
}

fn invalid(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidTrailer {
        reason: reason.into(),
    }
}

fn scan_section(input: &[u8]) -> Result<SectionFrame> {
    let mut lines = [LineSpan::default(); MAX_FIELDS + 1];
    let mut retained_lines = 0usize;
    let mut state = ScanState::LineStart { offset: 0 };

    loop {
        state = match state {
            ScanState::LineStart { offset } => {
                if offset >= input.len() {
                    return if input.len() > MAX_SECTION_BYTES {
                        Err(PolyguardError::LimitExceeded {
                            limit: "trailer_bytes".into(),
                            max: MAX_SECTION_BYTES,
                            actual: input.len(),
                        })
                    } else {
                        Err(PolyguardError::Incomplete)
                    };
                }
                if offset >= MAX_SECTION_BYTES {
                    return Err(PolyguardError::LimitExceeded {
                        limit: "trailer_bytes".into(),
                        max: MAX_SECTION_BYTES,
                        actual: input.len(),
                    });
                }

                match input[offset] {
                    b'\r' if input.get(offset + 1) == Some(&b'\n') => {
                        let bytes_consumed = offset + 2;
                        if bytes_consumed > MAX_SECTION_BYTES {
                            return Err(PolyguardError::LimitExceeded {
                                limit: "trailer_bytes".into(),
                                max: MAX_SECTION_BYTES,
                                actual: bytes_consumed,
                            });
                        }
                        return Ok(SectionFrame {
                            lines,
                            retained_lines,
                            bytes_consumed,
                        });
                    }
                    b'\r' | b'\n' => return Err(invalid("bare_line_ending")),
                    _ => ScanState::LineBytes {
                        start: offset,
                        offset: offset + 1,
                    },
                }
            }
            ScanState::LineBytes { start, offset } => {
                if offset >= input.len() {
                    return if input.len() > MAX_SECTION_BYTES {
                        Err(PolyguardError::LimitExceeded {
                            limit: "trailer_bytes".into(),
                            max: MAX_SECTION_BYTES,
                            actual: input.len(),
                        })
                    } else {
                        Err(PolyguardError::Incomplete)
                    };
                }
                if offset >= MAX_SECTION_BYTES {
                    return Err(PolyguardError::LimitExceeded {
                        limit: "trailer_bytes".into(),
                        max: MAX_SECTION_BYTES,
                        actual: input.len(),
                    });
                }

                match input[offset] {
                    b'\r' if input.get(offset + 1) == Some(&b'\n') => {
                        if retained_lines < lines.len() {
                            lines[retained_lines] = LineSpan { start, end: offset };
                            retained_lines += 1;
                        }
                        ScanState::LineStart { offset: offset + 2 }
                    }
                    b'\r' | b'\n' => return Err(invalid("bare_line_ending")),
                    _ => ScanState::LineBytes {
                        start,
                        offset: offset + 1,
                    },
                }
            }
        };
    }
}

fn is_token_byte(byte: u8) -> bool {
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

fn is_forbidden(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "host"
            | "connection"
            | "trailer"
            | "upgrade"
            | "forwarded"
            | "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
    ) || name.starts_with("x-forwarded-")
}

fn radix_order(mut indexed_names: Vec<(usize, &str)>) -> Vec<(usize, &str)> {
    const RADIX: usize = 128;

    for position in (0..MAX_NAME_BYTES).rev() {
        let mut counts = [0usize; RADIX];
        for (_, name) in &indexed_names {
            let bucket = name
                .as_bytes()
                .get(position)
                .map_or(0, |byte| *byte as usize + 1);
            counts[bucket] += 1;
        }
        let mut offsets = [0usize; RADIX];
        for bucket in 1..RADIX {
            offsets[bucket] = offsets[bucket - 1] + counts[bucket - 1];
        }
        let mut ordered = vec![(0usize, ""); indexed_names.len()];
        for entry in indexed_names {
            let bucket = entry
                .1
                .as_bytes()
                .get(position)
                .map_or(0, |byte| *byte as usize + 1);
            ordered[offsets[bucket]] = entry;
            offsets[bucket] += 1;
        }
        indexed_names = ordered;
    }
    indexed_names
}

fn earliest_duplicate(indexed_names: &[(usize, &str)]) -> Option<usize> {
    let mut earliest = None;
    let mut group_start = 0usize;
    while group_start < indexed_names.len() {
        let name = indexed_names[group_start].1;
        let mut group_end = group_start + 1;
        let mut lowest = indexed_names[group_start].0;
        let mut second_lowest = usize::MAX;
        while group_end < indexed_names.len() && indexed_names[group_end].1 == name {
            let index = indexed_names[group_end].0;
            if index < lowest {
                second_lowest = lowest;
                lowest = index;
            } else if index < second_lowest {
                second_lowest = index;
            }
            group_end += 1;
        }
        if second_lowest != usize::MAX {
            earliest =
                Some(earliest.map_or(second_lowest, |current: usize| current.min(second_lowest)));
        }
        group_start = group_end;
    }
    earliest
}

fn catalog_declarations(declared_names: &[String]) -> Result<DeclarationCatalog<'_>> {
    let mut valid_prefix = Vec::new();
    let mut first_issue = None;
    for (index, name) in declared_names.iter().enumerate() {
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME_BYTES
            && name.bytes().all(is_token_byte)
            && !name.bytes().any(|byte| byte.is_ascii_uppercase());
        if !valid {
            first_issue = Some((index, "invalid_declaration"));
            break;
        }
        if is_forbidden(name) {
            first_issue = Some((index, "forbidden_field"));
            break;
        }
        valid_prefix.push((index, name.as_str()));
    }

    let ordered = radix_order(valid_prefix);
    if let Some(duplicate_index) = earliest_duplicate(&ordered)
        && first_issue.is_none_or(|(issue_index, _)| duplicate_index < issue_index)
    {
        return Err(invalid("duplicate_declaration"));
    }
    if let Some((_, reason)) = first_issue {
        return Err(invalid(reason));
    }
    Ok(DeclarationCatalog {
        names: ordered.into_iter().map(|(_, name)| name).collect(),
    })
}

fn parse_field(line: &[u8]) -> Result<HeaderField> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(invalid("obs_fold"));
    }

    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(invalid("invalid_name"));
    };
    let name_bytes = &line[..colon];
    if matches!(name_bytes.last(), Some(b' ' | b'\t')) {
        return Err(invalid("whitespace_before_colon"));
    }
    if name_bytes.is_empty()
        || name_bytes.len() > MAX_NAME_BYTES
        || !name_bytes.iter().copied().all(is_token_byte)
    {
        return Err(invalid("invalid_name"));
    }

    let raw_value = &line[colon + 1..];
    if raw_value
        .iter()
        .any(|byte| !matches!(*byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
    {
        return Err(invalid("invalid_value_byte"));
    }
    let value_start = raw_value
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(raw_value.len());
    let value_end = raw_value
        .iter()
        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
        .map_or(value_start, |index| index + 1);

    let name = name_bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    Ok(HeaderField {
        name,
        value: raw_value[value_start..value_end].to_vec(),
    })
}

fn authorize_field(
    field: &HeaderField,
    declarations: &DeclarationCatalog<'_>,
    received: &[String],
) -> FieldDecision {
    if is_forbidden(&field.name) {
        FieldDecision::Reject("forbidden_field")
    } else if declarations
        .names
        .binary_search(&field.name.as_str())
        .is_err()
    {
        FieldDecision::Reject("undeclared_field")
    } else if received.contains(&field.name) {
        FieldDecision::Reject("duplicate_field")
    } else {
        FieldDecision::Permit
    }
}

pub fn parse_trailer_section(input: &[u8], declared_names: &[String]) -> Result<TrailerBlock> {
    let frame = scan_section(input)?;
    let declarations = catalog_declarations(declared_names)?;
    let mut received = Vec::with_capacity(frame.retained_lines.min(MAX_FIELDS));
    let mut fields = Vec::with_capacity(frame.retained_lines.min(MAX_FIELDS));

    for (index, span) in frame.lines[..frame.retained_lines].iter().enumerate() {
        if index == MAX_FIELDS {
            return Err(invalid("too_many_fields"));
        }
        let field = parse_field(&input[span.start..span.end])?;
        match authorize_field(&field, &declarations, &received) {
            FieldDecision::Permit => {
                received.push(field.name.clone());
                fields.push(field);
            }
            FieldDecision::Reject(reason) => return Err(invalid(reason)),
        }
    }

    Ok(TrailerBlock {
        fields,
        bytes_consumed: frame.bytes_consumed,
    })
}
