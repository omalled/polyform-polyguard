use crate::{HttpVersion, PolyguardError, RequestLine, Result};

const MAX_REQUEST_LINE_BYTES: usize = 8192;
const MAX_METHOD_BYTES: usize = 32;
const HTTP_11_BYTES: &[u8] = b"HTTP/1.1";
const TOKEN_BYTES: [bool; 256] = token_byte_lookup();

const fn token_byte_lookup() -> [bool; 256] {
    let mut lookup = [false; 256];
    let mut byte = b'0';
    while byte <= b'9' {
        lookup[byte as usize] = true;
        byte += 1;
    }
    byte = b'A';
    while byte <= b'Z' {
        lookup[byte as usize] = true;
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        lookup[byte as usize] = true;
        byte += 1;
    }
    let punctuation = b"!#$%&'*+-.^_`|~";
    let mut index = 0;
    while index < punctuation.len() {
        lookup[punctuation[index] as usize] = true;
        index += 1;
    }
    lookup
}

#[derive(Clone, Copy)]
enum TargetFault {
    None,
    Fragment,
    NonVisible,
}

#[derive(Clone, Copy)]
struct SemanticRecord {
    method_end: usize,
    method_is_token: bool,
    target_end: usize,
    target_fault: TargetFault,
    version_len: usize,
    version_matches: bool,
}

enum Machine {
    Method {
        length: usize,
        is_token: bool,
    },
    Target {
        method_end: usize,
        method_is_token: bool,
        length: usize,
        fault: TargetFault,
    },
    Version(SemanticRecord),
}

enum GrammarFailure {
    InvalidSpacing,
}

pub(crate) fn parse_request_line(input: &[u8]) -> Result<RequestLine> {
    let content_length = request_line_boundary(input)?;
    let line = &input[..content_length];
    let record = run_decision_machine(line)?;

    if record.method_end > MAX_METHOD_BYTES || !record.method_is_token {
        return Err(PolyguardError::InvalidMethod);
    }
    match record.target_fault {
        TargetFault::Fragment => return Err(invalid_target("fragment_not_allowed")),
        TargetFault::NonVisible => return Err(invalid_target("non_visible_ascii")),
        TargetFault::None => {}
    }
    if record.version_len != HTTP_11_BYTES.len() || !record.version_matches {
        return Err(PolyguardError::UnsupportedVersion);
    }

    let target_start = record.method_end + 1;
    let method = line[..record.method_end]
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    let target = std::str::from_utf8(&line[target_start..record.target_end])
        .expect("decision machine accepted only visible ASCII target bytes")
        .to_owned();

    Ok(RequestLine {
        method,
        target,
        version: HttpVersion::Http11,
        bytes_consumed: content_length + 2,
    })
}

fn request_line_boundary(input: &[u8]) -> Result<usize> {
    let observations = input.iter().copied().zip(
        input
            .iter()
            .copied()
            .skip(1)
            .map(Some)
            .chain(std::iter::once(None)),
    );

    for (offset, (byte, following)) in observations.enumerate().take(MAX_REQUEST_LINE_BYTES + 1) {
        if offset == MAX_REQUEST_LINE_BYTES {
            return if byte == b'\r' && following == Some(b'\n') {
                Ok(offset)
            } else {
                Err(PolyguardError::LimitExceeded {
                    limit: "request_line_bytes".into(),
                    max: MAX_REQUEST_LINE_BYTES,
                    actual: MAX_REQUEST_LINE_BYTES + 1,
                })
            };
        }

        match (byte, following) {
            (b'\r', Some(b'\n')) => return Ok(offset),
            (b'\r' | b'\n', _) => return Err(invalid_line("bare_line_ending")),
            (0..=8 | 11..=12 | 14..=31 | 127, _) => {
                return Err(invalid_line("control_character"));
            }
            _ => {}
        }
    }

    Err(PolyguardError::Incomplete)
}

fn run_decision_machine(line: &[u8]) -> Result<SemanticRecord> {
    let terminal = line.iter().copied().enumerate().try_fold(
        Machine::Method {
            length: 0,
            is_token: true,
        },
        transition,
    );

    match terminal {
        Err(GrammarFailure::InvalidSpacing) => Err(invalid_line("invalid_spacing")),
        Ok(Machine::Method { .. }) => Err(invalid_line("invalid_spacing")),
        Ok(Machine::Target { length: 0, .. }) => Err(invalid_line("invalid_spacing")),
        Ok(Machine::Target { .. }) => Err(PolyguardError::UnsupportedVersion),
        Ok(Machine::Version(record)) if record.version_len == 0 => {
            Err(invalid_line("invalid_spacing"))
        }
        Ok(Machine::Version(record)) => Ok(record),
    }
}

fn transition(
    machine: Machine,
    (offset, byte): (usize, u8),
) -> std::result::Result<Machine, GrammarFailure> {
    if byte == b'\t' {
        return Err(GrammarFailure::InvalidSpacing);
    }

    match (machine, byte) {
        (Machine::Method { length: 0, .. }, b' ') => Err(GrammarFailure::InvalidSpacing),
        (
            Machine::Method {
                length: _,
                is_token,
            },
            b' ',
        ) => Ok(Machine::Target {
            method_end: offset,
            method_is_token: is_token,
            length: 0,
            fault: TargetFault::None,
        }),
        (Machine::Method { length, is_token }, data) => Ok(Machine::Method {
            length: length + 1,
            is_token: is_token && TOKEN_BYTES[data as usize],
        }),
        (Machine::Target { length: 0, .. }, b' ') => Err(GrammarFailure::InvalidSpacing),
        (
            Machine::Target {
                method_end,
                method_is_token,
                length: _,
                fault,
            },
            b' ',
        ) => Ok(Machine::Version(SemanticRecord {
            method_end,
            method_is_token,
            target_end: offset,
            target_fault: fault,
            version_len: 0,
            version_matches: true,
        })),
        (
            Machine::Target {
                method_end,
                method_is_token,
                length,
                fault,
            },
            data,
        ) => Ok(Machine::Target {
            method_end,
            method_is_token,
            length: length + 1,
            fault: next_target_fault(fault, data),
        }),
        (Machine::Version(_), b' ') => Err(GrammarFailure::InvalidSpacing),
        (Machine::Version(mut record), data) => {
            record.version_matches = record.version_matches
                && HTTP_11_BYTES.get(record.version_len).copied() == Some(data);
            record.version_len += 1;
            Ok(Machine::Version(record))
        }
    }
}

fn next_target_fault(current: TargetFault, byte: u8) -> TargetFault {
    match current {
        TargetFault::Fragment | TargetFault::NonVisible => current,
        TargetFault::None if byte == b'#' => TargetFault::Fragment,
        TargetFault::None if !byte.is_ascii_graphic() => TargetFault::NonVisible,
        TargetFault::None => TargetFault::None,
    }
}

fn invalid_line(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRequestLine {
        reason: reason.into(),
    }
}

fn invalid_target(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidTarget {
        reason: reason.into(),
    }
}
