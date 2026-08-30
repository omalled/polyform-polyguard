use crate::{HttpVersion, PolyguardError, RequestLine, Result};

const REQUEST_LINE_LIMIT: usize = 8192;
const METHOD_LIMIT: usize = 32;
const HTTP_11: &[u8] = b"HTTP/1.1";
const TOKEN_PUNCTUATION: &[u8] = b"!#$%&'*+-.^_`|~";

enum LineBoundary {
    Complete(usize),
    Incomplete,
    OverLimit(usize),
    BareEnding,
    Control,
}

enum RequestParts<'a> {
    Complete {
        method: &'a [u8],
        target: &'a [u8],
        version: &'a [u8],
    },
    MissingVersion,
    InvalidSpacing,
}

enum PartState {
    Method,
    Target {
        method_end: usize,
    },
    Version {
        method_end: usize,
        target_end: usize,
    },
    Invalid,
}

pub(crate) fn parse_request_line(input: &[u8]) -> Result<RequestLine> {
    let line_end = match locate_boundary(input) {
        LineBoundary::Complete(index) => index,
        LineBoundary::Incomplete => return Err(PolyguardError::Incomplete),
        LineBoundary::OverLimit(actual) => {
            return Err(PolyguardError::LimitExceeded {
                limit: "request_line_bytes".into(),
                max: REQUEST_LINE_LIMIT,
                actual,
            });
        }
        LineBoundary::BareEnding => return Err(request_line_error("bare_line_ending")),
        LineBoundary::Control => return Err(request_line_error("control_character")),
    };

    let (method, target, version) = match partition(&input[..line_end]) {
        RequestParts::Complete {
            method,
            target,
            version,
        } => (method, target, version),
        RequestParts::MissingVersion => return Err(PolyguardError::UnsupportedVersion),
        RequestParts::InvalidSpacing => return Err(request_line_error("invalid_spacing")),
    };

    if !(1..=METHOD_LIMIT).contains(&method.len()) || !method.iter().copied().all(is_token) {
        return Err(PolyguardError::InvalidMethod);
    }

    if target.is_empty() {
        return Err(request_line_error("invalid_spacing"));
    }
    match target
        .iter()
        .copied()
        .find(|byte| *byte == b'#' || !byte.is_ascii_graphic())
    {
        Some(b'#') => {
            return Err(PolyguardError::InvalidTarget {
                reason: "fragment_not_allowed".into(),
            });
        }
        Some(_) => {
            return Err(PolyguardError::InvalidTarget {
                reason: "non_visible_ascii".into(),
            });
        }
        None => {}
    }

    if version != HTTP_11 {
        return Err(PolyguardError::UnsupportedVersion);
    }

    // Both slices have been proven ASCII before conversion, so UTF-8 conversion cannot fail.
    let method = std::str::from_utf8(method)
        .expect("validated ASCII method")
        .to_ascii_lowercase();
    let target = std::str::from_utf8(target)
        .expect("validated ASCII target")
        .to_owned();

    Ok(RequestLine {
        method,
        target,
        version: HttpVersion::Http11,
        bytes_consumed: line_end + 2,
    })
}

fn locate_boundary(input: &[u8]) -> LineBoundary {
    let mut bytes = input.iter().copied().enumerate().peekable();

    while let Some((index, byte)) = bytes.next() {
        if index == REQUEST_LINE_LIMIT {
            return if byte == b'\r' && matches!(bytes.peek(), Some((_, b'\n'))) {
                LineBoundary::Complete(index)
            } else {
                LineBoundary::OverLimit(REQUEST_LINE_LIMIT + 1)
            };
        }

        match byte {
            b'\r' if matches!(bytes.peek(), Some((_, b'\n'))) => {
                return LineBoundary::Complete(index);
            }
            b'\r' | b'\n' => return LineBoundary::BareEnding,
            0..=8 | 11..=31 | 127 => return LineBoundary::Control,
            _ => {}
        }
    }

    LineBoundary::Incomplete
}

fn partition(line: &[u8]) -> RequestParts<'_> {
    let state = line
        .iter()
        .copied()
        .enumerate()
        .fold(PartState::Method, |state, (index, byte)| {
            match (state, byte) {
                (_, b'\t') => PartState::Invalid,
                (PartState::Method, b' ') if index == 0 => PartState::Invalid,
                (PartState::Method, b' ') => PartState::Target { method_end: index },
                (PartState::Target { .. }, b' ') if line[index - 1] == b' ' => PartState::Invalid,
                (PartState::Target { method_end }, b' ') => PartState::Version {
                    method_end,
                    target_end: index,
                },
                (PartState::Version { .. }, b' ') | (PartState::Invalid, _) => PartState::Invalid,
                (state, _) => state,
            }
        });

    match state {
        PartState::Version {
            method_end,
            target_end,
        } if target_end + 1 < line.len() => RequestParts::Complete {
            method: &line[..method_end],
            target: &line[method_end + 1..target_end],
            version: &line[target_end + 1..],
        },
        PartState::Target { method_end } if method_end + 1 < line.len() => {
            RequestParts::MissingVersion
        }
        _ => RequestParts::InvalidSpacing,
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(&byte)
}

fn request_line_error(reason: &str) -> PolyguardError {
    PolyguardError::InvalidRequestLine {
        reason: reason.into(),
    }
}
