use crate::{HttpVersion, PolyguardError, RequestLine, Result};

const MAX_REQUEST_LINE_BYTES: usize = 8192;
const MAX_METHOD_BYTES: usize = 32;

pub(crate) fn parse_request_line(input: &[u8]) -> Result<RequestLine> {
    let line_end = request_line_end(input)?;
    let line = &input[..line_end];

    let mut spaces = 0usize;
    let mut left_space = 0usize;
    let mut right_space = 0usize;

    for (offset, &byte) in line.iter().enumerate().rev() {
        if byte == b'\t' {
            return Err(invalid_request_line("invalid_spacing"));
        }
        if byte == b' ' {
            spaces += 1;
            left_space = offset;
            if spaces == 1 {
                right_space = offset;
            }
        }
    }

    if spaces == 1 && left_space != 0 && left_space + 1 < line_end {
        return Err(PolyguardError::UnsupportedVersion);
    }
    if spaces != 2
        || left_space == 0
        || right_space == left_space + 1
        || right_space + 1 == line_end
    {
        return Err(invalid_request_line("invalid_spacing"));
    }

    let method_bytes = &line[..left_space];
    if method_bytes.len() > MAX_METHOD_BYTES {
        return Err(PolyguardError::InvalidMethod);
    }
    for &byte in method_bytes {
        if !is_method_token(byte) {
            return Err(PolyguardError::InvalidMethod);
        }
    }

    let target_bytes = &line[left_space + 1..right_space];
    if target_bytes.len() > MAX_REQUEST_LINE_BYTES {
        return Err(invalid_target("non_visible_ascii"));
    }
    for &byte in target_bytes {
        if byte == b'#' {
            return Err(invalid_target("fragment_not_allowed"));
        }
        if !(b'!'..=b'~').contains(&byte) {
            return Err(invalid_target("non_visible_ascii"));
        }
    }

    if &line[right_space + 1..] != b"HTTP/1.1" {
        return Err(PolyguardError::UnsupportedVersion);
    }

    let method = method_bytes
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    let target = target_bytes.iter().map(|&byte| char::from(byte)).collect();

    Ok(RequestLine {
        method,
        target,
        version: HttpVersion::Http11,
        bytes_consumed: line_end + 2,
    })
}

fn request_line_end(input: &[u8]) -> Result<usize> {
    let mut offset = 0usize;
    while offset < input.len() && offset <= MAX_REQUEST_LINE_BYTES {
        let byte = input[offset];

        if offset == MAX_REQUEST_LINE_BYTES {
            if byte == b'\r' && input.get(offset + 1) == Some(&b'\n') {
                return Ok(offset);
            }
            return Err(PolyguardError::LimitExceeded {
                limit: "request_line_bytes".into(),
                max: MAX_REQUEST_LINE_BYTES,
                actual: MAX_REQUEST_LINE_BYTES + 1,
            });
        }
        if byte == b'\r' {
            if input.get(offset + 1) == Some(&b'\n') {
                return Ok(offset);
            }
            return Err(invalid_request_line("bare_line_ending"));
        }
        if byte == b'\n' {
            return Err(invalid_request_line("bare_line_ending"));
        }
        if (byte < b' ' && byte != b'\t') || byte == 127 {
            return Err(invalid_request_line("control_character"));
        }

        offset += 1;
    }

    Err(PolyguardError::Incomplete)
}

fn is_method_token(byte: u8) -> bool {
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

fn invalid_request_line(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidRequestLine {
        reason: reason.into(),
    }
}

fn invalid_target(reason: &'static str) -> PolyguardError {
    PolyguardError::InvalidTarget {
        reason: reason.into(),
    }
}
