use polyform_polyguard::{
    BodyFraming, HeaderBlock, HeaderField, HttpVersion, RequestLine, registered_implementations,
};

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn generated_valid_targets_have_one_typed_meaning() {
    let mut state = 0x9112_2026_0830_u64;
    for case in 0..2_048 {
        let left = next(&mut state) % 10_000;
        let right = next(&mut state) % 10_000;
        let target = format!("/segment-{left}/item-{right}?case={case}");
        let wire = format!("GET {target} HTTP/1.1\r\n");
        let parsed: Vec<_> = registered_implementations()
            .iter()
            .filter_map(|implementation| implementation.parse_request_line)
            .map(|function| function(wire.as_bytes()))
            .collect();
        assert_eq!(parsed.len(), 5);
        assert!(parsed.windows(2).all(|pair| pair[0] == pair[1]));
        let request = parsed[0].as_ref().unwrap();
        assert_eq!(request.target, target);

        let normalized: Vec<_> = registered_implementations()
            .iter()
            .filter_map(|implementation| implementation.normalize_request_target)
            .map(|function| function(request))
            .collect();
        assert_eq!(normalized.len(), 5);
        assert!(normalized.windows(2).all(|pair| pair[0] == pair[1]));
        let normalized = normalized[0].as_ref().unwrap();
        assert_eq!(normalized.path_and_query, target);
        assert!(!normalized.routing_path.contains('?'));
    }
}

#[test]
fn generated_identical_lengths_always_have_one_framing() {
    let request = RequestLine {
        method: "post".into(),
        target: "/".into(),
        version: HttpVersion::Http11,
        bytes_consumed: 0,
    };
    let mut state = 0x434c_4652_414d_4553_u64;
    for _ in 0..1_024 {
        let length = next(&mut state) % 1_000_000;
        let copies = (next(&mut state) % 4 + 1) as usize;
        let headers = HeaderBlock {
            fields: (0..copies)
                .map(|_| HeaderField {
                    name: "content-length".into(),
                    value: length.to_string().into_bytes(),
                })
                .collect(),
            bytes_consumed: 0,
        };
        let outcomes: Vec<_> = registered_implementations()
            .iter()
            .filter_map(|implementation| implementation.determine_body_framing)
            .map(|function| function(&request, &headers))
            .collect();
        assert_eq!(outcomes, vec![Ok(BodyFraming::ContentLength(length)); 5]);
    }
}
