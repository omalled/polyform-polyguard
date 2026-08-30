use crate::{OutcomeCategory, PolyguardError, Result, TelemetryOutcome};

const MAX_CODE_BYTES: usize = "implementation_disagreement".len();

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CodeKey(usize, u8, u8);

#[derive(Clone, Copy)]
struct BoundedCode<'a>(&'a str);

impl<'a> BoundedCode<'a> {
    fn new(code: &'a str) -> Result<Self> {
        if code.is_empty() || code.len() > MAX_CODE_BYTES {
            return Err(PolyguardError::SerializationInvariant);
        }

        Ok(Self(code))
    }

    fn key(self) -> CodeKey {
        let bytes = self.0.as_bytes();
        CodeKey(bytes.len(), bytes[0], bytes[bytes.len() - 1])
    }
}

#[derive(Clone, Copy)]
enum FixedCategory {
    Accepted,
    ClientSyntax,
    AmbiguousFraming,
    PolicyRejected,
    RouteMissing,
    UpstreamFailure,
    Timeout,
    ImplementationDisagreement,
    InternalFailure,
}

impl FixedCategory {
    fn emit(self) -> TelemetryOutcome {
        let category = match self {
            Self::Accepted => OutcomeCategory::Accepted,
            Self::ClientSyntax => OutcomeCategory::ClientSyntax,
            Self::AmbiguousFraming => OutcomeCategory::AmbiguousFraming,
            Self::PolicyRejected => OutcomeCategory::PolicyRejected,
            Self::RouteMissing => OutcomeCategory::RouteMissing,
            Self::UpstreamFailure => OutcomeCategory::UpstreamFailure,
            Self::Timeout => OutcomeCategory::Timeout,
            Self::ImplementationDisagreement => OutcomeCategory::ImplementationDisagreement,
            Self::InternalFailure => OutcomeCategory::InternalFailure,
        };

        TelemetryOutcome {
            category,
            success: matches!(self, Self::Accepted),
        }
    }
}

struct Rule {
    key: CodeKey,
    literal: &'static str,
    category: FixedCategory,
    permits_upstream: bool,
}

// Sorted by CodeKey so lookup remains bounded without allocating or scanning user input.
const RULES: [Rule; 9] = [
    Rule {
        key: CodeKey(7, b't', b't'),
        literal: "timeout",
        category: FixedCategory::Timeout,
        permits_upstream: true,
    },
    Rule {
        key: CodeKey(8, b'a', b'd'),
        literal: "accepted",
        category: FixedCategory::Accepted,
        permits_upstream: true,
    },
    Rule {
        key: CodeKey(13, b'c', b'x'),
        literal: "client_syntax",
        category: FixedCategory::ClientSyntax,
        permits_upstream: false,
    },
    Rule {
        key: CodeKey(13, b'r', b'g'),
        literal: "route_missing",
        category: FixedCategory::RouteMissing,
        permits_upstream: false,
    },
    Rule {
        key: CodeKey(15, b'p', b'd'),
        literal: "policy_rejected",
        category: FixedCategory::PolicyRejected,
        permits_upstream: false,
    },
    Rule {
        key: CodeKey(16, b'i', b'e'),
        literal: "internal_failure",
        category: FixedCategory::InternalFailure,
        permits_upstream: true,
    },
    Rule {
        key: CodeKey(16, b'u', b'e'),
        literal: "upstream_failure",
        category: FixedCategory::UpstreamFailure,
        permits_upstream: true,
    },
    Rule {
        key: CodeKey(17, b'a', b'g'),
        literal: "ambiguous_framing",
        category: FixedCategory::AmbiguousFraming,
        permits_upstream: false,
    },
    Rule {
        key: CodeKey(27, b'i', b't'),
        literal: "implementation_disagreement",
        category: FixedCategory::ImplementationDisagreement,
        permits_upstream: false,
    },
];

struct MatchedRule(&'static Rule);

impl MatchedRule {
    fn locate(code: BoundedCode<'_>) -> Result<Self> {
        let key = code.key();
        let Ok(index) = RULES.binary_search_by_key(&key, |rule| rule.key) else {
            return Err(PolyguardError::SerializationInvariant);
        };

        let rule = &RULES[index];
        if code.0 != rule.literal {
            return Err(PolyguardError::SerializationInvariant);
        }

        Ok(Self(rule))
    }

    fn emit(self, upstream_reached: bool) -> Result<TelemetryOutcome> {
        if upstream_reached && !self.0.permits_upstream {
            return Err(PolyguardError::SerializationInvariant);
        }

        Ok(self.0.category.emit())
    }
}

/// Classify a fixed internal code through a bounded fingerprint index.
pub fn classify_telemetry_outcome(code: &str, upstream_reached: bool) -> Result<TelemetryOutcome> {
    let bounded = BoundedCode::new(code)?;
    let matched = MatchedRule::locate(bounded)?;
    matched.emit(upstream_reached)
}
