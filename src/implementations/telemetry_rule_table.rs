use crate::{OutcomeCategory, PolyguardError, Result, TelemetryOutcome};

const MAX_CODE_BYTES: usize = "implementation_disagreement".len();

#[derive(Clone, Copy)]
enum UpstreamConstraint {
    Either,
    MustNotBeReached,
}

struct OutcomeRule {
    code: &'static str,
    category: OutcomeCategory,
    success: bool,
    upstream: UpstreamConstraint,
}

const RULES: [OutcomeRule; 9] = [
    OutcomeRule {
        code: "accepted",
        category: OutcomeCategory::Accepted,
        success: true,
        upstream: UpstreamConstraint::Either,
    },
    OutcomeRule {
        code: "client_syntax",
        category: OutcomeCategory::ClientSyntax,
        success: false,
        upstream: UpstreamConstraint::MustNotBeReached,
    },
    OutcomeRule {
        code: "ambiguous_framing",
        category: OutcomeCategory::AmbiguousFraming,
        success: false,
        upstream: UpstreamConstraint::MustNotBeReached,
    },
    OutcomeRule {
        code: "policy_rejected",
        category: OutcomeCategory::PolicyRejected,
        success: false,
        upstream: UpstreamConstraint::MustNotBeReached,
    },
    OutcomeRule {
        code: "route_missing",
        category: OutcomeCategory::RouteMissing,
        success: false,
        upstream: UpstreamConstraint::MustNotBeReached,
    },
    OutcomeRule {
        code: "upstream_failure",
        category: OutcomeCategory::UpstreamFailure,
        success: false,
        upstream: UpstreamConstraint::Either,
    },
    OutcomeRule {
        code: "timeout",
        category: OutcomeCategory::Timeout,
        success: false,
        upstream: UpstreamConstraint::Either,
    },
    OutcomeRule {
        code: "implementation_disagreement",
        category: OutcomeCategory::ImplementationDisagreement,
        success: false,
        upstream: UpstreamConstraint::MustNotBeReached,
    },
    OutcomeRule {
        code: "internal_failure",
        category: OutcomeCategory::InternalFailure,
        success: false,
        upstream: UpstreamConstraint::Either,
    },
];

struct RecognizedOutcome(&'static OutcomeRule);

impl RecognizedOutcome {
    fn parse(code: &str) -> Result<Self> {
        if code.len() > MAX_CODE_BYTES {
            return Err(PolyguardError::SerializationInvariant);
        }

        let rule = RULES
            .iter()
            .find(|rule| rule.code == code)
            .ok_or(PolyguardError::SerializationInvariant)?;
        Ok(Self(rule))
    }

    fn validate_upstream(self, upstream_reached: bool) -> Result<Self> {
        if upstream_reached && matches!(self.0.upstream, UpstreamConstraint::MustNotBeReached) {
            return Err(PolyguardError::SerializationInvariant);
        }
        Ok(self)
    }

    fn into_public(self) -> TelemetryOutcome {
        TelemetryOutcome {
            category: self.0.category.clone(),
            success: self.0.success,
        }
    }
}

/// Classify a fixed internal outcome without incorporating request or error data.
pub fn classify_telemetry_outcome(code: &str, upstream_reached: bool) -> Result<TelemetryOutcome> {
    let recognized = RecognizedOutcome::parse(code)?;
    let consistent = recognized.validate_upstream(upstream_reached)?;
    Ok(consistent.into_public())
}
