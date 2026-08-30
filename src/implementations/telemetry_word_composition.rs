use crate::{OutcomeCategory, PolyguardError, Result, TelemetryOutcome};

const MAX_CODE_BYTES: usize = "implementation_disagreement".len();

#[derive(Clone, Copy)]
enum Word {
    Accepted,
    Ambiguous,
    Client,
    Disagreement,
    Failure,
    Framing,
    Implementation,
    Internal,
    Missing,
    Policy,
    Rejected,
    Route,
    Syntax,
    Timeout,
    Upstream,
}

#[derive(Clone, Copy)]
struct Words {
    first: Word,
    second: Option<Word>,
}

#[derive(Clone, Copy)]
enum Reachability {
    Either,
    BeforeUpstream,
}

struct ValidatedOutcome {
    category: OutcomeCategory,
    reachability: Reachability,
}

fn parse_word(word: &str) -> Result<Word> {
    match word {
        "accepted" => Ok(Word::Accepted),
        "ambiguous" => Ok(Word::Ambiguous),
        "client" => Ok(Word::Client),
        "disagreement" => Ok(Word::Disagreement),
        "failure" => Ok(Word::Failure),
        "framing" => Ok(Word::Framing),
        "implementation" => Ok(Word::Implementation),
        "internal" => Ok(Word::Internal),
        "missing" => Ok(Word::Missing),
        "policy" => Ok(Word::Policy),
        "rejected" => Ok(Word::Rejected),
        "route" => Ok(Word::Route),
        "syntax" => Ok(Word::Syntax),
        "timeout" => Ok(Word::Timeout),
        "upstream" => Ok(Word::Upstream),
        _ => Err(PolyguardError::SerializationInvariant),
    }
}

fn split_words(code: &str) -> Result<Words> {
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase())
    {
        return Err(PolyguardError::SerializationInvariant);
    }

    let mut pieces = code.split('_');
    let first = parse_word(pieces.next().unwrap_or_default())?;
    let second = pieces.next().map(parse_word).transpose()?;
    if pieces.next().is_some() {
        return Err(PolyguardError::SerializationInvariant);
    }

    Ok(Words { first, second })
}

fn compose(words: Words) -> Result<ValidatedOutcome> {
    use OutcomeCategory as Category;
    use Reachability::{BeforeUpstream, Either};
    use Word::*;

    let (category, reachability) = match (words.first, words.second) {
        (Accepted, None) => (Category::Accepted, Either),
        (Client, Some(Syntax)) => (Category::ClientSyntax, BeforeUpstream),
        (Ambiguous, Some(Framing)) => (Category::AmbiguousFraming, BeforeUpstream),
        (Policy, Some(Rejected)) => (Category::PolicyRejected, BeforeUpstream),
        (Route, Some(Missing)) => (Category::RouteMissing, BeforeUpstream),
        (Upstream, Some(Failure)) => (Category::UpstreamFailure, Either),
        (Timeout, None) => (Category::Timeout, Either),
        (Implementation, Some(Disagreement)) => {
            (Category::ImplementationDisagreement, BeforeUpstream)
        }
        (Internal, Some(Failure)) => (Category::InternalFailure, Either),
        _ => return Err(PolyguardError::SerializationInvariant),
    };

    Ok(ValidatedOutcome {
        category,
        reachability,
    })
}

fn validate_boundary(code: &str) -> Result<ValidatedOutcome> {
    compose(split_words(code)?)
}

fn validate_reachability(outcome: &ValidatedOutcome, upstream_reached: bool) -> Result<()> {
    if upstream_reached && matches!(outcome.reachability, Reachability::BeforeUpstream) {
        return Err(PolyguardError::SerializationInvariant);
    }
    Ok(())
}

fn project(outcome: ValidatedOutcome) -> TelemetryOutcome {
    let success = matches!(outcome.category, OutcomeCategory::Accepted);
    TelemetryOutcome {
        category: outcome.category,
        success,
    }
}

/// Classify a fixed code by composing its validated vocabulary words.
pub fn classify_telemetry_outcome(code: &str, upstream_reached: bool) -> Result<TelemetryOutcome> {
    let outcome = validate_boundary(code)?;
    validate_reachability(&outcome, upstream_reached)?;
    Ok(project(outcome))
}
