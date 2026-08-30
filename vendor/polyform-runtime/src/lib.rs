//! Small application-facing runtime for fetching compositions and reporting outcomes.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("invalid platform response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("composition authentication failed: {0}")]
    Authentication(String),
    #[error("composition rollback rejected: {0}")]
    Rollback(String),
    #[error("composition is incompatible with this binary: {0}")]
    Inventory(String),
    #[error("composition state failed: {0}")]
    State(String),
    #[error("execution response did not contain an ID")]
    MissingExecutionId,
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Composition {
    #[serde(default, alias = "variants")]
    pub implementations: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Assignment {
    pub client_id: String,
    pub release_id: serde_json::Value,
    #[serde(alias = "generation")]
    pub revision: u64,
    pub implementations: HashMap<String, String>,
    pub list_version: u64,
    pub statuses: BTreeMap<String, String>,
    pub nonce: String,
    pub composition_public_key: String,
    pub composition_delegation_signature: String,
    pub signature: String,
    #[serde(default)]
    pub reason: Option<String>,
}

pub type ImplementationInventory = BTreeMap<String, BTreeSet<String>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseTrust {
    pub schema_version: u32,
    pub release_id: String,
    pub application: String,
    pub version: String,
    pub artifact_sha256: String,
    pub release_public_key: String,
    pub composition_public_key: String,
    pub composition_delegation_signature: String,
}

impl ReleaseTrust {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        serde_json::from_slice(
            &fs::read(path).map_err(|error| RuntimeError::State(error.to_string()))?,
        )
        .map_err(RuntimeError::from)
    }

    pub fn verify_delegation(&self) -> Result<()> {
        verify_ed25519(
            &self.release_public_key,
            &self.composition_delegation_signature,
            &composition_delegation_message(self),
            "composition-key delegation",
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PersistedState {
    release_id: String,
    client_id: String,
    list_version: u64,
    revision: u64,
    implementations: BTreeMap<String, String>,
    statuses: BTreeMap<String, String>,
    quarantined: BTreeMap<String, u64>,
    assignment_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CallTelemetry {
    pub spec_function: String,
    pub implementation_id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
}

impl CallTelemetry {
    pub fn new(
        spec_function: impl Into<String>,
        implementation_id: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            spec_function: spec_function.into(),
            implementation_id: implementation_id.into(),
            outcome: outcome.into(),
            duration_ms: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetryEvent {
    pub client_id: String,
    pub release_id: String,
    pub composition_revision: u64,
    pub event_type: String,
    pub spec_function: String,
    pub implementation_id: String,
    pub message_code: Option<String>,
    pub recent_calls: Vec<CallTelemetry>,
}

pub struct Client {
    base_url: String,
    agent: ureq::Agent,
    pub client_id: String,
    pub release_id: String,
    pub revision: u64,
    pub list_version: u64,
    pub composition: Composition,
    trust: ReleaseTrust,
    inventory: ImplementationInventory,
    state_path: PathBuf,
    state: PersistedState,
}

impl Client {
    pub fn register(
        base_url: &str,
        installation_id: Option<&str>,
        strategy: &str,
        trust: ReleaseTrust,
        inventory: ImplementationInventory,
        state_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let base_url = base_url.trim_end_matches('/').to_owned();
        let state_path = state_path.into();
        let prior = load_state(&state_path)?;
        let nonce = new_nonce()?;
        let assignment: Assignment = agent
            .post(&format!("{base_url}/api/v1/clients"))
            .send_json(serde_json::json!({
                "release_id": trust.release_id,
                "installation_id": installation_id,
                "strategy": strategy,
                "nonce": nonce,
            }))
            .map_err(http_error)?
            .into_json()
            .map_err(|error| RuntimeError::Http(error.to_string()))?;
        let state = verify_assignment(&assignment, &nonce, &trust, &inventory, prior.as_ref())?;
        persist_state(&state_path, &state)?;
        Ok(Self::from_verified(
            base_url, agent, trust, inventory, state_path, state,
        ))
    }

    fn from_verified(
        base_url: String,
        agent: ureq::Agent,
        trust: ReleaseTrust,
        inventory: ImplementationInventory,
        state_path: PathBuf,
        state: PersistedState,
    ) -> Self {
        Self {
            base_url,
            agent,
            client_id: state.client_id.clone(),
            release_id: state.release_id.clone(),
            revision: state.revision,
            list_version: state.list_version,
            composition: Composition {
                implementations: state.implementations.clone().into_iter().collect(),
            },
            trust,
            inventory,
            state_path,
            state,
        }
    }

    pub fn refresh(&mut self) -> Result<bool> {
        let nonce = new_nonce()?;
        let assignment: Assignment = self
            .agent
            .get(&format!(
                "{}/api/v1/clients/{}/composition?nonce={}",
                self.base_url, self.client_id, nonce
            ))
            .call()
            .map_err(http_error)?
            .into_json()
            .map_err(|error| RuntimeError::Http(error.to_string()))?;
        let next = verify_assignment(
            &assignment,
            &nonce,
            &self.trust,
            &self.inventory,
            Some(&self.state),
        )?;
        let changed = next.revision != self.revision || next.list_version != self.list_version;
        persist_state(&self.state_path, &next)?;
        self.client_id.clone_from(&next.client_id);
        self.release_id.clone_from(&next.release_id);
        self.revision = next.revision;
        self.list_version = next.list_version;
        self.composition = Composition {
            implementations: next.implementations.clone().into_iter().collect(),
        };
        self.state = next;
        Ok(changed)
    }

    pub fn report_execution(
        &self,
        operation: &str,
        success: bool,
        duration_ms: f64,
        error_kind: Option<&str>,
        calls: &[CallTelemetry],
    ) -> Result<u64> {
        let value: serde_json::Value = self
            .agent
            .post(&format!("{}/api/v1/executions", self.base_url))
            .send_json(serde_json::json!({
                "client_id": self.client_id,
                "composition_revision": self.revision,
                "operation": operation,
                "success": success,
                "duration_ms": duration_ms,
                "error_kind": error_kind,
                "calls": calls
            }))
            .map_err(http_error)?
            .into_json()
            .map_err(|error| RuntimeError::Http(error.to_string()))?;
        value
            .get("execution_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or(RuntimeError::MissingExecutionId)
    }

    pub fn report_event(&self, event: &TelemetryEvent) -> Result<()> {
        self.agent
            .post(&format!("{}/api/v1/telemetry", self.base_url))
            .send_json(event)
            .map_err(http_error)?;
        Ok(())
    }
}

pub fn composition_delegation_message(trust: &ReleaseTrust) -> String {
    format!(
        "polyform-composition-delegation-v1\napplication={}\nversion={}\nartifact_sha256={}\ncomposition_public_key={}",
        trust.application, trust.version, trust.artifact_sha256, trust.composition_public_key
    )
}

pub fn composition_assignment_message(assignment: &Assignment) -> String {
    let mut lines = vec![
        "polyform-composition-v1".to_owned(),
        format!("client_id={}", assignment.client_id),
        format!("release_id={}", json_scalar(&assignment.release_id)),
        format!("list_version={}", assignment.list_version),
        format!("revision={}", assignment.revision),
        format!("nonce={}", assignment.nonce),
    ];
    let implementations = assignment
        .implementations
        .iter()
        .map(|(function, implementation)| (function.clone(), implementation.clone()))
        .collect::<BTreeMap<_, _>>();
    lines.extend(
        implementations
            .iter()
            .map(|(function, implementation)| format!("assignment:{function}={implementation}")),
    );
    lines.extend(
        assignment
            .statuses
            .iter()
            .map(|(implementation, status)| format!("status:{implementation}={status}")),
    );
    lines.join("\n")
}

fn verify_assignment(
    assignment: &Assignment,
    expected_nonce: &str,
    trust: &ReleaseTrust,
    inventory: &ImplementationInventory,
    prior: Option<&PersistedState>,
) -> Result<PersistedState> {
    if trust.schema_version != 1 {
        return Err(RuntimeError::Authentication(format!(
            "unsupported release trust schema {}",
            trust.schema_version
        )));
    }
    let release_id = json_scalar(&assignment.release_id);
    if release_id != trust.release_id {
        return Err(RuntimeError::Authentication(format!(
            "expected release {}, received {release_id}",
            trust.release_id
        )));
    }
    if assignment.nonce != expected_nonce {
        return Err(RuntimeError::Authentication(
            "response nonce did not match this request".into(),
        ));
    }
    if assignment.composition_public_key != trust.composition_public_key
        || assignment.composition_delegation_signature != trust.composition_delegation_signature
    {
        return Err(RuntimeError::Authentication(
            "composition signer did not match the verified release trust".into(),
        ));
    }
    trust.verify_delegation()?;
    let signed_message = composition_assignment_message(assignment);
    verify_ed25519(
        &trust.composition_public_key,
        &assignment.signature,
        &signed_message,
        "composition assignment",
    )?;

    if inventory.is_empty() {
        return Err(RuntimeError::Inventory(
            "the binary supplied an empty implementation inventory".into(),
        ));
    }
    let implementations = assignment
        .implementations
        .iter()
        .map(|(function, implementation)| (function.clone(), implementation.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_functions = inventory.keys().cloned().collect::<BTreeSet<_>>();
    let received_functions = implementations.keys().cloned().collect::<BTreeSet<_>>();
    if received_functions != expected_functions {
        return Err(RuntimeError::Inventory(format!(
            "expected functions {expected_functions:?}, received {received_functions:?}"
        )));
    }
    for (function, implementation) in &implementations {
        if !inventory
            .get(function)
            .is_some_and(|allowed| allowed.contains(implementation))
        {
            return Err(RuntimeError::Inventory(format!(
                "implementation '{implementation}' is not compiled for '{function}'"
            )));
        }
    }
    let expected_implementations = inventory
        .values()
        .flat_map(|values| values.iter().cloned())
        .collect::<BTreeSet<_>>();
    let received_implementations = assignment.statuses.keys().cloned().collect::<BTreeSet<_>>();
    if received_implementations != expected_implementations {
        return Err(RuntimeError::Inventory(
            "signed status list did not exactly match the binary inventory".into(),
        ));
    }
    if let Some((implementation, status)) = assignment
        .statuses
        .iter()
        .find(|(_, status)| !matches!(status.as_str(), "active" | "quarantined" | "disabled"))
    {
        return Err(RuntimeError::Inventory(format!(
            "unknown status '{status}' for '{implementation}'"
        )));
    }
    for implementation in implementations.values() {
        if assignment.statuses.get(implementation).map(String::as_str) != Some("active") {
            return Err(RuntimeError::Inventory(format!(
                "assigned implementation '{implementation}' is not active"
            )));
        }
    }

    let mut quarantined = prior
        .map(|state| state.quarantined.clone())
        .unwrap_or_default();
    if let Some(previous) = prior {
        if previous.release_id != release_id {
            return Err(RuntimeError::Rollback(
                "persisted state belongs to another release".into(),
            ));
        }
        if !previous.client_id.is_empty() && previous.client_id != assignment.client_id {
            return Err(RuntimeError::Rollback(
                "server changed the installation's client identity".into(),
            ));
        }
        if assignment.list_version < previous.list_version {
            return Err(RuntimeError::Rollback(format!(
                "list version {} is older than {}",
                assignment.list_version, previous.list_version
            )));
        }
        if assignment.revision < previous.revision {
            return Err(RuntimeError::Rollback(format!(
                "composition revision {} is older than {}",
                assignment.revision, previous.revision
            )));
        }
        if assignment.list_version == previous.list_version
            && assignment.statuses != previous.statuses
        {
            return Err(RuntimeError::Rollback(
                "status list changed without a higher list version".into(),
            ));
        }
        if assignment.revision == previous.revision && implementations != previous.implementations {
            return Err(RuntimeError::Rollback(
                "composition changed without a higher revision".into(),
            ));
        }
    }

    let can_restore = prior.is_none_or(|state| assignment.list_version > state.list_version);
    for (implementation, status) in &assignment.statuses {
        match status.as_str() {
            "quarantined" | "disabled" => {
                quarantined
                    .entry(implementation.clone())
                    .or_insert(assignment.list_version);
            }
            "active" if can_restore => {
                quarantined.remove(implementation);
            }
            _ => {}
        }
    }
    for implementation in implementations.values() {
        if quarantined.contains_key(implementation) {
            return Err(RuntimeError::Rollback(format!(
                "local quarantine floor blocks '{implementation}'"
            )));
        }
    }

    Ok(PersistedState {
        release_id,
        client_id: assignment.client_id.clone(),
        list_version: assignment.list_version,
        revision: assignment.revision,
        implementations,
        statuses: assignment.statuses.clone(),
        quarantined,
        assignment_hash: hex::encode(Sha256::digest(signed_message.as_bytes())),
    })
}

fn verify_ed25519(public_key: &str, signature: &str, message: &str, label: &str) -> Result<()> {
    let key_bytes: [u8; 32] = BASE64
        .decode(public_key)
        .map_err(|error| RuntimeError::Authentication(format!("invalid {label} key: {error}")))?
        .try_into()
        .map_err(|_| RuntimeError::Authentication(format!("{label} key must be 32 bytes")))?;
    let signature_bytes: [u8; 64] = BASE64
        .decode(signature)
        .map_err(|error| {
            RuntimeError::Authentication(format!("invalid {label} signature: {error}"))
        })?
        .try_into()
        .map_err(|_| RuntimeError::Authentication(format!("{label} signature must be 64 bytes")))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| RuntimeError::Authentication(format!("invalid {label} key: {error}")))?
        .verify(message.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| RuntimeError::Authentication(format!("invalid {label} signature")))
}

fn new_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        RuntimeError::State(format!("could not generate request nonce: {error}"))
    })?;
    Ok(hex::encode(bytes))
}

fn load_state(path: &Path) -> Result<Option<PersistedState>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| RuntimeError::State(format!("invalid {}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(RuntimeError::State(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}

fn persist_state(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| RuntimeError::State(error.to_string()))?;
    }
    let temporary = path.with_extension("polyform-state.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(state).map_err(RuntimeError::from)?,
    )
    .map_err(|error| RuntimeError::State(error.to_string()))?;
    fs::rename(&temporary, path).map_err(|error| RuntimeError::State(error.to_string()))
}

fn json_scalar(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn http_error(error: ureq::Error) -> RuntimeError {
    match error {
        ureq::Error::Status(code, response) => RuntimeError::Http(format!(
            "server returned {code}: {}",
            response.into_string().unwrap_or_default()
        )),
        other => RuntimeError::Http(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_fixture() -> (
        ReleaseTrust,
        ImplementationInventory,
        SigningKey,
        Assignment,
    ) {
        let release_key = SigningKey::from_bytes(&[7_u8; 32]);
        let composition_key = SigningKey::from_bytes(&[9_u8; 32]);
        let mut trust = ReleaseTrust {
            schema_version: 1,
            release_id: "42".into(),
            application: "example/app".into(),
            version: "1.0.0".into(),
            artifact_sha256: "a".repeat(64),
            release_public_key: BASE64.encode(release_key.verifying_key().as_bytes()),
            composition_public_key: BASE64.encode(composition_key.verifying_key().as_bytes()),
            composition_delegation_signature: String::new(),
        };
        trust.composition_delegation_signature = BASE64.encode(
            release_key
                .sign(composition_delegation_message(&trust).as_bytes())
                .to_bytes(),
        );
        let inventory = BTreeMap::from([
            (
                "parse".into(),
                BTreeSet::from(["parse.first".into(), "parse.second".into()]),
            ),
            (
                "write".into(),
                BTreeSet::from(["write.first".into(), "write.second".into()]),
            ),
        ]);
        let mut assignment = Assignment {
            client_id: "pc_test".into(),
            release_id: serde_json::json!(42),
            revision: 2,
            implementations: HashMap::from([
                ("parse".into(), "parse.first".into()),
                ("write".into(), "write.first".into()),
            ]),
            list_version: 2,
            statuses: BTreeMap::from([
                ("parse.first".into(), "active".into()),
                ("parse.second".into(), "active".into()),
                ("write.first".into(), "active".into()),
                ("write.second".into(), "active".into()),
            ]),
            nonce: "request-2".into(),
            composition_public_key: trust.composition_public_key.clone(),
            composition_delegation_signature: trust.composition_delegation_signature.clone(),
            signature: String::new(),
            reason: Some("test".into()),
        };
        sign_assignment(&composition_key, &mut assignment);
        (trust, inventory, composition_key, assignment)
    }

    fn sign_assignment(key: &SigningKey, assignment: &mut Assignment) {
        assignment.signature = BASE64.encode(
            key.sign(composition_assignment_message(assignment).as_bytes())
                .to_bytes(),
        );
    }

    #[test]
    fn telemetry_event_contains_metadata_only() {
        let value = serde_json::to_value(TelemetryEvent {
            client_id: "pc_12345678".into(),
            release_id: "1".into(),
            composition_revision: 2,
            event_type: "integrity_failure".into(),
            spec_function: "validate_crc".into(),
            implementation_id: "validate_crc.chunked".into(),
            message_code: Some("crc".into()),
            recent_calls: vec![CallTelemetry::new(
                "validate_crc",
                "validate_crc.chunked",
                "error",
            )],
        })
        .unwrap();
        assert!(value.get("archive").is_none());
        assert!(value.get("message").is_none());
        assert_eq!(value["recent_calls"][0]["outcome"], "error");
    }

    #[test]
    fn forged_and_captured_assignments_are_rejected() {
        let (trust, inventory, _, assignment) = signed_fixture();
        let mut forged = assignment.clone();
        forged
            .implementations
            .insert("parse".into(), "parse.second".into());
        assert!(matches!(
            verify_assignment(&forged, "request-2", &trust, &inventory, None),
            Err(RuntimeError::Authentication(_))
        ));
        assert!(matches!(
            verify_assignment(&assignment, "a-new-request", &trust, &inventory, None),
            Err(RuntimeError::Authentication(_))
        ));
    }

    #[test]
    fn lower_versions_and_same_version_changes_are_rejected() {
        let (trust, inventory, key, assignment) = signed_fixture();
        let current =
            verify_assignment(&assignment, "request-2", &trust, &inventory, None).unwrap();
        let mut older = assignment.clone();
        older.list_version = 1;
        older.revision = 1;
        older.nonce = "request-3".into();
        sign_assignment(&key, &mut older);
        assert!(matches!(
            verify_assignment(&older, "request-3", &trust, &inventory, Some(&current)),
            Err(RuntimeError::Rollback(_))
        ));

        let mut equivocation = assignment.clone();
        equivocation.nonce = "request-4".into();
        equivocation
            .implementations
            .insert("parse".into(), "parse.second".into());
        sign_assignment(&key, &mut equivocation);
        assert!(matches!(
            verify_assignment(
                &equivocation,
                "request-4",
                &trust,
                &inventory,
                Some(&current)
            ),
            Err(RuntimeError::Rollback(_))
        ));
    }

    #[test]
    fn unknown_missing_and_quarantined_implementations_are_rejected() {
        let (trust, inventory, key, assignment) = signed_fixture();
        let mut unknown = assignment.clone();
        unknown.nonce = "unknown".into();
        unknown
            .implementations
            .insert("parse".into(), "parse.not-in-binary".into());
        sign_assignment(&key, &mut unknown);
        assert!(matches!(
            verify_assignment(&unknown, "unknown", &trust, &inventory, None),
            Err(RuntimeError::Inventory(_))
        ));

        let mut missing = assignment.clone();
        missing.nonce = "missing".into();
        missing.implementations.remove("write");
        sign_assignment(&key, &mut missing);
        assert!(matches!(
            verify_assignment(&missing, "missing", &trust, &inventory, None),
            Err(RuntimeError::Inventory(_))
        ));

        let mut incomplete_statuses = assignment.clone();
        incomplete_statuses.nonce = "incomplete-statuses".into();
        incomplete_statuses.statuses.remove("parse.second");
        sign_assignment(&key, &mut incomplete_statuses);
        assert!(matches!(
            verify_assignment(
                &incomplete_statuses,
                "incomplete-statuses",
                &trust,
                &inventory,
                None
            ),
            Err(RuntimeError::Inventory(_))
        ));

        let mut malformed_status = assignment.clone();
        malformed_status.nonce = "malformed-status".into();
        malformed_status
            .statuses
            .insert("parse.second".into(), "maybe".into());
        sign_assignment(&key, &mut malformed_status);
        assert!(matches!(
            verify_assignment(
                &malformed_status,
                "malformed-status",
                &trust,
                &inventory,
                None
            ),
            Err(RuntimeError::Inventory(_))
        ));

        let mut quarantined = assignment.clone();
        quarantined.nonce = "quarantine".into();
        quarantined.list_version = 3;
        quarantined.revision = 3;
        quarantined
            .statuses
            .insert("parse.first".into(), "quarantined".into());
        sign_assignment(&key, &mut quarantined);
        assert!(matches!(
            verify_assignment(&quarantined, "quarantine", &trust, &inventory, None),
            Err(RuntimeError::Inventory(_))
        ));
    }

    #[test]
    fn quarantine_floor_requires_an_explicit_higher_version_restore() {
        let (trust, inventory, key, mut assignment) = signed_fixture();
        assignment.list_version = 3;
        assignment.revision = 3;
        assignment.nonce = "quarantine".into();
        assignment
            .implementations
            .insert("parse".into(), "parse.second".into());
        assignment
            .statuses
            .insert("parse.first".into(), "quarantined".into());
        sign_assignment(&key, &mut assignment);
        let current =
            verify_assignment(&assignment, "quarantine", &trust, &inventory, None).unwrap();
        assert!(current.quarantined.contains_key("parse.first"));

        let mut same_version_restore = assignment.clone();
        same_version_restore.nonce = "same".into();
        same_version_restore
            .statuses
            .insert("parse.first".into(), "active".into());
        same_version_restore
            .implementations
            .insert("parse".into(), "parse.first".into());
        same_version_restore.revision = 4;
        sign_assignment(&key, &mut same_version_restore);
        assert!(matches!(
            verify_assignment(
                &same_version_restore,
                "same",
                &trust,
                &inventory,
                Some(&current)
            ),
            Err(RuntimeError::Rollback(_))
        ));

        let mut restored = same_version_restore;
        restored.nonce = "restored".into();
        restored.list_version = 4;
        sign_assignment(&key, &mut restored);
        let next =
            verify_assignment(&restored, "restored", &trust, &inventory, Some(&current)).unwrap();
        assert!(!next.quarantined.contains_key("parse.first"));
    }
}
