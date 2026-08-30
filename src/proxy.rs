//! Bounded, fail-closed HTTP/1.1 reverse-proxy runtime.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;

use polyform_runtime::{
    CallTelemetry, Client as PolyformClient, ImplementationInventory, ReleaseTrust,
};

use crate::{
    BodyFraming, EffectiveAuthority, ForwardingPolicy, HeaderBlock, Implementation,
    NormalizedTarget, OutcomeCategory, PolyguardError, Result, RouteRule, SanitizedHeaders,
    TargetForm, TrailerBlock, UpgradeDecision, registered_implementations,
};

const MAX_REQUEST_LINE_BYTES: usize = 8_192;
const MAX_REQUEST_HEADER_BYTES: usize = 32_768;
const MAX_TRAILER_BYTES: usize = 8_192;
const SERVER_HEADER: &[u8] = b"server: polyguard/0.1.2\r\n";

static TERMINATE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listener: ListenerConfig,
    #[serde(default)]
    pub limits: Limits,
    pub upstreams: Vec<UpstreamConfig>,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub polyform: Option<PolyformConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolyformConfig {
    pub base_url: String,
    pub trust_file: String,
    pub state_file: String,
    #[serde(default)]
    pub installation_id: Option<String>,
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub report_telemetry: bool,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub address: String,
    #[serde(default)]
    pub trust_forwarding_headers: bool,
    #[serde(default = "default_security_mode")]
    pub security_mode: String,
    #[serde(default = "default_agreement_width")]
    pub agreement_implementations: usize,
    #[serde(default)]
    pub quarantined_implementations: Vec<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_header_timeout")]
    pub request_header_timeout_ms: u64,
    #[serde(default = "default_body_timeout")]
    pub request_body_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub upstream_connect_timeout_ms: u64,
    #[serde(default = "default_response_timeout")]
    pub upstream_response_timeout_ms: u64,
    #[serde(default = "default_shutdown_timeout")]
    pub graceful_shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_request_body_bytes: usize,
    pub max_response_header_bytes: usize,
    pub max_response_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 16 * 1024 * 1024,
            max_response_header_bytes: 32 * 1024,
            max_response_body_bytes: 64 * 1024 * 1024,
        }
    }
}

fn default_security_mode() -> String {
    "agreement".into()
}
fn default_agreement_width() -> usize {
    2
}
fn default_max_connections() -> usize {
    1_024
}
fn default_header_timeout() -> u64 {
    5_000
}
fn default_body_timeout() -> u64 {
    30_000
}
fn default_connect_timeout() -> u64 {
    3_000
}
fn default_response_timeout() -> u64 {
    30_000
}
fn default_shutdown_timeout() -> u64 {
    10_000
}
fn default_strategy() -> String {
    "balanced".into()
}
fn default_refresh_interval() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

thread_local! {
    static CALL_TRACE: RefCell<Vec<CallTelemetry>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(toml::de::Error),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "configuration I/O error: {error}"),
            Self::Toml(error) => write!(formatter, "configuration syntax error: {error}"),
            Self::Invalid(reason) => write!(formatter, "invalid configuration: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load_config(path: &Path) -> std::result::Result<Config, ConfigError> {
    let source = fs::read_to_string(path).map_err(ConfigError::Io)?;
    let config: Config = toml::from_str(&source).map_err(ConfigError::Toml)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn validate_config(config: &Config) -> std::result::Result<(), ConfigError> {
    SocketAddr::from_str(&config.listener.address).map_err(|_| {
        ConfigError::Invalid("listener.address must be a literal socket address".into())
    })?;
    if config.listener.security_mode != "agreement" {
        return Err(ConfigError::Invalid(
            "listener.security_mode must be agreement".into(),
        ));
    }
    if !(2..=5).contains(&config.listener.agreement_implementations) {
        return Err(ConfigError::Invalid(
            "listener.agreement_implementations must be between 2 and 5".into(),
        ));
    }
    if config.listener.max_connections == 0 || config.listener.max_connections > 65_536 {
        return Err(ConfigError::Invalid(
            "listener.max_connections must be 1..=65536".into(),
        ));
    }
    for (name, value) in [
        (
            "request_header_timeout_ms",
            config.listener.request_header_timeout_ms,
        ),
        (
            "request_body_timeout_ms",
            config.listener.request_body_timeout_ms,
        ),
        (
            "upstream_connect_timeout_ms",
            config.listener.upstream_connect_timeout_ms,
        ),
        (
            "upstream_response_timeout_ms",
            config.listener.upstream_response_timeout_ms,
        ),
        (
            "graceful_shutdown_timeout_ms",
            config.listener.graceful_shutdown_timeout_ms,
        ),
    ] {
        if value == 0 || value > 300_000 {
            return Err(ConfigError::Invalid(format!(
                "listener.{name} must be 1..=300000"
            )));
        }
    }
    if config.limits.max_request_body_bytes == 0
        || config.limits.max_response_header_bytes < 1_024
        || config.limits.max_response_body_bytes == 0
    {
        return Err(ConfigError::Invalid(
            "body limits must be positive and response headers at least 1024 bytes".into(),
        ));
    }
    let registry_ids: BTreeSet<_> = registered_implementations()
        .iter()
        .map(|entry| entry.id)
        .collect();
    let mut quarantined = BTreeSet::new();
    for id in &config.listener.quarantined_implementations {
        if !registry_ids.contains(id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "unknown quarantined implementation {id}"
            )));
        }
        if !quarantined.insert(id) {
            return Err(ConfigError::Invalid(format!(
                "duplicate quarantined implementation {id}"
            )));
        }
    }
    let mut upstreams = BTreeSet::new();
    for upstream in &config.upstreams {
        validate_identifier("upstream name", &upstream.name)?;
        if !upstreams.insert(upstream.name.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate upstream {}",
                upstream.name
            )));
        }
        SocketAddr::from_str(&upstream.address).map_err(|_| {
            ConfigError::Invalid(format!(
                "upstream {} address must be a literal socket address",
                upstream.name
            ))
        })?;
    }
    if upstreams.is_empty() || config.routes.is_empty() || config.routes.len() > 256 {
        return Err(ConfigError::Invalid(
            "configure 1..=256 routes and at least one upstream".into(),
        ));
    }
    for route in &config.routes {
        if !upstreams.contains(route.upstream.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "route references unknown upstream {}",
                route.upstream
            )));
        }
    }
    if let Some(polyform) = &config.polyform {
        if !(polyform.base_url.starts_with("https://")
            || polyform.base_url.starts_with("http://127.0.0.1:")
            || polyform.base_url.starts_with("http://localhost:"))
        {
            return Err(ConfigError::Invalid(
                "polyform.base_url must use HTTPS, except for an explicit loopback test service"
                    .into(),
            ));
        }
        if polyform.trust_file.is_empty() || polyform.state_file.is_empty() {
            return Err(ConfigError::Invalid(
                "polyform trust_file and state_file are required".into(),
            ));
        }
        if polyform.refresh_interval_seconds == 0 || polyform.refresh_interval_seconds > 86_400 {
            return Err(ConfigError::Invalid(
                "polyform.refresh_interval_seconds must be 1..=86400".into(),
            ));
        }
        validate_identifier("polyform strategy", &polyform.strategy)?;
        if let Some(installation_id) = &polyform.installation_id {
            validate_identifier("polyform installation_id", installation_id)?;
        }
    }
    let routes = route_rules(config);
    let agreement = Agreement::new(
        config.listener.agreement_implementations,
        &quarantined,
        BTreeMap::new(),
    );
    agreement
        .run("match_route", |implementation| {
            implementation.match_route.map(|function| {
                function(
                    &EffectiveAuthority {
                        host: config.routes[0].host.clone(),
                        port: None,
                    },
                    &NormalizedTarget {
                        form: TargetForm::Origin,
                        scheme: None,
                        authority: None,
                        path_and_query: "/".into(),
                        routing_path: "/".into(),
                    },
                    &routes,
                )
            })
        })
        .map(|_| ())
        .or_else(|fault| match fault {
            Fault::Protocol(PolyguardError::NoRoute) => Ok(()),
            other => Err(ConfigError::Invalid(format!(
                "route table rejected by agreement set: {}",
                other.code()
            ))),
        })?;
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> std::result::Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::Invalid(format!(
            "{label} must be 1..=64 safe ASCII characters"
        )));
    }
    Ok(())
}

#[derive(Debug)]
enum Fault {
    Protocol(PolyguardError),
    Disagreement { function: &'static str },
    Timeout,
    UpstreamTimeout,
    TooLarge,
    ClientIo,
    Upstream,
    Internal,
}

impl Fault {
    fn code(&self) -> &'static str {
        match self {
            Self::Protocol(
                PolyguardError::AmbiguousFraming
                | PolyguardError::ConflictingContentLength
                | PolyguardError::InvalidTransferEncoding,
            ) => "ambiguous_framing",
            Self::Protocol(PolyguardError::NoRoute) => "route_missing",
            Self::Protocol(
                PolyguardError::UnsupportedUpgrade | PolyguardError::UnsupportedVersion,
            ) => "policy_rejected",
            Self::Protocol(_) | Self::ClientIo | Self::TooLarge => "client_syntax",
            Self::Disagreement { .. } => "implementation_disagreement",
            Self::Timeout | Self::UpstreamTimeout => "timeout",
            Self::Upstream => "upstream_failure",
            Self::Internal => "internal_failure",
        }
    }

    fn status(&self) -> (u16, &'static str) {
        match self {
            Self::Protocol(PolyguardError::NoRoute) => (404, "Not Found"),
            Self::Protocol(PolyguardError::UnsupportedUpgrade) => (501, "Not Implemented"),
            Self::Timeout => (408, "Request Timeout"),
            Self::UpstreamTimeout => (504, "Gateway Timeout"),
            Self::TooLarge | Self::Protocol(PolyguardError::LimitExceeded { .. }) => {
                (413, "Content Too Large")
            }
            Self::Upstream => (502, "Bad Gateway"),
            Self::Internal => (500, "Internal Server Error"),
            _ => (400, "Bad Request"),
        }
    }
}

struct Agreement {
    width: usize,
    quarantined: BTreeSet<String>,
    primary: RwLock<BTreeMap<String, String>>,
}

impl Agreement {
    fn new(
        width: usize,
        quarantined: &BTreeSet<&String>,
        primary: BTreeMap<String, String>,
    ) -> Self {
        Self {
            width,
            quarantined: quarantined.iter().map(|value| (*value).clone()).collect(),
            primary: RwLock::new(primary),
        }
    }

    fn update_primary(&self, primary: BTreeMap<String, String>) {
        *self.primary.write().expect("composition lock poisoned") = primary;
    }

    fn run<T, F>(&self, function: &'static str, mut invoke: F) -> std::result::Result<T, Fault>
    where
        T: Clone + Eq + Debug,
        F: FnMut(&Implementation) -> Option<Result<T>>,
    {
        let primary_id = self
            .primary
            .read()
            .expect("composition lock poisoned")
            .get(function)
            .cloned();
        let mut candidates = Vec::new();
        if let Some(primary_id) = primary_id.as_deref()
            && let Some(primary) = registered_implementations()
                .iter()
                .find(|entry| entry.id == primary_id)
        {
            candidates.push(primary);
        }
        candidates.extend(
            registered_implementations()
                .iter()
                .filter(|entry| Some(entry.id) != primary_id.as_deref()),
        );
        let mut reference: Option<Result<T>> = None;
        let mut called = 0;
        for implementation in candidates {
            if self.quarantined.contains(implementation.id) {
                continue;
            }
            let Some(outcome) = invoke(implementation) else {
                continue;
            };
            trace_call(
                function,
                implementation.id,
                telemetry_call_outcome(outcome.is_ok()),
            );
            called += 1;
            if let Some(expected) = &reference {
                if expected != &outcome {
                    mark_trace_disagreement(function);
                    return Err(Fault::Disagreement { function });
                }
            } else {
                reference = Some(outcome);
            }
            if called == self.width {
                break;
            }
        }
        if called != self.width {
            return Err(Fault::Internal);
        }
        reference
            .expect("agreement width is nonzero")
            .map_err(Fault::Protocol)
    }

    fn selected_ids(&self) -> BTreeMap<&'static str, Vec<&'static str>> {
        let mut result = BTreeMap::new();
        macro_rules! collect {
            ($name:literal, $field:ident) => {{
                let primary_id = self
                    .primary
                    .read()
                    .expect("composition lock poisoned")
                    .get($name)
                    .cloned();
                let mut ids = Vec::new();
                if let Some(primary_id) = primary_id.as_deref() {
                    if let Some(primary) = registered_implementations().iter().find(|entry| {
                        entry.id == primary_id
                            && entry.$field.is_some()
                            && !self.quarantined.contains(entry.id)
                    }) {
                        ids.push(primary.id);
                    }
                }
                ids.extend(
                    registered_implementations()
                        .iter()
                        .filter(|entry| {
                            !self.quarantined.contains(entry.id)
                                && entry.$field.is_some()
                                && Some(entry.id) != primary_id.as_deref()
                        })
                        .take(self.width.saturating_sub(ids.len()))
                        .map(|entry| entry.id),
                );
                result.insert($name, ids);
            }};
        }
        collect!("parse_request_line", parse_request_line);
        collect!("parse_header_section", parse_header_section);
        collect!("determine_body_framing", determine_body_framing);
        collect!("parse_chunk_metadata", parse_chunk_metadata);
        collect!("parse_trailer_section", parse_trailer_section);
        collect!("normalize_request_target", normalize_request_target);
        collect!("reconcile_authority", reconcile_authority);
        collect!("remove_hop_by_hop_headers", remove_hop_by_hop_headers);
        collect!(
            "construct_canonical_upstream_head",
            construct_canonical_upstream_head
        );
        collect!("match_route", match_route);
        collect!("apply_forwarding_policy", apply_forwarding_policy);
        collect!("decide_upgrade", decide_upgrade);
        collect!("classify_telemetry_outcome", classify_telemetry_outcome);
        result
    }
}

fn begin_trace() {
    CALL_TRACE.with(|trace| trace.borrow_mut().clear());
}

fn trace_call(function: &str, implementation: &str, outcome: &str) {
    CALL_TRACE.with(|trace| {
        trace
            .borrow_mut()
            .push(CallTelemetry::new(function, implementation, outcome));
    });
}

fn telemetry_call_outcome(success: bool) -> &'static str {
    if success { "ok" } else { "error" }
}

fn mark_trace_disagreement(function: &str) {
    CALL_TRACE.with(|trace| {
        for call in trace
            .borrow_mut()
            .iter_mut()
            .filter(|call| call.spec_function == function)
        {
            call.outcome = "error".into();
        }
    });
}

fn take_trace() -> Vec<CallTelemetry> {
    CALL_TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

fn active_composition_calls(
    calls: &[CallTelemetry],
    active: &HashMap<String, String>,
) -> Vec<CallTelemetry> {
    calls
        .iter()
        .filter(|call| {
            active
                .get(&call.spec_function)
                .is_some_and(|implementation| implementation == &call.implementation_id)
        })
        .cloned()
        .collect()
}

struct Metrics {
    accepted: AtomicU64,
    rejected: AtomicU64,
    disagreements: AtomicU64,
    upstream_failures: AtomicU64,
    timeouts: AtomicU64,
    active: AtomicUsize,
}

impl Metrics {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            disagreements: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            active: AtomicUsize::new(0),
        }
    }
}

struct Runtime {
    config: Config,
    agreement: Agreement,
    upstreams: BTreeMap<String, SocketAddr>,
    routes: Vec<RouteRule>,
    metrics: Metrics,
    polyform: Option<RuntimePolyform>,
}

struct RuntimePolyform {
    client: Mutex<PolyformClient>,
    refresh_interval: Duration,
    report_telemetry: bool,
}

pub fn run(config: Config) -> io::Result<()> {
    validate_config(&config).map_err(io::Error::other)?;
    let listen_address: SocketAddr = config.listener.address.parse().expect("validated");
    let quarantined: BTreeSet<&String> =
        config.listener.quarantined_implementations.iter().collect();
    let polyform = initialize_polyform(&config)?;
    let primary = polyform
        .as_ref()
        .map(|runtime| {
            runtime
                .client
                .lock()
                .expect("runtime lock poisoned")
                .composition
                .implementations
                .clone()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let agreement = Agreement::new(
        config.listener.agreement_implementations,
        &quarantined,
        primary,
    );
    let selected = agreement.selected_ids();
    if selected.values().any(|ids| ids.len() != agreement.width) {
        return Err(io::Error::other(
            "quarantine leaves an incomplete agreement set",
        ));
    }
    let upstreams = config
        .upstreams
        .iter()
        .map(|entry| {
            (
                entry.name.clone(),
                entry.address.parse().expect("validated"),
            )
        })
        .collect();
    let routes = route_rules(&config);
    let shutdown_timeout = Duration::from_millis(config.listener.graceful_shutdown_timeout_ms);
    let max_connections = config.listener.max_connections;
    let runtime = Arc::new(Runtime {
        config,
        agreement,
        upstreams,
        routes,
        metrics: Metrics::new(),
        polyform,
    });
    install_signal_handlers();
    TERMINATE.store(false, Ordering::SeqCst);
    let listener = TcpListener::bind(listen_address)?;
    listener.set_nonblocking(true)?;
    log_json(
        json!({"event":"started","address":listen_address.to_string(),"security_mode":"agreement","selected":selected}),
    );

    let mut next_refresh = runtime
        .polyform
        .as_ref()
        .map(|polyform| Instant::now() + polyform.refresh_interval);
    while !TERMINATE.load(Ordering::SeqCst) {
        if next_refresh.is_some_and(|deadline| Instant::now() >= deadline) {
            refresh_polyform(&runtime);
            next_refresh = runtime
                .polyform
                .as_ref()
                .map(|polyform| Instant::now() + polyform.refresh_interval);
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if runtime.metrics.active.fetch_add(1, Ordering::SeqCst) >= max_connections {
                    runtime.metrics.active.fetch_sub(1, Ordering::SeqCst);
                    let _ = write_simple_response(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        b"busy\n",
                        &[],
                    );
                    continue;
                }
                let shared = Arc::clone(&runtime);
                thread::spawn(move || {
                    begin_trace();
                    let started = Instant::now();
                    let result = handle_connection(&mut stream, peer, &shared);
                    let (code, function) = match &result {
                        Ok(()) => ("accepted", None),
                        Err(Fault::Disagreement { function }) => {
                            ("implementation_disagreement", Some(*function))
                        }
                        Err(fault) => (fault.code(), None),
                    };
                    if result.is_ok() {
                        shared.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        shared.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    if matches!(result, Err(Fault::Disagreement { .. })) {
                        shared.metrics.disagreements.fetch_add(1, Ordering::Relaxed);
                    }
                    if matches!(result, Err(Fault::Upstream)) {
                        shared
                            .metrics
                            .upstream_failures
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    if matches!(result, Err(Fault::Timeout | Fault::UpstreamTimeout)) {
                        shared.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = classify_outcome(&shared.agreement, code, result.is_ok());
                    let calls = take_trace();
                    report_polyform(
                        &shared,
                        result.is_ok(),
                        started.elapsed().as_secs_f64() * 1_000.0,
                        code,
                        &calls,
                    );
                    log_json(
                        json!({"event":"request","outcome":code,"disagreement_function":function,"latency_ms":started.elapsed().as_millis()}),
                    );
                    shared.metrics.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    drop(listener);
    let deadline = Instant::now() + shutdown_timeout;
    while runtime.metrics.active.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    log_json(
        json!({"event":"stopped","active_connections":runtime.metrics.active.load(Ordering::Relaxed)}),
    );
    Ok(())
}

fn route_rules(config: &Config) -> Vec<RouteRule> {
    config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| RouteRule {
            host: route.host.clone(),
            path_prefix: route.path_prefix.clone(),
            upstream: route.upstream.clone(),
            declaration_order: index,
        })
        .collect()
}

fn implementation_inventory() -> ImplementationInventory {
    let mut inventory = ImplementationInventory::new();
    macro_rules! add {
        ($name:literal, $field:ident) => {
            inventory.insert(
                $name.into(),
                registered_implementations()
                    .iter()
                    .filter(|entry| entry.$field.is_some())
                    .map(|entry| entry.id.to_owned())
                    .collect(),
            );
        };
    }
    add!("parse_request_line", parse_request_line);
    add!("parse_header_section", parse_header_section);
    add!("determine_body_framing", determine_body_framing);
    add!("parse_chunk_metadata", parse_chunk_metadata);
    add!("parse_trailer_section", parse_trailer_section);
    add!("normalize_request_target", normalize_request_target);
    add!("reconcile_authority", reconcile_authority);
    add!("remove_hop_by_hop_headers", remove_hop_by_hop_headers);
    add!(
        "construct_canonical_upstream_head",
        construct_canonical_upstream_head
    );
    add!("match_route", match_route);
    add!("apply_forwarding_policy", apply_forwarding_policy);
    add!("decide_upgrade", decide_upgrade);
    add!("classify_telemetry_outcome", classify_telemetry_outcome);
    inventory
}

fn initialize_polyform(config: &Config) -> io::Result<Option<RuntimePolyform>> {
    let Some(settings) = &config.polyform else {
        return Ok(None);
    };
    let attempt = || -> std::result::Result<RuntimePolyform, polyform_runtime::RuntimeError> {
        let trust = ReleaseTrust::from_file(&settings.trust_file)?;
        let state_path = Path::new(&settings.state_file);
        if let Some(parent) = state_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| polyform_runtime::RuntimeError::State(error.to_string()))?;
        }
        let client = PolyformClient::register(
            &settings.base_url,
            settings.installation_id.as_deref(),
            &settings.strategy,
            trust,
            implementation_inventory(),
            state_path,
        )?;
        Ok(RuntimePolyform {
            client: Mutex::new(client),
            refresh_interval: Duration::from_secs(settings.refresh_interval_seconds),
            report_telemetry: settings.report_telemetry,
        })
    };
    match attempt() {
        Ok(runtime) => {
            log_json(json!({"event":"polyform_registered","status":"active"}));
            Ok(Some(runtime))
        }
        Err(error) if settings.required => Err(io::Error::other(format!(
            "required Polyform runtime registration failed: {error}"
        ))),
        Err(_) => {
            log_json(
                json!({"event":"polyform_registration","status":"unavailable","fallback":"local_agreement"}),
            );
            Ok(None)
        }
    }
}

fn refresh_polyform(runtime: &Runtime) {
    let Some(polyform) = &runtime.polyform else {
        return;
    };
    let mut client = polyform.client.lock().expect("runtime lock poisoned");
    match client.refresh() {
        Ok(changed) => {
            if changed {
                runtime.agreement.update_primary(
                    client
                        .composition
                        .implementations
                        .clone()
                        .into_iter()
                        .collect(),
                );
            }
            log_json(
                json!({"event":"polyform_refresh","status":"ok","composition_changed":changed}),
            );
        }
        Err(_) => log_json(
            json!({"event":"polyform_refresh","status":"failed","composition_retained":true}),
        ),
    }
}

fn report_polyform(
    runtime: &Runtime,
    success: bool,
    duration_ms: f64,
    outcome: &str,
    calls: &[CallTelemetry],
) {
    let Some(polyform) = &runtime.polyform else {
        return;
    };
    if !polyform.report_telemetry {
        return;
    }
    let client = polyform.client.lock().expect("runtime lock poisoned");
    let active_calls = active_composition_calls(calls, &client.composition.implementations);
    if client
        .report_execution(
            "proxy_request",
            success,
            duration_ms,
            (!success).then_some(outcome),
            &active_calls,
        )
        .is_err()
    {
        log_json(json!({"event":"polyform_telemetry","status":"failed"}));
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    peer: SocketAddr,
    runtime: &Runtime,
) -> std::result::Result<(), Fault> {
    let result = process_request(stream, peer, runtime);
    if let Err(fault) = &result {
        let (status, reason) = fault.status();
        let _ = write_simple_response(stream, status, reason, b"request rejected\n", &[]);
    }
    let _ = stream.shutdown(Shutdown::Both);
    result
}

fn process_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    runtime: &Runtime,
) -> std::result::Result<(), Fault> {
    stream
        .set_read_timeout(Some(Duration::from_millis(
            runtime.config.listener.request_header_timeout_ms,
        )))
        .map_err(|_| Fault::ClientIo)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(
            runtime.config.listener.upstream_response_timeout_ms,
        )))
        .map_err(|_| Fault::ClientIo)?;
    let (head, remainder) = read_head(stream, MAX_REQUEST_LINE_BYTES + MAX_REQUEST_HEADER_BYTES)?;
    let request = runtime
        .agreement
        .run("parse_request_line", |implementation| {
            implementation
                .parse_request_line
                .map(|function| function(&head))
        })?;
    if request.bytes_consumed > head.len() {
        return Err(Fault::Internal);
    }
    let header_bytes = &head[request.bytes_consumed..];
    let headers = runtime
        .agreement
        .run("parse_header_section", |implementation| {
            implementation
                .parse_header_section
                .map(|function| function(header_bytes))
        })?;
    if request.bytes_consumed + headers.bytes_consumed != head.len() {
        return Err(Fault::Protocol(PolyguardError::InvalidHeader {
            index: 0,
            reason: "trailing_bytes".into(),
        }));
    }
    if has_header(&headers, "expect") {
        return Err(Fault::Protocol(PolyguardError::UnsupportedUpgrade));
    }
    let framing = runtime
        .agreement
        .run("determine_body_framing", |implementation| {
            implementation
                .determine_body_framing
                .map(|function| function(&request, &headers))
        })?;
    let target = runtime
        .agreement
        .run("normalize_request_target", |implementation| {
            implementation
                .normalize_request_target
                .map(|function| function(&request))
        })?;
    let authority = runtime
        .agreement
        .run("reconcile_authority", |implementation| {
            implementation
                .reconcile_authority
                .map(|function| function(&target, &headers))
        })?;
    let sanitized = runtime
        .agreement
        .run("remove_hop_by_hop_headers", |implementation| {
            implementation
                .remove_hop_by_hop_headers
                .map(|function| function(&headers))
        })?;
    let upgrade = runtime.agreement.run("decide_upgrade", |implementation| {
        implementation
            .decide_upgrade
            .map(|function| function(&request, &headers, &framing))
    })?;
    if upgrade != UpgradeDecision::None {
        return Err(Fault::Protocol(PolyguardError::UnsupportedUpgrade));
    }

    if let Some(admin) = admin_response(&target.routing_path, runtime) {
        return write_simple_response(stream, admin.0, admin.1, &admin.2, &[])
            .map_err(|_| Fault::ClientIo);
    }
    let route = runtime.agreement.run("match_route", |implementation| {
        implementation
            .match_route
            .map(|function| function(&authority, &target, &runtime.routes))
    })?;
    let upstream_address = *runtime
        .upstreams
        .get(&route.upstream)
        .ok_or(Fault::Internal)?;
    let authority_text = authority_string(&authority);
    let forwarding_policy = ForwardingPolicy {
        trust_incoming: runtime.config.listener.trust_forwarding_headers,
        client_ip: peer.ip().to_string(),
        proto: "http".into(),
        host: authority_text,
    };
    let forwarding = runtime
        .agreement
        .run("apply_forwarding_policy", |implementation| {
            implementation
                .apply_forwarding_policy
                .map(|function| function(&forwarding_policy, &headers))
        })?;
    stream
        .set_read_timeout(Some(Duration::from_millis(
            runtime.config.listener.request_body_timeout_ms,
        )))
        .map_err(|_| Fault::ClientIo)?;
    let mut input = BufferedInput::new(stream, remainder);
    let body = read_request_body(&mut input, &framing, &headers, runtime)?;
    if input.has_immediate_extra()? {
        return Err(Fault::Protocol(PolyguardError::AmbiguousFraming));
    }
    let upstream_framing = if body.is_empty() {
        BodyFraming::None
    } else {
        BodyFraming::ContentLength(body.len() as u64)
    };
    let canonical =
        runtime
            .agreement
            .run("construct_canonical_upstream_head", |implementation| {
                implementation
                    .construct_canonical_upstream_head
                    .map(|function| {
                        function(
                            &request.method,
                            &target,
                            &authority,
                            &sanitized,
                            &upstream_framing,
                            &forwarding,
                        )
                    })
            })?;
    let response = exchange_upstream(
        upstream_address,
        &canonical.bytes,
        &body,
        &request.method,
        runtime,
    )?;
    stream.write_all(&response).map_err(|_| Fault::ClientIo)?;
    Ok(())
}

fn has_header(headers: &HeaderBlock, name: &str) -> bool {
    headers.fields.iter().any(|field| field.name == name)
}

fn authority_string(authority: &EffectiveAuthority) -> String {
    match authority.port {
        Some(port) => format!("{}:{port}", authority.host),
        None => authority.host.clone(),
    }
}

fn read_request_body(
    input: &mut BufferedInput<'_>,
    framing: &BodyFraming,
    headers: &HeaderBlock,
    runtime: &Runtime,
) -> std::result::Result<Vec<u8>, Fault> {
    match framing {
        BodyFraming::None => Ok(Vec::new()),
        BodyFraming::ContentLength(length) => {
            let length = usize::try_from(*length).map_err(|_| Fault::TooLarge)?;
            if length > runtime.config.limits.max_request_body_bytes {
                return Err(Fault::TooLarge);
            }
            input.read_exact_vec(length)
        }
        BodyFraming::Chunked => read_chunked(
            input,
            headers,
            runtime.config.limits.max_request_body_bytes,
            &runtime.agreement,
        ),
    }
}

fn read_chunked(
    input: &mut BufferedInput<'_>,
    headers: &HeaderBlock,
    max: usize,
    agreement: &Agreement,
) -> std::result::Result<Vec<u8>, Fault> {
    let mut decoded = Vec::new();
    loop {
        let line = input.read_line(4_096)?;
        let metadata = agreement.run("parse_chunk_metadata", |implementation| {
            implementation
                .parse_chunk_metadata
                .map(|function| function(&line))
        })?;
        if metadata.bytes_consumed != line.len() {
            return Err(Fault::Protocol(PolyguardError::InvalidChunk {
                reason: "trailing_bytes".into(),
            }));
        }
        let size = usize::try_from(metadata.size).map_err(|_| Fault::TooLarge)?;
        if decoded
            .len()
            .checked_add(size)
            .filter(|total| *total <= max)
            .is_none()
        {
            return Err(Fault::TooLarge);
        }
        if size == 0 {
            let trailers_wire = input.read_trailers(MAX_TRAILER_BYTES)?;
            let declared = declared_trailers(headers)?;
            let trailers: TrailerBlock =
                agreement.run("parse_trailer_section", |implementation| {
                    implementation
                        .parse_trailer_section
                        .map(|function| function(&trailers_wire, &declared))
                })?;
            if trailers.bytes_consumed != trailers_wire.len() {
                return Err(Fault::Protocol(PolyguardError::InvalidTrailer {
                    reason: "trailing_bytes".into(),
                }));
            }
            return Ok(decoded);
        }
        decoded.extend_from_slice(&input.read_exact_vec(size)?);
        if input.read_exact_vec(2)? != b"\r\n" {
            return Err(Fault::Protocol(PolyguardError::InvalidChunk {
                reason: "invalid_terminator".into(),
            }));
        }
    }
}

fn declared_trailers(headers: &HeaderBlock) -> std::result::Result<Vec<String>, Fault> {
    let mut result = Vec::new();
    for field in headers
        .fields
        .iter()
        .filter(|field| field.name == "trailer")
    {
        let value = std::str::from_utf8(&field.value).map_err(|_| {
            Fault::Protocol(PolyguardError::InvalidTrailer {
                reason: "invalid_declaration".into(),
            })
        })?;
        for part in value.split(',') {
            let name = part.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(Fault::Protocol(PolyguardError::InvalidTrailer {
                    reason: "invalid_declaration".into(),
                }));
            }
            result.push(name);
        }
    }
    Ok(result)
}

struct BufferedInput<'a> {
    stream: &'a mut TcpStream,
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a> BufferedInput<'a> {
    fn new(stream: &'a mut TcpStream, buffer: Vec<u8>) -> Self {
        Self {
            stream,
            buffer,
            offset: 0,
        }
    }
    fn buffered_len(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    fn has_immediate_extra(&mut self) -> std::result::Result<bool, Fault> {
        if self.buffered_len() != 0 {
            return Ok(true);
        }
        self.stream
            .set_nonblocking(true)
            .map_err(|_| Fault::ClientIo)?;
        let mut byte = [0_u8; 1];
        let result = match self.stream.peek(&mut byte) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
            Err(_) => Err(Fault::ClientIo),
        };
        self.stream
            .set_nonblocking(false)
            .map_err(|_| Fault::ClientIo)?;
        result
    }
    fn read_byte(&mut self) -> std::result::Result<u8, Fault> {
        if self.offset < self.buffer.len() {
            let byte = self.buffer[self.offset];
            self.offset += 1;
            return Ok(byte);
        }
        self.buffer.clear();
        self.offset = 0;
        let mut byte = [0_u8; 1];
        self.stream.read_exact(&mut byte).map_err(map_client_io)?;
        Ok(byte[0])
    }
    fn read_exact_vec(&mut self, length: usize) -> std::result::Result<Vec<u8>, Fault> {
        let mut output = Vec::with_capacity(length);
        let available = self.buffered_len().min(length);
        output.extend_from_slice(&self.buffer[self.offset..self.offset + available]);
        self.offset += available;
        output.resize(length, 0);
        if available < length {
            self.stream
                .read_exact(&mut output[available..])
                .map_err(map_client_io)?;
        }
        Ok(output)
    }
    fn read_line(&mut self, max: usize) -> std::result::Result<Vec<u8>, Fault> {
        let mut output = Vec::new();
        while output.len() <= max {
            output.push(self.read_byte()?);
            if output.ends_with(b"\r\n") {
                return Ok(output);
            }
        }
        Err(Fault::TooLarge)
    }
    fn read_trailers(&mut self, max: usize) -> std::result::Result<Vec<u8>, Fault> {
        let mut output = Vec::new();
        loop {
            let line = self.read_line(max.saturating_sub(output.len()))?;
            let empty = line == b"\r\n";
            output.extend_from_slice(&line);
            if output.len() > max {
                return Err(Fault::TooLarge);
            }
            if empty {
                return Ok(output);
            }
        }
    }

    fn read_to_eof_bounded(self, max: usize) -> std::result::Result<Vec<u8>, Fault> {
        let mut output = self.buffer[self.offset..].to_vec();
        let mut scratch = [0_u8; 16_384];
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => return Ok(output),
                Ok(count) => {
                    if output
                        .len()
                        .checked_add(count)
                        .filter(|value| *value <= max)
                        .is_none()
                    {
                        return Err(Fault::Upstream);
                    }
                    output.extend_from_slice(&scratch[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(Fault::Timeout);
                }
                Err(_) => return Err(Fault::Upstream),
            }
        }
    }
}

fn read_head(stream: &mut TcpStream, max: usize) -> std::result::Result<(Vec<u8>, Vec<u8>), Fault> {
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 2_048];
    loop {
        let count = stream.read(&mut scratch).map_err(map_client_io)?;
        if count == 0 {
            return Err(Fault::ClientIo);
        }
        bytes.extend_from_slice(&scratch[..count]);
        if let Some(end) = find_sequence(&bytes, b"\r\n\r\n") {
            if end + 4 > max {
                return Err(Fault::TooLarge);
            }
            let remainder = bytes.split_off(end + 4);
            return Ok((bytes, remainder));
        }
        if bytes.len() > max {
            return Err(Fault::TooLarge);
        }
    }
}

fn exchange_upstream(
    address: SocketAddr,
    request_head: &[u8],
    body: &[u8],
    method: &str,
    runtime: &Runtime,
) -> std::result::Result<Vec<u8>, Fault> {
    let mut upstream = TcpStream::connect_timeout(
        &address,
        Duration::from_millis(runtime.config.listener.upstream_connect_timeout_ms),
    )
    .map_err(|_| Fault::Upstream)?;
    upstream
        .set_read_timeout(Some(Duration::from_millis(
            runtime.config.listener.upstream_response_timeout_ms,
        )))
        .map_err(|_| Fault::Upstream)?;
    upstream
        .set_write_timeout(Some(Duration::from_millis(
            runtime.config.listener.upstream_response_timeout_ms,
        )))
        .map_err(|_| Fault::Upstream)?;
    upstream
        .write_all(request_head)
        .and_then(|_| upstream.write_all(body))
        .map_err(|_| Fault::Upstream)?;
    upstream
        .shutdown(Shutdown::Write)
        .map_err(|_| Fault::Upstream)?;
    let (head, remainder) = read_upstream_head(
        &mut upstream,
        runtime.config.limits.max_response_header_bytes,
    )?;
    let (status, reason, offset) = parse_status_line(&head)?;
    let header_wire = &head[offset..];
    let headers = runtime
        .agreement
        .run("parse_header_section", |implementation| {
            implementation
                .parse_header_section
                .map(|function| function(header_wire))
        })?;
    if headers.bytes_consumed != header_wire.len() {
        return Err(Fault::Upstream);
    }
    let sanitized = runtime
        .agreement
        .run("remove_hop_by_hop_headers", |implementation| {
            implementation
                .remove_hop_by_hop_headers
                .map(|function| function(&headers))
        })?;
    let no_body =
        method == "head" || (100..200).contains(&status) || status == 204 || status == 304;
    let framing = response_framing(&headers, no_body)?;
    let mut input = BufferedInput::new(&mut upstream, remainder);
    let response_body = match framing {
        ResponseFraming::None => Vec::new(),
        ResponseFraming::Length(length) => {
            if length > runtime.config.limits.max_response_body_bytes {
                return Err(Fault::Upstream);
            }
            input.read_exact_vec(length).map_err(map_upstream_fault)?
        }
        ResponseFraming::Chunked => read_chunked(
            &mut input,
            &headers,
            runtime.config.limits.max_response_body_bytes,
            &runtime.agreement,
        )
        .map_err(map_upstream_fault)?,
        ResponseFraming::Close => {
            input.read_to_eof_bounded(runtime.config.limits.max_response_body_bytes)?
        }
    };
    serialize_response(status, reason, &sanitized, &response_body)
}

enum ResponseFraming {
    None,
    Length(usize),
    Chunked,
    Close,
}

fn response_framing(
    headers: &HeaderBlock,
    no_body: bool,
) -> std::result::Result<ResponseFraming, Fault> {
    if no_body {
        return Ok(ResponseFraming::None);
    }
    let transfer: Vec<_> = headers
        .fields
        .iter()
        .filter(|field| field.name == "transfer-encoding")
        .collect();
    let lengths: Vec<_> = headers
        .fields
        .iter()
        .filter(|field| field.name == "content-length")
        .collect();
    if !transfer.is_empty() && !lengths.is_empty() {
        return Err(Fault::Upstream);
    }
    if !transfer.is_empty() {
        if transfer.len() != 1 || !transfer[0].value.eq_ignore_ascii_case(b"chunked") {
            return Err(Fault::Upstream);
        }
        return Ok(ResponseFraming::Chunked);
    }
    if !lengths.is_empty() {
        let first = parse_decimal(&lengths[0].value).ok_or(Fault::Upstream)?;
        if lengths
            .iter()
            .any(|field| parse_decimal(&field.value) != Some(first))
        {
            return Err(Fault::Upstream);
        }
        return Ok(ResponseFraming::Length(first));
    }
    Ok(ResponseFraming::Close)
}

fn parse_decimal(value: &[u8]) -> Option<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0_usize, |total, byte| {
        total.checked_mul(10)?.checked_add(usize::from(byte - b'0'))
    })
}

fn read_upstream_head(
    stream: &mut TcpStream,
    max: usize,
) -> std::result::Result<(Vec<u8>, Vec<u8>), Fault> {
    read_head(stream, max).map_err(map_upstream_fault)
}

fn map_upstream_fault(fault: Fault) -> Fault {
    match fault {
        Fault::Timeout => Fault::UpstreamTimeout,
        Fault::UpstreamTimeout => Fault::UpstreamTimeout,
        _ => Fault::Upstream,
    }
}

fn parse_status_line(head: &[u8]) -> std::result::Result<(u16, &str, usize), Fault> {
    let end = find_sequence(head, b"\r\n").ok_or(Fault::Upstream)?;
    let line = std::str::from_utf8(&head[..end]).map_err(|_| Fault::Upstream)?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(Fault::Upstream)?;
    let code = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(Fault::Upstream)?;
    let reason = parts.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !(100..=599).contains(&code)
        || !reason
            .bytes()
            .all(|byte| matches!(byte, b'\t' | b' '..=b'~'))
    {
        return Err(Fault::Upstream);
    }
    Ok((code, reason, end + 2))
}

fn serialize_response(
    status: u16,
    reason: &str,
    headers: &SanitizedHeaders,
    body: &[u8],
) -> std::result::Result<Vec<u8>, Fault> {
    let mut output = Vec::new();
    write!(&mut output, "HTTP/1.1 {status} {reason}\r\n").map_err(|_| Fault::Internal)?;
    output.extend_from_slice(SERVER_HEADER);
    for field in &headers.fields {
        if matches!(
            field.name.as_str(),
            "content-length" | "transfer-encoding" | "server"
        ) {
            continue;
        }
        output.extend_from_slice(field.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(&field.value);
        output.extend_from_slice(b"\r\n");
    }
    write!(
        &mut output,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|_| Fault::Internal)?;
    output.extend_from_slice(body);
    Ok(output)
}

fn admin_response(path: &str, runtime: &Runtime) -> Option<(u16, &'static str, Vec<u8>)> {
    match path {
        "/_polyguard/health" => Some((200, "OK", b"ok\n".to_vec())),
        "/_polyguard/ready" => Some((200, "OK", b"ready\n".to_vec())),
        "/_polyguard/metrics" => Some((200, "OK", format!(
            "# TYPE polyguard_requests_total counter\npolyguard_requests_total{{outcome=\"accepted\"}} {}\npolyguard_requests_total{{outcome=\"rejected\"}} {}\npolyguard_disagreements_total {}\npolyguard_upstream_failures_total {}\npolyguard_timeouts_total {}\npolyguard_active_connections {}\n",
            runtime.metrics.accepted.load(Ordering::Relaxed), runtime.metrics.rejected.load(Ordering::Relaxed),
            runtime.metrics.disagreements.load(Ordering::Relaxed), runtime.metrics.upstream_failures.load(Ordering::Relaxed),
            runtime.metrics.timeouts.load(Ordering::Relaxed), runtime.metrics.active.load(Ordering::Relaxed),
        ).into_bytes())),
        _ => None,
    }
}

fn write_simple_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> io::Result<()> {
    let mut response = Vec::new();
    write!(&mut response, "HTTP/1.1 {status} {reason}\r\n").expect("vec write");
    response.extend_from_slice(SERVER_HEADER);
    for (name, value) in extra {
        write!(&mut response, "{name}: {value}\r\n").expect("vec write");
    }
    write!(&mut response, "content-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).expect("vec write");
    response.extend_from_slice(body);
    stream.write_all(&response)
}

fn classify_outcome(
    agreement: &Agreement,
    code: &str,
    reached: bool,
) -> std::result::Result<OutcomeCategory, Fault> {
    agreement
        .run("classify_telemetry_outcome", |implementation| {
            implementation
                .classify_telemetry_outcome
                .map(|function| function(code, reached))
        })
        .map(|outcome| outcome.category)
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn map_client_io(error: io::Error) -> Fault {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        Fault::Timeout
    } else {
        Fault::ClientIo
    }
}

fn log_json(mut value: serde_json::Value) {
    if let Some(object) = value.as_object_mut() {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        object.insert("timestamp_ms".into(), json!(timestamp_ms));
    }
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, &value);
    let _ = stdout.write_all(b"\n");
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe extern "C" {
        fn signal(signal: i32, handler: usize) -> usize;
    }
    extern "C" fn stop(_: i32) {
        TERMINATE.store(true, Ordering::SeqCst);
    }
    unsafe {
        signal(2, stop as *const () as usize);
        signal(15, stop as *const () as usize);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_framing_rejects_te_and_content_length() {
        let headers = HeaderBlock {
            fields: vec![
                crate::HeaderField {
                    name: "transfer-encoding".into(),
                    value: b"chunked".to_vec(),
                },
                crate::HeaderField {
                    name: "content-length".into(),
                    value: b"1".to_vec(),
                },
            ],
            bytes_consumed: 0,
        };
        assert!(matches!(
            response_framing(&headers, false),
            Err(Fault::Upstream)
        ));
    }

    #[test]
    fn decimal_parser_is_checked_and_strict() {
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"001"), Some(1));
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"1x"), None);
    }

    #[test]
    fn server_composition_is_primary_without_reducing_agreement_width() {
        let mut primary = BTreeMap::new();
        primary.insert(
            "parse_request_line".into(),
            "request-line-reverse-offsets".into(),
        );
        let quarantined = BTreeSet::new();
        let agreement = Agreement::new(3, &quarantined, primary);
        let selected = agreement.selected_ids();
        assert_eq!(selected["parse_request_line"].len(), 3);
        assert_eq!(
            selected["parse_request_line"][0],
            "request-line-reverse-offsets"
        );

        begin_trace();
        agreement
            .run("parse_request_line", |implementation| {
                implementation
                    .parse_request_line
                    .map(|function| function(b"GET / HTTP/1.1\r\n"))
            })
            .unwrap();
        let calls = take_trace();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].implementation_id, "request-line-reverse-offsets");
        let telemetry = serde_json::to_string(&calls).unwrap();
        assert!(!telemetry.contains("GET /"));
    }

    #[test]
    fn hosted_telemetry_uses_the_server_call_outcome_vocabulary() {
        assert_eq!(telemetry_call_outcome(true), "ok");
        assert_eq!(telemetry_call_outcome(false), "error");

        begin_trace();
        trace_call("parse_request_line", "request-line-state-pipeline", "ok");
        mark_trace_disagreement("parse_request_line");
        let calls = take_trace();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].outcome, "error");
        assert!(["ok", "error", "timeout", "panic"].contains(&calls[0].outcome.as_str()));
    }

    #[test]
    fn hosted_telemetry_reports_only_invoked_active_composition_members() {
        let calls = vec![
            CallTelemetry::new("parse_request_line", "request-line-state-pipeline", "ok"),
            CallTelemetry::new("parse_request_line", "request-line-direct-guards", "ok"),
            CallTelemetry::new("match_route", "route-direct-domain", "error"),
        ];
        let active = HashMap::from([
            (
                "parse_request_line".into(),
                "request-line-state-pipeline".into(),
            ),
            ("match_route".into(), "route-direct-domain".into()),
        ]);
        let selected = active_composition_calls(&calls, &active);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].implementation_id, "request-line-state-pipeline");
        assert_eq!(selected[1].implementation_id, "route-direct-domain");
        assert_eq!(selected[1].outcome, "error");
    }
}
