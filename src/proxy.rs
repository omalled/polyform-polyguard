//! Bounded, fail-closed HTTP/1.1 reverse-proxy runtime.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};

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
const MAX_HEADER_VALUE_BYTES: usize = 8_192;
const MAX_TRAILER_BYTES: usize = 8_192;
const MAX_CONFIGURED_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIGURED_RESPONSE_HEADER_BYTES: usize = 1024 * 1024;
const MAX_CONFIGURED_RESPONSE_BODY_BYTES: usize = 1024 * 1024 * 1024;
const MAX_CONFIGURED_INFLIGHT_BODY_BYTES: usize = 1024 * 1024 * 1024;
const SERVER_HEADER: &[u8] =
    concat!("server: polyguard/", env!("CARGO_PKG_VERSION"), "\r\n").as_bytes();

static TERMINATE: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listener: ListenerConfig,
    #[serde(default)]
    pub listeners: Vec<AdditionalListenerConfig>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub compression: CompressionConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub polyform: Option<PolyformConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub address: String,
    #[serde(default)]
    pub management_address: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub certificate_chain_file: String,
    #[serde(default)]
    pub private_key_file: String,
    #[serde(default)]
    pub certificates: Vec<TlsCertificateConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCertificateConfig {
    pub server_names: Vec<String>,
    pub certificate_chain_file: String,
    pub private_key_file: String,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdditionalListenerConfig {
    pub address: String,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub host: String,
    pub path_prefix: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    #[serde(default)]
    pub default: bool,
    pub server_names: Vec<String>,
    pub routes: Vec<ActionRouteConfig>,
    #[serde(default)]
    pub response_headers: Vec<HeaderValueConfig>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRouteConfig {
    pub path: String,
    #[serde(default, rename = "match")]
    pub match_kind: RouteMatchKind,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
    #[serde(default)]
    pub request_headers: Vec<HeaderValueConfig>,
    #[serde(default)]
    pub response_headers: Vec<HeaderValueConfig>,
    #[serde(default)]
    pub deny: Vec<String>,
    pub action: RouteActionConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMatchKind {
    Exact,
    #[default]
    Prefix,
    BoundaryPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteActionConfig {
    Proxy {
        upstream: String,
        #[serde(default)]
        replace_prefix: Option<String>,
        #[serde(default)]
        host_header: Option<String>,
    },
    Redirect {
        status: u16,
        location: String,
    },
    Respond {
        status: u16,
        #[serde(default)]
        body: String,
        #[serde(default = "default_text_content_type")]
        content_type: String,
    },
    Static {
        directory: String,
        #[serde(default)]
        mapping: StaticMapping,
        #[serde(default = "default_indexes")]
        index: Vec<String>,
        #[serde(default = "default_true")]
        try_files: bool,
        #[serde(default)]
        error_page_404: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticMapping {
    #[default]
    Root,
    Alias,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderValueConfig {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub always: bool,
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_request_body_bytes: usize,
    pub max_response_header_bytes: usize,
    pub max_response_body_bytes: usize,
    pub max_inflight_body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub min_size_bytes: usize,
    pub types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_size_bytes: 1_024,
            types: vec![
                "text/plain".into(),
                "text/css".into(),
                "text/html".into(),
                "application/javascript".into(),
                "application/json".into(),
                "application/xml".into(),
                "image/svg+xml".into(),
            ],
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 16 * 1024 * 1024,
            max_response_header_bytes: 32 * 1024,
            max_response_body_bytes: 64 * 1024 * 1024,
            max_inflight_body_bytes: 128 * 1024 * 1024,
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
    128
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
fn default_text_content_type() -> String {
    "text/plain; charset=utf-8".into()
}
fn default_indexes() -> Vec<String> {
    vec!["index.html".into()]
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
    validate_config_files(&config)?;
    Ok(config)
}

pub fn validate_config_files(config: &Config) -> std::result::Result<(), ConfigError> {
    validate_config(config)?;
    for (label, tls) in configured_tls(config) {
        load_tls_config(tls).map_err(|error| {
            ConfigError::Invalid(format!(
                "{label} certificate/key validation failed: {error}"
            ))
        })?;
    }
    Ok(())
}

fn configured_tls(config: &Config) -> Vec<(String, Option<&TlsConfig>)> {
    let mut settings = Vec::new();
    if config.listener.tls.is_some() {
        settings.push(("listener.tls".into(), config.listener.tls.as_ref()));
    }
    settings.extend(
        config
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, listener)| listener.tls.is_some())
            .map(|(index, listener)| (format!("listeners[{index}].tls"), listener.tls.as_ref())),
    );
    settings
}

fn validate_tls_settings(
    label: &str,
    settings: Option<&TlsConfig>,
) -> std::result::Result<(), ConfigError> {
    let Some(settings) = settings else {
        return Ok(());
    };
    let has_chain = !settings.certificate_chain_file.trim().is_empty();
    let has_key = !settings.private_key_file.trim().is_empty();
    if has_chain != has_key {
        return Err(ConfigError::Invalid(format!(
            "{label} legacy certificate and private-key paths must be provided together"
        )));
    }
    if has_chain && settings.certificate_chain_file == settings.private_key_file {
        return Err(ConfigError::Invalid(format!(
            "{label} certificate and private key must be separate files"
        )));
    }
    if !has_chain && settings.certificates.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{label} must configure a certificate/key pair or named certificates"
        )));
    }
    if settings.certificates.len() > 256 {
        return Err(ConfigError::Invalid(format!(
            "{label} supports at most 256 named certificates"
        )));
    }
    let mut names = BTreeSet::new();
    let mut defaults = usize::from(has_chain);
    for (index, certificate) in settings.certificates.iter().enumerate() {
        if certificate.certificate_chain_file.trim().is_empty()
            || certificate.private_key_file.trim().is_empty()
        {
            return Err(ConfigError::Invalid(format!(
                "{label}.certificates[{index}] certificate and private-key paths must not be empty"
            )));
        }
        if certificate.certificate_chain_file == certificate.private_key_file {
            return Err(ConfigError::Invalid(format!(
                "{label}.certificates[{index}] certificate and private key must be separate files"
            )));
        }
        if certificate.server_names.is_empty() && !certificate.default {
            return Err(ConfigError::Invalid(format!(
                "{label}.certificates[{index}] must declare at least one server name"
            )));
        }
        for name in &certificate.server_names {
            if !valid_sni_pattern(name) {
                return Err(ConfigError::Invalid(format!(
                    "{label}.certificates[{index}] has invalid server name {name}"
                )));
            }
            if !names.insert(name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "{label} assigns server name {name} more than once"
                )));
            }
        }
        if certificate.default {
            defaults += 1;
        }
    }
    if defaults > 1 {
        return Err(ConfigError::Invalid(format!(
            "{label} configures more than one default certificate"
        )));
    }
    Ok(())
}

fn valid_sni_pattern(value: &str) -> bool {
    let host = value.strip_prefix("*.").unwrap_or(value);
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.is_ascii()
        && host.split('.').count() >= 2
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_method(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|byte| {
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
        })
}

fn valid_header_name(value: &str) -> bool {
    valid_method(value) && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn valid_template(value: &str) -> bool {
    if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return false;
    }
    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'$' {
            offset += 1;
            continue;
        }
        let start = offset;
        offset += 1;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
        {
            offset += 1;
        }
        let variable = &value[start..offset];
        if !matches!(
            variable,
            "$host"
                | "$http_host"
                | "$remote_addr"
                | "$scheme"
                | "$request_uri"
                | "$proxy_add_x_forwarded_for"
        ) {
            return false;
        }
    }
    true
}

fn valid_config_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_LINE_BYTES
        && value.starts_with('/')
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!'..=b'~') && !matches!(byte, b'?' | b'#' | b'\\'))
}

fn validate_header_values(
    label: &str,
    headers: &[HeaderValueConfig],
    response: bool,
) -> std::result::Result<(), ConfigError> {
    let mut names = BTreeSet::new();
    for (index, header) in headers.iter().enumerate() {
        if !valid_header_name(&header.name) {
            return Err(ConfigError::Invalid(format!(
                "{label}[{index}].name must be a lowercase HTTP field name"
            )));
        }
        let prohibited = if response {
            matches!(
                header.name.as_str(),
                "connection" | "content-length" | "server" | "transfer-encoding"
            )
        } else {
            matches!(
                header.name.as_str(),
                "connection"
                    | "content-length"
                    | "forwarded"
                    | "host"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "x-forwarded-for"
                    | "x-forwarded-host"
                    | "x-forwarded-proto"
            )
        };
        if prohibited {
            return Err(ConfigError::Invalid(format!(
                "{label}[{index}] cannot configure security-managed header {}",
                header.name
            )));
        }
        if !names.insert(header.name.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "{label} configures header {} more than once",
                header.name
            )));
        }
        if header.value.len() > MAX_HEADER_VALUE_BYTES || !valid_template(&header.value) {
            return Err(ConfigError::Invalid(format!(
                "{label}[{index}].value contains an unsafe value or unsupported variable"
            )));
        }
        for method in &header.methods {
            if !valid_method(method) {
                return Err(ConfigError::Invalid(format!(
                    "{label}[{index}] has invalid method {method}"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum IpNetwork {
    V4 { address: u32, prefix: u8 },
    V6 { address: u128, prefix: u8 },
}

impl IpNetwork {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        match address.parse::<IpAddr>().ok()? {
            IpAddr::V4(address) => {
                let prefix = match prefix {
                    Some(prefix) => prefix.parse().ok()?,
                    None => 32,
                };
                (prefix <= 32).then_some(Self::V4 {
                    address: u32::from(address),
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                let prefix = match prefix {
                    Some(prefix) => prefix.parse().ok()?,
                    None => 128,
                };
                (prefix <= 128).then_some(Self::V6 {
                    address: u128::from(address),
                    prefix,
                })
            }
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { address, prefix }, IpAddr::V4(candidate)) => {
                let shift = 32 - u32::from(prefix);
                shift == 32 || (address >> shift) == (u32::from(candidate) >> shift)
            }
            (Self::V6 { address, prefix }, IpAddr::V6(candidate)) => {
                let shift = 128 - u32::from(prefix);
                shift == 128 || (address >> shift) == (u128::from(candidate) >> shift)
            }
            _ => false,
        }
    }
}

pub fn validate_config(config: &Config) -> std::result::Result<(), ConfigError> {
    let listener_address = SocketAddr::from_str(&config.listener.address).map_err(|_| {
        ConfigError::Invalid("listener.address must be a literal socket address".into())
    })?;
    let management_address = config
        .listener
        .management_address
        .as_deref()
        .map(SocketAddr::from_str)
        .transpose()
        .map_err(|_| {
            ConfigError::Invalid(
                "listener.management_address must be a literal socket address".into(),
            )
        })?;
    if management_address == Some(listener_address) {
        return Err(ConfigError::Invalid(
            "listener.management_address must differ from the traffic listener".into(),
        ));
    }
    if config.listener.security_mode != "agreement" {
        return Err(ConfigError::Invalid(
            "listener.security_mode must be agreement".into(),
        ));
    }
    validate_tls_settings("listener.tls", config.listener.tls.as_ref())?;
    let mut listener_addresses = BTreeSet::from([listener_address]);
    for (index, listener) in config.listeners.iter().enumerate() {
        let address = SocketAddr::from_str(&listener.address).map_err(|_| {
            ConfigError::Invalid(format!(
                "listeners[{index}].address must be a literal socket address"
            ))
        })?;
        if !listener_addresses.insert(address) {
            return Err(ConfigError::Invalid(format!(
                "listeners[{index}].address duplicates another traffic listener"
            )));
        }
        if management_address == Some(address) {
            return Err(ConfigError::Invalid(format!(
                "listeners[{index}].address must differ from the management listener"
            )));
        }
        validate_tls_settings(&format!("listeners[{index}].tls"), listener.tls.as_ref())?;
    }
    if !(2..=5).contains(&config.listener.agreement_implementations) {
        return Err(ConfigError::Invalid(
            "listener.agreement_implementations must be between 2 and 5".into(),
        ));
    }
    if config.listener.max_connections == 0 || config.listener.max_connections > 1_024 {
        return Err(ConfigError::Invalid(
            "listener.max_connections must be 1..=1024".into(),
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
        || config.limits.max_request_body_bytes > MAX_CONFIGURED_REQUEST_BODY_BYTES
        || config.limits.max_response_header_bytes < 1_024
        || config.limits.max_response_header_bytes > MAX_CONFIGURED_RESPONSE_HEADER_BYTES
        || config.limits.max_response_body_bytes == 0
        || config.limits.max_response_body_bytes > MAX_CONFIGURED_RESPONSE_BODY_BYTES
        || config.limits.max_inflight_body_bytes == 0
        || config.limits.max_inflight_body_bytes > MAX_CONFIGURED_INFLIGHT_BODY_BYTES
    {
        return Err(ConfigError::Invalid(
            "configured limits exceed Polyguard's hard request, response-header, response-body, or aggregate-memory bounds".into(),
        ));
    }
    if config.compression.min_size_bytes > config.limits.max_response_body_bytes
        || config.compression.types.is_empty()
        || config.compression.types.iter().any(|content_type| {
            content_type != "*"
                && (content_type.is_empty()
                || content_type.bytes().any(
                    |byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'/' | b'+' | b'-' | b'.'),
                ))
        })
    {
        return Err(ConfigError::Invalid(
            "compression types and minimum size must be bounded safe media types".into(),
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
    let total_routes = config.routes.len()
        + config
            .sites
            .iter()
            .map(|site| site.routes.len())
            .sum::<usize>();
    if total_routes == 0 || total_routes > 256 {
        return Err(ConfigError::Invalid(
            "configure 1..=256 routes across legacy routes and sites".into(),
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
    let mut site_names = BTreeSet::new();
    for (site_index, site) in config.sites.iter().enumerate() {
        if site.server_names.is_empty() && !site.default {
            return Err(ConfigError::Invalid(format!(
                "sites[{site_index}] must declare at least one server name"
            )));
        }
        for name in &site.server_names {
            if !valid_sni_pattern(name) {
                return Err(ConfigError::Invalid(format!(
                    "sites[{site_index}] has invalid server name {name}"
                )));
            }
            if !site_names.insert(name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "server name {name} is assigned to more than one site"
                )));
            }
        }
        if site.routes.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "sites[{site_index}] must configure at least one route"
            )));
        }
        validate_header_values(
            &format!("sites[{site_index}].response_headers"),
            &site.response_headers,
            true,
        )?;
        for (deny_index, network) in site.deny.iter().enumerate() {
            if IpNetwork::parse(network).is_none() {
                return Err(ConfigError::Invalid(format!(
                    "sites[{site_index}].deny[{deny_index}] is not an IP address or CIDR"
                )));
            }
        }
        for (route_index, route) in site.routes.iter().enumerate() {
            let label = format!("sites[{site_index}].routes[{route_index}]");
            if !valid_config_path(&route.path) {
                return Err(ConfigError::Invalid(format!(
                    "{label}.path must be a bounded normalized absolute path"
                )));
            }
            if route.max_request_body_bytes.is_some_and(|limit| {
                limit == 0
                    || limit > config.limits.max_request_body_bytes
                    || limit > config.limits.max_inflight_body_bytes
            }) {
                return Err(ConfigError::Invalid(format!(
                    "{label}.max_request_body_bytes must be positive and no greater than the global request and in-flight body limits"
                )));
            }
            for method in &route.methods {
                if !valid_method(method) {
                    return Err(ConfigError::Invalid(format!(
                        "{label} has invalid method {method}"
                    )));
                }
            }
            if route
                .schemes
                .iter()
                .any(|scheme| !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https"))
            {
                return Err(ConfigError::Invalid(format!(
                    "{label}.schemes may contain only http or https"
                )));
            }
            validate_header_values(
                &format!("{label}.request_headers"),
                &route.request_headers,
                false,
            )?;
            validate_header_values(
                &format!("{label}.response_headers"),
                &route.response_headers,
                true,
            )?;
            for (deny_index, network) in route.deny.iter().enumerate() {
                if IpNetwork::parse(network).is_none() {
                    return Err(ConfigError::Invalid(format!(
                        "{label}.deny[{deny_index}] is not an IP address or CIDR"
                    )));
                }
            }
            match &route.action {
                RouteActionConfig::Proxy {
                    upstream,
                    replace_prefix,
                    host_header,
                } => {
                    if !upstreams.contains(upstream.as_str()) {
                        return Err(ConfigError::Invalid(format!(
                            "{label} references unknown upstream {upstream}"
                        )));
                    }
                    if replace_prefix
                        .as_deref()
                        .is_some_and(|replacement| !valid_config_path(replacement))
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action.replace_prefix must be a normalized absolute path"
                        )));
                    }
                    if host_header
                        .as_deref()
                        .is_some_and(|value| !matches!(value, "$host" | "$http_host"))
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action.host_header must be $host or $http_host"
                        )));
                    }
                }
                RouteActionConfig::Redirect { status, location } => {
                    if !matches!(status, 301 | 302 | 303 | 307 | 308)
                        || location.len() > MAX_REQUEST_LINE_BYTES
                        || !valid_template(location)
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action must use a supported redirect status and safe location template"
                        )));
                    }
                }
                RouteActionConfig::Respond {
                    status,
                    body,
                    content_type,
                } => {
                    if !(200..=599).contains(status)
                        || body.len() > 1_048_576
                        || content_type.is_empty()
                        || content_type.len() > 1_024
                        || !valid_template(body)
                        || !valid_template(content_type)
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action has an invalid response status, body, or content type"
                        )));
                    }
                }
                RouteActionConfig::Static {
                    directory,
                    index,
                    error_page_404,
                    ..
                } => {
                    let directory = Path::new(directory);
                    if !directory.is_absolute()
                        || !directory.metadata().is_ok_and(|metadata| metadata.is_dir())
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action.directory must be an existing absolute directory"
                        )));
                    }
                    if index.is_empty()
                        || index.iter().any(|name| {
                            name.is_empty()
                                || Path::new(name)
                                    .components()
                                    .any(|component| !matches!(component, Component::Normal(_)))
                        })
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action.index must contain safe relative file names"
                        )));
                    }
                    if error_page_404
                        .as_deref()
                        .is_some_and(|path| !valid_config_path(path))
                    {
                        return Err(ConfigError::Invalid(format!(
                            "{label}.action.error_page_404 must be a normalized absolute path"
                        )));
                    }
                }
            }
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
    if let Some(first_route) = config.routes.first() {
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
                            host: first_route.host.clone(),
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
    }
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
    ExpectationFailed,
    Busy,
    Forbidden,
    ClientClosed,
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
            Self::Protocol(_) | Self::ClientIo | Self::TooLarge | Self::ExpectationFailed => {
                "client_syntax"
            }
            Self::ClientClosed => "client_closed",
            Self::Busy => "overloaded",
            Self::Forbidden => "policy_rejected",
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
            Self::ExpectationFailed => (417, "Expectation Failed"),
            Self::Busy => (503, "Service Unavailable"),
            Self::Forbidden => (403, "Forbidden"),
            Self::Upstream => (502, "Bad Gateway"),
            Self::Internal => (500, "Internal Server Error"),
            Self::ClientClosed => (400, "Bad Request"),
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
    telemetry_dropped: AtomicU64,
    active: AtomicUsize,
}

struct MemoryBudget {
    used: AtomicUsize,
    limit: AtomicUsize,
}

impl MemoryBudget {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit),
        })
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> std::result::Result<MemoryPermit, Fault> {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(bytes).ok_or(Fault::Busy)?;
            if next > self.limit.load(Ordering::Acquire) {
                return Err(Fault::Busy);
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(MemoryPermit {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct MemoryPermit {
    budget: Arc<MemoryBudget>,
    bytes: usize,
}

impl MemoryPermit {
    fn grow(&mut self, bytes: usize) -> std::result::Result<(), Fault> {
        let mut additional = self.budget.reserve(bytes)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Fault::Busy)?;
        additional.bytes = 0;
        Ok(())
    }

    fn absorb(&mut self, mut other: MemoryPermit) -> std::result::Result<(), Fault> {
        if !Arc::ptr_eq(&self.budget, &other.budget) {
            return Err(Fault::Internal);
        }
        self.bytes = self.bytes.checked_add(other.bytes).ok_or(Fault::Busy)?;
        other.bytes = 0;
        Ok(())
    }
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct BufferedBody {
    bytes: Vec<u8>,
    _permit: MemoryPermit,
}

enum ClientStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl ClientStream {
    fn new(stream: TcpStream, tls: Option<Arc<ServerConfig>>) -> io::Result<Self> {
        match tls {
            Some(config) => Ok(Self::Tls(Box::new(StreamOwned::new(
                ServerConnection::new(config).map_err(io::Error::other)?,
                stream,
            )))),
            None => Ok(Self::Plain(stream)),
        }
    }

    fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        }
    }

    fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    fn tls_server_name(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.conn.server_name(),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket().set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket().set_write_timeout(timeout)
    }

    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        if let Self::Tls(stream) = self
            && matches!(how, Shutdown::Write | Shutdown::Both)
        {
            stream.conn.send_close_notify();
            stream.flush()?;
        }
        self.socket().shutdown(how)
    }
}

impl Read for ClientStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(output),
            Self::Tls(stream) => stream.read(output),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(input),
            Self::Tls(stream) => stream.write(input),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

#[derive(Debug)]
struct ServerNameResolver {
    exact: BTreeMap<String, Arc<CertifiedKey>>,
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for ServerNameResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = client_hello.server_name() else {
            return self.default.clone();
        };
        let name = name.to_ascii_lowercase();
        if let Some(certificate) = self.exact.get(&name) {
            return Some(Arc::clone(certificate));
        }
        self.wildcard
            .iter()
            .find(|(suffix, _)| {
                name.len() > suffix.len()
                    && name.ends_with(suffix)
                    && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
            })
            .map(|(_, certificate)| Arc::clone(certificate))
            .or_else(|| self.default.clone())
    }
}

fn load_certified_key(
    certificate_file: &str,
    private_key_file: &str,
) -> io::Result<Arc<CertifiedKey>> {
    let certificates = CertificateDer::pem_file_iter(certificate_file)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate chain contained no certificates",
        ));
    }
    let private_key = PrivateKeyDer::from_pem_file(private_key_file)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(certificates, private_key, &provider)
        .map(Arc::new)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn load_tls_config(settings: Option<&TlsConfig>) -> io::Result<Option<Arc<ServerConfig>>> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let mut resolver = ServerNameResolver {
        exact: BTreeMap::new(),
        wildcard: Vec::new(),
        default: None,
    };
    if !settings.certificate_chain_file.is_empty() {
        resolver.default = Some(load_certified_key(
            &settings.certificate_chain_file,
            &settings.private_key_file,
        )?);
    }
    for certificate in &settings.certificates {
        let certified_key = load_certified_key(
            &certificate.certificate_chain_file,
            &certificate.private_key_file,
        )?;
        for name in &certificate.server_names {
            if let Some(suffix) = name.strip_prefix("*.") {
                resolver
                    .wildcard
                    .push((suffix.to_owned(), Arc::clone(&certified_key)));
            } else {
                resolver
                    .exact
                    .insert(name.clone(), Arc::clone(&certified_key));
            }
        }
        if certificate.default {
            resolver.default = Some(certified_key);
        }
    }
    resolver
        .wildcard
        .sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(Arc::new(config)))
}

impl Metrics {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            disagreements: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            telemetry_dropped: AtomicU64::new(0),
            active: AtomicUsize::new(0),
        }
    }
}

struct Runtime {
    config: Config,
    agreement: Agreement,
    upstreams: BTreeMap<String, SocketAddr>,
    routes: Vec<RuntimeRoute>,
    metrics: Arc<Metrics>,
    body_memory: Arc<MemoryBudget>,
    polyform: Option<Arc<RuntimePolyform>>,
}

struct BoundListener {
    address: SocketAddr,
    socket: TcpListener,
}

struct LiveState {
    runtime: Arc<Runtime>,
    tls: BTreeMap<SocketAddr, Option<Arc<ServerConfig>>>,
}

#[derive(Debug, Clone)]
struct RuntimeRoute {
    id: String,
    host: String,
    path: String,
    match_kind: RouteMatchKind,
    methods: Vec<String>,
    schemes: Vec<String>,
    max_request_body_bytes: usize,
    request_headers: Vec<HeaderValueConfig>,
    response_headers: Vec<HeaderValueConfig>,
    deny: Vec<IpNetwork>,
    action: RuntimeAction,
    declaration_order: usize,
}

#[derive(Debug, Clone)]
enum RuntimeAction {
    Proxy {
        upstream: String,
        replace_prefix: Option<String>,
        host_header: Option<String>,
    },
    Redirect {
        status: u16,
        location: String,
    },
    Respond {
        status: u16,
        body: String,
        content_type: String,
    },
    Static {
        directory: PathBuf,
        mapping: StaticMapping,
        index: Vec<String>,
        try_files: bool,
        error_page_404: Option<String>,
    },
}

struct RuntimePolyform {
    client: Arc<Mutex<PolyformClient>>,
    refresh_interval: Duration,
    report_telemetry: bool,
    telemetry_tx: SyncSender<TelemetryReport>,
    refresh_in_progress: AtomicBool,
}

struct TelemetryReport {
    success: bool,
    duration_ms: f64,
    outcome: String,
    calls: Vec<CallTelemetry>,
}

type ReloadLoader = Arc<dyn Fn() -> io::Result<Config> + Send + Sync>;

fn load_listener_tls(
    config: &Config,
) -> io::Result<BTreeMap<SocketAddr, Option<Arc<ServerConfig>>>> {
    let mut listeners = BTreeMap::new();
    listeners.insert(
        config.listener.address.parse().expect("validated"),
        load_tls_config(config.listener.tls.as_ref())?,
    );
    for listener in &config.listeners {
        listeners.insert(
            listener.address.parse().expect("validated"),
            load_tls_config(listener.tls.as_ref())?,
        );
    }
    Ok(listeners)
}

fn build_runtime(
    config: Config,
    metrics: Arc<Metrics>,
    body_memory: Arc<MemoryBudget>,
    polyform: Option<Arc<RuntimePolyform>>,
) -> io::Result<Arc<Runtime>> {
    validate_config(&config).map_err(io::Error::other)?;
    let quarantined: BTreeSet<&String> =
        config.listener.quarantined_implementations.iter().collect();
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
    let routes = compile_runtime_routes(&config);
    Ok(Arc::new(Runtime {
        config,
        agreement,
        upstreams,
        routes,
        metrics,
        body_memory,
        polyform,
    }))
}

pub fn run(config: Config) -> io::Result<()> {
    run_inner(config, None)
}

pub fn run_reloading<F>(config: Config, loader: F) -> io::Result<()>
where
    F: Fn() -> io::Result<Config> + Send + Sync + 'static,
{
    run_inner(config, Some(Arc::new(loader)))
}

fn run_inner(config: Config, reload_loader: Option<ReloadLoader>) -> io::Result<()> {
    validate_config(&config).map_err(io::Error::other)?;
    let management_address = config
        .listener
        .management_address
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()
        .expect("validated");
    let metrics = Arc::new(Metrics::new());
    let tls = load_listener_tls(&config)?;
    let body_memory = MemoryBudget::new(config.limits.max_inflight_body_bytes);
    let polyform = initialize_polyform(&config)?;
    let runtime = build_runtime(config, Arc::clone(&metrics), body_memory, polyform)?;
    let live = Arc::new(RwLock::new(LiveState { runtime, tls }));
    install_signal_handlers();
    TERMINATE.store(false, Ordering::SeqCst);
    RELOAD.store(false, Ordering::SeqCst);
    let listener_addresses = live
        .read()
        .expect("live state lock poisoned")
        .tls
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let listeners = listener_addresses
        .into_iter()
        .map(|address| {
            let socket = bind_listener(address)?;
            socket.set_nonblocking(true)?;
            Ok(BoundListener { address, socket })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let management_listener = management_address.map(bind_listener).transpose()?;
    if let Some(listener) = &management_listener {
        listener.set_nonblocking(true)?;
    }
    let bound_addresses: Vec<_> = listeners
        .iter()
        .map(|listener| {
            let state = live.read().expect("live state lock poisoned");
            json!({
                "address": listener.address.to_string(),
                "transport": if state.tls.get(&listener.address).is_some_and(Option::is_some) { "https" } else { "http" }
            })
        })
        .collect();
    let selected = live
        .read()
        .expect("live state lock poisoned")
        .runtime
        .agreement
        .selected_ids();
    log_json(
        json!({"event":"started","listeners":bound_addresses,"security_mode":"agreement","selected":selected}),
    );
    let management_thread = management_listener
        .map(|listener| {
            let live = Arc::clone(&live);
            thread::Builder::new()
                .name("polyguard-management".into())
                .spawn(move || run_management_listener(listener, live))
        })
        .transpose()?;

    let mut next_refresh = live
        .read()
        .expect("live state lock poisoned")
        .runtime
        .polyform
        .as_ref()
        .map(|polyform| Instant::now() + polyform.refresh_interval);
    while !TERMINATE.load(Ordering::SeqCst) {
        if RELOAD.swap(false, Ordering::SeqCst) {
            let reload_result = reload_loader.as_ref().map_or_else(
                || Err(io::Error::other("no reload source configured")),
                |loader| {
                    let new_config = loader()?;
                    validate_config(&new_config).map_err(io::Error::other)?;
                    let new_management = new_config
                        .listener
                        .management_address
                        .as_deref()
                        .map(str::parse::<SocketAddr>)
                        .transpose()
                        .map_err(io::Error::other)?;
                    if new_management != management_address {
                        return Err(io::Error::other(
                            "reload cannot change the management listener",
                        ));
                    }
                    let new_tls = load_listener_tls(&new_config)?;
                    let current_addresses = listeners
                        .iter()
                        .map(|listener| listener.address)
                        .collect::<BTreeSet<_>>();
                    let new_addresses = new_tls.keys().copied().collect::<BTreeSet<_>>();
                    if current_addresses != new_addresses {
                        return Err(io::Error::other(
                            "reload cannot add or remove traffic listener addresses",
                        ));
                    }
                    let body_memory = Arc::clone(
                        &live
                            .read()
                            .expect("live state lock poisoned")
                            .runtime
                            .body_memory,
                    );
                    let polyform = {
                        let state = live.read().expect("live state lock poisoned");
                        if new_config.polyform == state.runtime.config.polyform
                            && state.runtime.polyform.is_some()
                        {
                            state.runtime.polyform.clone()
                        } else {
                            drop(state);
                            initialize_polyform(&new_config)?
                        }
                    };
                    let new_body_limit = new_config.limits.max_inflight_body_bytes;
                    let new_runtime = build_runtime(
                        new_config,
                        Arc::clone(&metrics),
                        Arc::clone(&body_memory),
                        polyform,
                    )?;
                    body_memory.limit.store(new_body_limit, Ordering::Release);
                    *live.write().expect("live state lock poisoned") = LiveState {
                        runtime: new_runtime,
                        tls: new_tls,
                    };
                    Ok(())
                },
            );
            match reload_result {
                Ok(()) => {
                    let state = live.read().expect("live state lock poisoned");
                    next_refresh = state
                        .runtime
                        .polyform
                        .as_ref()
                        .map(|polyform| Instant::now() + polyform.refresh_interval);
                    log_json(json!({"event":"configuration_reload","status":"ok"}));
                }
                Err(_) => log_json(
                    json!({"event":"configuration_reload","status":"failed","previous_generation_retained":true}),
                ),
            }
        }
        if next_refresh.is_some_and(|deadline| Instant::now() >= deadline) {
            let runtime = Arc::clone(&live.read().expect("live state lock poisoned").runtime);
            schedule_polyform_refresh(&runtime);
            next_refresh = runtime
                .polyform
                .as_ref()
                .map(|polyform| Instant::now() + polyform.refresh_interval);
        }
        let mut accepted_connection = false;
        for listener in &listeners {
            match listener.socket.accept() {
                Ok((mut stream, peer)) => {
                    accepted_connection = true;
                    let state = live.read().expect("live state lock poisoned");
                    let shared = Arc::clone(&state.runtime);
                    let tls = state.tls.get(&listener.address).cloned().flatten();
                    drop(state);
                    if stream.set_nonblocking(false).is_err() {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    if metrics.active.fetch_add(1, Ordering::SeqCst)
                        >= shared.config.listener.max_connections
                    {
                        metrics.active.fetch_sub(1, Ordering::SeqCst);
                        if tls.is_none() {
                            let _ = write_simple_response(
                                &mut stream,
                                503,
                                "Service Unavailable",
                                b"busy\n",
                                &[],
                            );
                        } else {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        continue;
                    }
                    let spawn_failure = Arc::clone(&shared);
                    if thread::Builder::new()
                        .name("polyguard-request".into())
                        .spawn(move || {
                            let mut stream = match ClientStream::new(stream, tls) {
                                Ok(stream) => stream,
                                Err(_) => {
                                    shared.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                    shared.metrics.active.fetch_sub(1, Ordering::SeqCst);
                                    return;
                                }
                            };
                            let result = handle_connection(&mut stream, peer, &shared);
                            if let Err(fault) = result {
                                log_json(json!({"event":"connection","outcome":fault.code()}));
                            }
                            shared.metrics.active.fetch_sub(1, Ordering::SeqCst);
                        })
                        .is_err()
                    {
                        spawn_failure
                            .metrics
                            .rejected
                            .fetch_add(1, Ordering::Relaxed);
                        spawn_failure.metrics.active.fetch_sub(1, Ordering::SeqCst);
                        log_json(json!({"event":"request_worker","status":"spawn_failed"}));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if !accepted_connection {
            thread::sleep(Duration::from_millis(10));
        }
    }
    drop(listeners);
    let shutdown_timeout = {
        let state = live.read().expect("live state lock poisoned");
        Duration::from_millis(state.runtime.config.listener.graceful_shutdown_timeout_ms)
    };
    let deadline = Instant::now() + shutdown_timeout;
    while metrics.active.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if let Some(thread) = management_thread {
        let _ = thread.join();
    }
    log_json(
        json!({"event":"stopped","active_connections":metrics.active.load(Ordering::Relaxed)}),
    );
    Ok(())
}

fn bind_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        // A literal IPv6 listener is IPv6-only. This both avoids surprising
        // IPv4-mapped traffic and permits imported Nginx configurations to
        // bind explicit 0.0.0.0 and [::] listeners on the same port.
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(128)?;
    Ok(socket.into())
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

fn compile_runtime_routes(config: &Config) -> Vec<RuntimeRoute> {
    let mut routes = Vec::new();
    for route in &config.routes {
        let declaration_order = routes.len();
        routes.push(RuntimeRoute {
            id: format!("action-{declaration_order}"),
            host: route.host.clone(),
            path: route.path_prefix.clone(),
            match_kind: RouteMatchKind::BoundaryPrefix,
            methods: Vec::new(),
            schemes: Vec::new(),
            max_request_body_bytes: config.limits.max_request_body_bytes,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            deny: Vec::new(),
            action: RuntimeAction::Proxy {
                upstream: route.upstream.clone(),
                replace_prefix: None,
                host_header: None,
            },
            declaration_order,
        });
    }
    for site in &config.sites {
        let server_names = site
            .server_names
            .iter()
            .map(String::as_str)
            .chain(site.default.then_some("*"));
        for server_name in server_names {
            for route in &site.routes {
                let declaration_order = routes.len();
                let mut response_headers = site.response_headers.clone();
                response_headers.extend(route.response_headers.clone());
                let mut deny = site
                    .deny
                    .iter()
                    .map(|network| IpNetwork::parse(network).expect("validated"))
                    .collect::<Vec<_>>();
                deny.extend(
                    route
                        .deny
                        .iter()
                        .map(|network| IpNetwork::parse(network).expect("validated")),
                );
                let action = match &route.action {
                    RouteActionConfig::Proxy {
                        upstream,
                        replace_prefix,
                        host_header,
                    } => RuntimeAction::Proxy {
                        upstream: upstream.clone(),
                        replace_prefix: replace_prefix.clone(),
                        host_header: host_header.clone(),
                    },
                    RouteActionConfig::Redirect { status, location } => RuntimeAction::Redirect {
                        status: *status,
                        location: location.clone(),
                    },
                    RouteActionConfig::Respond {
                        status,
                        body,
                        content_type,
                    } => RuntimeAction::Respond {
                        status: *status,
                        body: body.clone(),
                        content_type: content_type.clone(),
                    },
                    RouteActionConfig::Static {
                        directory,
                        mapping,
                        index,
                        try_files,
                        error_page_404,
                    } => RuntimeAction::Static {
                        directory: fs::canonicalize(directory).expect("validated static root"),
                        mapping: *mapping,
                        index: index.clone(),
                        try_files: *try_files,
                        error_page_404: error_page_404.clone(),
                    },
                };
                routes.push(RuntimeRoute {
                    id: format!("action-{declaration_order}"),
                    host: server_name.to_owned(),
                    path: route.path.clone(),
                    match_kind: route.match_kind,
                    methods: route
                        .methods
                        .iter()
                        .map(|method| method.to_ascii_lowercase())
                        .collect(),
                    schemes: route
                        .schemes
                        .iter()
                        .map(|scheme| scheme.to_ascii_lowercase())
                        .collect(),
                    max_request_body_bytes: route
                        .max_request_body_bytes
                        .unwrap_or(config.limits.max_request_body_bytes),
                    request_headers: route.request_headers.clone(),
                    response_headers,
                    deny,
                    action,
                    declaration_order,
                });
            }
        }
    }
    routes
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

fn initialize_polyform(config: &Config) -> io::Result<Option<Arc<RuntimePolyform>>> {
    let Some(settings) = &config.polyform else {
        return Ok(None);
    };
    let attempt =
        || -> std::result::Result<Arc<RuntimePolyform>, polyform_runtime::RuntimeError> {
            let trust = ReleaseTrust::from_file(&settings.trust_file)?;
            let state_path = Path::new(&settings.state_file);
            if let Some(parent) = state_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)
                    .map_err(|error| polyform_runtime::RuntimeError::State(error.to_string()))?;
            }
            let client = Arc::new(Mutex::new(PolyformClient::register(
                &settings.base_url,
                settings.installation_id.as_deref(),
                &settings.strategy,
                trust,
                implementation_inventory(),
                state_path,
            )?));
            let (telemetry_tx, telemetry_rx) = sync_channel::<TelemetryReport>(1_024);
            let telemetry_client = Arc::clone(&client);
            thread::Builder::new()
                .name("polyguard-telemetry".into())
                .spawn(move || {
                    while let Ok(report) = telemetry_rx.recv() {
                        let client = telemetry_client.lock().expect("runtime lock poisoned");
                        let active_calls = active_composition_calls(
                            &report.calls,
                            &client.composition.implementations,
                        );
                        if client
                            .report_execution(
                                "proxy_request",
                                report.success,
                                report.duration_ms,
                                (!report.success).then_some(report.outcome.as_str()),
                                &active_calls,
                            )
                            .is_err()
                        {
                            log_json(json!({"event":"polyform_telemetry","status":"failed"}));
                        }
                    }
                })
                .map_err(|error| polyform_runtime::RuntimeError::State(error.to_string()))?;
            Ok(Arc::new(RuntimePolyform {
                client,
                refresh_interval: Duration::from_secs(settings.refresh_interval_seconds),
                report_telemetry: settings.report_telemetry,
                telemetry_tx,
                refresh_in_progress: AtomicBool::new(false),
            }))
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

fn schedule_polyform_refresh(runtime: &Arc<Runtime>) {
    let Some(polyform) = &runtime.polyform else {
        return;
    };
    if polyform
        .refresh_in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let refresh_runtime = Arc::clone(runtime);
    if thread::Builder::new()
        .name("polyguard-composition-refresh".into())
        .spawn(move || refresh_polyform(&refresh_runtime))
        .is_err()
        && let Some(polyform) = &runtime.polyform
    {
        polyform.refresh_in_progress.store(false, Ordering::Release);
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
    polyform.refresh_in_progress.store(false, Ordering::Release);
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
    let report = TelemetryReport {
        success,
        duration_ms,
        outcome: outcome.into(),
        calls: calls.to_vec(),
    };
    if let Err(error) = polyform.telemetry_tx.try_send(report) {
        runtime
            .metrics
            .telemetry_dropped
            .fetch_add(1, Ordering::Relaxed);
        let status = match error {
            TrySendError::Full(_) => "queue_full",
            TrySendError::Disconnected(_) => "worker_unavailable",
        };
        log_json(json!({"event":"polyform_telemetry","status":status}));
    }
}

fn run_management_listener(listener: TcpListener, live: Arc<RwLock<LiveState>>) {
    while !TERMINATE.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let runtime = Arc::clone(&live.read().expect("live state lock poisoned").runtime);
                let result = process_management_request(&mut stream, &runtime);
                if let Err(fault) = result {
                    let (status, reason) = fault.status();
                    let _ = write_simple_response(
                        &mut stream,
                        status,
                        reason,
                        b"management request rejected\n",
                        &[],
                    );
                }
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn process_management_request(
    stream: &mut TcpStream,
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
    if !remainder.is_empty() {
        return Err(Fault::Protocol(PolyguardError::AmbiguousFraming));
    }
    let request = runtime
        .agreement
        .run("parse_request_line", |implementation| {
            implementation
                .parse_request_line
                .map(|function| function(&head))
        })?;
    if request.method != "get" {
        return Err(Fault::Protocol(PolyguardError::InvalidMethod));
    }
    let header_wire = &head[request.bytes_consumed..];
    let headers = runtime
        .agreement
        .run("parse_header_section", |implementation| {
            implementation
                .parse_header_section
                .map(|function| function(header_wire))
        })?;
    if headers.bytes_consumed != header_wire.len() {
        return Err(Fault::Protocol(PolyguardError::InvalidHeader {
            index: 0,
            reason: "trailing_bytes".into(),
        }));
    }
    let framing = runtime
        .agreement
        .run("determine_body_framing", |implementation| {
            implementation
                .determine_body_framing
                .map(|function| function(&request, &headers))
        })?;
    if framing != BodyFraming::None {
        return Err(Fault::Protocol(PolyguardError::AmbiguousFraming));
    }
    let target = runtime
        .agreement
        .run("normalize_request_target", |implementation| {
            implementation
                .normalize_request_target
                .map(|function| function(&request))
        })?;
    runtime
        .agreement
        .run("reconcile_authority", |implementation| {
            implementation
                .reconcile_authority
                .map(|function| function(&target, &headers))
        })?;
    let (status, reason, body) = admin_response(&target.routing_path, runtime)
        .ok_or(Fault::Protocol(PolyguardError::NoRoute))?;
    write_simple_response(stream, status, reason, &body, &[]).map_err(|_| Fault::ClientIo)
}

fn handle_connection(
    stream: &mut ClientStream,
    peer: SocketAddr,
    runtime: &Runtime,
) -> std::result::Result<(), Fault> {
    let mut completed = 0_usize;
    loop {
        begin_trace();
        let started = Instant::now();
        let result = process_request(stream, peer, runtime);
        let idle_close = matches!(result, Err(Fault::ClientClosed))
            || (completed != 0 && matches!(result, Err(Fault::ClientIo | Fault::Timeout)));
        if idle_close {
            let _ = take_trace();
        } else {
            record_request_result(runtime, &result, started);
        }
        match result {
            Ok(true) if completed < 999 => completed += 1,
            Ok(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(Fault::ClientIo | Fault::Timeout) if completed != 0 => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(Fault::ClientClosed) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(fault) => {
                let (status, reason) = fault.status();
                let _ = write_simple_response(stream, status, reason, b"request rejected\n", &[]);
                let _ = stream.shutdown(Shutdown::Both);
                return Err(fault);
            }
        }
    }
}

fn record_request_result(
    runtime: &Runtime,
    result: &std::result::Result<bool, Fault>,
    started: Instant,
) {
    let (code, function) = match result {
        Ok(_) => ("accepted", None),
        Err(Fault::Disagreement { function }) => ("implementation_disagreement", Some(*function)),
        Err(fault) => (fault.code(), None),
    };
    let success = result.is_ok();
    if success {
        runtime.metrics.accepted.fetch_add(1, Ordering::Relaxed);
    } else {
        runtime.metrics.rejected.fetch_add(1, Ordering::Relaxed);
    }
    if matches!(result, Err(Fault::Disagreement { .. })) {
        runtime
            .metrics
            .disagreements
            .fetch_add(1, Ordering::Relaxed);
    }
    if matches!(result, Err(Fault::Upstream)) {
        runtime
            .metrics
            .upstream_failures
            .fetch_add(1, Ordering::Relaxed);
    }
    if matches!(result, Err(Fault::Timeout | Fault::UpstreamTimeout)) {
        runtime.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
    }
    let _ = classify_outcome(&runtime.agreement, code, success);
    let calls = take_trace();
    let elapsed = started.elapsed();
    report_polyform(
        runtime,
        success,
        elapsed.as_secs_f64() * 1_000.0,
        code,
        &calls,
    );
    log_json(json!({
        "event":"request",
        "outcome":code,
        "disagreement_function":function,
        "latency_ms":elapsed.as_millis()
    }));
}

fn client_allows_keep_alive(headers: &HeaderBlock) -> bool {
    !headers
        .fields
        .iter()
        .filter(|field| field.name == "connection")
        .flat_map(|field| field.value.split(|byte| *byte == b','))
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
}

fn runtime_host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

fn runtime_host_specificity(pattern: &str) -> (u8, usize) {
    if pattern == "*" {
        (0, 0)
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        (1, suffix.len())
    } else {
        (2, pattern.len())
    }
}

fn runtime_path_matches(route: &RuntimeRoute, path: &str) -> bool {
    match route.match_kind {
        RouteMatchKind::Exact => path == route.path,
        RouteMatchKind::Prefix => path.starts_with(&route.path),
        RouteMatchKind::BoundaryPrefix => {
            route.path == "/"
                || path == route.path
                || path
                    .strip_prefix(&route.path)
                    .is_some_and(|remainder| remainder.starts_with('/'))
        }
    }
}

fn runtime_route_eligible(
    route: &RuntimeRoute,
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    method: &str,
    scheme: &str,
) -> bool {
    runtime_host_matches(&route.host, &authority.host)
        && runtime_path_matches(route, &target.routing_path)
        && (route.methods.is_empty() || route.methods.iter().any(|item| item == method))
        && (route.schemes.is_empty() || route.schemes.iter().any(|item| item == scheme))
}

fn select_route_fold(
    routes: &[RuntimeRoute],
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    method: &str,
    scheme: &str,
) -> Option<usize> {
    let mut winner: Option<usize> = None;
    for (index, route) in routes.iter().enumerate() {
        if !runtime_route_eligible(route, authority, target, method, scheme) {
            continue;
        }
        winner = match winner {
            None => Some(index),
            Some(current_index) => {
                let current = &routes[current_index];
                let route_host_specificity = runtime_host_specificity(&route.host);
                let current_host_specificity = runtime_host_specificity(&current.host);
                if route_host_specificity != current_host_specificity {
                    if route_host_specificity > current_host_specificity {
                        Some(index)
                    } else {
                        Some(current_index)
                    }
                } else {
                    let route_exact = route.match_kind == RouteMatchKind::Exact;
                    let current_exact = current.match_kind == RouteMatchKind::Exact;
                    if route_exact != current_exact {
                        if route_exact {
                            Some(index)
                        } else {
                            Some(current_index)
                        }
                    } else if route.path.len() != current.path.len() {
                        if route.path.len() > current.path.len() {
                            Some(index)
                        } else {
                            Some(current_index)
                        }
                    } else if route.declaration_order < current.declaration_order {
                        Some(index)
                    } else {
                        Some(current_index)
                    }
                }
            }
        };
    }
    winner
}

fn select_route_sorted(
    routes: &[RuntimeRoute],
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    method: &str,
    scheme: &str,
) -> Option<usize> {
    let mut candidates = routes
        .iter()
        .enumerate()
        .filter(|(_, route)| runtime_route_eligible(route, authority, target, method, scheme))
        .map(|(index, route)| {
            (
                index,
                runtime_host_specificity(&route.host),
                route.match_kind == RouteMatchKind::Exact,
                route.path.len(),
                route.declaration_order,
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.4.cmp(&right.4))
    });
    candidates.first().map(|candidate| candidate.0)
}

fn select_runtime_route<'a>(
    runtime: &'a Runtime,
    authority: &EffectiveAuthority,
    target: &NormalizedTarget,
    method: &str,
    scheme: &str,
) -> std::result::Result<&'a RuntimeRoute, Fault> {
    let folded = select_route_fold(&runtime.routes, authority, target, method, scheme);
    let sorted = select_route_sorted(&runtime.routes, authority, target, method, scheme);
    if folded != sorted {
        return Err(Fault::Disagreement {
            function: "select_route_action",
        });
    }
    let index = folded.ok_or(Fault::Protocol(PolyguardError::NoRoute))?;
    let selected = &runtime.routes[index];
    let guard = [RouteRule {
        host: authority.host.clone(),
        path_prefix: "/".into(),
        upstream: selected.id.clone(),
        declaration_order: 0,
    }];
    let guarded = runtime.agreement.run("match_route", |implementation| {
        implementation
            .match_route
            .map(|function| function(authority, target, &guard))
    })?;
    if guarded.upstream != selected.id {
        return Err(Fault::Internal);
    }
    Ok(selected)
}

fn process_request(
    stream: &mut ClientStream,
    peer: SocketAddr,
    runtime: &Runtime,
) -> std::result::Result<bool, Fault> {
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
    let accepts_gzip = client_accepts_gzip(&headers);
    let request_keep_alive = client_allows_keep_alive(&headers);
    let framing = runtime
        .agreement
        .run("determine_body_framing", |implementation| {
            implementation
                .determine_body_framing
                .map(|function| function(&request, &headers))
        })?;
    let expect_continue = parse_expect_continue(&headers)?;
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
    if stream.tls_server_name().is_some_and(|server_name| {
        !server_name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&authority.host)
    }) {
        return Err(Fault::Forbidden);
    }
    let mut sanitized = runtime
        .agreement
        .run("remove_hop_by_hop_headers", |implementation| {
            implementation
                .remove_hop_by_hop_headers
                .map(|function| function(&headers))
        })?;
    sanitized.fields.retain(|field| field.name != "expect");
    let upgrade = runtime.agreement.run("decide_upgrade", |implementation| {
        implementation
            .decide_upgrade
            .map(|function| function(&request, &headers, &framing))
    })?;
    if upgrade != UpgradeDecision::None {
        return Err(Fault::Protocol(PolyguardError::UnsupportedUpgrade));
    }

    let scheme = if stream.is_tls() { "https" } else { "http" };
    let route = select_runtime_route(runtime, &authority, &target, &request.method, scheme)?;
    enforce_declared_body_limit(&framing, route.max_request_body_bytes)?;
    if route.deny.iter().any(|network| network.contains(peer.ip())) {
        return Err(Fault::Forbidden);
    }
    let authority_text = authority_string(&authority);
    let remote_addr = peer.ip().to_string();
    let forwarding_policy = ForwardingPolicy {
        trust_incoming: runtime.config.listener.trust_forwarding_headers,
        client_ip: remote_addr.clone(),
        proto: scheme.into(),
        host: authority_text.clone(),
    };
    let forwarding = runtime
        .agreement
        .run("apply_forwarding_policy", |implementation| {
            implementation
                .apply_forwarding_policy
                .map(|function| function(&forwarding_policy, &headers))
        })?;
    let context = TemplateContext {
        host: &authority.host,
        http_host: &authority_text,
        remote_addr: &remote_addr,
        scheme,
        request_uri: &target.path_and_query,
        proxy_add_x_forwarded_for: &forwarding.x_forwarded_for,
    };
    match &route.action {
        RuntimeAction::Redirect { status, location } => {
            let location = render_template(location, &context, MAX_REQUEST_LINE_BYTES)?;
            let mut response_headers = render_response_headers(
                &route.response_headers,
                &context,
                &request.method,
                *status,
            )?;
            response_headers.push(("location".into(), location));
            write_configured_response(
                stream,
                *status,
                "text/plain; charset=utf-8",
                &[],
                &response_headers,
                request.method == "head",
                !(request_keep_alive && framing == BodyFraming::None && remainder.is_empty()),
            )
            .map_err(|_| Fault::ClientIo)?;
            return Ok(request_keep_alive && framing == BodyFraming::None && remainder.is_empty());
        }
        RuntimeAction::Respond {
            status,
            body,
            content_type,
        } => {
            let body_length = rendered_template_length(
                body,
                &context,
                runtime.config.limits.max_response_body_bytes,
            )?;
            let permit = runtime.body_memory.reserve(body_length)?;
            let body = render_template(
                body,
                &context,
                runtime.config.limits.max_response_body_bytes,
            )?;
            let content_type = render_template(content_type, &context, 1_024)?;
            let mut response_headers = render_response_headers(
                &route.response_headers,
                &context,
                &request.method,
                *status,
            )?;
            let body = body.into_bytes();
            let mut body = BufferedBody {
                bytes: body,
                _permit: permit,
            };
            if let Some(compressed) = gzip_body_accounted(
                &runtime.config.compression,
                accepts_gzip,
                &content_type,
                &body.bytes,
                &runtime.body_memory,
                &mut body._permit,
            )? {
                body.bytes = compressed;
                add_gzip_headers(&mut response_headers);
            }
            write_configured_response(
                stream,
                *status,
                &content_type,
                &body.bytes,
                &response_headers,
                request.method == "head",
                !(request_keep_alive && framing == BodyFraming::None && remainder.is_empty()),
            )
            .map_err(|_| Fault::ClientIo)?;
            return Ok(request_keep_alive && framing == BodyFraming::None && remainder.is_empty());
        }
        RuntimeAction::Static { .. } => {
            let response = serve_static(
                route,
                &target,
                &request.method,
                &headers,
                runtime.config.limits.max_response_body_bytes,
                &runtime.body_memory,
            )?;
            let mut response_headers = render_response_headers(
                &route.response_headers,
                &context,
                &request.method,
                response.status,
            )?;
            response_headers.extend(response.headers);
            let mut body = response.body;
            if response.status == 200
                && let Some(compressed) = gzip_body_accounted(
                    &runtime.config.compression,
                    accepts_gzip,
                    response.content_type,
                    &body.bytes,
                    &runtime.body_memory,
                    &mut body._permit,
                )?
            {
                body.bytes = compressed;
                add_gzip_headers(&mut response_headers);
            }
            write_configured_response(
                stream,
                response.status,
                response.content_type,
                &body.bytes,
                &response_headers,
                request.method == "head",
                !(request_keep_alive && framing == BodyFraming::None && remainder.is_empty()),
            )
            .map_err(|_| Fault::ClientIo)?;
            return Ok(request_keep_alive && framing == BodyFraming::None && remainder.is_empty());
        }
        RuntimeAction::Proxy { .. } => {}
    }
    if expect_continue && framing != BodyFraming::None {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| Fault::ClientIo)?;
    }
    apply_request_headers(
        &mut sanitized,
        &route.request_headers,
        &context,
        &request.method,
    )?;
    stream
        .set_read_timeout(Some(Duration::from_millis(
            runtime.config.listener.request_body_timeout_ms,
        )))
        .map_err(|_| Fault::ClientIo)?;
    let mut input = BufferedInput::new(stream, remainder);
    let body = read_request_body(
        &mut input,
        &framing,
        &headers,
        runtime,
        route.max_request_body_bytes,
    )?;
    if input.has_immediate_extra()? {
        return Err(Fault::Protocol(PolyguardError::AmbiguousFraming));
    }
    let upstream_framing = if body.bytes.is_empty() {
        BodyFraming::None
    } else {
        BodyFraming::ContentLength(body.bytes.len() as u64)
    };
    let (upstream_name, replace_prefix, host_header) = match &route.action {
        RuntimeAction::Proxy {
            upstream,
            replace_prefix,
            host_header,
        } => (upstream, replace_prefix.as_deref(), host_header.as_deref()),
        RuntimeAction::Redirect { .. }
        | RuntimeAction::Respond { .. }
        | RuntimeAction::Static { .. } => unreachable!(),
    };
    let upstream_address = *runtime
        .upstreams
        .get(upstream_name)
        .ok_or(Fault::Internal)?;
    let upstream_target = rewrite_target(&target, &route.path, replace_prefix)?;
    let mut upstream_authority = authority.clone();
    if host_header == Some("$host") {
        upstream_authority.port = None;
    }
    let canonical =
        runtime
            .agreement
            .run("construct_canonical_upstream_head", |implementation| {
                implementation
                    .construct_canonical_upstream_head
                    .map(|function| {
                        function(
                            &request.method,
                            &upstream_target,
                            &upstream_authority,
                            &sanitized,
                            &upstream_framing,
                            &forwarding,
                        )
                    })
            })?;
    let response = exchange_upstream(
        UpstreamExchange {
            address: upstream_address,
            request_head: &canonical.bytes,
            body,
            method: &request.method,
            accepts_gzip,
            client_keep_alive: request_keep_alive,
            configured_response_headers: &route.response_headers,
            template_context: &context,
        },
        runtime,
    )?;
    stream
        .write_all(&response.head)
        .and_then(|_| stream.write_all(&response.body.bytes))
        .map_err(|_| Fault::ClientIo)?;
    Ok(request_keep_alive)
}

fn parse_expect_continue(headers: &HeaderBlock) -> std::result::Result<bool, Fault> {
    let mut values = headers
        .fields
        .iter()
        .filter(|field| field.name == "expect")
        .map(|field| field.value.trim_ascii());
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() || !value.eq_ignore_ascii_case(b"100-continue") {
        return Err(Fault::ExpectationFailed);
    }
    Ok(true)
}

fn enforce_declared_body_limit(
    framing: &BodyFraming,
    max_request_body_bytes: usize,
) -> std::result::Result<(), Fault> {
    if let BodyFraming::ContentLength(length) = framing
        && usize::try_from(*length)
            .map(|length| length > max_request_body_bytes)
            .unwrap_or(true)
    {
        return Err(Fault::TooLarge);
    }
    Ok(())
}

fn authority_string(authority: &EffectiveAuthority) -> String {
    match authority.port {
        Some(port) => format!("{}:{port}", authority.host),
        None => authority.host.clone(),
    }
}

struct TemplateContext<'a> {
    host: &'a str,
    http_host: &'a str,
    remote_addr: &'a str,
    scheme: &'a str,
    request_uri: &'a str,
    proxy_add_x_forwarded_for: &'a str,
}

fn template_replacement<'a>(
    variable: &str,
    context: &'a TemplateContext<'_>,
) -> std::result::Result<&'a str, Fault> {
    match variable {
        "$host" => Ok(context.host),
        "$http_host" => Ok(context.http_host),
        "$remote_addr" => Ok(context.remote_addr),
        "$scheme" => Ok(context.scheme),
        "$request_uri" => Ok(context.request_uri),
        "$proxy_add_x_forwarded_for" => Ok(context.proxy_add_x_forwarded_for),
        _ => Err(Fault::Internal),
    }
}

fn rendered_template_length(
    value: &str,
    context: &TemplateContext<'_>,
    max: usize,
) -> std::result::Result<usize, Fault> {
    let bytes = value.as_bytes();
    let mut offset = 0;
    let mut literal_start = 0;
    let mut length = 0_usize;
    while offset < bytes.len() {
        if bytes[offset] != b'$' {
            offset += 1;
            continue;
        }
        length = length
            .checked_add(offset - literal_start)
            .filter(|length| *length <= max)
            .ok_or(Fault::TooLarge)?;
        let start = offset;
        offset += 1;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
        {
            offset += 1;
        }
        let replacement = template_replacement(&value[start..offset], context)?;
        length = length
            .checked_add(replacement.len())
            .filter(|length| *length <= max)
            .ok_or(Fault::TooLarge)?;
        literal_start = offset;
    }
    length
        .checked_add(value.len() - literal_start)
        .filter(|length| *length <= max)
        .ok_or(Fault::TooLarge)
}

fn render_template(
    value: &str,
    context: &TemplateContext<'_>,
    max: usize,
) -> std::result::Result<String, Fault> {
    let length = rendered_template_length(value, context, max)?;
    let mut rendered = String::with_capacity(length);
    let bytes = value.as_bytes();
    let mut offset = 0;
    let mut literal_start = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'$' {
            offset += 1;
            continue;
        }
        rendered.push_str(&value[literal_start..offset]);
        let start = offset;
        offset += 1;
        while offset < bytes.len()
            && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
        {
            offset += 1;
        }
        rendered.push_str(template_replacement(&value[start..offset], context)?);
        literal_start = offset;
    }
    rendered.push_str(&value[literal_start..]);
    if rendered
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(Fault::Internal);
    }
    Ok(rendered)
}

fn header_applies(header: &HeaderValueConfig, method: &str, status: u16) -> bool {
    let method_matches = header.methods.is_empty()
        || header
            .methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(method));
    let status_matches = header.always
        || matches!(
            status,
            200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
        );
    method_matches && status_matches
}

fn client_accepts_gzip(headers: &HeaderBlock) -> bool {
    let mut gzip = None;
    let mut wildcard = None;
    for item in headers
        .fields
        .iter()
        .filter(|field| field.name == "accept-encoding")
        .flat_map(|field| field.value.split(|byte| *byte == b','))
    {
        let Ok(item) = std::str::from_utf8(item) else {
            continue;
        };
        let mut parts = item.trim().split(';');
        let coding = parts.next().unwrap_or("").trim();
        if !(coding.eq_ignore_ascii_case("gzip") || coding == "*") {
            continue;
        }
        let mut quality = Some(1_000_u16);
        let mut saw_quality = false;
        for parameter in parts {
            let Some((name, value)) = parameter.trim().split_once('=') else {
                quality = None;
                break;
            };
            if !name.trim().eq_ignore_ascii_case("q") || saw_quality {
                quality = None;
                break;
            }
            saw_quality = true;
            quality = parse_quality(value.trim());
        }
        let quality = quality.unwrap_or(0);
        let selected = if coding.eq_ignore_ascii_case("gzip") {
            &mut gzip
        } else {
            &mut wildcard
        };
        *selected = Some(selected.unwrap_or(0).max(quality));
    }
    gzip.or(wildcard).is_some_and(|quality| quality != 0)
}

fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut digits = fraction.bytes().map(|byte| u16::from(byte - b'0'));
            Some(
                digits.next().unwrap_or(0) * 100
                    + digits.next().unwrap_or(0) * 10
                    + digits.next().unwrap_or(0),
            )
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1_000),
        _ => None,
    }
}

fn compression_type_matches(config: &CompressionConfig, content_type: &str) -> bool {
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim();
    config
        .types
        .iter()
        .any(|configured| configured == "*" || configured.eq_ignore_ascii_case(media_type))
}

fn gzip_body(
    config: &CompressionConfig,
    accepted: bool,
    content_type: &str,
    body: &[u8],
) -> std::result::Result<Option<Vec<u8>>, Fault> {
    if !config.enabled
        || !accepted
        || body.len() < config.min_size_bytes
        || !compression_type_matches(config, content_type)
    {
        return Ok(None);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).map_err(|_| Fault::Internal)?;
    encoder.finish().map(Some).map_err(|_| Fault::Internal)
}

fn gzip_body_accounted(
    config: &CompressionConfig,
    accepted: bool,
    content_type: &str,
    body: &[u8],
    budget: &Arc<MemoryBudget>,
    body_permit: &mut MemoryPermit,
) -> std::result::Result<Option<Vec<u8>>, Fault> {
    if !config.enabled
        || !accepted
        || body.len() < config.min_size_bytes
        || !compression_type_matches(config, content_type)
    {
        return Ok(None);
    }
    let Some(allocation_bound) = body
        .len()
        .checked_add(body.len() >> 12)
        .and_then(|value| value.checked_add(body.len() >> 14))
        .and_then(|value| value.checked_add(body.len() >> 25))
        .and_then(|value| value.checked_add(64))
    else {
        return Ok(None);
    };
    let Ok(allocation_permit) = budget.reserve(allocation_bound) else {
        return Ok(None);
    };
    let compressed = gzip_body(config, accepted, content_type, body)?.ok_or(Fault::Internal)?;
    if compressed.len() > allocation_bound {
        return Err(Fault::Internal);
    }
    body_permit.absorb(allocation_permit)?;
    Ok(Some(compressed))
}

fn add_gzip_headers(headers: &mut Vec<(String, String)>) {
    headers.push(("content-encoding".into(), "gzip".into()));
    if !headers.iter().any(|(name, _)| name == "vary") {
        headers.push(("vary".into(), "Accept-Encoding".into()));
    }
}

fn apply_request_headers(
    headers: &mut SanitizedHeaders,
    configured: &[HeaderValueConfig],
    context: &TemplateContext<'_>,
    method: &str,
) -> std::result::Result<(), Fault> {
    for header in configured {
        if !header.methods.is_empty()
            && !header
                .methods
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(method))
        {
            continue;
        }
        let value = render_template(&header.value, context, MAX_HEADER_VALUE_BYTES)?.into_bytes();
        headers.fields.retain(|field| field.name != header.name);
        headers.fields.push(crate::HeaderField {
            name: header.name.clone(),
            value,
        });
    }
    Ok(())
}

fn render_response_headers(
    configured: &[HeaderValueConfig],
    context: &TemplateContext<'_>,
    method: &str,
    status: u16,
) -> std::result::Result<Vec<(String, String)>, Fault> {
    configured
        .iter()
        .filter(|header| header_applies(header, method, status))
        .map(|header| {
            render_template(&header.value, context, MAX_HEADER_VALUE_BYTES)
                .map(|value| (header.name.clone(), value))
        })
        .collect()
}

fn rewrite_target(
    target: &NormalizedTarget,
    matched_prefix: &str,
    replacement: Option<&str>,
) -> std::result::Result<NormalizedTarget, Fault> {
    let Some(replacement) = replacement else {
        return Ok(target.clone());
    };
    let remainder = target
        .routing_path
        .strip_prefix(matched_prefix)
        .ok_or(Fault::Internal)?;
    let mut routing_path = String::with_capacity(replacement.len() + remainder.len());
    routing_path.push_str(replacement);
    routing_path.push_str(remainder);
    if !routing_path.starts_with('/') || routing_path.len() > MAX_REQUEST_LINE_BYTES {
        return Err(Fault::Internal);
    }
    let query = target
        .path_and_query
        .strip_prefix(&target.routing_path)
        .ok_or(Fault::Internal)?;
    Ok(NormalizedTarget {
        form: TargetForm::Origin,
        scheme: None,
        authority: None,
        path_and_query: format!("{routing_path}{query}"),
        routing_path,
    })
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Content Too Large",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}

fn write_configured_response<W: Write>(
    stream: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(String, String)],
    head_only: bool,
    close: bool,
) -> io::Result<()> {
    let mut response = Vec::new();
    write!(
        &mut response,
        "HTTP/1.1 {status} {}\r\n",
        reason_phrase(status)
    )
    .expect("vec write");
    response.extend_from_slice(SERVER_HEADER);
    for (name, value) in headers {
        write!(&mut response, "{name}: {value}\r\n").expect("vec write");
    }
    let body_length = if matches!(status, 204 | 304) {
        0
    } else {
        body.len()
    };
    write!(
        &mut response,
        "content-type: {content_type}\r\ncontent-length: {body_length}\r\nconnection: {}\r\n\r\n",
        if close { "close" } else { "keep-alive" }
    )
    .expect("vec write");
    if !head_only && body_length != 0 {
        response.extend_from_slice(body);
    }
    stream.write_all(&response)
}

struct StaticResponse {
    status: u16,
    content_type: &'static str,
    body: BufferedBody,
    headers: Vec<(String, String)>,
}

fn static_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn static_candidate(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut candidate = root.to_path_buf();
    for component in relative
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if component == "." || component == ".." || component.contains('\0') {
            return None;
        }
        candidate.push(component);
    }
    Some(candidate)
}

fn read_static_file(
    root: &Path,
    candidate: &Path,
    indexes: &[String],
    try_files: bool,
    max_bytes: usize,
    budget: &Arc<MemoryBudget>,
) -> std::result::Result<Option<(PathBuf, BufferedBody)>, Fault> {
    let Some(file) = resolve_static_file(root, candidate, indexes, try_files) else {
        return Ok(None);
    };
    let Ok(opened) = fs::File::open(&file) else {
        return Ok(None);
    };
    let Ok(metadata) = opened.metadata() else {
        return Ok(None);
    };
    let Ok(length) = usize::try_from(metadata.len()) else {
        return Ok(None);
    };
    if length > max_bytes {
        return Ok(None);
    }
    let permit = budget.reserve(length)?;
    let mut body = Vec::with_capacity(length);
    if opened
        .take(u64::try_from(length).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut body)
        .is_err()
        || body.len() > length
    {
        return Ok(None);
    }
    Ok(Some((
        file,
        BufferedBody {
            bytes: body,
            _permit: permit,
        },
    )))
}

fn resolve_static_file(
    root: &Path,
    candidate: &Path,
    indexes: &[String],
    try_files: bool,
) -> Option<PathBuf> {
    let Ok(resolved) = fs::canonicalize(candidate) else {
        return None;
    };
    if !resolved.starts_with(root) {
        return None;
    }
    let file = if resolved.is_dir() {
        if !try_files {
            return None;
        }
        indexes.iter().find_map(|index| {
            let indexed = resolved.join(index);
            let canonical = fs::canonicalize(indexed).ok()?;
            (canonical.starts_with(root) && canonical.is_file()).then_some(canonical)
        })?
    } else if resolved.is_file() {
        resolved
    } else {
        return None;
    };
    Some(file)
}

fn serve_static(
    route: &RuntimeRoute,
    target: &NormalizedTarget,
    method: &str,
    request_headers: &HeaderBlock,
    max_bytes: usize,
    budget: &Arc<MemoryBudget>,
) -> std::result::Result<StaticResponse, Fault> {
    let RuntimeAction::Static {
        directory,
        mapping,
        index,
        try_files,
        error_page_404,
    } = &route.action
    else {
        return Err(Fault::Internal);
    };
    let relative = match mapping {
        StaticMapping::Root => target.routing_path.trim_start_matches('/'),
        StaticMapping::Alias => target
            .routing_path
            .strip_prefix(&route.path)
            .ok_or(Fault::Internal)?
            .trim_start_matches('/'),
    };
    let candidate = static_candidate(directory, relative).ok_or(Fault::Internal)?;
    if !matches!(method, "get" | "head")
        && resolve_static_file(directory, &candidate, index, *try_files).is_some()
    {
        let body = b"method not allowed\n".to_vec();
        return Ok(StaticResponse {
            status: 405,
            content_type: "text/plain; charset=utf-8",
            body: BufferedBody {
                _permit: budget.reserve(body.len())?,
                bytes: body,
            },
            headers: Vec::new(),
        });
    }
    if let Some((path, mut body)) =
        read_static_file(directory, &candidate, index, *try_files, max_bytes, budget)?
    {
        let mut status = 200;
        let mut response_headers = vec![("accept-ranges".into(), "bytes".into())];
        if let Some(range) = requested_byte_range(request_headers, body.bytes.len()) {
            match range {
                Ok((start, end)) => {
                    let complete_length = body.bytes.len();
                    body.bytes.copy_within(start..=end, 0);
                    body.bytes.truncate(end - start + 1);
                    status = 206;
                    response_headers.push((
                        "content-range".into(),
                        format!("bytes {start}-{end}/{complete_length}"),
                    ));
                }
                Err(()) => {
                    let complete_length = body.bytes.len();
                    body.bytes.clear();
                    status = 416;
                    response_headers
                        .push(("content-range".into(), format!("bytes */{complete_length}")));
                }
            }
        }
        return Ok(StaticResponse {
            status,
            content_type: static_content_type(&path),
            body,
            headers: response_headers,
        });
    }
    if let Some(error_page) = error_page_404 {
        let candidate = static_candidate(directory, error_page.trim_start_matches('/'))
            .ok_or(Fault::Internal)?;
        if let Some((path, body)) =
            read_static_file(directory, &candidate, &[], false, max_bytes, budget)?
        {
            return Ok(StaticResponse {
                status: 404,
                content_type: static_content_type(&path),
                body,
                headers: Vec::new(),
            });
        }
    }
    let body = b"not found\n".to_vec();
    Ok(StaticResponse {
        status: 404,
        content_type: "text/plain; charset=utf-8",
        body: BufferedBody {
            _permit: budget.reserve(body.len())?,
            bytes: body,
        },
        headers: Vec::new(),
    })
}

fn requested_byte_range(
    headers: &HeaderBlock,
    length: usize,
) -> Option<std::result::Result<(usize, usize), ()>> {
    let values = headers
        .fields
        .iter()
        .filter(|field| field.name == "range")
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    if values.len() != 1 {
        return Some(Err(()));
    }
    let value = std::str::from_utf8(&values[0].value).ok()?.trim();
    let range = value.strip_prefix("bytes=")?;
    if range.contains(',') || length == 0 {
        return Some(Err(()));
    }
    let (start, end) = range.split_once('-')?;
    let parsed = if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?;
        if suffix == 0 {
            return Some(Err(()));
        }
        let start = length.saturating_sub(suffix);
        (start, length - 1)
    } else {
        let start = start.parse::<usize>().ok()?;
        let end = if end.is_empty() {
            length - 1
        } else {
            end.parse::<usize>().ok()?.min(length - 1)
        };
        if start >= length || end < start {
            return Some(Err(()));
        }
        (start, end)
    };
    Some(Ok(parsed))
}

fn read_request_body(
    input: &mut BufferedInput<'_, ClientStream>,
    framing: &BodyFraming,
    headers: &HeaderBlock,
    runtime: &Runtime,
    max_request_body_bytes: usize,
) -> std::result::Result<BufferedBody, Fault> {
    match framing {
        BodyFraming::None => Ok(BufferedBody {
            bytes: Vec::new(),
            _permit: runtime.body_memory.reserve(0)?,
        }),
        BodyFraming::ContentLength(length) => {
            let length = usize::try_from(*length).map_err(|_| Fault::TooLarge)?;
            if length > max_request_body_bytes {
                return Err(Fault::TooLarge);
            }
            let permit = runtime.body_memory.reserve(length)?;
            Ok(BufferedBody {
                bytes: input.read_exact_vec(length)?,
                _permit: permit,
            })
        }
        BodyFraming::Chunked => {
            let mut permit = runtime.body_memory.reserve(0)?;
            let bytes = read_chunked(
                input,
                headers,
                max_request_body_bytes,
                &runtime.agreement,
                &mut permit,
            )?;
            Ok(BufferedBody {
                bytes,
                _permit: permit,
            })
        }
    }
}

fn read_chunked<S: Read>(
    input: &mut BufferedInput<'_, S>,
    headers: &HeaderBlock,
    max: usize,
    agreement: &Agreement,
    permit: &mut MemoryPermit,
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
        permit.grow(size)?;
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

struct BufferedInput<'a, S: Read> {
    stream: &'a mut S,
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a, S: Read> BufferedInput<'a, S> {
    fn new(stream: &'a mut S, buffer: Vec<u8>) -> Self {
        Self {
            stream,
            buffer,
            offset: 0,
        }
    }
    fn buffered_len(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
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

    fn read_to_eof_bounded(
        self,
        max: usize,
        permit: &mut MemoryPermit,
    ) -> std::result::Result<Vec<u8>, Fault> {
        let mut output = self.buffer[self.offset..].to_vec();
        if output.len() > max {
            return Err(Fault::Upstream);
        }
        permit.grow(output.len())?;
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
                    permit.grow(count)?;
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

impl BufferedInput<'_, ClientStream> {
    fn has_immediate_extra(&mut self) -> std::result::Result<bool, Fault> {
        if self.buffered_len() != 0 {
            return Ok(true);
        }
        let mut byte = [0_u8; 1];
        match self.stream {
            ClientStream::Plain(stream) => {
                stream.set_nonblocking(true).map_err(|_| Fault::ClientIo)?;
                let result = match stream.peek(&mut byte) {
                    Ok(0) => Ok(false),
                    Ok(_) => Ok(true),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
                    Err(_) => Err(Fault::ClientIo),
                };
                stream.set_nonblocking(false).map_err(|_| Fault::ClientIo)?;
                result
            }
            ClientStream::Tls(stream) => match stream.conn.reader().read(&mut byte) {
                Ok(0) => Ok(false),
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
                Err(_) => Err(Fault::ClientIo),
            },
        }
    }
}

fn read_head<R: Read>(
    stream: &mut R,
    max: usize,
) -> std::result::Result<(Vec<u8>, Vec<u8>), Fault> {
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 2_048];
    loop {
        let count = stream.read(&mut scratch).map_err(map_client_io)?;
        if count == 0 {
            return if bytes.is_empty() {
                Err(Fault::ClientClosed)
            } else {
                Err(Fault::ClientIo)
            };
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

struct UpstreamExchange<'a> {
    address: SocketAddr,
    request_head: &'a [u8],
    body: BufferedBody,
    method: &'a str,
    accepts_gzip: bool,
    client_keep_alive: bool,
    configured_response_headers: &'a [HeaderValueConfig],
    template_context: &'a TemplateContext<'a>,
}

fn exchange_upstream(
    exchange: UpstreamExchange<'_>,
    runtime: &Runtime,
) -> std::result::Result<UpstreamResponse, Fault> {
    let UpstreamExchange {
        address,
        request_head,
        body,
        method,
        accepts_gzip,
        client_keep_alive,
        configured_response_headers,
        template_context,
    } = exchange;
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
        .and_then(|_| upstream.write_all(&body.bytes))
        .map_err(|_| Fault::Upstream)?;
    drop(body);
    upstream
        .shutdown(Shutdown::Write)
        .map_err(|_| Fault::Upstream)?;
    let (head, remainder) = read_upstream_head(
        &mut upstream,
        runtime.config.limits.max_response_header_bytes,
    )?;
    let (status, reason, offset) = parse_status_line(&head)?;
    if (100..200).contains(&status) {
        return Err(Fault::Upstream);
    }
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
    let mut sanitized = runtime
        .agreement
        .run("remove_hop_by_hop_headers", |implementation| {
            implementation
                .remove_hop_by_hop_headers
                .map(|function| function(&headers))
        })?;
    for (name, value) in render_response_headers(
        configured_response_headers,
        template_context,
        method,
        status,
    )? {
        sanitized.fields.push(crate::HeaderField {
            name,
            value: value.into_bytes(),
        });
    }
    let no_body =
        method == "head" || (100..200).contains(&status) || status == 204 || status == 304;
    let framing = response_framing(&headers, no_body)?;
    let mut input = BufferedInput::new(&mut upstream, remainder);
    let mut response_body = match framing {
        ResponseFraming::None => BufferedBody {
            bytes: Vec::new(),
            _permit: runtime.body_memory.reserve(0)?,
        },
        ResponseFraming::Length(length) => {
            if length > runtime.config.limits.max_response_body_bytes {
                return Err(Fault::Upstream);
            }
            let permit = runtime.body_memory.reserve(length)?;
            BufferedBody {
                bytes: input.read_exact_vec(length).map_err(map_upstream_fault)?,
                _permit: permit,
            }
        }
        ResponseFraming::Chunked => {
            let mut permit = runtime.body_memory.reserve(0)?;
            let bytes = read_chunked(
                &mut input,
                &headers,
                runtime.config.limits.max_response_body_bytes,
                &runtime.agreement,
                &mut permit,
            )
            .map_err(map_upstream_fault)?;
            BufferedBody {
                bytes,
                _permit: permit,
            }
        }
        ResponseFraming::Close => {
            let mut permit = runtime.body_memory.reserve(0)?;
            let bytes = input
                .read_to_eof_bounded(runtime.config.limits.max_response_body_bytes, &mut permit)?;
            BufferedBody {
                bytes,
                _permit: permit,
            }
        }
    };
    let already_encoded = sanitized
        .fields
        .iter()
        .any(|field| field.name == "content-encoding");
    let content_type = sanitized
        .fields
        .iter()
        .rev()
        .find(|field| field.name == "content-type")
        .and_then(|field| std::str::from_utf8(&field.value).ok())
        .map(str::to_owned);
    if !already_encoded
        && let Some(content_type) = content_type
        && let Some(compressed) = gzip_body_accounted(
            &runtime.config.compression,
            accepts_gzip,
            &content_type,
            &response_body.bytes,
            &runtime.body_memory,
            &mut response_body._permit,
        )?
    {
        response_body.bytes = compressed;
        sanitized.fields.push(crate::HeaderField {
            name: "content-encoding".into(),
            value: b"gzip".to_vec(),
        });
        if let Some(vary) = sanitized
            .fields
            .iter_mut()
            .find(|field| field.name == "vary")
        {
            if !vary
                .value
                .split(|byte| *byte == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"accept-encoding"))
            {
                vary.value.extend_from_slice(b", Accept-Encoding");
            }
        } else {
            sanitized.fields.push(crate::HeaderField {
                name: "vary".into(),
                value: b"Accept-Encoding".to_vec(),
            });
        }
    }
    let head = serialize_response_head(
        status,
        reason,
        &sanitized,
        response_body.bytes.len(),
        client_keep_alive,
    )?;
    Ok(UpstreamResponse {
        head,
        body: response_body,
    })
}

struct UpstreamResponse {
    head: Vec<u8>,
    body: BufferedBody,
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
        Fault::Busy => Fault::Busy,
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

fn serialize_response_head(
    status: u16,
    reason: &str,
    headers: &SanitizedHeaders,
    body_len: usize,
    keep_alive: bool,
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
        "content-length: {}\r\nconnection: {}\r\n\r\n",
        body_len,
        if keep_alive { "keep-alive" } else { "close" }
    )
    .map_err(|_| Fault::Internal)?;
    Ok(output)
}

fn admin_response(path: &str, runtime: &Runtime) -> Option<(u16, &'static str, Vec<u8>)> {
    match path {
        "/_polyguard/health" => Some((200, "OK", b"ok\n".to_vec())),
        "/_polyguard/ready" => {
            let agreement_ready = runtime
                .agreement
                .selected_ids()
                .values()
                .all(|ids| ids.len() == runtime.agreement.width);
            let capacity_ready = runtime.metrics.active.load(Ordering::Relaxed)
                < runtime.config.listener.max_connections
                && runtime.body_memory.used.load(Ordering::Relaxed)
                    < runtime.body_memory.limit.load(Ordering::Relaxed);
            if agreement_ready && capacity_ready {
                Some((200, "OK", b"ready\n".to_vec()))
            } else {
                Some((503, "Service Unavailable", b"not ready\n".to_vec()))
            }
        }
        "/_polyguard/metrics" => Some((200, "OK", format!(
            "# TYPE polyguard_requests_total counter\npolyguard_requests_total{{outcome=\"accepted\"}} {}\npolyguard_requests_total{{outcome=\"rejected\"}} {}\npolyguard_disagreements_total {}\npolyguard_upstream_failures_total {}\npolyguard_timeouts_total {}\npolyguard_telemetry_dropped_total {}\npolyguard_active_connections {}\npolyguard_inflight_body_bytes {}\npolyguard_inflight_body_limit_bytes {}\n",
            runtime.metrics.accepted.load(Ordering::Relaxed), runtime.metrics.rejected.load(Ordering::Relaxed),
            runtime.metrics.disagreements.load(Ordering::Relaxed), runtime.metrics.upstream_failures.load(Ordering::Relaxed),
            runtime.metrics.timeouts.load(Ordering::Relaxed), runtime.metrics.telemetry_dropped.load(Ordering::Relaxed),
            runtime.metrics.active.load(Ordering::Relaxed), runtime.body_memory.used.load(Ordering::Relaxed), runtime.body_memory.limit.load(Ordering::Relaxed),
        ).into_bytes())),
        _ => None,
    }
}

fn write_simple_response<W: Write>(
    stream: &mut W,
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
    extern "C" fn reload(_: i32) {
        RELOAD.store(true, Ordering::SeqCst);
    }
    unsafe {
        signal(1, reload as *const () as usize);
        signal(2, stop as *const () as usize);
        signal(15, stop as *const () as usize);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    #[test]
    fn explicit_ipv4_and_ipv6_wildcards_can_share_a_port() {
        let ipv4 = bind_listener("0.0.0.0:0".parse().unwrap()).unwrap();
        let port = ipv4.local_addr().unwrap().port();
        let ipv6 = bind_listener(format!("[::]:{port}").parse().unwrap()).unwrap();
        assert!(socket2::SockRef::from(&ipv6).only_v6().unwrap());
        assert_eq!(ipv6.local_addr().unwrap().port(), port);
    }

    #[test]
    fn declared_body_limit_is_enforced_before_action_handling() {
        assert!(matches!(
            enforce_declared_body_limit(&BodyFraming::ContentLength(5), 4),
            Err(Fault::TooLarge)
        ));
        assert!(enforce_declared_body_limit(&BodyFraming::ContentLength(4), 4).is_ok());
        assert!(enforce_declared_body_limit(&BodyFraming::Chunked, 4).is_ok());
    }

    #[test]
    fn missing_static_resource_wins_over_method_rejection() {
        let directory = std::env::temp_dir().join(format!(
            "polyguard-static-method-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("index.html"), b"ok").unwrap();
        let directory = fs::canonicalize(&directory).unwrap();
        let route = RuntimeRoute {
            id: "static".into(),
            host: "example.test".into(),
            path: "/".into(),
            match_kind: RouteMatchKind::Prefix,
            methods: Vec::new(),
            schemes: Vec::new(),
            max_request_body_bytes: 1_024,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            deny: Vec::new(),
            action: RuntimeAction::Static {
                directory: directory.clone(),
                mapping: StaticMapping::Root,
                index: vec!["index.html".into()],
                try_files: true,
                error_page_404: None,
            },
            declaration_order: 0,
        };
        let target = |path: &str| NormalizedTarget {
            form: TargetForm::Origin,
            scheme: None,
            authority: None,
            path_and_query: path.into(),
            routing_path: path.into(),
        };
        let headers = HeaderBlock {
            fields: Vec::new(),
            bytes_consumed: 0,
        };
        let budget = MemoryBudget::new(1_024);
        let existing =
            serve_static(&route, &target("/"), "post", &headers, 1_024, &budget).unwrap();
        assert_eq!(existing.status, 405);
        let missing = serve_static(
            &route,
            &target("/missing"),
            "post",
            &headers,
            1_024,
            &budget,
        )
        .unwrap();
        assert_eq!(missing.status, 404);
        fs::remove_dir_all(directory).unwrap();
    }

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
    fn aggregate_body_memory_is_bounded_and_released() {
        let budget = MemoryBudget::new(8);
        let mut first = budget.reserve(5).unwrap();
        assert!(matches!(budget.reserve(4), Err(Fault::Busy)));
        first.grow(3).unwrap();
        assert!(matches!(budget.reserve(1), Err(Fault::Busy)));
        drop(first);
        let full = budget.reserve(8).unwrap();
        assert_eq!(budget.used.load(Ordering::Relaxed), 8);
        drop(full);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn static_file_reads_reserve_the_shared_body_budget_before_allocation() {
        let directory = std::env::temp_dir().join(format!(
            "polyguard-static-budget-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let file = directory.join("asset.txt");
        fs::write(&file, b"12345678").unwrap();
        let canonical_directory = fs::canonicalize(&directory).unwrap();
        let canonical_file = canonical_directory.join("asset.txt");
        let tight = MemoryBudget::new(4);
        assert!(matches!(
            read_static_file(&canonical_directory, &canonical_file, &[], false, 8, &tight),
            Err(Fault::Busy)
        ));
        let exact = MemoryBudget::new(8);
        let (_, body) =
            read_static_file(&canonical_directory, &canonical_file, &[], false, 8, &exact)
                .unwrap()
                .unwrap();
        assert_eq!(&body.bytes, b"12345678");
        assert_eq!(exact.used.load(Ordering::Relaxed), 8);
        drop(body);
        assert_eq!(exact.used.load(Ordering::Relaxed), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cidr_matching_handles_both_address_families_and_zero_prefixes() {
        assert!(
            IpNetwork::parse("192.0.2.0/24")
                .unwrap()
                .contains("192.0.2.42".parse().unwrap())
        );
        assert!(
            !IpNetwork::parse("192.0.2.0/24")
                .unwrap()
                .contains("192.0.3.1".parse().unwrap())
        );
        assert!(
            IpNetwork::parse("::/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert!(
            !IpNetwork::parse("0.0.0.0/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn templates_preserve_utf8_while_replacing_bounded_variables() {
        let context = TemplateContext {
            host: "app.example.test",
            http_host: "app.example.test:8443",
            remote_addr: "192.0.2.1",
            scheme: "https",
            request_uri: "/path",
            proxy_add_x_forwarded_for: "192.0.2.1",
        };
        assert_eq!(
            render_template(
                "café — $scheme://$host$request_uri",
                &context,
                MAX_HEADER_VALUE_BYTES,
            )
            .unwrap(),
            "café — https://app.example.test/path"
        );
        assert!(matches!(
            render_template("$request_uri$request_uri", &context, 9),
            Err(Fault::TooLarge)
        ));
    }

    #[test]
    fn action_route_selection_agrees_on_host_exact_path_method_and_scheme_priority() {
        let route = |host: &str,
                     path: &str,
                     match_kind: RouteMatchKind,
                     methods: &[&str],
                     schemes: &[&str],
                     order: usize| RuntimeRoute {
            id: format!("action-{order}"),
            host: host.into(),
            path: path.into(),
            match_kind,
            methods: methods.iter().map(|value| (*value).into()).collect(),
            schemes: schemes.iter().map(|value| (*value).into()).collect(),
            max_request_body_bytes: 1,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            deny: Vec::new(),
            action: RuntimeAction::Respond {
                status: 200,
                body: String::new(),
                content_type: "text/plain".into(),
            },
            declaration_order: order,
        };
        let routes = vec![
            route("*", "/", RouteMatchKind::Prefix, &[], &[], 0),
            route(
                "*.example.test",
                "/api/status",
                RouteMatchKind::Prefix,
                &[],
                &[],
                1,
            ),
            route(
                "app.example.test",
                "/api",
                RouteMatchKind::Prefix,
                &[],
                &["https"],
                2,
            ),
            route(
                "app.example.test",
                "/api/status",
                RouteMatchKind::Exact,
                &["get"],
                &["https"],
                3,
            ),
        ];
        let authority = EffectiveAuthority {
            host: "app.example.test".into(),
            port: None,
        };
        let target = NormalizedTarget {
            form: TargetForm::Origin,
            scheme: None,
            authority: None,
            path_and_query: "/api/status".into(),
            routing_path: "/api/status".into(),
        };
        assert_eq!(
            select_route_fold(&routes, &authority, &target, "get", "https"),
            Some(3)
        );
        assert_eq!(
            select_route_sorted(&routes, &authority, &target, "get", "https"),
            Some(3)
        );
        assert_eq!(
            select_route_fold(&routes, &authority, &target, "post", "http"),
            Some(1)
        );
    }

    #[test]
    fn gzip_is_negotiated_only_for_configured_types_and_round_trips() {
        let config = CompressionConfig {
            enabled: true,
            min_size_bytes: 1,
            types: vec!["text/plain".into()],
        };
        let body = b"repeated repeated repeated repeated";
        let compressed = gzip_body(&config, true, "text/plain; charset=utf-8", body)
            .unwrap()
            .unwrap();
        let mut decoder = GzDecoder::new(compressed.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
        assert!(
            gzip_body(&config, false, "text/plain", body)
                .unwrap()
                .is_none()
        );
        assert!(
            gzip_body(&config, true, "image/png", body)
                .unwrap()
                .is_none()
        );
        let encodings = |value: &[u8]| HeaderBlock {
            fields: vec![crate::HeaderField {
                name: "accept-encoding".into(),
                value: value.to_vec(),
            }],
            bytes_consumed: 0,
        };
        assert!(!client_accepts_gzip(&encodings(b"gzip;q=0, *;q=1")));
        assert!(client_accepts_gzip(&encodings(b"br, *;q=0.5")));
        assert!(!client_accepts_gzip(&encodings(b"gzip;q=0.0001")));

        let tight_budget = MemoryBudget::new(body.len());
        let mut body_permit = tight_budget.reserve(body.len()).unwrap();
        assert!(
            gzip_body_accounted(
                &config,
                true,
                "text/plain",
                body,
                &tight_budget,
                &mut body_permit,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn tls_configuration_rejects_mismatched_key_material() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["example.test".into()]).unwrap();
        let CertifiedKey {
            signing_key: wrong_key,
            ..
        } = generate_simple_self_signed(vec!["other.test".into()]).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "polyguard-tls-config-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let certificate_path = directory.join("certificate.pem");
        let key_path = directory.join("private-key.pem");
        fs::write(&certificate_path, cert.pem()).unwrap();
        fs::write(&key_path, wrong_key.serialize_pem()).unwrap();
        let settings = TlsConfig {
            certificate_chain_file: certificate_path.to_string_lossy().into_owned(),
            private_key_file: key_path.to_string_lossy().into_owned(),
            certificates: Vec::new(),
        };
        assert!(load_tls_config(Some(&settings)).is_err());
        fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        assert!(load_tls_config(Some(&settings)).unwrap().is_some());
        fs::remove_dir_all(directory).unwrap();
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
