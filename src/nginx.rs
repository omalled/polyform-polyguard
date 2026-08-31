//! Fail-closed loader for the bounded Nginx HTTP configuration subset that Polyguard supports.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::proxy::{
    ActionRouteConfig, AdditionalListenerConfig, CompressionConfig, Config, HeaderValueConfig,
    Limits, ListenerConfig, RouteActionConfig, RouteMatchKind, SiteConfig, StaticMapping,
    TlsCertificateConfig, TlsConfig, UpstreamConfig,
};

const MAX_CONFIG_BYTES: usize = 32 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 16;
const MAX_INCLUDED_FILES: usize = 1_024;

#[derive(Debug)]
pub enum NginxError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Syntax {
        path: PathBuf,
        line: usize,
        message: String,
    },
    Unsupported(Vec<CompatibilityIssue>),
    Invalid(String),
}

impl fmt::Display for NginxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Syntax {
                path,
                line,
                message,
            } => {
                write!(formatter, "{}:{line}: {message}", path.display())
            }
            Self::Unsupported(issues) => {
                write!(
                    formatter,
                    "Nginx configuration uses {} unsupported directive(s)",
                    issues.len()
                )
            }
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for NginxError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityIssue {
    pub path: PathBuf,
    pub line: usize,
    pub directive: String,
    pub message: String,
}

impl fmt::Display for CompatibilityIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: {}: {}",
            self.path.display(),
            self.line,
            self.directive,
            self.message
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Directive {
    name: String,
    args: Vec<String>,
    children: Vec<Directive>,
    path: PathBuf,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    LeftBrace,
    RightBrace,
    Semicolon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

fn tokenize(path: &Path, source: &str) -> Result<Vec<Token>, NginxError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut offset = 0;
    let mut line = 1;
    while offset < bytes.len() {
        match bytes[offset] {
            b' ' | b'\t' | b'\r' => offset += 1,
            b'\n' => {
                line += 1;
                offset += 1;
            }
            b'#' => {
                while offset < bytes.len() && bytes[offset] != b'\n' {
                    offset += 1;
                }
            }
            b'{' => {
                tokens.push(Token {
                    kind: TokenKind::LeftBrace,
                    line,
                });
                offset += 1;
            }
            b'}' => {
                tokens.push(Token {
                    kind: TokenKind::RightBrace,
                    line,
                });
                offset += 1;
            }
            b';' => {
                tokens.push(Token {
                    kind: TokenKind::Semicolon,
                    line,
                });
                offset += 1;
            }
            _ => {
                let token_line = line;
                let mut value = Vec::new();
                let quote = match bytes[offset] {
                    b'\'' | b'"' => {
                        let quote = bytes[offset];
                        offset += 1;
                        Some(quote)
                    }
                    _ => None,
                };
                loop {
                    if offset >= bytes.len() {
                        if quote.is_some() {
                            return Err(NginxError::Syntax {
                                path: path.to_path_buf(),
                                line: token_line,
                                message: "unterminated quoted value".into(),
                            });
                        }
                        break;
                    }
                    let byte = bytes[offset];
                    if quote == Some(byte) {
                        offset += 1;
                        break;
                    }
                    if quote.is_none()
                        && matches!(
                            byte,
                            b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b';' | b'#'
                        )
                    {
                        break;
                    }
                    if byte == b'\\' {
                        offset += 1;
                        let Some(escaped) = bytes.get(offset).copied() else {
                            return Err(NginxError::Syntax {
                                path: path.to_path_buf(),
                                line: token_line,
                                message: "trailing escape".into(),
                            });
                        };
                        value.push(escaped);
                        if escaped == b'\n' {
                            line += 1;
                        }
                        offset += 1;
                        continue;
                    }
                    value.push(byte);
                    if byte == b'\n' {
                        line += 1;
                    }
                    offset += 1;
                }
                let value = String::from_utf8(value).map_err(|_| NginxError::Syntax {
                    path: path.to_path_buf(),
                    line: token_line,
                    message: "configuration values must be UTF-8".into(),
                })?;
                if value.is_empty() && quote.is_none() {
                    continue;
                }
                tokens.push(Token {
                    kind: TokenKind::Word(value),
                    line: token_line,
                });
            }
        }
    }
    Ok(tokens)
}

fn parse_directives(path: &Path, tokens: &[Token]) -> Result<Vec<Directive>, NginxError> {
    fn parse_block(
        path: &Path,
        tokens: &[Token],
        offset: &mut usize,
        nested: bool,
    ) -> Result<Vec<Directive>, NginxError> {
        let mut directives = Vec::new();
        while *offset < tokens.len() {
            if tokens[*offset].kind == TokenKind::RightBrace {
                if !nested {
                    return Err(NginxError::Syntax {
                        path: path.to_path_buf(),
                        line: tokens[*offset].line,
                        message: "unexpected closing brace".into(),
                    });
                }
                *offset += 1;
                return Ok(directives);
            }
            let TokenKind::Word(name) = &tokens[*offset].kind else {
                return Err(NginxError::Syntax {
                    path: path.to_path_buf(),
                    line: tokens[*offset].line,
                    message: "expected directive name".into(),
                });
            };
            let line = tokens[*offset].line;
            let name = name.clone();
            *offset += 1;
            let mut args = Vec::new();
            loop {
                let Some(token) = tokens.get(*offset) else {
                    return Err(NginxError::Syntax {
                        path: path.to_path_buf(),
                        line,
                        message: format!("directive {name} is missing a terminator"),
                    });
                };
                match &token.kind {
                    TokenKind::Word(value) => {
                        args.push(value.clone());
                        *offset += 1;
                    }
                    TokenKind::Semicolon => {
                        *offset += 1;
                        directives.push(Directive {
                            name,
                            args,
                            children: Vec::new(),
                            path: path.to_path_buf(),
                            line,
                        });
                        break;
                    }
                    TokenKind::LeftBrace => {
                        *offset += 1;
                        let children = parse_block(path, tokens, offset, true)?;
                        directives.push(Directive {
                            name,
                            args,
                            children,
                            path: path.to_path_buf(),
                            line,
                        });
                        break;
                    }
                    TokenKind::RightBrace => {
                        return Err(NginxError::Syntax {
                            path: path.to_path_buf(),
                            line: token.line,
                            message: format!("directive {name} is missing a terminator"),
                        });
                    }
                }
            }
        }
        if nested {
            return Err(NginxError::Syntax {
                path: path.to_path_buf(),
                line: tokens.last().map_or(1, |token| token.line),
                message: "unterminated block".into(),
            });
        }
        Ok(directives)
    }

    let mut offset = 0;
    parse_block(path, tokens, &mut offset, false)
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let (mut pattern_offset, mut value_offset) = (0, 0);
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut star, mut checkpoint) = (None, 0);
    while value_offset < value.len() {
        if pattern.get(pattern_offset) == Some(&b'?')
            || pattern.get(pattern_offset) == value.get(value_offset)
        {
            pattern_offset += 1;
            value_offset += 1;
        } else if pattern.get(pattern_offset) == Some(&b'*') {
            star = Some(pattern_offset);
            pattern_offset += 1;
            checkpoint = value_offset;
        } else if let Some(star_offset) = star {
            pattern_offset = star_offset + 1;
            checkpoint += 1;
            value_offset = checkpoint;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_offset) == Some(&b'*') {
        pattern_offset += 1;
    }
    pattern_offset == pattern.len()
}

fn expand_include(pattern: &Path) -> Result<Vec<PathBuf>, NginxError> {
    let text = pattern.to_string_lossy();
    if !text.contains(['*', '?']) {
        return Ok(vec![pattern.to_path_buf()]);
    }
    let parent = pattern.parent().unwrap_or_else(|| Path::new("."));
    if parent.to_string_lossy().contains(['*', '?']) {
        return Err(NginxError::Invalid(format!(
            "include wildcard directories are unsupported: {}",
            pattern.display()
        )));
    }
    let file_pattern = pattern
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NginxError::Invalid("include pattern must be UTF-8".into()))?;
    let mut matches = fs::read_dir(parent)
        .map_err(|source| NginxError::Io {
            path: parent.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok)
        .filter(|entry| wildcard_matches(file_pattern, &entry.file_name().to_string_lossy()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    matches.sort();
    Ok(matches)
}

struct Loader {
    prefix: PathBuf,
    stack: BTreeSet<PathBuf>,
    files: usize,
    total_bytes: usize,
}

impl Loader {
    fn load(path: &Path) -> Result<Vec<Directive>, NginxError> {
        let canonical = fs::canonicalize(path).map_err(|source| NginxError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut loader = Self {
            prefix: canonical
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            stack: BTreeSet::new(),
            files: 0,
            total_bytes: 0,
        };
        loader.load_file(&canonical, 0)
    }

    fn load_file(&mut self, path: &Path, depth: usize) -> Result<Vec<Directive>, NginxError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(NginxError::Invalid("Nginx include depth exceeds 16".into()));
        }
        let canonical = fs::canonicalize(path).map_err(|source| NginxError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !self.stack.insert(canonical.clone()) {
            return Err(NginxError::Invalid(format!(
                "Nginx include cycle: {}",
                canonical.display()
            )));
        }
        self.files += 1;
        if self.files > MAX_INCLUDED_FILES {
            return Err(NginxError::Invalid(
                "Nginx configuration includes too many files".into(),
            ));
        }
        let source = fs::read_to_string(&canonical).map_err(|source| NginxError::Io {
            path: canonical.clone(),
            source,
        })?;
        self.total_bytes = self.total_bytes.saturating_add(source.len());
        if self.total_bytes > MAX_CONFIG_BYTES {
            return Err(NginxError::Invalid(
                "Nginx configuration exceeds 32 MiB".into(),
            ));
        }
        let tokens = tokenize(&canonical, &source)?;
        let directives = parse_directives(&canonical, &tokens)?;
        let result = self.expand_directives(directives, depth);
        self.stack.remove(&canonical);
        result
    }

    fn expand_directives(
        &mut self,
        directives: Vec<Directive>,
        depth: usize,
    ) -> Result<Vec<Directive>, NginxError> {
        let mut expanded = Vec::new();
        for mut directive in directives {
            if directive.name == "include" {
                if directive.args.len() != 1 || !directive.children.is_empty() {
                    return Err(NginxError::Syntax {
                        path: directive.path,
                        line: directive.line,
                        message: "include requires exactly one path".into(),
                    });
                }
                let requested = Path::new(&directive.args[0]);
                let pattern = if requested.is_absolute() {
                    requested.to_path_buf()
                } else {
                    self.prefix.join(requested)
                };
                for path in expand_include(&pattern)? {
                    expanded.extend(self.load_file(&path, depth + 1)?);
                }
                continue;
            }
            directive.children = self.expand_directives(directive.children, depth)?;
            expanded.push(directive);
        }
        Ok(expanded)
    }
}

pub fn parse(path: &Path) -> Result<(), NginxError> {
    Loader::load(path).map(|_| ())
}

pub fn compatibility_issues(path: &Path) -> Result<Vec<CompatibilityIssue>, NginxError> {
    let directives = Loader::load(path)?;
    let mut translator = Translator::default();
    translator.inspect_root(&directives);
    Ok(translator.issues)
}

pub fn load_config(path: &Path) -> Result<Config, NginxError> {
    let directives = Loader::load(path)?;
    let mut translator = Translator::default();
    let config = translator.translate(&directives)?;
    if translator.issues.is_empty() {
        Ok(config)
    } else {
        Err(NginxError::Unsupported(translator.issues))
    }
}

#[derive(Debug, Clone)]
struct ListenSpec {
    address: SocketAddr,
    tls: bool,
    default: bool,
}

#[derive(Debug, Clone)]
struct ServerSpec {
    names: Vec<String>,
    listens: Vec<ListenSpec>,
    certificate: Option<String>,
    private_key: Option<String>,
    root: Option<String>,
    indexes: Vec<String>,
    error_page_404: Option<String>,
    response_headers: Vec<HeaderValueConfig>,
    deny: Vec<String>,
    max_request_body_bytes: Option<usize>,
    returns: Vec<ActionRouteConfig>,
    host_returns: BTreeMap<String, Vec<ActionRouteConfig>>,
    locations: Vec<ActionRouteConfig>,
}

#[derive(Debug)]
struct ListenerBuild {
    address: SocketAddr,
    tls: bool,
    certificates: Vec<TlsCertificateConfig>,
    has_default: bool,
}

fn parse_size(value: &str) -> Option<usize> {
    let split = value
        .find(|byte: char| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split].parse::<usize>().ok()?;
    let multiplier = match value[split..].to_ascii_lowercase().as_str() {
        "" => 1,
        "k" => 1_024,
        "m" => 1_024 * 1_024,
        "g" => 1_024 * 1_024 * 1_024,
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn parse_listen(directive: &Directive) -> Option<ListenSpec> {
    let endpoint = directive.args.first()?;
    if directive.args.iter().skip(1).any(|argument| {
        !matches!(
            argument.as_str(),
            "ssl" | "default" | "default_server" | "ipv6only=on"
        )
    }) {
        return None;
    }
    let address = if endpoint.chars().all(|character| character.is_ascii_digit()) {
        format!("0.0.0.0:{endpoint}").parse().ok()?
    } else if let Some(port) = endpoint.strip_prefix("*:") {
        format!("0.0.0.0:{port}").parse().ok()?
    } else {
        endpoint.parse().ok()?
    };
    Some(ListenSpec {
        address,
        tls: directive
            .args
            .iter()
            .skip(1)
            .any(|argument| argument == "ssl"),
        default: directive
            .args
            .iter()
            .skip(1)
            .any(|argument| matches!(argument.as_str(), "default" | "default_server")),
    })
}

fn header_from_add(directive: &Directive, methods: Vec<String>) -> Option<HeaderValueConfig> {
    if !(2..=3).contains(&directive.args.len()) {
        return None;
    }
    Some(HeaderValueConfig {
        name: directive.args[0].to_ascii_lowercase(),
        value: directive.args[1].clone(),
        always: directive
            .args
            .get(2)
            .is_some_and(|argument| argument == "always"),
        methods,
    })
}

fn return_action(directive: &Directive) -> Option<RouteActionConfig> {
    let status = directive.args.first()?.parse::<u16>().ok()?;
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        Some(RouteActionConfig::Redirect {
            status,
            location: directive.args.get(1)?.clone(),
        })
    } else if (200..=599).contains(&status) && directive.args.len() <= 2 {
        Some(RouteActionConfig::Respond {
            status,
            body: directive.args.get(1).cloned().unwrap_or_default(),
            content_type: "text/plain; charset=utf-8".into(),
        })
    } else {
        None
    }
}

fn if_condition(directive: &Directive) -> Option<(String, String, String)> {
    let mut parts = directive.args.clone();
    let first = parts.first_mut()?;
    if first == "(" {
        parts.remove(0);
    } else {
        *first = first.strip_prefix('(')?.to_owned();
    }
    let last = parts.last_mut()?;
    if last == ")" {
        parts.pop();
    } else {
        *last = last.strip_suffix(')')?.to_owned();
    }
    let [variable, operator, value] = parts.as_slice() else {
        return None;
    };
    Some((variable.clone(), operator.clone(), value.clone()))
}

fn parse_proxy_pass(value: &str) -> Option<(SocketAddr, Option<String>)> {
    let remainder = value.strip_prefix("http://")?;
    let (authority, uri) = remainder
        .split_once('/')
        .map_or((remainder, None), |(authority, path)| {
            (authority, Some(format!("/{path}")))
        });
    if uri.as_deref().is_some_and(|uri| uri.contains(['?', '#'])) {
        return None;
    }
    Some((authority.parse().ok()?, uri))
}

fn inherited<'a>(directives: &'a [Directive], name: &str) -> impl Iterator<Item = &'a Directive> {
    directives
        .iter()
        .filter(move |directive| directive.name == name)
}

#[derive(Default)]
struct Translator {
    issues: Vec<CompatibilityIssue>,
}

impl Translator {
    fn issue(&mut self, directive: &Directive, message: impl Into<String>) {
        self.issues.push(CompatibilityIssue {
            path: directive.path.clone(),
            line: directive.line,
            directive: directive.name.clone(),
            message: message.into(),
        });
    }

    fn parse_location(
        &mut self,
        directive: &Directive,
        server: &ServerSpec,
        upstream_names: &mut BTreeMap<SocketAddr, String>,
    ) -> Option<Vec<ActionRouteConfig>> {
        let (match_kind, path) = match directive.args.as_slice() {
            [path] if path.starts_with('/') => (RouteMatchKind::Prefix, path.clone()),
            [operator, path] if operator == "=" && path.starts_with('/') => {
                (RouteMatchKind::Exact, path.clone())
            }
            [operator, path] if operator == "^~" && path.starts_with('/') => {
                (RouteMatchKind::Prefix, path.clone())
            }
            _ => {
                self.issue(directive, "only exact and prefix locations are supported");
                return None;
            }
        };
        let mut root = server.root.clone();
        let mut mapping = StaticMapping::Root;
        let mut indexes = server.indexes.clone();
        let mut try_files = false;
        let mut response_headers = if directive
            .children
            .iter()
            .any(|child| child.name == "add_header")
        {
            Vec::new()
        } else {
            server.response_headers.clone()
        };
        let mut request_headers = Vec::new();
        let mut deny = server.deny.clone();
        let mut max_request_body_bytes = server.max_request_body_bytes;
        let mut proxy = None;
        let mut host_header = None;
        let mut action = None;
        let mut conditional_routes = Vec::new();

        for child in &directive.children {
            match child.name.as_str() {
                "root" if child.args.len() == 1 => {
                    root = Some(child.args[0].clone());
                    mapping = StaticMapping::Root;
                }
                "alias" if child.args.len() == 1 => {
                    root = Some(child.args[0].clone());
                    mapping = StaticMapping::Alias;
                }
                "index" if !child.args.is_empty() => indexes = child.args.clone(),
                "try_files"
                    if child.args == ["$uri".to_owned(), "$uri/".to_owned(), "=404".to_owned()] =>
                {
                    try_files = true;
                }
                "try_files" => self.issue(child, "only `try_files $uri $uri/ =404` is supported"),
                "client_max_body_size" if child.args.len() == 1 => {
                    max_request_body_bytes = parse_size(&child.args[0]);
                    if max_request_body_bytes.is_none() {
                        self.issue(child, "invalid client_max_body_size");
                    }
                }
                "proxy_pass" if child.args.len() == 1 => {
                    let Some((address, replacement)) = parse_proxy_pass(&child.args[0]) else {
                        self.issue(
                            child,
                            "proxy_pass must use a literal cleartext HTTP socket address",
                        );
                        continue;
                    };
                    let next = upstream_names.len();
                    let name = upstream_names
                        .entry(address)
                        .or_insert_with(|| format!("nginx-upstream-{next}"))
                        .clone();
                    proxy = Some((name, replacement));
                }
                "proxy_set_header" if child.args.len() == 2 => {
                    let name = child.args[0].to_ascii_lowercase();
                    let value = child.args[1].clone();
                    match name.as_str() {
                        "host" if matches!(value.as_str(), "$host" | "$http_host") => {
                            host_header = Some(value)
                        }
                        "x-forwarded-for" if value == "$proxy_add_x_forwarded_for" => {}
                        "x-forwarded-proto" if value == "$scheme" => {}
                        "x-forwarded-host" if matches!(value.as_str(), "$host" | "$http_host") => {}
                        "forwarded" => self.issue(
                            child,
                            "Forwarded is security-managed and cannot be overridden",
                        ),
                        _ => request_headers.push(HeaderValueConfig {
                            name,
                            value,
                            always: false,
                            methods: Vec::new(),
                        }),
                    }
                }
                "proxy_set_header" => {
                    self.issue(child, "proxy_set_header requires a name and value")
                }
                "proxy_http_version" if child.args == ["1.1"] => {}
                "proxy_http_version" => {
                    self.issue(child, "only HTTP/1.1 upstream requests are supported")
                }
                "proxy_redirect" if child.args == ["off"] => {}
                "proxy_redirect" => self.issue(child, "only `proxy_redirect off` is supported"),
                "add_header" => match header_from_add(child, Vec::new()) {
                    Some(header) => response_headers.push(header),
                    None => self.issue(
                        child,
                        "add_header requires a name, value, and optional always",
                    ),
                },
                "deny" if child.args.len() == 1 && child.args[0] != "all" => {
                    deny.push(child.args[0].clone())
                }
                "deny" if child.args == ["all"] => {
                    deny.push("0.0.0.0/0".into());
                    deny.push("::/0".into());
                }
                "deny" => self.issue(child, "deny requires one IP address, CIDR, or all"),
                "return" => match return_action(child) {
                    Some(returned) => action = Some(returned),
                    None => self.issue(child, "unsupported return status or arguments"),
                },
                "if" => {
                    let Some((variable, operator, value)) = if_condition(child) else {
                        self.issue(child, "unsupported if condition");
                        continue;
                    };
                    if variable != "$request_method" || operator != "=" {
                        self.issue(child, "locations only support request-method conditions");
                        continue;
                    }
                    let methods = vec![value];
                    let mut conditional_headers = Vec::new();
                    let mut conditional_action = None;
                    let mut conditional_content_type = None;
                    for nested in &child.children {
                        match nested.name.as_str() {
                            "add_header" => match header_from_add(nested, methods.clone()) {
                                Some(header)
                                    if header.name == "content-length" && header.value == "0" => {}
                                Some(header) if header.name == "content-type" => {
                                    conditional_content_type = Some(header.value)
                                }
                                Some(header) => conditional_headers.push(header),
                                None => self.issue(nested, "invalid conditional add_header"),
                            },
                            "return" => match return_action(nested) {
                                Some(returned) => conditional_action = Some(returned),
                                None => self.issue(nested, "unsupported conditional return"),
                            },
                            _ => self.issue(nested, "unsupported directive inside location if"),
                        }
                    }
                    if let Some(mut conditional_action) = conditional_action {
                        if let (RouteActionConfig::Respond { content_type, .. }, Some(configured)) =
                            (&mut conditional_action, conditional_content_type)
                        {
                            *content_type = configured;
                        }
                        conditional_routes.push(ActionRouteConfig {
                            path: path.clone(),
                            match_kind,
                            methods,
                            schemes: Vec::new(),
                            max_request_body_bytes,
                            request_headers: request_headers.clone(),
                            response_headers: conditional_headers,
                            deny: Vec::new(),
                            action: conditional_action,
                        });
                    } else if !conditional_headers.is_empty() {
                        let faithfully_inherited = conditional_headers.len()
                            == response_headers.len()
                            && conditional_headers.iter().all(|conditional| {
                                response_headers.iter().any(|inherited| {
                                    inherited.name == conditional.name
                                        && inherited.value == conditional.value
                                        && inherited.always == conditional.always
                                })
                            });
                        if response_headers.is_empty() {
                            response_headers.extend(conditional_headers);
                        } else if !faithfully_inherited {
                            self.issue(
                                child,
                                "conditional add_header overrides cannot be represented unless they exactly match the inherited header set",
                            );
                        }
                    }
                }
                "root" | "alias" | "index" | "client_max_body_size" | "proxy_pass" => {
                    self.issue(child, "invalid or unsupported directive arguments")
                }
                _ => {}
            }
        }

        for route in &mut conditional_routes {
            let conditional_headers = std::mem::take(&mut route.response_headers);
            route.response_headers = if conditional_headers.is_empty() {
                response_headers.clone()
            } else {
                conditional_headers
            };
        }

        let explicit_return = action.is_some();
        if explicit_return {
            deny.clear();
        }
        let action = action.or_else(|| {
            proxy.map(|(upstream, replace_prefix)| RouteActionConfig::Proxy {
                upstream,
                replace_prefix,
                host_header,
            })
        });
        let action = match action {
            Some(action) => action,
            None => {
                let Some(directory) = root else {
                    self.issue(directive, "location has no proxy, response, or static root");
                    return None;
                };
                RouteActionConfig::Static {
                    directory,
                    mapping,
                    index: if indexes.is_empty() {
                        vec!["index.html".into()]
                    } else {
                        indexes
                    },
                    try_files,
                    error_page_404: server.error_page_404.clone(),
                }
            }
        };
        conditional_routes.push(ActionRouteConfig {
            path,
            match_kind,
            methods: Vec::new(),
            schemes: Vec::new(),
            max_request_body_bytes,
            request_headers,
            response_headers,
            deny,
            action,
        });
        Some(conditional_routes)
    }

    fn parse_server(
        &mut self,
        directive: &Directive,
        upstream_names: &mut BTreeMap<SocketAddr, String>,
        http_max_request_body_bytes: Option<usize>,
    ) -> Option<ServerSpec> {
        let mut server = ServerSpec {
            names: Vec::new(),
            listens: Vec::new(),
            certificate: None,
            private_key: None,
            root: None,
            indexes: vec!["index.html".into()],
            error_page_404: None,
            response_headers: Vec::new(),
            deny: Vec::new(),
            max_request_body_bytes: http_max_request_body_bytes,
            returns: Vec::new(),
            host_returns: BTreeMap::new(),
            locations: Vec::new(),
        };
        for child in &directive.children {
            match child.name.as_str() {
                "listen" => match parse_listen(child) {
                    Some(listen) => server.listens.push(listen),
                    None => self.issue(child, "unsupported listen address"),
                },
                "server_name" if !child.args.is_empty() => {
                    for name in &child.args {
                        if name == "_" {
                            continue;
                        } else if name.starts_with('~') || name.contains('$') {
                            self.issue(child, "regex and variable server names are unsupported");
                        } else {
                            server
                                .names
                                .push(name.trim_end_matches('.').to_ascii_lowercase());
                        }
                    }
                }
                "root" if child.args.len() == 1 => server.root = Some(child.args[0].clone()),
                "index" if !child.args.is_empty() => server.indexes = child.args.clone(),
                "error_page" if child.args.len() == 2 && child.args[0] == "404" => {
                    server.error_page_404 = Some(child.args[1].clone())
                }
                "client_max_body_size" if child.args.len() == 1 => {
                    server.max_request_body_bytes = parse_size(&child.args[0]);
                    if server.max_request_body_bytes.is_none() {
                        self.issue(child, "invalid client_max_body_size");
                    }
                }
                "ssl_certificate" if child.args.len() == 1 => {
                    server.certificate = Some(child.args[0].clone())
                }
                "ssl_certificate_key" if child.args.len() == 1 => {
                    server.private_key = Some(child.args[0].clone())
                }
                "add_header" => match header_from_add(child, Vec::new()) {
                    Some(header) => server.response_headers.push(header),
                    None => self.issue(child, "invalid add_header"),
                },
                "deny" if child.args.len() == 1 && child.args[0] != "all" => {
                    server.deny.push(child.args[0].clone())
                }
                "deny" if child.args == ["all"] => {
                    server.deny.push("0.0.0.0/0".into());
                    server.deny.push("::/0".into());
                }
                "return" => match return_action(child) {
                    Some(action) => server.returns.push(ActionRouteConfig {
                        path: "/".into(),
                        match_kind: RouteMatchKind::Prefix,
                        methods: Vec::new(),
                        schemes: Vec::new(),
                        max_request_body_bytes: None,
                        request_headers: Vec::new(),
                        response_headers: server.response_headers.clone(),
                        deny: Vec::new(),
                        action,
                    }),
                    None => self.issue(child, "unsupported server return"),
                },
                "if" => {
                    let Some((variable, operator, value)) = if_condition(child) else {
                        self.issue(child, "unsupported server if condition");
                        continue;
                    };
                    if variable != "$host" || operator != "=" {
                        self.issue(child, "servers only support host equality conditions");
                        continue;
                    }
                    for nested in &child.children {
                        if nested.name == "return" {
                            if let Some(action) = return_action(nested) {
                                server.host_returns.entry(value.clone()).or_default().push(
                                    ActionRouteConfig {
                                        path: "/".into(),
                                        match_kind: RouteMatchKind::Prefix,
                                        methods: Vec::new(),
                                        schemes: Vec::new(),
                                        max_request_body_bytes: None,
                                        request_headers: Vec::new(),
                                        response_headers: server.response_headers.clone(),
                                        deny: Vec::new(),
                                        action,
                                    },
                                );
                            } else {
                                self.issue(nested, "unsupported return inside host condition");
                            }
                        }
                    }
                }
                "server_name"
                | "root"
                | "index"
                | "error_page"
                | "client_max_body_size"
                | "ssl_certificate"
                | "ssl_certificate_key" => {
                    self.issue(child, "invalid or unsupported directive arguments")
                }
                _ => {}
            }
        }
        if server.listens.is_empty() {
            server.listens.push(ListenSpec {
                address: "0.0.0.0:80".parse().expect("literal socket"),
                tls: false,
                default: false,
            });
        }
        for route in server
            .returns
            .iter_mut()
            .chain(server.host_returns.values_mut().flatten())
        {
            route.response_headers = server.response_headers.clone();
            route.deny.clear();
            route.max_request_body_bytes = server.max_request_body_bytes;
        }
        let schemes = server
            .listens
            .iter()
            .map(|listen| if listen.tls { "https" } else { "http" }.to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for route in server
            .returns
            .iter_mut()
            .chain(server.host_returns.values_mut().flatten())
        {
            route.schemes = schemes.clone();
        }
        let snapshot = server.clone();
        for child in &directive.children {
            if child.name == "location"
                && let Some(mut routes) = self.parse_location(child, &snapshot, upstream_names)
            {
                for route in &mut routes {
                    route.schemes = schemes.clone();
                }
                server.locations.extend(routes);
            }
        }
        Some(server)
    }

    fn inspect_root(&mut self, directives: &[Directive]) {
        for directive in directives {
            match directive.name.as_str() {
                "user" | "worker_processes" | "pid" | "load_module" => {}
                "events" => self.inspect_events(&directive.children),
                "http" => self.inspect_http(&directive.children),
                _ => self.issue(directive, "unsupported top-level directive"),
            }
        }
    }

    fn inspect_events(&mut self, directives: &[Directive]) {
        for directive in directives {
            if !matches!(
                directive.name.as_str(),
                "worker_connections" | "multi_accept"
            ) {
                self.issue(directive, "unsupported events directive");
            }
        }
    }

    fn inspect_http(&mut self, directives: &[Directive]) {
        for directive in directives {
            match directive.name.as_str() {
                "sendfile"
                | "tcp_nopush"
                | "tcp_nodelay"
                | "keepalive_timeout"
                | "types_hash_max_size"
                | "server_names_hash_bucket_size"
                | "default_type"
                | "client_max_body_size"
                | "ssl_protocols"
                | "ssl_prefer_server_ciphers"
                | "ssl_ciphers"
                | "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_session_tickets"
                | "access_log"
                | "error_log"
                | "gzip"
                | "gzip_vary"
                | "gzip_proxied"
                | "gzip_comp_level"
                | "gzip_buffers"
                | "gzip_http_version"
                | "gzip_min_length"
                | "gzip_types"
                | "log_format" => {}
                "types" => {}
                "server" => self.inspect_server(&directive.children),
                _ => self.issue(directive, "unsupported HTTP directive"),
            }
        }
    }

    fn inspect_server(&mut self, directives: &[Directive]) {
        for directive in directives {
            match directive.name.as_str() {
                "listen"
                | "server_name"
                | "root"
                | "index"
                | "error_page"
                | "client_max_body_size"
                | "ssl_certificate"
                | "ssl_certificate_key"
                | "ssl_dhparam"
                | "ssl_protocols"
                | "ssl_prefer_server_ciphers"
                | "ssl_ciphers"
                | "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_session_tickets"
                | "add_header"
                | "deny"
                | "return" => {}
                "location" => self.inspect_location(&directive.children),
                "if" => self.inspect_if(directive),
                _ => self.issue(directive, "unsupported server directive"),
            }
        }
    }

    fn inspect_location(&mut self, directives: &[Directive]) {
        for directive in directives {
            match directive.name.as_str() {
                "proxy_pass"
                | "proxy_http_version"
                | "proxy_set_header"
                | "proxy_redirect"
                | "root"
                | "alias"
                | "index"
                | "try_files"
                | "client_max_body_size"
                | "add_header"
                | "deny"
                | "return" => {}
                "if" => self.inspect_if(directive),
                _ => self.issue(directive, "unsupported location directive"),
            }
        }
    }

    fn inspect_if(&mut self, directive: &Directive) {
        let supported_condition = if_condition(directive).is_some_and(|(variable, operator, _)| {
            matches!(variable.as_str(), "$host" | "$request_method") && operator == "="
        });
        if !supported_condition {
            self.issue(
                directive,
                "only equality checks for $host or $request_method are supported",
            );
        }
        for child in &directive.children {
            if !matches!(child.name.as_str(), "add_header" | "return") {
                self.issue(child, "unsupported directive inside if");
            }
        }
    }

    fn translate(&mut self, directives: &[Directive]) -> Result<Config, NginxError> {
        self.inspect_root(directives);
        if !self.issues.is_empty() {
            return Err(NginxError::Unsupported(self.issues.clone()));
        }
        let http_blocks = directives
            .iter()
            .filter(|directive| directive.name == "http")
            .collect::<Vec<_>>();
        let [http] = http_blocks.as_slice() else {
            return Err(NginxError::Invalid(
                "Nginx configuration must contain exactly one http block".into(),
            ));
        };

        let gzip_enabled = inherited(&http.children, "gzip")
            .last()
            .and_then(|directive| directive.args.first())
            .is_some_and(|value| value == "on");
        let mut gzip_types = inherited(&http.children, "gzip_types")
            .last()
            .map(|directive| directive.args.clone())
            .unwrap_or_default();
        if !gzip_types.iter().any(|item| item == "text/html") {
            gzip_types.push("text/html".into());
        }
        let gzip_min_size =
            if let Some(directive) = inherited(&http.children, "gzip_min_length").last() {
                if directive.args.len() != 1 {
                    return Err(NginxError::Invalid("invalid gzip_min_length".into()));
                }
                parse_size(&directive.args[0])
                    .ok_or_else(|| NginxError::Invalid("invalid gzip_min_length".into()))?
            } else {
                20
            };
        let compression = CompressionConfig {
            enabled: gzip_enabled,
            min_size_bytes: gzip_min_size,
            types: gzip_types,
        };

        let http_max_request_body_bytes =
            if let Some(directive) = inherited(&http.children, "client_max_body_size").last() {
                if directive.args.len() != 1 {
                    return Err(NginxError::Invalid(
                        "invalid HTTP client_max_body_size".into(),
                    ));
                }
                Some(parse_size(&directive.args[0]).ok_or_else(|| {
                    NginxError::Invalid("invalid HTTP client_max_body_size".into())
                })?)
            } else {
                Some(1_024 * 1_024)
            };

        let mut upstream_names = BTreeMap::new();
        let mut servers = Vec::new();
        for directive in &http.children {
            if directive.name == "server"
                && let Some(server) =
                    self.parse_server(directive, &mut upstream_names, http_max_request_body_bytes)
            {
                servers.push(server);
            }
        }
        if !self.issues.is_empty() {
            return Err(NginxError::Unsupported(self.issues.clone()));
        }
        if servers.is_empty() {
            return Err(NginxError::Invalid(
                "Nginx http block contains no server blocks".into(),
            ));
        }

        let mut default_owners = BTreeMap::<SocketAddr, (usize, bool)>::new();
        for (server_index, server) in servers.iter().enumerate() {
            for listen in &server.listens {
                match default_owners.get(&listen.address).copied() {
                    None => {
                        default_owners.insert(listen.address, (server_index, listen.default));
                    }
                    Some((owner, true)) if listen.default && owner != server_index => {
                        return Err(NginxError::Invalid(format!(
                            "listener {} has more than one default server",
                            listen.address
                        )));
                    }
                    Some((_, false)) if listen.default => {
                        default_owners.insert(listen.address, (server_index, true));
                    }
                    _ => {}
                }
            }
        }

        let mut listener_builds = BTreeMap::<SocketAddr, ListenerBuild>::new();
        for server in &servers {
            for listen in &server.listens {
                let build =
                    listener_builds
                        .entry(listen.address)
                        .or_insert_with(|| ListenerBuild {
                            address: listen.address,
                            tls: listen.tls,
                            certificates: Vec::new(),
                            has_default: false,
                        });
                if build.tls != listen.tls {
                    return Err(NginxError::Invalid(format!(
                        "listener {} mixes TLS and cleartext server blocks",
                        listen.address
                    )));
                }
                if listen.tls {
                    let (Some(certificate), Some(private_key)) =
                        (&server.certificate, &server.private_key)
                    else {
                        return Err(NginxError::Invalid(format!(
                            "TLS server on {} has no certificate/key pair",
                            listen.address
                        )));
                    };
                    let is_default = listen.default;
                    build.has_default |= is_default;
                    build.certificates.push(TlsCertificateConfig {
                        server_names: server.names.clone(),
                        certificate_chain_file: certificate.clone(),
                        private_key_file: private_key.clone(),
                        default: is_default,
                    });
                }
            }
        }
        for build in listener_builds.values_mut().filter(|build| build.tls) {
            if !build.has_default
                && let Some(first) = build.certificates.first_mut()
            {
                first.default = true;
                build.has_default = true;
            }
        }

        let mut sites = BTreeMap::<String, SiteConfig>::new();
        let mut assignments = BTreeMap::<(String, String), Vec<ActionRouteConfig>>::new();
        for (server_index, server) in servers.into_iter().enumerate() {
            let schemes = server
                .listens
                .iter()
                .map(|listen| if listen.tls { "https" } else { "http" })
                .collect::<BTreeSet<_>>();
            let mut key_scopes = server
                .names
                .iter()
                .cloned()
                .map(|key| (key, schemes.clone()))
                .collect::<Vec<_>>();
            let default_schemes = server
                .listens
                .iter()
                .filter(|listen| {
                    default_owners
                        .get(&listen.address)
                        .is_some_and(|(owner, _)| *owner == server_index)
                })
                .map(|listen| if listen.tls { "https" } else { "http" })
                .collect::<BTreeSet<_>>();
            if !default_schemes.is_empty() {
                key_scopes.push(("*".into(), default_schemes));
            }
            for (key, key_schemes) in key_scopes {
                let host_returns = server.host_returns.get(&key);
                let mut effective_routes = Vec::new();
                if let Some(routes) = host_returns {
                    effective_routes.extend(routes.clone());
                }
                effective_routes.extend(server.returns.clone());
                if host_returns.is_none_or(Vec::is_empty) && server.returns.is_empty() {
                    effective_routes.extend(server.locations.clone());
                }
                let site = sites.entry(key.clone()).or_insert_with(|| SiteConfig {
                    default: key == "*",
                    server_names: (key != "*").then_some(key.clone()).into_iter().collect(),
                    routes: Vec::new(),
                    response_headers: Vec::new(),
                    deny: Vec::new(),
                });
                for scheme in &key_schemes {
                    let mut scoped_routes = effective_routes.clone();
                    for route in &mut scoped_routes {
                        route.schemes = vec![(*scheme).into()];
                    }
                    let assignment_key = (key.clone(), (*scheme).into());
                    if let Some(existing) = assignments.get(&assignment_key) {
                        if existing != &scoped_routes {
                            return Err(NginxError::Invalid(format!(
                                "server name {key} has conflicting {scheme} behavior on multiple listeners"
                            )));
                        }
                    } else {
                        assignments.insert(assignment_key, scoped_routes.clone());
                        site.routes.extend(scoped_routes);
                    }
                }
            }
        }
        sites.retain(|_, site| !site.routes.is_empty());
        if sites.is_empty() {
            return Err(NginxError::Invalid(
                "no translatable routes were found in Nginx server blocks".into(),
            ));
        }

        let mut built_listeners = listener_builds
            .into_values()
            .map(|build| AdditionalListenerConfig {
                address: build.address.to_string(),
                tls: build.tls.then_some(TlsConfig {
                    certificate_chain_file: String::new(),
                    private_key_file: String::new(),
                    certificates: build.certificates,
                }),
            })
            .collect::<Vec<_>>();
        built_listeners.sort_by(|left, right| left.address.cmp(&right.address));
        let primary = built_listeners
            .first()
            .cloned()
            .ok_or_else(|| NginxError::Invalid("no listeners were found".into()))?;
        built_listeners.remove(0);
        let listener = ListenerConfig {
            address: primary.address,
            management_address: None,
            tls: primary.tls,
            trust_forwarding_headers: false,
            security_mode: "agreement".into(),
            agreement_implementations: 2,
            quarantined_implementations: Vec::new(),
            max_connections: 1_024,
            request_header_timeout_ms: 5_000,
            request_body_timeout_ms: 30_000,
            upstream_connect_timeout_ms: 3_000,
            upstream_response_timeout_ms: 30_000,
            graceful_shutdown_timeout_ms: 10_000,
        };
        let upstreams = upstream_names
            .into_iter()
            .map(|(address, name)| UpstreamConfig {
                name,
                address: address.to_string(),
            })
            .collect();
        let sites = sites.into_values().collect::<Vec<_>>();
        let imported_request_limit = sites
            .iter()
            .flat_map(|site| &site.routes)
            .filter_map(|route| route.max_request_body_bytes)
            .max()
            .unwrap_or(1_024 * 1_024);
        let mut limits = Limits::default();
        limits.max_request_body_bytes = imported_request_limit;
        limits.max_inflight_body_bytes = limits.max_inflight_body_bytes.max(imported_request_limit);
        let config = Config {
            listener,
            listeners: built_listeners,
            limits,
            compression,
            upstreams,
            routes: Vec::new(),
            sites,
            polyform: None,
        };
        crate::proxy::validate_config_files(&config)
            .map_err(|error| NginxError::Invalid(error.to_string()))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "polyguard-nginx-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("temporary directory");
        path
    }

    #[test]
    fn tokenizer_preserves_quoted_values_and_ignores_comments() {
        let path = Path::new("test.conf");
        let tokens = tokenize(
            path,
            "add_header Content-Security-Policy \"script-src 'self'\"; # comment\n",
        )
        .unwrap();
        assert_eq!(
            tokens,
            vec![
                Token {
                    kind: TokenKind::Word("add_header".into()),
                    line: 1
                },
                Token {
                    kind: TokenKind::Word("Content-Security-Policy".into()),
                    line: 1
                },
                Token {
                    kind: TokenKind::Word("script-src 'self'".into()),
                    line: 1
                },
                Token {
                    kind: TokenKind::Semicolon,
                    line: 1
                },
            ]
        );
    }

    #[test]
    fn translator_builds_proxy_static_redirect_headers_and_limits() {
        let directory = temporary_directory("translate");
        let static_root = directory.join("public");
        fs::create_dir(&static_root).unwrap();
        fs::write(static_root.join("index.html"), "ok").unwrap();
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            format!(
                r#"
events {{ worker_connections 128; }}
http {{
    gzip on;
    client_max_body_size 1m;
    server {{
        listen 127.0.0.1:8080;
        server_name app.example.test;
        client_max_body_size 3m;
        root {};
        index index.html;
        location = /legacy {{ return 308 https://$host$request_uri; }}
        location /api/ {{
            proxy_pass http://127.0.0.1:3000/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            client_max_body_size 2m;
        }}
        location /other/ {{
            proxy_pass http://127.0.0.1:3000/;
            proxy_http_version 1.1;
        }}
        location / {{
            try_files $uri $uri/ =404;
            add_header X-Content-Type-Options nosniff;
        }}
    }}
}}
"#,
                static_root.display()
            ),
        )
        .unwrap();
        let config = load_config(&config_path).unwrap();
        assert!(config.compression.enabled);
        assert_eq!(config.limits.max_request_body_bytes, 3 * 1024 * 1024);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.sites.len(), 2);
        let site = config
            .sites
            .iter()
            .find(|site| site.server_names == ["app.example.test"])
            .unwrap();
        assert_eq!(site.routes.len(), 4);
        assert!(matches!(
            site.routes[0].action,
            RouteActionConfig::Redirect { status: 308, .. }
        ));
        assert_eq!(site.routes[1].max_request_body_bytes, Some(2 * 1024 * 1024));
        assert_eq!(site.routes[2].max_request_body_bytes, Some(3 * 1024 * 1024));
        assert!(matches!(
            site.routes[3].action,
            RouteActionConfig::Static { .. }
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn includes_are_resolved_and_unsupported_regex_locations_fail_closed() {
        let directory = temporary_directory("include");
        let sites = directory.join("sites");
        fs::create_dir(&sites).unwrap();
        let included = sites.join("site.conf");
        fs::write(
            &included,
            "server { listen 127.0.0.1:8080; server_name api.example.test; location ~ \\.php$ { return 404; } }",
        )
        .unwrap();
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            format!(
                "events {{}} http {{ include {}; }}",
                sites.join("*.conf").display()
            ),
        )
        .unwrap();
        let error = load_config(&config_path).unwrap_err();
        let NginxError::Unsupported(issues) = error else {
            panic!("expected compatibility issues");
        };
        assert!(issues.iter().any(|issue| issue.directive == "location"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn nested_relative_includes_use_the_root_configuration_prefix() {
        let directory = temporary_directory("relative-include-prefix");
        let sites = directory.join("sites-enabled");
        fs::create_dir(&sites).unwrap();
        fs::write(
            directory.join("proxy_params"),
            "proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr;",
        )
        .unwrap();
        fs::write(
            sites.join("app.conf"),
            "server { listen 127.0.0.1:8080; server_name app.example.test; location / { include proxy_params; proxy_pass http://127.0.0.1:3000; } }",
        )
        .unwrap();
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            "events {} http { include sites-enabled/*.conf; }",
        )
        .unwrap();

        let config = load_config(&config_path).unwrap();
        assert_eq!(config.upstreams.len(), 1);
        assert!(config.sites.iter().any(|site| {
            site.server_names == ["app.example.test"]
                && site
                    .routes
                    .iter()
                    .any(|route| matches!(route.action, RouteActionConfig::Proxy { .. }))
        }));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conditional_add_header_obeys_nginx_inheritance_without_duplicates() {
        let directory = temporary_directory("conditional-header-inheritance");
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            r#"
events {}
http {
    server {
        listen 127.0.0.1:8080;
        server_name app.example.test;
        add_header Access-Control-Allow-Origin '*';
        location / {
            if ($request_method = 'GET') {
                add_header Access-Control-Allow-Origin '*';
            }
            return 200 ok;
        }
    }
}
"#,
        )
        .unwrap();

        let config = load_config(&config_path).unwrap();
        let route = &config
            .sites
            .iter()
            .find(|site| site.server_names == ["app.example.test"])
            .unwrap()
            .routes[0];
        assert_eq!(route.response_headers.len(), 1);
        assert_eq!(
            route.response_headers[0].name,
            "access-control-allow-origin"
        );
        assert!(route.response_headers[0].methods.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conflicting_same_scheme_virtual_hosts_on_distinct_listeners_fail_closed() {
        let directory = temporary_directory("listener-conflict");
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            r#"
events {}
http {
    server { listen 127.0.0.1:8080; server_name app.example.test; return 200 first; }
    server { listen 127.0.0.1:8081; server_name app.example.test; return 200 second; }
}
"#,
        )
        .unwrap();
        let error = load_config(&config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting http behavior on multiple listeners")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invalid_arguments_for_translated_directives_fail_closed() {
        let directory = temporary_directory("invalid-arguments");
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            "events {} http { server { listen 127.0.0.1:8080; server_name app.example.test; location / { root /tmp extra; } } }",
        )
        .unwrap();
        let error = load_config(&config_path).unwrap_err();
        let NginxError::Unsupported(issues) = error else {
            panic!("expected compatibility issues");
        };
        assert!(issues.iter().any(|issue| {
            issue.directive == "root"
                && issue.message == "invalid or unsupported directive arguments"
        }));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn translator_handles_multi_certificate_tls_cors_acl_and_host_redirects() {
        let directory = temporary_directory("full-subset");
        let static_root = directory.join("public");
        fs::create_dir(&static_root).unwrap();
        fs::write(static_root.join("index.html"), "home").unwrap();
        let CertifiedKey {
            cert: first_cert,
            signing_key: first_key,
        } = generate_simple_self_signed(vec!["first.example.test".into()]).unwrap();
        let CertifiedKey {
            cert: second_cert,
            signing_key: second_key,
        } = generate_simple_self_signed(vec!["second.example.test".into()]).unwrap();
        let first_certificate = directory.join("first.pem");
        let first_private_key = directory.join("first-key.pem");
        let second_certificate = directory.join("second.pem");
        let second_private_key = directory.join("second-key.pem");
        fs::write(&first_certificate, first_cert.pem()).unwrap();
        fs::write(&first_private_key, first_key.serialize_pem()).unwrap();
        fs::write(&second_certificate, second_cert.pem()).unwrap();
        fs::write(&second_private_key, second_key.serialize_pem()).unwrap();
        let config_path = directory.join("nginx.conf");
        fs::write(
            &config_path,
            format!(
                r#"
events {{ worker_connections 256; }}
http {{
    gzip on;
    server {{
        listen 127.0.0.1:8443 ssl default_server;
        server_name first.example.test;
        ssl_certificate {};
        ssl_certificate_key {};
        root {};
        deny 192.0.2.8;
        location / {{
            try_files $uri $uri/ =404;
            if ($request_method = 'OPTIONS') {{
                add_header Content-Type 'text/plain; charset=utf-8';
                add_header Content-Length 0;
                add_header Access-Control-Allow-Origin '*';
                return 204;
            }}
            if ($request_method = 'GET') {{
                add_header Access-Control-Allow-Origin '*';
            }}
        }}
    }}
    server {{
        listen 127.0.0.1:8443 ssl;
        server_name second.example.test;
        ssl_certificate {};
        ssl_certificate_key {};
        location / {{
            return 200 second;
            add_header Strict-Transport-Security 'max-age=31536000' always;
        }}
    }}
    server {{
        listen 127.0.0.1:8080;
        server_name first.example.test second.example.test;
        if ($host = first.example.test) {{ return 308 https://$host$request_uri; }}
        if ($host = second.example.test) {{ return 308 https://$host$request_uri; }}
        return 404;
    }}
}}
"#,
                first_certificate.display(),
                first_private_key.display(),
                static_root.display(),
                second_certificate.display(),
                second_private_key.display(),
            ),
        )
        .unwrap();
        let config = load_config(&config_path).unwrap();
        assert_eq!(config.listeners.len() + 1, 2);
        let tls = config
            .listeners
            .iter()
            .find_map(|listener| listener.tls.as_ref())
            .or(config.listener.tls.as_ref())
            .unwrap();
        assert_eq!(tls.certificates.len(), 2);
        assert_eq!(config.sites.len(), 3);
        assert!(config.sites.iter().any(|site| {
            site.server_names == ["first.example.test"]
                && site.routes.iter().any(|route| {
                    route.methods == ["OPTIONS"]
                        && route.deny.is_empty()
                        && matches!(route.action, RouteActionConfig::Respond { status: 204, .. })
                })
        }));
        assert!(config.sites.iter().any(|site| {
            site.server_names == ["second.example.test"]
                && site.routes.iter().any(|route| {
                    matches!(route.action, RouteActionConfig::Respond { status: 200, .. })
                        && route.response_headers.iter().any(|header| {
                            header.name == "strict-transport-security"
                                && header.value == "max-age=31536000"
                        })
                })
        }));
        assert!(config.sites.iter().any(|site| {
            site.server_names.contains(&"first.example.test".to_owned())
                && site.routes.iter().any(|route| {
                    matches!(
                        route.action,
                        RouteActionConfig::Redirect { status: 308, .. }
                    )
                })
        }));
        fs::remove_dir_all(directory).unwrap();
    }
}
