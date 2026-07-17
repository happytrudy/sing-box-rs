use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    BoxPacketConnection, BoxStream, Network, OutboundManager, Session,
    config::{HeadlessRuleConfig, RouteConfig, RouteRuleConfig, RuleSetConfig},
    parse_extended_json,
};

#[derive(Debug)]
pub enum RuleSetFetchResult {
    NotModified,
    Modified {
        content: Vec<u8>,
        etag: Option<String>,
    },
}

#[async_trait]
pub trait RuleSetFetcher: Send + Sync {
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<RuleSetFetchResult>;
}

pub struct Router {
    outbounds: Arc<OutboundManager>,
    final_outbound: String,
    rules: Vec<CompiledRule>,
    rule_sets: HashMap<String, Arc<CompiledRuleSet>>,
    rule_set_services: Vec<RuleSetService>,
    service_tasks: Mutex<Vec<JoinHandle<()>>>,
    service_cancel: CancellationToken,
    services_started: AtomicBool,
}

impl Router {
    pub async fn build(
        outbounds: Arc<OutboundManager>,
        config: RouteConfig,
        default_outbound: String,
    ) -> Result<Self> {
        Self::build_with_fetcher(outbounds, config, default_outbound, None).await
    }

    pub async fn build_with_fetcher(
        outbounds: Arc<OutboundManager>,
        config: RouteConfig,
        default_outbound: String,
        fetcher: Option<Arc<dyn RuleSetFetcher>>,
    ) -> Result<Self> {
        let final_outbound = if config.final_outbound.is_empty() {
            default_outbound
        } else {
            config.final_outbound
        };
        anyhow::ensure!(!final_outbound.is_empty(), "route final outbound is empty");
        anyhow::ensure!(
            outbounds.get(&final_outbound).await.is_some(),
            "final outbound not found: {final_outbound}"
        );

        let mut rule_sets = HashMap::new();
        let mut rule_set_services = Vec::new();
        for rule_set in config.rule_set {
            let tag = rule_set.tag.clone();
            anyhow::ensure!(!tag.is_empty(), "rule-set tag cannot be empty");
            anyhow::ensure!(
                !rule_sets.contains_key(&tag),
                "duplicate rule-set tag: {tag}"
            );
            let (compiled, service) = prepare_rule_set(rule_set, fetcher.clone()).await?;
            rule_sets.insert(tag, compiled);
            if let Some(service) = service {
                rule_set_services.push(service);
            }
        }

        let mut rules = Vec::with_capacity(config.rules.len());
        for (index, rule) in config.rules.into_iter().enumerate() {
            let compiled = CompiledRule::compile(rule)
                .with_context(|| format!("compile route rule {index}"))?;
            for tag in &compiled.matcher.rule_sets {
                anyhow::ensure!(rule_sets.contains_key(tag), "rule-set not found: {tag}");
            }
            if let RuleAction::Route { outbound } = &compiled.action {
                anyhow::ensure!(
                    outbounds.get(outbound).await.is_some(),
                    "route outbound not found: {outbound}"
                );
            }
            rules.push(compiled);
        }

        Ok(Self {
            outbounds,
            final_outbound,
            rules,
            rule_sets,
            rule_set_services,
            service_tasks: Mutex::new(Vec::new()),
            service_cancel: CancellationToken::new(),
            services_started: AtomicBool::new(false),
        })
    }

    pub async fn start(&self) {
        if self
            .services_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut tasks = self.service_tasks.lock().await;
        for service in self.rule_set_services.clone() {
            let cancel = self.service_cancel.clone();
            tasks.push(tokio::spawn(async move {
                match service {
                    RuleSetService::Local {
                        tag,
                        path,
                        format,
                        state,
                        fingerprint,
                    } => {
                        watch_local_rule_set(tag, path, format, state, fingerprint, cancel).await;
                    }
                    RuleSetService::Remote {
                        tag,
                        url,
                        format,
                        update_interval,
                        fetcher,
                        state,
                        etag,
                    } => {
                        update_remote_rule_set(
                            tag,
                            url,
                            format,
                            update_interval,
                            fetcher,
                            state,
                            etag,
                            cancel,
                        )
                        .await;
                    }
                }
            }));
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.service_cancel.cancel();
        let tasks = {
            let mut tasks = self.service_tasks.lock().await;
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.await.context("join rule-set update task")?;
        }
        Ok(())
    }

    fn select(&self, session: &mut Session) -> Result<String> {
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.matcher.matches(session, &self.rule_sets) {
                continue;
            }
            tracing::debug!(rule = index, inbound = %session.inbound, "matched route rule");
            match &rule.action {
                RuleAction::RouteOptions {
                    override_address,
                    override_port,
                } => {
                    if let Some(address) = override_address {
                        session.destination.host.clone_from(address);
                    }
                    if let Some(port) = override_port {
                        session.destination.port = *port;
                    }
                }
                RuleAction::Route { outbound } => return Ok(outbound.clone()),
                RuleAction::Reject { method } => {
                    anyhow::bail!("connection rejected by route rule using {method}")
                }
            }
        }
        Ok(self.final_outbound.clone())
    }

    pub async fn connect(&self, session: &mut Session) -> Result<BoxStream> {
        let tag = match &session.outbound {
            Some(tag) => tag.clone(),
            None => self.select(session)?,
        };
        let outbound = self
            .outbounds
            .get(&tag)
            .await
            .with_context(|| format!("route outbound not found: {tag}"))?;
        session.outbound = Some(tag);
        outbound.connect(session).await
    }

    pub async fn connect_packet(&self, session: &mut Session) -> Result<BoxPacketConnection> {
        let tag = match &session.outbound {
            Some(tag) => tag.clone(),
            None => self.select(session)?,
        };
        let outbound = self
            .outbounds
            .get(&tag)
            .await
            .with_context(|| format!("route outbound not found: {tag}"))?;
        session.outbound = Some(tag);
        outbound.connect_packet(session).await
    }

    pub async fn relay(
        &self,
        session: Session,
        mut inbound: BoxStream,
        mut outbound: BoxStream,
    ) -> Result<()> {
        tracing::info!(
            inbound = %session.inbound,
            outbound = ?session.outbound,
            destination = %session.destination,
            user = ?session.user,
            "routing TCP connection"
        );
        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    }

    pub async fn route(&self, mut session: Session, inbound: BoxStream) -> Result<()> {
        let outbound = self.connect(&mut session).await?;
        self.relay(session, inbound, outbound).await
    }

    pub async fn relay_packet(
        &self,
        session: Session,
        inbound: BoxPacketConnection,
        outbound: BoxPacketConnection,
    ) -> Result<()> {
        tracing::info!(
            inbound = %session.inbound,
            outbound = ?session.outbound,
            user = ?session.user,
            "routing UDP session"
        );
        let upload = async {
            loop {
                outbound.send(inbound.recv().await?).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };
        let download = async {
            loop {
                inbound.send(outbound.recv().await?).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }

    pub async fn route_packet(
        &self,
        mut session: Session,
        inbound: BoxPacketConnection,
    ) -> Result<()> {
        let outbound = self.connect_packet(&mut session).await?;
        self.relay_packet(session, inbound, outbound).await
    }
}

struct CompiledRule {
    matcher: RuleMatcher,
    action: RuleAction,
}

impl CompiledRule {
    fn compile(config: RouteRuleConfig) -> Result<Self> {
        let matcher = RuleMatcher::from_route(&config)?;
        anyhow::ensure!(!matcher.is_empty(), "route rule has no match conditions");
        let action = match config.action.as_str() {
            "" | "route" => {
                anyhow::ensure!(
                    !config.outbound.is_empty(),
                    "route action requires outbound"
                );
                RuleAction::Route {
                    outbound: config.outbound,
                }
            }
            "route-options" => {
                anyhow::ensure!(
                    !config.override_address.is_empty() || config.override_port != 0,
                    "route-options action is empty"
                );
                RuleAction::RouteOptions {
                    override_address: (!config.override_address.is_empty())
                        .then_some(config.override_address),
                    override_port: (config.override_port != 0).then_some(config.override_port),
                }
            }
            "reject" => {
                let method = if config.method.is_empty() {
                    "default".to_owned()
                } else {
                    config.method
                };
                anyhow::ensure!(
                    matches!(method.as_str(), "default" | "drop" | "reply"),
                    "unknown reject method: {method}"
                );
                anyhow::ensure!(
                    !(method == "drop" && config.no_drop),
                    "no_drop cannot be used with drop"
                );
                RuleAction::Reject { method }
            }
            action => anyhow::bail!("unsupported route action: {action}"),
        };
        Ok(Self { matcher, action })
    }
}

enum RuleAction {
    RouteOptions {
        override_address: Option<String>,
        override_port: Option<u16>,
    },
    Route {
        outbound: String,
    },
    Reject {
        method: String,
    },
}

struct CompiledRuleSet {
    rules: RwLock<Arc<[HeadlessRule]>>,
}

impl CompiledRuleSet {
    fn new(rules: Vec<HeadlessRule>) -> Self {
        Self {
            rules: RwLock::new(rules.into()),
        }
    }

    fn replace(&self, rules: Vec<HeadlessRule>) {
        *self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = rules.into();
    }

    fn matches(&self, session: &Session) -> bool {
        self.rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|rule| rule.matches(session))
    }
}

#[derive(Clone, Copy)]
enum RuleSetFormat {
    Source,
    Binary,
}

impl RuleSetFormat {
    fn resolve(configured: &str, location: &str) -> Result<Self> {
        let inferred = || {
            let path = location
                .split(['?', '#'])
                .next()
                .unwrap_or(location)
                .to_ascii_lowercase();
            if path.ends_with(".json") {
                Some(Self::Source)
            } else if path.ends_with(".srs") {
                Some(Self::Binary)
            } else {
                None
            }
        };
        match configured {
            "source" => Ok(Self::Source),
            "binary" => Ok(Self::Binary),
            "" => inferred()
                .with_context(|| format!("cannot infer rule-set format from location: {location}")),
            format => anyhow::bail!("unsupported rule-set format: {format}"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileFingerprint {
    length: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone)]
enum RuleSetService {
    Local {
        tag: String,
        path: PathBuf,
        format: RuleSetFormat,
        state: Arc<CompiledRuleSet>,
        fingerprint: FileFingerprint,
    },
    Remote {
        tag: String,
        url: String,
        format: RuleSetFormat,
        update_interval: Duration,
        fetcher: Arc<dyn RuleSetFetcher>,
        state: Arc<CompiledRuleSet>,
        etag: Option<String>,
    },
}

async fn prepare_rule_set(
    config: RuleSetConfig,
    fetcher: Option<Arc<dyn RuleSetFetcher>>,
) -> Result<(Arc<CompiledRuleSet>, Option<RuleSetService>)> {
    let tag = config.tag.clone();
    match config.kind.as_str() {
        "" | "inline" => {
            anyhow::ensure!(
                config.format.is_empty(),
                "inline rule-set cannot specify format"
            );
            let rules = compile_rule_set_rules(&tag, config.rules)?;
            Ok((Arc::new(CompiledRuleSet::new(rules)), None))
        }
        "local" => {
            anyhow::ensure!(!config.path.is_empty(), "local rule-set path is empty");
            let format = RuleSetFormat::resolve(&config.format, &config.path)?;
            let path = PathBuf::from(config.path);
            let content = tokio::fs::read(&path)
                .await
                .with_context(|| format!("read rule-set {}", path.display()))?;
            let rules = decode_and_compile_rule_set(&tag, format, &content)
                .with_context(|| format!("load rule-set {}", path.display()))?;
            let fingerprint = file_fingerprint(&path).await?;
            let state = Arc::new(CompiledRuleSet::new(rules));
            Ok((
                Arc::clone(&state),
                Some(RuleSetService::Local {
                    tag,
                    path,
                    format,
                    state,
                    fingerprint,
                }),
            ))
        }
        "remote" => {
            anyhow::ensure!(!config.url.is_empty(), "remote rule-set URL is empty");
            anyhow::ensure!(
                config.download_detour.is_empty(),
                "remote rule-set download_detour is not supported"
            );
            anyhow::ensure!(
                config.http_client.is_none(),
                "remote rule-set http_client is not supported"
            );
            let format = RuleSetFormat::resolve(&config.format, &config.url)?;
            let update_interval = if config.update_interval.is_empty() {
                Duration::from_secs(24 * 60 * 60)
            } else {
                parse_duration(&config.update_interval)
                    .with_context(|| format!("invalid update_interval for rule-set {tag}"))?
            };
            anyhow::ensure!(!update_interval.is_zero(), "update_interval cannot be zero");
            let fetcher = fetcher.context("remote rule-set requires a rule-set fetcher")?;
            let response = fetcher
                .fetch(&config.url, None)
                .await
                .with_context(|| format!("download remote rule-set {tag}"))?;
            let (content, etag) = match response {
                RuleSetFetchResult::Modified { content, etag } => (content, etag),
                RuleSetFetchResult::NotModified => {
                    anyhow::bail!("remote rule-set returned not-modified without a local copy")
                }
            };
            let rules = decode_and_compile_rule_set(&tag, format, &content)
                .with_context(|| format!("load remote rule-set {tag}"))?;
            let state = Arc::new(CompiledRuleSet::new(rules));
            Ok((
                Arc::clone(&state),
                Some(RuleSetService::Remote {
                    tag,
                    url: config.url,
                    format,
                    update_interval,
                    fetcher,
                    state,
                    etag,
                }),
            ))
        }
        kind => anyhow::bail!("unsupported rule-set type: {kind}"),
    }
}

fn decode_and_compile_rule_set(
    tag: &str,
    format: RuleSetFormat,
    content: &[u8],
) -> Result<Vec<HeadlessRule>> {
    let source = match format {
        RuleSetFormat::Source => {
            let content = std::str::from_utf8(content).context("source rule-set is not UTF-8")?;
            parse_extended_json(content).context("decode source rule-set")?
        }
        RuleSetFormat::Binary => crate::srs::decode(content).context("decode binary rule-set")?,
    };
    anyhow::ensure!(
        (1..=5).contains(&source.version),
        "unsupported rule-set version: {}",
        source.version
    );
    compile_rule_set_rules(tag, source.rules)
}

fn compile_rule_set_rules(tag: &str, rules: Vec<HeadlessRuleConfig>) -> Result<Vec<HeadlessRule>> {
    anyhow::ensure!(!rules.is_empty(), "rule-set {tag} is empty");
    rules
        .into_iter()
        .enumerate()
        .map(|(index, rule)| {
            HeadlessRule::compile(rule)
                .with_context(|| format!("compile rule-set {tag} rule {index}"))
        })
        .collect()
}

async fn file_fingerprint(path: &Path) -> Result<FileFingerprint> {
    let metadata = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("read rule-set metadata {}", path.display()))?;
    Ok(FileFingerprint {
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

async fn watch_local_rule_set(
    tag: String,
    path: PathBuf,
    format: RuleSetFormat,
    state: Arc<CompiledRuleSet>,
    mut fingerprint: FileFingerprint,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {}
        }
        let current = match file_fingerprint(&path).await {
            Ok(current) => current,
            Err(error) => {
                tracing::warn!(rule_set = %tag, %error, "failed to inspect local rule-set");
                continue;
            }
        };
        if current == fingerprint {
            continue;
        }
        fingerprint = current;
        let result = async {
            let content = tokio::fs::read(&path).await?;
            decode_and_compile_rule_set(&tag, format, &content)
        }
        .await;
        match result {
            Ok(rules) => {
                let count = rules.len();
                state.replace(rules);
                tracing::info!(rule_set = %tag, rules = count, "reloaded local rule-set");
            }
            Err(error) => {
                tracing::warn!(rule_set = %tag, %error, "failed to reload local rule-set");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn update_remote_rule_set(
    tag: String,
    url: String,
    format: RuleSetFormat,
    update_interval: Duration,
    fetcher: Arc<dyn RuleSetFetcher>,
    state: Arc<CompiledRuleSet>,
    mut etag: Option<String>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            () = tokio::time::sleep(update_interval) => {}
        }
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            response = fetcher.fetch(&url, etag.as_deref()) => response,
        };
        match response {
            Ok(RuleSetFetchResult::NotModified) => {
                tracing::debug!(rule_set = %tag, "remote rule-set is unchanged");
            }
            Ok(RuleSetFetchResult::Modified {
                content,
                etag: next_etag,
            }) => match decode_and_compile_rule_set(&tag, format, &content) {
                Ok(rules) => {
                    let count = rules.len();
                    state.replace(rules);
                    etag = next_etag;
                    tracing::info!(rule_set = %tag, rules = count, "updated remote rule-set");
                }
                Err(error) => {
                    tracing::warn!(rule_set = %tag, %error, "invalid remote rule-set update");
                }
            },
            Err(error) => {
                tracing::warn!(rule_set = %tag, %error, "failed to update remote rule-set");
            }
        }
    }
}

fn parse_duration(value: &str) -> Result<Duration> {
    let mut remaining = value;
    let mut seconds = 0f64;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .context("duration is missing a unit")?;
        anyhow::ensure!(number_end > 0, "duration is missing a number");
        let number = remaining[..number_end].parse::<f64>()?;
        anyhow::ensure!(
            number.is_finite() && number >= 0.0,
            "invalid duration number"
        );
        remaining = &remaining[number_end..];
        let unit_end = remaining
            .find(|character: char| character.is_ascii_digit() || character == '.')
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        let multiplier = match unit {
            "ns" => 1e-9,
            "us" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 60.0 * 60.0,
            "d" => 24.0 * 60.0 * 60.0,
            _ => anyhow::bail!("unknown duration unit: {unit}"),
        };
        seconds += number * multiplier;
        remaining = &remaining[unit_end..];
    }
    anyhow::ensure!(seconds.is_finite(), "duration is too large");
    Ok(Duration::from_secs_f64(seconds))
}

enum HeadlessRule {
    Default(Box<RuleMatcher>),
    Logical {
        mode: LogicalMode,
        rules: Vec<HeadlessRule>,
        invert: bool,
    },
}

impl HeadlessRule {
    fn compile(config: HeadlessRuleConfig) -> Result<Self> {
        if config.kind.is_empty() || config.kind == "default" {
            let matcher = RuleMatcher::from_headless(&config)?;
            anyhow::ensure!(!matcher.is_empty(), "headless rule has no match conditions");
            Ok(Self::Default(Box::new(matcher)))
        } else if config.kind == "logical" {
            anyhow::ensure!(!config.rules.is_empty(), "logical rule is empty");
            let mode = match config.mode.as_str() {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                mode => anyhow::bail!("unknown logical rule mode: {mode}"),
            };
            Ok(Self::Logical {
                mode,
                rules: config
                    .rules
                    .into_iter()
                    .map(Self::compile)
                    .collect::<Result<_>>()?,
                invert: config.invert,
            })
        } else {
            anyhow::bail!("unsupported headless rule type: {}", config.kind)
        }
    }

    fn matches(&self, session: &Session) -> bool {
        match self {
            Self::Default(rule) => rule.matches_without_sets(session),
            Self::Logical {
                mode,
                rules,
                invert,
            } => {
                let matched = match mode {
                    LogicalMode::And => rules.iter().all(|rule| rule.matches(session)),
                    LogicalMode::Or => rules.iter().any(|rule| rule.matches(session)),
                };
                matched != *invert
            }
        }
    }
}

enum LogicalMode {
    And,
    Or,
}

#[derive(Default)]
struct RuleMatcher {
    inbounds: Vec<String>,
    networks: Vec<Network>,
    users: Vec<String>,
    domains: Vec<String>,
    domain_suffixes: Vec<String>,
    domain_keywords: Vec<String>,
    source_cidrs: Vec<IpCidr>,
    source_private: Option<bool>,
    destination_cidrs: Vec<IpCidr>,
    destination_private: Option<bool>,
    source_ports: PortMatcher,
    destination_ports: PortMatcher,
    rule_sets: Vec<String>,
    invert: bool,
}

impl RuleMatcher {
    fn from_route(config: &RouteRuleConfig) -> Result<Self> {
        Ok(Self {
            inbounds: config.inbound.0.clone(),
            networks: compile_networks(config.network.as_slice())?,
            users: config.auth_user.0.clone(),
            domains: normalize_domains(config.domain.as_slice()),
            domain_suffixes: normalize_domains(config.domain_suffix.as_slice()),
            domain_keywords: normalize_domains(config.domain_keyword.as_slice()),
            source_cidrs: compile_cidrs(config.source_ip_cidr.as_slice())?,
            source_private: config.source_ip_is_private,
            destination_cidrs: compile_cidrs(config.ip_cidr.as_slice())?,
            destination_private: config.ip_is_private,
            source_ports: PortMatcher::compile(
                config.source_port.as_slice(),
                config.source_port_range.as_slice(),
            )?,
            destination_ports: PortMatcher::compile(
                config.port.as_slice(),
                config.port_range.as_slice(),
            )?,
            rule_sets: config.rule_set.0.clone(),
            invert: config.invert,
        })
    }

    fn from_headless(config: &HeadlessRuleConfig) -> Result<Self> {
        Ok(Self {
            networks: compile_networks(config.network.as_slice())?,
            domains: normalize_domains(config.domain.as_slice()),
            domain_suffixes: normalize_domains(config.domain_suffix.as_slice()),
            domain_keywords: normalize_domains(config.domain_keyword.as_slice()),
            source_cidrs: compile_cidrs(config.source_ip_cidr.as_slice())?,
            destination_cidrs: compile_cidrs(config.ip_cidr.as_slice())?,
            source_ports: PortMatcher::compile(
                config.source_port.as_slice(),
                config.source_port_range.as_slice(),
            )?,
            destination_ports: PortMatcher::compile(
                config.port.as_slice(),
                config.port_range.as_slice(),
            )?,
            invert: config.invert,
            ..Self::default()
        })
    }

    fn is_empty(&self) -> bool {
        self.inbounds.is_empty()
            && self.networks.is_empty()
            && self.users.is_empty()
            && self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.domain_keywords.is_empty()
            && self.source_cidrs.is_empty()
            && self.source_private.is_none()
            && self.destination_cidrs.is_empty()
            && self.destination_private.is_none()
            && self.source_ports.is_empty()
            && self.destination_ports.is_empty()
            && self.rule_sets.is_empty()
    }

    fn matches(
        &self,
        session: &Session,
        rule_sets: &HashMap<String, Arc<CompiledRuleSet>>,
    ) -> bool {
        let mut matched = self.matches_base(session);
        if !self.rule_sets.is_empty() {
            matched &= self
                .rule_sets
                .iter()
                .any(|tag| rule_sets.get(tag).is_some_and(|set| set.matches(session)));
        }
        matched != self.invert
    }

    fn matches_without_sets(&self, session: &Session) -> bool {
        self.matches_base(session) != self.invert
    }

    fn matches_base(&self, session: &Session) -> bool {
        let source = session.source;
        let destination_ip = IpAddr::from_str(&session.destination.host).ok();
        let host = session.destination.host.to_ascii_lowercase();
        let domain_matches = self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.domain_keywords.is_empty()
            || self.domains.iter().any(|value| value == &host)
            || self.domain_suffixes.iter().any(|value| {
                if value.starts_with('.') {
                    host.ends_with(value)
                } else {
                    host == *value || host.ends_with(&format!(".{value}"))
                }
            })
            || self
                .domain_keywords
                .iter()
                .any(|value| host.contains(value));
        (self.inbounds.is_empty() || self.inbounds.contains(&session.inbound))
            && (self.networks.is_empty() || self.networks.contains(&session.network))
            && (self.users.is_empty()
                || session
                    .user
                    .as_ref()
                    .is_some_and(|user| self.users.contains(user)))
            && domain_matches
            && (self.source_cidrs.is_empty()
                || source.is_some_and(|source| {
                    self.source_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(source.ip()))
                }))
            && self.source_private.is_none_or(|expected| {
                source.is_some_and(|source| is_private(source.ip()) == expected)
            })
            && (self.destination_cidrs.is_empty()
                || destination_ip
                    .is_some_and(|ip| self.destination_cidrs.iter().any(|cidr| cidr.contains(ip))))
            && self
                .destination_private
                .is_none_or(|expected| destination_ip.is_some_and(|ip| is_private(ip) == expected))
            && (self.source_ports.is_empty()
                || source.is_some_and(|source| self.source_ports.contains(source.port())))
            && (self.destination_ports.is_empty()
                || self.destination_ports.contains(session.destination.port))
    }
}

fn normalize_domains(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn compile_networks(values: &[String]) -> Result<Vec<Network>> {
    values
        .iter()
        .map(|value| match value.as_str() {
            "tcp" => Ok(Network::Tcp),
            "udp" => Ok(Network::Udp),
            _ => anyhow::bail!("unsupported network: {value}"),
        })
        .collect()
}

fn compile_cidrs(values: &[String]) -> Result<Vec<IpCidr>> {
    values.iter().map(|value| value.parse()).collect()
}

#[derive(Default)]
struct PortMatcher {
    exact: Vec<u16>,
    ranges: Vec<(u16, u16)>,
}

impl PortMatcher {
    fn compile(exact: &[u16], ranges: &[String]) -> Result<Self> {
        let ranges = ranges
            .iter()
            .map(|range| {
                let (start, end) = range
                    .split_once(':')
                    .with_context(|| format!("invalid port range: {range}"))?;
                let start = if start.is_empty() { 0 } else { start.parse()? };
                let end = if end.is_empty() {
                    u16::MAX
                } else {
                    end.parse()?
                };
                anyhow::ensure!(start <= end, "invalid port range: {range}");
                Ok((start, end))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            exact: exact.to_vec(),
            ranges,
        })
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.ranges.is_empty()
    }

    fn contains(&self, port: u16) -> bool {
        self.exact.contains(&port)
            || self
                .ranges
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&port))
    }
}

struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl FromStr for IpCidr {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>()?)),
            None => (value, None),
        };
        let network: IpAddr = address.parse()?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(maximum);
        anyhow::ensure!(prefix <= maximum, "invalid CIDR prefix: {value}");
        Ok(Self { network, prefix })
    }
}

impl IpCidr {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address == Ipv4Addr::BROADCAST
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || (u128::from(address) & (u128::MAX << 121))
                    == (u128::from(Ipv6Addr::from_str("fc00::").expect("valid IPv6"))
                        & (u128::MAX << 121))
                || (u128::from(address) & (u128::MAX << 118))
                    == (u128::from(Ipv6Addr::from_str("fe80::").expect("valid IPv6"))
                        & (u128::MAX << 118))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::Mutex as StdMutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{Address, config::RuleSetSource};

    fn session(source: &str, destination: &str, port: u16) -> Session {
        Session {
            network: Network::Tcp,
            source: Some(source.parse().unwrap()),
            destination: Address::new(destination, port).unwrap(),
            inbound: "hy2-in".into(),
            inbound_type: "hysteria2".into(),
            outbound: None,
            user: Some("alice".into()),
        }
    }

    #[test]
    fn matches_cidr_ports_and_domains() {
        let config: RouteRuleConfig = serde_json::from_value(serde_json::json!({
            "inbound": "hy2-in",
            "source_ip_cidr": "192.0.2.0/24",
            "domain_suffix": ["example.com"],
            "port": 443,
            "outbound": "direct"
        }))
        .unwrap();
        let rule = CompiledRule::compile(config).unwrap();
        assert!(rule.matcher.matches_without_sets(&session(
            "192.0.2.1:1234",
            "www.example.com",
            443
        )));
        assert!(!rule.matcher.matches_without_sets(&session(
            "198.51.100.1:1234",
            "www.example.com",
            443
        )));
    }

    #[test]
    fn leading_dot_suffix_excludes_root_domain() {
        let config: HeadlessRuleConfig = serde_json::from_value(serde_json::json!({
            "domain_suffix": ".example.com"
        }))
        .unwrap();
        let rule = HeadlessRule::compile(config).unwrap();
        assert!(rule.matches(&session("192.0.2.1:1234", "www.example.com", 443)));
        assert!(!rule.matches(&session("192.0.2.1:1234", "example.com", 443)));
    }

    #[test]
    fn cidr_matches_ipv4_and_ipv6() {
        assert!(
            "192.0.2.0/24"
                .parse::<IpCidr>()
                .unwrap()
                .contains("192.0.2.123".parse().unwrap())
        );
        assert!(
            "2001:db8::/32"
                .parse::<IpCidr>()
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn route_options_continue_and_reject_is_terminal() {
        let rewrite = CompiledRule::compile(
            serde_json::from_value(serde_json::json!({
                "inbound": "tunnel",
                "action": "route-options",
                "override_address": "127.0.0.1"
            }))
            .unwrap(),
        )
        .unwrap();
        let route = CompiledRule::compile(
            serde_json::from_value(serde_json::json!({
                "inbound": "tunnel",
                "action": "route",
                "outbound": "direct"
            }))
            .unwrap(),
        )
        .unwrap();
        let reject = CompiledRule::compile(
            serde_json::from_value(serde_json::json!({
                "inbound": "denied",
                "action": "reject",
                "method": "drop"
            }))
            .unwrap(),
        )
        .unwrap();
        let router = Router {
            outbounds: Arc::new(OutboundManager::new()),
            final_outbound: "fallback".into(),
            rules: vec![rewrite, route, reject],
            rule_sets: HashMap::new(),
            rule_set_services: Vec::new(),
            service_tasks: Mutex::new(Vec::new()),
            service_cancel: CancellationToken::new(),
            services_started: AtomicBool::new(false),
        };
        let mut allowed = session("192.0.2.1:1234", "example.com", 443);
        allowed.inbound = "tunnel".into();
        assert_eq!(router.select(&mut allowed).unwrap(), "direct");
        assert_eq!(allowed.destination.host, "127.0.0.1");

        let mut denied = session("192.0.2.1:1234", "example.com", 443);
        denied.inbound = "denied".into();
        assert!(router.select(&mut denied).is_err());
    }

    #[test]
    fn route_rule_matches_source_rule_set() {
        let headless: HeadlessRuleConfig = serde_json::from_value(serde_json::json!({
            "source_ip_cidr": "192.0.2.0/24"
        }))
        .unwrap();
        let mut rule_sets = HashMap::new();
        rule_sets.insert(
            "allow".into(),
            Arc::new(CompiledRuleSet::new(vec![
                HeadlessRule::compile(headless).unwrap(),
            ])),
        );
        let rule = CompiledRule::compile(
            serde_json::from_value(serde_json::json!({
                "inbound": "hy2-in",
                "rule_set": "allow",
                "outbound": "direct"
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            rule.matcher
                .matches(&session("192.0.2.100:1234", "example.com", 443), &rule_sets)
        );
        assert!(!rule.matcher.matches(
            &session("198.51.100.1:1234", "example.com", 443),
            &rule_sets
        ));
    }

    #[test]
    fn parses_official_style_update_intervals() {
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("2h45m").unwrap(), Duration::from_secs(9_900));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert!(parse_duration("1week").is_err());
    }

    #[tokio::test]
    async fn hot_reloads_local_rule_set_atomically() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sing-box-rs-hot-{unique}.json"));
        std::fs::write(
            &path,
            r#"{"version":5,"rules":[{"source_ip_cidr":"192.0.2.0/24"}]}"#,
        )
        .unwrap();
        let initial = tokio::fs::read(&path).await.unwrap();
        let state = Arc::new(CompiledRuleSet::new(
            decode_and_compile_rule_set("hot", RuleSetFormat::Source, &initial).unwrap(),
        ));
        let fingerprint = file_fingerprint(&path).await.unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(watch_local_rule_set(
            "hot".into(),
            path.clone(),
            RuleSetFormat::Source,
            Arc::clone(&state),
            fingerprint,
            cancel.clone(),
        ));
        assert!(state.matches(&session("192.0.2.1:1234", "example.com", 443)));
        std::fs::write(
            &path,
            r#"{
                "version": 5,
                "rules": [{"source_ip_cidr": "198.51.100.0/24"}]
            }"#,
        )
        .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !state.matches(&session("198.51.100.1:1234", "example.com", 443)) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "rule-set was not reloaded"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!state.matches(&session("192.0.2.1:1234", "example.com", 443)));
        cancel.cancel();
        task.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    struct QueueFetcher {
        responses: StdMutex<VecDeque<RuleSetFetchResult>>,
        etags: StdMutex<Vec<Option<String>>>,
    }

    #[async_trait]
    impl RuleSetFetcher for QueueFetcher {
        async fn fetch(&self, _url: &str, etag: Option<&str>) -> Result<RuleSetFetchResult> {
            self.etags.lock().unwrap().push(etag.map(str::to_owned));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .context("missing queued response")
        }
    }

    #[tokio::test]
    async fn remote_updater_uses_etag_and_replaces_snapshot() {
        let initial: RuleSetSource = serde_json::from_value(serde_json::json!({
            "version": 5,
            "rules": [{"source_ip_cidr": "192.0.2.0/24"}]
        }))
        .unwrap();
        let state = Arc::new(CompiledRuleSet::new(
            compile_rule_set_rules("remote", initial.rules).unwrap(),
        ));
        let fetcher = Arc::new(QueueFetcher {
            responses: StdMutex::new(VecDeque::from([RuleSetFetchResult::Modified {
                content: br#"{"version":5,"rules":[{"source_ip_cidr":"198.51.100.0/24"}]}"#
                    .to_vec(),
                etag: Some("new".into()),
            }])),
            etags: StdMutex::new(Vec::new()),
        });
        let cancel = CancellationToken::new();
        let task = tokio::spawn(update_remote_rule_set(
            "remote".into(),
            "https://example.com/rules.json".into(),
            RuleSetFormat::Source,
            Duration::from_millis(20),
            Arc::clone(&fetcher) as Arc<dyn RuleSetFetcher>,
            Arc::clone(&state),
            Some("old".into()),
            cancel.clone(),
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !state.matches(&session("198.51.100.1:1234", "example.com", 443)) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "remote rule-set was not updated"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
        task.await.unwrap();
        assert_eq!(
            fetcher.etags.lock().unwrap().as_slice(),
            &[Some("old".into())]
        );
    }
}
