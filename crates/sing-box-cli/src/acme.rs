use std::{
    env,
    future::Future,
    io::Cursor,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use http::{Request, Response};
use http_body_util::BodyExt;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    Error as AcmeError, HttpClient as AcmeHttpClient, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sing_box_core::{Certificate, CertificateProvider, Lifecycle, Registry, StartStage};
use tokio::{sync::Mutex, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::rule_set_fetcher::{HttpClient, HttpRequest};

const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const RENEW_RETRY: Duration = Duration::from_secs(60 * 60);
const ACME_POLL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_PROPAGATION_DELAY: Duration = Duration::from_secs(10);
const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeOptions {
    #[serde(deserialize_with = "deserialize_one_or_many")]
    domain: Vec<String>,
    #[serde(default)]
    data_directory: String,
    #[serde(default)]
    default_server_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    account_key: String,
    #[serde(default)]
    disable_http_challenge: bool,
    #[serde(default)]
    disable_tls_alpn_challenge: bool,
    #[serde(default)]
    alternative_http_port: u16,
    #[serde(default)]
    alternative_tls_port: u16,
    #[serde(default)]
    external_account: Option<Value>,
    dns01_challenge: Dns01Options,
    #[serde(default)]
    key_type: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    http_client: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dns01Options {
    provider: String,
    api_token: String,
    #[serde(default)]
    zone_token: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    propagation_delay: String,
    #[serde(default)]
    propagation_timeout: String,
    #[serde(default, deserialize_with = "deserialize_optional_one_or_many")]
    resolvers: Vec<String>,
    #[serde(default)]
    override_domain: String,
}

fn deserialize_one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

fn deserialize_optional_one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_one_or_many(deserializer)
}

struct ProviderPaths {
    directory: PathBuf,
    account: PathBuf,
    certificate: PathBuf,
}

impl ProviderPaths {
    fn new(tag: &str, configured: &str) -> Result<Self> {
        anyhow::ensure!(
            !tag.is_empty() && tag != "." && tag != ".." && !tag.contains(['/', '\\']),
            "invalid certificate provider tag for storage: {tag}"
        );
        let root = if configured.is_empty() {
            if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
                PathBuf::from(data_home).join("certmagic")
            } else {
                let home = env::var_os("HOME").context(
                    "HOME or XDG_DATA_HOME is required when ACME data_directory is empty",
                )?;
                PathBuf::from(home).join(".local/share/certmagic")
            }
        } else {
            PathBuf::from(configured)
        };
        let directory = root.join("sing-box-rs").join(tag);
        Ok(Self {
            account: directory.join("account.json"),
            certificate: directory.join("certificate.json"),
            directory,
        })
    }
}

struct AcmeProviderInner {
    tag: String,
    options: AcmeOptions,
    paths: ProviderPaths,
    http: Arc<HttpClient>,
    account: Mutex<Option<Account>>,
    sender: watch::Sender<Option<Arc<Certificate>>>,
    cancel: CancellationToken,
}

pub struct AcmeCertificateProvider {
    inner: Arc<AcmeProviderInner>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl AcmeCertificateProvider {
    fn new(tag: String, mut options: AcmeOptions, http: Arc<HttpClient>) -> Result<Self> {
        validate_options(&options)?;
        options.dns01_challenge.api_token = resolve_secret(&options.dns01_challenge.api_token)?;
        anyhow::ensure!(
            !options.dns01_challenge.api_token.is_empty(),
            "Cloudflare api_token cannot be empty"
        );
        let paths = ProviderPaths::new(&tag, &options.data_directory)?;
        let (sender, _) = watch::channel(None);
        Ok(Self {
            inner: Arc::new(AcmeProviderInner {
                tag,
                options,
                paths,
                http,
                account: Mutex::new(None),
                sender,
                cancel: CancellationToken::new(),
            }),
            task: Mutex::new(None),
        })
    }
}

#[async_trait]
impl Lifecycle for AcmeCertificateProvider {
    async fn start(&self, stage: StartStage) -> Result<()> {
        if stage != StartStage::Start || self.task.lock().await.is_some() {
            return Ok(());
        }
        tokio::fs::create_dir_all(&self.inner.paths.directory)
            .await
            .with_context(|| {
                format!(
                    "create ACME data directory {}",
                    self.inner.paths.directory.display()
                )
            })?;
        secure_directory(&self.inner.paths.directory).await?;

        let cached = match load_cached_certificate(
            &self.inner.paths.certificate,
            &self.inner.options.domain,
        )
        .await
        {
            Ok(cached) => cached,
            Err(error) => {
                tracing::warn!(provider = %self.inner.tag, %error, "ignoring invalid cached certificate");
                None
            }
        };
        let initial_delay = match cached {
            Some(cached) if cached.not_after > SystemTime::now() => {
                self.inner
                    .sender
                    .send_replace(Some(Arc::clone(&cached.material)));
                renewal_delay(cached.not_after)
            }
            _ => {
                let issued = issue_certificate(&self.inner).await?;
                self.inner
                    .sender
                    .send_replace(Some(Arc::clone(&issued.material)));
                renewal_delay(issued.not_after)
            }
        };

        let inner = Arc::clone(&self.inner);
        *self.task.lock().await = Some(tokio::spawn(async move {
            renewal_loop(inner, initial_delay).await;
        }));
        tracing::info!(provider = %self.inner.tag, "started ACME certificate provider");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.inner.cancel.cancel();
        if let Some(task) = self.task.lock().await.take() {
            task.await.context("join ACME renewal task")?;
        }
        Ok(())
    }
}

impl CertificateProvider for AcmeCertificateProvider {
    fn kind(&self) -> &'static str {
        "acme"
    }

    fn tag(&self) -> &str {
        &self.inner.tag
    }

    fn subscribe(&self, server_name: &str) -> Result<watch::Receiver<Option<Arc<Certificate>>>> {
        let server_name = if server_name.is_empty() {
            &self.inner.options.default_server_name
        } else {
            server_name
        };
        if !server_name.is_empty() {
            anyhow::ensure!(
                self.inner
                    .options
                    .domain
                    .iter()
                    .any(|domain| domain_matches(domain, server_name)),
                "certificate provider {} does not cover server name {server_name}",
                self.inner.tag
            );
        }
        Ok(self.inner.sender.subscribe())
    }
}

pub fn register(registry: &mut Registry, http: Arc<HttpClient>) -> Result<()> {
    registry.register_certificate_provider::<AcmeOptions, _, _>(
        "acme",
        move |_context, tag, options| {
            let http = Arc::clone(&http);
            async move {
                Ok(Arc::new(AcmeCertificateProvider::new(tag, options, http)?)
                    as Arc<dyn CertificateProvider>)
            }
        },
    )
}

fn validate_options(options: &AcmeOptions) -> Result<()> {
    anyhow::ensure!(!options.domain.is_empty(), "ACME domain cannot be empty");
    for domain in &options.domain {
        anyhow::ensure!(
            !domain.is_empty()
                && !domain.contains(['/', '\\', ' ', '\r', '\n'])
                && !domain.trim_start_matches("*.").is_empty(),
            "invalid ACME domain: {domain}"
        );
        anyhow::ensure!(
            domain
                .trim_start_matches("*.")
                .parse::<std::net::IpAddr>()
                .is_err(),
            "ACME DNS-01 provider does not support IP identifiers: {domain}"
        );
    }
    anyhow::ensure!(
        matches!(options.key_type.as_str(), "" | "p256"),
        "only ACME key_type p256 is currently supported"
    );
    anyhow::ensure!(
        options.account_key.is_empty(),
        "ACME account_key is not currently supported"
    );
    anyhow::ensure!(
        options.external_account.is_none(),
        "ACME external_account is not currently supported"
    );
    anyhow::ensure!(
        options.http_client.is_none(),
        "ACME custom http_client is not currently supported"
    );
    anyhow::ensure!(
        options.dns01_challenge.provider == "cloudflare",
        "only Cloudflare ACME DNS-01 is currently supported"
    );
    anyhow::ensure!(
        options.dns01_challenge.zone_token.is_empty(),
        "Cloudflare zone_token is not currently supported; use api_token"
    );
    anyhow::ensure!(
        options.dns01_challenge.resolvers.is_empty(),
        "custom ACME DNS-01 resolvers are not currently supported"
    );
    anyhow::ensure!(
        options.dns01_challenge.override_domain.is_empty(),
        "ACME DNS-01 override_domain is not currently supported"
    );
    // These challenge fields are accepted for configuration compatibility but
    // are inactive because dns01_challenge disables HTTP and TLS-ALPN challenges.
    let _ = (
        options.disable_http_challenge,
        options.disable_tls_alpn_challenge,
        options.alternative_http_port,
        options.alternative_tls_port,
    );
    acme_directory(&options.provider)?;
    Ok(())
}

fn acme_directory(provider: &str) -> Result<String> {
    match provider {
        "" | "letsencrypt" => Ok(LetsEncrypt::Production.url().to_owned()),
        "letsencrypt-staging" => Ok(LETS_ENCRYPT_STAGING.to_owned()),
        provider if provider.starts_with("https://") => Ok(provider.to_owned()),
        provider => anyhow::bail!("unsupported ACME provider: {provider}"),
    }
}

fn resolve_secret(value: &str) -> Result<String> {
    if let Some(name) = value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        anyhow::ensure!(!name.is_empty(), "empty environment variable reference");
        return env::var(name).with_context(|| format!("environment variable {name} is not set"));
    }
    Ok(value.to_owned())
}

fn domain_matches(pattern: &str, server_name: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let server_name = server_name.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            server_name.ends_with(&format!(".{suffix}"))
                && !server_name[..server_name.len() - suffix.len() - 1].contains('.')
        }
        None => pattern == server_name,
    }
}

struct ManagedCertificate {
    material: Arc<Certificate>,
    not_after: SystemTime,
}

#[derive(Deserialize, Serialize)]
struct CachedCertificate {
    certificate_pem: String,
    private_key_pem: String,
}

async fn load_cached_certificate(
    path: &Path,
    expected_domains: &[String],
) -> Result<Option<ManagedCertificate>> {
    let content = match tokio::fs::read(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let cached: CachedCertificate = serde_json::from_slice(&content)
        .with_context(|| format!("decode cached certificate {}", path.display()))?;
    parse_managed_certificate(
        &cached.certificate_pem,
        &cached.private_key_pem,
        expected_domains,
    )
    .map(Some)
}

fn parse_managed_certificate(
    certificate_pem: &str,
    private_key_pem: &str,
    expected_domains: &[String],
) -> Result<ManagedCertificate> {
    let mut certificate_reader = Cursor::new(certificate_pem.as_bytes());
    let certificate_chain = rustls_pemfile::certs(&mut certificate_reader)
        .map(|certificate| certificate.map(|certificate| certificate.as_ref().to_vec()))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        !certificate_chain.is_empty(),
        "ACME certificate chain is empty"
    );
    let (_, certificate) = parse_x509_certificate(&certificate_chain[0])
        .map_err(|error| anyhow::anyhow!("parse ACME leaf certificate: {error}"))?;
    let alternative_names = certificate
        .subject_alternative_name()?
        .context("ACME leaf certificate has no subject alternative names")?
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for domain in expected_domains {
        anyhow::ensure!(
            alternative_names.contains(&domain.to_ascii_lowercase()),
            "ACME certificate does not cover configured domain {domain}"
        );
    }
    let timestamp = certificate.validity().not_after.timestamp();
    anyhow::ensure!(timestamp > 0, "invalid ACME certificate expiration");
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64);

    let mut key_reader = Cursor::new(private_key_pem.as_bytes());
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .context("ACME private key is empty")?
        .secret_der()
        .to_vec();
    Ok(ManagedCertificate {
        material: Arc::new(Certificate::new(certificate_chain, private_key)?),
        not_after,
    })
}

fn renewal_delay(not_after: SystemTime) -> Duration {
    not_after
        .checked_sub(RENEW_BEFORE)
        .and_then(|renew_at| renew_at.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
}

async fn renewal_loop(inner: Arc<AcmeProviderInner>, mut delay: Duration) {
    loop {
        tokio::select! {
            _ = inner.cancel.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
        match issue_certificate(&inner).await {
            Ok(certificate) => {
                delay = renewal_delay(certificate.not_after);
                inner
                    .sender
                    .send_replace(Some(Arc::clone(&certificate.material)));
                tracing::info!(provider = %inner.tag, "renewed ACME certificate");
            }
            Err(error) => {
                delay = RENEW_RETRY;
                tracing::warn!(provider = %inner.tag, %error, "failed to renew ACME certificate");
            }
        }
    }
}

async fn issue_certificate(inner: &AcmeProviderInner) -> Result<ManagedCertificate> {
    let account = load_or_create_account(inner).await?;
    let identifiers = inner
        .options
        .domain
        .iter()
        .cloned()
        .map(Identifier::Dns)
        .collect::<Vec<_>>();
    let mut new_order = NewOrder::new(&identifiers);
    if !inner.options.profile.is_empty() {
        new_order = new_order.profile(&inner.options.profile);
    }
    let mut order = account.new_order(&new_order).await?;
    let dns = CloudflareDns::new(inner)?;
    let mut records = Vec::new();
    let result = async {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => anyhow::bail!("unexpected ACME authorization status: {status:?}"),
            }
            let challenge = authorization
                .challenge(ChallengeType::Dns01)
                .context("ACME server did not offer DNS-01")?;
            let domain = challenge.identifier().to_string();
            let value = challenge.key_authorization().dns_value();
            records.push(dns.present(&domain, &value).await?);
        }

        if !records.is_empty() {
            tokio::time::sleep(dns.propagation_delay).await;
            for record in &records {
                dns.wait_for_propagation(record).await?;
            }
        }

        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            if authorization.status == AuthorizationStatus::Pending {
                authorization
                    .challenge(ChallengeType::Dns01)
                    .context("ACME server did not offer DNS-01")?
                    .set_ready()
                    .await?;
            }
        }

        let retry = RetryPolicy::default().timeout(ACME_POLL_TIMEOUT);
        let status = order.poll_ready(&retry).await?;
        anyhow::ensure!(status == OrderStatus::Ready, "ACME order became {status:?}");
        let private_key_pem = order.finalize().await?;
        let certificate_pem = order.poll_certificate(&retry).await?;
        let managed =
            parse_managed_certificate(&certificate_pem, &private_key_pem, &inner.options.domain)?;
        let cached = CachedCertificate {
            certificate_pem,
            private_key_pem,
        };
        atomic_write(
            &inner.paths.certificate,
            &serde_json::to_vec_pretty(&cached)?,
        )
        .await?;
        Ok::<_, anyhow::Error>(managed)
    }
    .await;

    for record in records.into_iter().rev() {
        if let Err(error) = dns.remove(&record).await {
            tracing::warn!(provider = %inner.tag, %error, "failed to remove ACME DNS record");
        }
    }
    result
}

async fn load_or_create_account(inner: &AcmeProviderInner) -> Result<Account> {
    let mut account = inner.account.lock().await;
    if let Some(account) = account.as_ref() {
        return Ok(account.clone());
    }
    let builder = Account::builder_with_http(Box::new(AcmeHttpAdapter {
        client: Arc::clone(&inner.http),
    }));
    let loaded = match tokio::fs::read(&inner.paths.account).await {
        Ok(content) => {
            let credentials: AccountCredentials = serde_json::from_slice(&content)
                .with_context(|| format!("decode {}", inner.paths.account.display()))?;
            builder.from_credentials(credentials).await?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let contact = (!inner.options.email.is_empty())
                .then(|| format!("mailto:{}", inner.options.email));
            let contact_refs = contact.iter().map(String::as_str).collect::<Vec<_>>();
            let (created, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    acme_directory(&inner.options.provider)?,
                    None,
                )
                .await?;
            atomic_write(
                &inner.paths.account,
                &serde_json::to_vec_pretty(&credentials)?,
            )
            .await?;
            created
        }
        Err(error) => return Err(error.into()),
    };
    *account = Some(loaded.clone());
    Ok(loaded)
}

struct AcmeHttpAdapter {
    client: Arc<HttpClient>,
}

impl AcmeHttpClient for AcmeHttpAdapter {
    fn request(
        &self,
        request: Request<BodyWrapper<bytes::Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = match body.collect().await {
                Ok(body) => body.to_bytes().to_vec(),
                Err(error) => match error {},
            };
            let headers = parts
                .headers
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.as_str().to_owned(),
                        value
                            .to_str()
                            .map_err(|error| AcmeError::Other(Box::new(error)))?
                            .to_owned(),
                    ))
                })
                .collect::<Result<Vec<_>, AcmeError>>()?;
            let response = client
                .execute(HttpRequest {
                    method: parts.method.as_str().to_owned(),
                    url: parts.uri.to_string(),
                    headers,
                    body,
                })
                .await
                .map_err(|error| AcmeError::Other(error.into()))?;
            let mut builder = Response::builder().status(response.status);
            for (name, value) in response.headers {
                builder = builder.header(name, value);
            }
            Ok(BytesResponse::from(
                builder.body(BodyWrapper::from(response.body))?,
            ))
        })
    }
}

struct CloudflareDns {
    http: Arc<HttpClient>,
    api_token: String,
    ttl: u32,
    propagation_delay: Duration,
    propagation_timeout: Duration,
}

struct DnsRecord {
    zone_id: String,
    record_id: String,
    name: String,
    value: String,
}

impl CloudflareDns {
    fn new(inner: &AcmeProviderInner) -> Result<Self> {
        let options = &inner.options.dns01_challenge;
        let ttl = if options.ttl.is_empty() {
            120
        } else {
            u32::try_from(parse_duration(&options.ttl)?.as_secs())?
        };
        anyhow::ensure!(ttl >= 60, "Cloudflare DNS TTL must be at least 60 seconds");
        Ok(Self {
            http: Arc::clone(&inner.http),
            api_token: options.api_token.clone(),
            ttl,
            propagation_delay: if options.propagation_delay.is_empty() {
                DEFAULT_PROPAGATION_DELAY
            } else {
                parse_duration(&options.propagation_delay)?
            },
            propagation_timeout: if options.propagation_timeout.is_empty() {
                DEFAULT_PROPAGATION_TIMEOUT
            } else {
                parse_duration(&options.propagation_timeout)?
            },
        })
    }

    async fn present(&self, domain: &str, value: &str) -> Result<DnsRecord> {
        let domain = domain.trim_start_matches("*.");
        let zone_id = self.find_zone(domain).await?;
        let name = format!("_acme-challenge.{domain}");
        #[derive(Serialize)]
        struct CreateRecord<'a> {
            r#type: &'static str,
            name: &'a str,
            content: &'a str,
            ttl: u32,
        }
        #[derive(Deserialize)]
        struct CreatedRecord {
            id: String,
        }
        let result: CreatedRecord = self
            .api(
                "POST",
                &format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"),
                serde_json::to_vec(&CreateRecord {
                    r#type: "TXT",
                    name: &name,
                    content: value,
                    ttl: self.ttl,
                })?,
            )
            .await?;
        Ok(DnsRecord {
            zone_id,
            record_id: result.id,
            name,
            value: value.to_owned(),
        })
    }

    async fn remove(&self, record: &DnsRecord) -> Result<()> {
        let _: Value = self
            .api(
                "DELETE",
                &format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    record.zone_id, record.record_id
                ),
                Vec::new(),
            )
            .await?;
        Ok(())
    }

    async fn find_zone(&self, domain: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Zone {
            id: String,
        }
        let labels = domain.split('.').collect::<Vec<_>>();
        for index in 0..labels.len().saturating_sub(1) {
            let candidate = labels[index..].join(".");
            let result: Vec<Zone> = self
                .api(
                    "GET",
                    &format!(
                        "https://api.cloudflare.com/client/v4/zones?name={}&status=active",
                        percent_encode(&candidate)
                    ),
                    Vec::new(),
                )
                .await?;
            if let Some(zone) = result.into_iter().next() {
                return Ok(zone.id);
            }
        }
        anyhow::bail!("Cloudflare zone not found for {domain}")
    }

    async fn api<T: DeserializeOwned>(&self, method: &str, url: &str, body: Vec<u8>) -> Result<T> {
        let mut headers = vec![(
            "Authorization".to_owned(),
            format!("Bearer {}", self.api_token),
        )];
        if !body.is_empty() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        let response = self
            .http
            .execute(HttpRequest {
                method: method.to_owned(),
                url: url.to_owned(),
                headers,
                body,
            })
            .await?;
        anyhow::ensure!(
            (200..300).contains(&response.status),
            "Cloudflare API returned HTTP {}: {}",
            response.status,
            response_excerpt(&response.body)
        );
        let envelope: CloudflareEnvelope<T> = serde_json::from_slice(&response.body)?;
        anyhow::ensure!(
            envelope.success,
            "Cloudflare API error: {}",
            envelope
                .errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        Ok(envelope.result)
    }

    async fn wait_for_propagation(&self, record: &DnsRecord) -> Result<()> {
        #[derive(Deserialize)]
        struct DnsAnswer {
            data: String,
        }
        #[derive(Deserialize)]
        struct DnsResponse {
            #[serde(default, rename = "Answer")]
            answer: Vec<DnsAnswer>,
        }
        let deadline = tokio::time::Instant::now() + self.propagation_timeout;
        loop {
            let response = self
                .http
                .execute(HttpRequest {
                    method: "GET".to_owned(),
                    url: format!(
                        "https://cloudflare-dns.com/dns-query?name={}&type=TXT",
                        percent_encode(&record.name)
                    ),
                    headers: vec![("Accept".to_owned(), "application/dns-json".to_owned())],
                    body: Vec::new(),
                })
                .await;
            if let Ok(response) = response
                && response.status == 200
                && serde_json::from_slice::<DnsResponse>(&response.body).is_ok_and(|dns| {
                    dns.answer
                        .iter()
                        .any(|answer| answer.data.trim_matches('"') == record.value)
                })
            {
                return Ok(());
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for DNS-01 record {}",
                record.name
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

#[derive(Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    result: T,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareError {
    message: String,
}

fn response_excerpt(body: &[u8]) -> String {
    String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned()
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
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
        remaining = &remaining[number_end..];
        let unit_end = remaining
            .find(|character: char| character.is_ascii_digit() || character == '.')
            .unwrap_or(remaining.len());
        let multiplier = match &remaining[..unit_end] {
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86_400.0,
            unit => anyhow::bail!("unknown duration unit: {unit}"),
        };
        seconds += number * multiplier;
        remaining = &remaining[unit_end..];
    }
    anyhow::ensure!(seconds.is_finite() && seconds >= 0.0, "invalid duration");
    Ok(Duration::from_secs_f64(seconds))
}

async fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, content)
        .await
        .with_context(|| format!("write {}", temporary.display()))?;
    secure_file(&temporary).await?;
    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
async fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn secure_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn secure_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn secure_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use rcgen::generate_simple_self_signed;

    use super::*;

    fn options(directory: &Path) -> AcmeOptions {
        AcmeOptions {
            domain: vec!["example.com".into()],
            data_directory: directory.display().to_string(),
            default_server_name: String::new(),
            email: "admin@example.com".into(),
            provider: "letsencrypt".into(),
            account_key: String::new(),
            disable_http_challenge: false,
            disable_tls_alpn_challenge: false,
            alternative_http_port: 0,
            alternative_tls_port: 0,
            external_account: None,
            dns01_challenge: Dns01Options {
                provider: "cloudflare".into(),
                api_token: "test-token".into(),
                zone_token: String::new(),
                ttl: String::new(),
                propagation_delay: String::new(),
                propagation_timeout: String::new(),
                resolvers: Vec::new(),
                override_domain: String::new(),
            },
            key_type: "p256".into(),
            profile: String::new(),
            http_client: None,
        }
    }

    #[test]
    fn parses_string_domain_and_environment_token() {
        let options: AcmeOptions = serde_json::from_value(serde_json::json!({
            "domain": "example.com",
            "email": "admin@example.com",
            "dns01_challenge": {
                "provider": "cloudflare",
                "api_token": "test"
            }
        }))
        .unwrap();
        assert_eq!(options.domain, ["example.com"]);
    }

    #[test]
    fn wildcard_only_matches_one_label() {
        assert!(domain_matches("*.example.com", "www.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "a.b.example.com"));
    }

    #[tokio::test]
    async fn starts_from_cached_certificate_without_network() {
        let directory = tempfile::tempdir().unwrap();
        let provider = AcmeCertificateProvider::new(
            "test".into(),
            options(directory.path()),
            Arc::new(HttpClient::new()),
        )
        .unwrap();
        tokio::fs::create_dir_all(&provider.inner.paths.directory)
            .await
            .unwrap();
        let certified = generate_simple_self_signed(["example.com".into()]).unwrap();
        let cached = CachedCertificate {
            certificate_pem: certified.cert.pem(),
            private_key_pem: certified.signing_key.serialize_pem(),
        };
        atomic_write(
            &provider.inner.paths.certificate,
            &serde_json::to_vec(&cached).unwrap(),
        )
        .await
        .unwrap();

        provider.start(StartStage::Start).await.unwrap();
        let receiver = provider.subscribe("example.com").unwrap();
        assert!(receiver.borrow().is_some());
        provider.close().await.unwrap();
    }
}
