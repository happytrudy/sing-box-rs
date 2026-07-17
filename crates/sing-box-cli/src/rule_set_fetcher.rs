use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use sing_box_core::{RuleSetFetchResult, RuleSetFetcher};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

const MAX_RESPONSE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub struct HttpRuleSetFetcher {
    client: Arc<HttpClient>,
}

impl HttpRuleSetFetcher {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_client(Arc::new(HttpClient::new()))
    }

    pub fn with_client(client: Arc<HttpClient>) -> Self {
        Self { client }
    }

    async fn fetch_inner(&self, url: &str, etag: Option<&str>) -> Result<RuleSetFetchResult> {
        let mut current_url = url.to_owned();
        for redirects in 0..=MAX_REDIRECTS {
            let parsed = ParsedUrl::parse(&current_url)?;
            let mut headers = Vec::new();
            if let Some(etag) = etag {
                anyhow::ensure!(
                    !etag.contains(['\r', '\n']),
                    "invalid ETag returned by rule-set server"
                );
                headers.push(("If-None-Match".to_owned(), etag.to_owned()));
            }
            headers.push((
                "Accept".to_owned(),
                "application/octet-stream, application/json".to_owned(),
            ));
            let response = self.client.request(&parsed, "GET", &headers, &[]).await?;
            match response.status {
                200 => {
                    let etag = response.header("etag").map(str::to_owned);
                    return Ok(RuleSetFetchResult::Modified {
                        content: response.body,
                        etag,
                    });
                }
                304 => return Ok(RuleSetFetchResult::NotModified),
                301 | 302 | 303 | 307 | 308 => {
                    anyhow::ensure!(redirects < MAX_REDIRECTS, "too many rule-set redirects");
                    let location = response
                        .header("location")
                        .context("rule-set redirect is missing Location")?;
                    current_url = parsed.resolve(location)?;
                }
                status => anyhow::bail!("rule-set server returned HTTP {status}"),
            }
        }
        unreachable!("redirect loop always returns or errors")
    }
}

pub struct HttpClient {
    tls_config: Arc<ClientConfig>,
}

impl HttpClient {
    pub fn new() -> Self {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(tls_config),
        }
    }

    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let parsed = ParsedUrl::parse(&request.url)?;
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.request(&parsed, &request.method, &request.headers, &request.body),
        )
        .await
        .context("HTTP request timed out")?
    }

    async fn request(
        &self,
        url: &ParsedUrl,
        method: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        anyhow::ensure!(
            !method.is_empty()
                && method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'-'),
            "invalid HTTP method"
        );
        for (name, value) in headers {
            anyhow::ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && !value.contains(['\r', '\n']),
                "invalid HTTP header"
            );
        }
        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .with_context(|| format!("connect rule-set server {}:{}", url.host, url.port))?;
        let mut stream: Box<dyn IoStream> = if url.https {
            let server_name = ServerName::try_from(url.host.clone())
                .context("invalid HTTPS rule-set server name")?;
            Box::new(
                TlsConnector::from(Arc::clone(&self.tls_config))
                    .connect(server_name, tcp)
                    .await
                    .context("connect HTTPS rule-set server")?,
            )
        } else {
            Box::new(tcp)
        };

        let mut request = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            url.target, url.host_header
        );
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            request.push_str(&format!(
                "User-Agent: sing-box-rs/{}\r\n",
                env!("CARGO_PKG_VERSION")
            ));
        }
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        if (!body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH"))
            && !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await?;

        let mut bytes = Vec::new();
        stream
            .take(MAX_RESPONSE_SIZE + 1)
            .read_to_end(&mut bytes)
            .await
            .context("read rule-set HTTP response")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_RESPONSE_SIZE,
            "rule-set HTTP response exceeds size limit"
        );
        HttpResponse::parse(bytes, method == "HEAD")
    }
}

pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[async_trait]
impl RuleSetFetcher for HttpRuleSetFetcher {
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<RuleSetFetchResult> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.fetch_inner(url, etag))
            .await
            .context("rule-set request timed out")?
    }
}

trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct ParsedUrl {
    https: bool,
    scheme: &'static str,
    authority: String,
    host: String,
    port: u16,
    host_header: String,
    target: String,
}

impl ParsedUrl {
    fn parse(value: &str) -> Result<Self> {
        let (https, scheme, rest, default_port) = if let Some(rest) = value.strip_prefix("https://")
        {
            (true, "https", rest, 443)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (false, "http", rest, 80)
        } else {
            anyhow::bail!("rule-set URL must use http:// or https://")
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        anyhow::ensure!(!authority.is_empty(), "rule-set URL host is empty");
        anyhow::ensure!(
            !authority.contains('@'),
            "rule-set URL userinfo is not supported"
        );
        let (host, port) = parse_authority(authority, default_port)?;
        let mut target = &rest[authority_end..];
        if let Some(fragment) = target.find('#') {
            target = &target[..fragment];
        }
        let target = if target.is_empty() {
            "/".to_owned()
        } else if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_owned()
        };
        anyhow::ensure!(
            !target.contains(['\r', '\n', ' ']),
            "invalid character in rule-set URL"
        );
        let host_header = if port == default_port {
            authority_host(&host)
        } else {
            format!("{}:{port}", authority_host(&host))
        };
        Ok(Self {
            https,
            scheme,
            authority: authority.to_owned(),
            host,
            port,
            host_header,
            target,
        })
    }

    fn resolve(&self, location: &str) -> Result<String> {
        anyhow::ensure!(
            !location.contains(['\r', '\n']),
            "invalid rule-set redirect location"
        );
        if location.starts_with("http://") || location.starts_with("https://") {
            return Ok(location.to_owned());
        }
        if let Some(location) = location.strip_prefix("//") {
            return Ok(format!("{}://{location}", self.scheme));
        }
        if location.starts_with('/') {
            return Ok(format!("{}://{}{}", self.scheme, self.authority, location));
        }
        let base = self.target.split('?').next().unwrap_or("/");
        let directory =
            base.rsplit_once('/').map_or(
                "/",
                |(directory, _)| {
                    if directory.is_empty() { "/" } else { directory }
                },
            );
        Ok(format!(
            "{}://{}{}/{}",
            self.scheme,
            self.authority,
            directory.trim_end_matches('/'),
            location
        ))
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .context("invalid bracketed IPv6 URL host")?;
        let host = &bracketed[..closing];
        let suffix = &bracketed[closing + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .context("invalid bracketed IPv6 URL authority")?
                .parse()?
        };
        anyhow::ensure!(!host.is_empty(), "rule-set URL host is empty");
        return Ok((host.to_owned(), port));
    }
    anyhow::ensure!(
        authority.matches(':').count() <= 1,
        "IPv6 rule-set URL hosts must use brackets"
    );
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            anyhow::ensure!(!host.is_empty(), "rule-set URL host is empty");
            Ok((host.to_owned(), port.parse()?))
        }
        None => Ok((authority.to_owned(), default_port)),
    }
}

fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn parse(mut bytes: Vec<u8>, head_request: bool) -> Result<Self> {
        let header_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .context("invalid rule-set HTTP response")?;
        anyhow::ensure!(
            header_end <= 64 * 1024,
            "rule-set HTTP headers are too large"
        );
        let body = bytes.split_off(header_end + 4);
        bytes.truncate(header_end);
        let header_text = std::str::from_utf8(&bytes).context("invalid rule-set HTTP headers")?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().context("missing HTTP status line")?;
        let mut status_parts = status_line.split_whitespace();
        let version = status_parts.next().context("missing HTTP version")?;
        anyhow::ensure!(
            version.starts_with("HTTP/1."),
            "unsupported HTTP response version"
        );
        let status = status_parts
            .next()
            .context("missing HTTP response status")?
            .parse()?;
        let mut headers = HashMap::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .with_context(|| format!("invalid HTTP header: {line}"))?;
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        let body = if head_request {
            Vec::new()
        } else if headers
            .get("transfer-encoding")
            .is_some_and(|value| value.split(',').any(|item| item.trim() == "chunked"))
        {
            decode_chunked(&body)?
        } else if let Some(length) = headers.get("content-length") {
            let length = length.parse::<usize>()?;
            anyhow::ensure!(
                body.len() >= length,
                "truncated rule-set HTTP response body"
            );
            body[..length].to_vec()
        } else {
            body
        };
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>> {
    let mut remaining = input;
    let mut output = Vec::new();
    loop {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("invalid chunked rule-set response")?;
        let line = std::str::from_utf8(&remaining[..line_end])?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or(""), 16)?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        anyhow::ensure!(
            remaining.len() >= size + 2 && &remaining[size..size + 2] == b"\r\n",
            "truncated chunked rule-set response"
        );
        anyhow::ensure!(
            output.len().saturating_add(size) as u64 <= MAX_RESPONSE_SIZE,
            "rule-set HTTP response exceeds size limit"
        );
        output.extend_from_slice(&remaining[..size]);
        remaining = &remaining[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_urls_and_relative_redirects() {
        let url = ParsedUrl::parse("https://[2001:db8::1]:8443/a/rules.srs?q=1").unwrap();
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 8443);
        assert_eq!(url.host_header, "[2001:db8::1]:8443");
        assert_eq!(
            url.resolve("next.srs").unwrap(),
            "https://[2001:db8::1]:8443/a/next.srs"
        );
    }

    #[test]
    fn decodes_chunked_response() {
        let response = HttpResponse::parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: test\r\n\r\n4\r\nrule\r\n3\r\nset\r\n0\r\n\r\n"
                .to_vec(),
            false,
        )
        .unwrap();
        assert_eq!(response.body, b"ruleset");
        assert_eq!(response.header("etag"), Some("test"));
    }

    #[tokio::test]
    async fn sends_conditional_request_and_handles_not_modified() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains("If-None-Match: \"version-1\"\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let result = HttpRuleSetFetcher::new()
            .fetch(
                &format!("http://{address}/rules.srs"),
                Some("\"version-1\""),
            )
            .await
            .unwrap();
        assert!(matches!(result, RuleSetFetchResult::NotModified));
        server.await.unwrap();
    }
}
