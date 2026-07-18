use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use sing_box_core::{Address, Dialer, ProxyStream, Session, SystemDialer};
use sing_quic::hysteria2::MasqueradeHandler;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::OnceCell,
};
use tokio_rustls::TlsConnector;

const MAX_PROXY_RESPONSE_SIZE: u64 = 64 * 1024 * 1024;
const PROXY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum MasqueradeOptions {
    Url(String),
    Object(MasqueradeObjectOptions),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum MasqueradeObjectOptions {
    File {
        directory: String,
    },
    Proxy {
        url: String,
        #[serde(default)]
        rewrite_host: bool,
    },
    String {
        #[serde(default)]
        status_code: u16,
        #[serde(default)]
        headers: HashMap<String, HeaderValues>,
        #[serde(default)]
        content: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum HeaderValues {
    One(String),
    Many(Vec<String>),
}

impl HeaderValues {
    fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

pub(super) fn build(
    options: Option<MasqueradeOptions>,
    system_dialer: SystemDialer,
) -> Result<Option<Arc<dyn MasqueradeHandler>>> {
    let Some(options) = options else {
        return Ok(None);
    };
    let handler = match options {
        MasqueradeOptions::Url(url) if url.starts_with("file:") => {
            Handler::File(FileHandler::new(parse_file_url(&url)?)?)
        }
        MasqueradeOptions::Url(url) => Handler::Proxy(ProxyHandler::new(
            ProxyTarget::parse(&url)?,
            false,
            system_dialer,
        )),
        MasqueradeOptions::Object(MasqueradeObjectOptions::File { directory }) => {
            Handler::File(FileHandler::new(directory)?)
        }
        MasqueradeOptions::Object(MasqueradeObjectOptions::Proxy { url, rewrite_host }) => {
            Handler::Proxy(ProxyHandler::new(
                ProxyTarget::parse(&url)?,
                rewrite_host,
                system_dialer,
            ))
        }
        MasqueradeOptions::Object(MasqueradeObjectOptions::String {
            status_code,
            headers,
            content,
        }) => Handler::Fixed(FixedHandler::new(status_code, headers, content)?),
    };
    Ok(Some(Arc::new(handler)))
}

fn parse_file_url(value: &str) -> Result<String> {
    let mut path = value
        .strip_prefix("file:")
        .expect("checked file URL scheme");
    if let Some(authority_and_path) = path.strip_prefix("//") {
        path = authority_and_path
            .find('/')
            .map_or("", |path_start| &authority_and_path[path_start..]);
    }
    let path_end = path.find(['?', '#']).unwrap_or(path.len());
    let path = percent_decode(&path[..path_end]).context("invalid masquerade file URL path")?;
    anyhow::ensure!(
        path.starts_with('/'),
        "masquerade file URL must contain an absolute path"
    );
    Ok(path)
}

enum Handler {
    File(FileHandler),
    Proxy(ProxyHandler),
    Fixed(FixedHandler),
}

impl MasqueradeHandler for Handler {
    fn handle(
        &self,
        source: std::net::SocketAddr,
        request: Request<Vec<u8>>,
    ) -> BoxFuture<'static, Response<Vec<u8>>> {
        match self {
            Self::File(handler) => handler.handle(request),
            Self::Proxy(handler) => handler.handle(source, request),
            Self::Fixed(handler) => handler.handle(),
        }
    }
}

struct FixedHandler {
    status: StatusCode,
    headers: HeaderMap,
    content: Vec<u8>,
}

impl FixedHandler {
    fn new(
        status_code: u16,
        configured_headers: HashMap<String, HeaderValues>,
        content: String,
    ) -> Result<Self> {
        let status = if status_code == 0 {
            StatusCode::OK
        } else {
            StatusCode::from_u16(status_code).context("invalid masquerade status_code")?
        };
        anyhow::ensure!(
            !status.is_informational(),
            "masquerade status_code cannot be informational"
        );
        let mut headers = HeaderMap::new();
        for (name, values) in configured_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid masquerade header name {name:?}"))?;
            for value in values.values() {
                headers.append(
                    name.clone(),
                    HeaderValue::from_str(value)
                        .with_context(|| format!("invalid masquerade header value for {name}"))?,
                );
            }
        }
        Ok(Self {
            status,
            headers,
            content: content.into_bytes(),
        })
    }

    fn handle(&self) -> BoxFuture<'static, Response<Vec<u8>>> {
        let status = self.status;
        let headers = self.headers.clone();
        let content = self.content.clone();
        Box::pin(async move {
            let mut response = Response::new(content);
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            response
        })
    }
}

struct FileHandler {
    root: PathBuf,
    canonical_root: Arc<OnceCell<PathBuf>>,
}

impl FileHandler {
    fn new(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        anyhow::ensure!(
            !directory.as_os_str().is_empty(),
            "masquerade file directory is empty"
        );
        if let Ok(metadata) = std::fs::metadata(directory) {
            anyhow::ensure!(metadata.is_dir(), "masquerade file path is not a directory");
        }
        let root = if directory.is_absolute() {
            directory.to_owned()
        } else {
            std::env::current_dir()?.join(directory)
        };
        Ok(Self {
            root,
            canonical_root: Arc::new(OnceCell::new()),
        })
    }

    fn handle(&self, request: Request<Vec<u8>>) -> BoxFuture<'static, Response<Vec<u8>>> {
        let root = self.root.clone();
        let canonical_root = Arc::clone(&self.canonical_root);
        Box::pin(async move { serve_file(root, canonical_root, request).await })
    }
}

async fn serve_file(
    root: PathBuf,
    canonical_root: Arc<OnceCell<PathBuf>>,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return response_with_header(
            StatusCode::METHOD_NOT_ALLOWED,
            "allow",
            "GET, HEAD",
            Vec::new(),
        );
    }
    let Some(relative) = safe_relative_path(request.uri().path()) else {
        return plain_response(StatusCode::NOT_FOUND, Vec::new());
    };
    let canonical_root = match canonical_root
        .get_or_try_init(|| async { tokio::fs::canonicalize(&root).await })
        .await
    {
        Ok(root) => root,
        Err(_) => return plain_response(StatusCode::NOT_FOUND, Vec::new()),
    };
    let requested = root.join(relative);
    let mut path = match tokio::fs::canonicalize(&requested).await {
        Ok(path) if path.starts_with(canonical_root) => path,
        _ => return plain_response(StatusCode::NOT_FOUND, Vec::new()),
    };
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(_) => return plain_response(StatusCode::NOT_FOUND, Vec::new()),
    };
    if metadata.is_dir() {
        if !request.uri().path().ends_with('/') {
            let mut location = format!("{}/", request.uri().path());
            if let Some(query) = request.uri().query() {
                location.push('?');
                location.push_str(query);
            }
            return response_with_header(
                StatusCode::MOVED_PERMANENTLY,
                LOCATION.as_str(),
                &location,
                Vec::new(),
            );
        }
        let index = path.join("index.html");
        if tokio::fs::metadata(&index)
            .await
            .is_ok_and(|metadata| metadata.is_file())
        {
            path = index;
        } else {
            return directory_listing(&path, request.uri().path()).await;
        }
    }
    let body = match tokio::fs::read(&path).await {
        Ok(body) => body,
        Err(_) => return plain_response(StatusCode::NOT_FOUND, Vec::new()),
    };
    let mut response = plain_response(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type(&path)));
    response
}

async fn directory_listing(path: &Path, request_path: &str) -> Response<Vec<u8>> {
    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
        Err(_) => return plain_response(StatusCode::NOT_FOUND, Vec::new()),
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(name) = entry.file_name().into_string() {
            let is_dir = entry.file_type().await.is_ok_and(|kind| kind.is_dir());
            names.push((name, is_dir));
        }
    }
    names.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let escaped_path = html_escape(request_path);
    let mut html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of {escaped_path}</title></head><body><h1>Index of {escaped_path}</h1><pre>"
    );
    if request_path != "/" {
        html.push_str("<a href=\"../\">../</a>\n");
    }
    for (name, is_dir) in names {
        let suffix = if is_dir { "/" } else { "" };
        html.push_str(&format!(
            "<a href=\"{}{}\">{}{}</a>\n",
            percent_encode_segment(&name),
            suffix,
            html_escape(&name),
            suffix
        ));
    }
    html.push_str("</pre></body></html>");
    let mut response = plain_response(StatusCode::OK, html.into_bytes());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn safe_relative_path(path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(path)?;
    if decoded.contains('\\') || decoded.contains('\0') {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in Path::new(decoded.trim_start_matches('/')).components() {
        match component {
            Component::Normal(component) => relative.push(component),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(relative)
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex_value(high)? << 4 | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

struct ProxyHandler {
    target: ProxyTarget,
    rewrite_host: bool,
    system_dialer: SystemDialer,
    tls_config: Arc<ClientConfig>,
}

impl ProxyHandler {
    fn new(target: ProxyTarget, rewrite_host: bool, system_dialer: SystemDialer) -> Self {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("configure masquerade TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Self {
            target,
            rewrite_host,
            system_dialer,
            tls_config: Arc::new(tls_config),
        }
    }

    fn handle(
        &self,
        source: std::net::SocketAddr,
        request: Request<Vec<u8>>,
    ) -> BoxFuture<'static, Response<Vec<u8>>> {
        let target = self.target.clone();
        let rewrite_host = self.rewrite_host;
        let system_dialer = self.system_dialer.clone();
        let tls_config = Arc::clone(&self.tls_config);
        Box::pin(async move {
            let result = tokio::time::timeout(
                PROXY_TIMEOUT,
                proxy_request(
                    target,
                    rewrite_host,
                    system_dialer,
                    tls_config,
                    source,
                    request,
                ),
            )
            .await;
            match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "Hysteria2 masquerade proxy request failed");
                    plain_response(StatusCode::BAD_GATEWAY, Vec::new())
                }
                Err(_) => {
                    tracing::warn!("Hysteria2 masquerade proxy request timed out");
                    plain_response(StatusCode::GATEWAY_TIMEOUT, Vec::new())
                }
            }
        })
    }
}

#[derive(Clone)]
struct ProxyTarget {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    base_path: String,
    base_query: Option<String>,
}

impl ProxyTarget {
    fn parse(value: &str) -> Result<Self> {
        let uri: Uri = value.parse().context("invalid masquerade proxy URL")?;
        let scheme = uri
            .scheme_str()
            .context("masquerade proxy URL is missing a scheme")?;
        let (https, default_port) = match scheme {
            "http" => (false, 80),
            "https" => (true, 443),
            _ => anyhow::bail!("unknown masquerade URL scheme: {scheme}"),
        };
        let authority = uri
            .authority()
            .context("masquerade proxy URL is missing a host")?;
        anyhow::ensure!(
            !authority.as_str().contains('@'),
            "masquerade proxy URL userinfo is not supported"
        );
        let host = uri
            .host()
            .context("masquerade proxy URL host is empty")?
            .to_owned();
        let port = uri.port_u16().unwrap_or(default_port);
        let base_path = if uri.path().is_empty() {
            "/".to_owned()
        } else {
            uri.path().to_owned()
        };
        Ok(Self {
            https,
            host,
            port,
            authority: authority.as_str().to_owned(),
            base_path,
            base_query: uri.query().map(str::to_owned),
        })
    }

    fn request_target(&self, request: &Uri) -> String {
        let path = join_url_path(&self.base_path, request.path());
        match (self.base_query.as_deref(), request.query()) {
            (None, None) => path,
            (Some(base), None) => format!("{path}?{base}"),
            (None, Some(query)) => format!("{path}?{query}"),
            (Some(base), Some(query)) => format!("{path}?{base}&{query}"),
        }
    }
}

fn join_url_path(base: &str, request: &str) -> String {
    match (base.ends_with('/'), request.starts_with('/')) {
        (true, true) => format!("{}{}", base, &request[1..]),
        (false, false) => format!("{base}/{request}"),
        _ => format!("{base}{request}"),
    }
}

async fn proxy_request(
    target: ProxyTarget,
    rewrite_host: bool,
    system_dialer: SystemDialer,
    tls_config: Arc<ClientConfig>,
    source: std::net::SocketAddr,
    request: Request<Vec<u8>>,
) -> Result<Response<Vec<u8>>> {
    let destination = Address::new(target.host.clone(), target.port)?;
    let stream = system_dialer
        .connect(&Session::outbound(destination))
        .await
        .context("connect masquerade proxy target")?;
    let mut stream: Box<dyn ProxyStream> = if target.https {
        let server_name = ServerName::try_from(target.host.clone())
            .context("invalid masquerade HTTPS server name")?;
        Box::new(
            TlsConnector::from(tls_config)
                .connect(server_name, stream)
                .await
                .context("connect masquerade HTTPS target")?,
        )
    } else {
        stream
    };

    let upstream_target = target.request_target(request.uri());
    let request_host = if rewrite_host {
        target.authority.clone()
    } else {
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_owned())
            .unwrap_or_else(|| target.authority.clone())
    };
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    remove_hop_by_hop_headers(&mut headers);
    headers.remove(HOST);
    headers.remove(CONTENT_LENGTH);
    let forwarded_for = match headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) if !existing.is_empty() => format!("{existing}, {}", source.ip()),
        _ => source.ip().to_string(),
    };
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&forwarded_for)?,
    );

    let mut encoded = Vec::new();
    encoded.extend_from_slice(parts.method.as_str().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(upstream_target.as_bytes());
    encoded.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    encoded.extend_from_slice(request_host.as_bytes());
    encoded.extend_from_slice(b"\r\n");
    for (name, value) in &headers {
        encoded.extend_from_slice(name.as_str().as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() || matches!(parts.method, Method::POST | Method::PUT | Method::PATCH) {
        encoded.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    encoded.extend_from_slice(b"Connection: close\r\n\r\n");
    encoded.extend_from_slice(&body);
    stream.write_all(&encoded).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream
        .take(MAX_PROXY_RESPONSE_SIZE + 1)
        .read_to_end(&mut response)
        .await?;
    anyhow::ensure!(
        response.len() as u64 <= MAX_PROXY_RESPONSE_SIZE,
        "masquerade proxy response exceeds size limit"
    );
    parse_proxy_response(&response, parts.method == Method::HEAD)
}

fn parse_proxy_response(bytes: &[u8], is_head: bool) -> Result<Response<Vec<u8>>> {
    let header_end = find_bytes(bytes, b"\r\n\r\n").context("invalid proxy HTTP response")?;
    let head = std::str::from_utf8(&bytes[..header_end]).context("proxy headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("proxy response status is missing")?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    anyhow::ensure!(
        version == "HTTP/1.0" || version == "HTTP/1.1",
        "unsupported proxy HTTP version"
    );
    let status = StatusCode::from_u16(
        status_parts
            .next()
            .context("proxy response status is missing")?
            .parse()?,
    )?;
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("malformed proxy response header")?;
        headers.append(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        );
    }
    let transfer_chunked = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        });
    let raw_body = &bytes[header_end + 4..];
    let body = if is_head || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED
    {
        Vec::new()
    } else if transfer_chunked {
        decode_chunked(raw_body)?
    } else if let Some(length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(str::parse::<usize>)
        .transpose()?
    {
        anyhow::ensure!(raw_body.len() >= length, "truncated proxy response body");
        raw_body[..length].to_vec()
    } else {
        raw_body.to_vec()
    };
    remove_hop_by_hop_headers(&mut headers);
    if !is_head {
        headers.remove(CONTENT_LENGTH);
    }
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<HashSet<_>>();
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
}

fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = find_bytes(bytes, b"\r\n").context("invalid chunked response")?;
        let size = std::str::from_utf8(&bytes[..line_end])?
            .split(';')
            .next()
            .context("chunk size is missing")?
            .trim();
        let size = usize::from_str_radix(size, 16).context("invalid chunk size")?;
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        anyhow::ensure!(bytes.len() >= size + 2, "truncated chunked response");
        decoded.extend_from_slice(&bytes[..size]);
        anyhow::ensure!(&bytes[size..size + 2] == b"\r\n", "invalid chunk ending");
        bytes = &bytes[size + 2..];
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn plain_response(status: StatusCode, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

fn response_with_header(
    status: StatusCode,
    name: &str,
    value: &str,
    body: Vec<u8>,
) -> Response<Vec<u8>> {
    let mut response = plain_response(status, body);
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        response.headers_mut().insert(name, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    #[test]
    fn parses_sing_box_masquerade_forms() {
        let url: MasqueradeOptions = serde_json::from_str(r#""http://127.0.0.1:8080""#).unwrap();
        assert!(matches!(url, MasqueradeOptions::Url(_)));
        assert_eq!(parse_file_url("file:/var/www").unwrap(), "/var/www");
        assert_eq!(
            parse_file_url("file://localhost/var/www%20root").unwrap(),
            "/var/www root"
        );
        let object: MasqueradeOptions = serde_json::from_str(
            r#"{
                "type": "string",
                "status_code": 201,
                "headers": {"x-test": ["one", "two"]},
                "content": "created"
            }"#,
        )
        .unwrap();
        assert!(matches!(
            object,
            MasqueradeOptions::Object(MasqueradeObjectOptions::String { .. })
        ));
    }

    #[tokio::test]
    async fn file_handler_serves_index_and_rejects_traversal() {
        let directory = tempdir().unwrap();
        tokio::fs::write(directory.path().join("index.html"), b"decoy")
            .await
            .unwrap();
        let handler = FileHandler::new(directory.path()).unwrap();
        let response = handler
            .handle(
                Request::get("https://example.com/")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"decoy");

        let response = handler
            .handle(
                Request::get("https://example.com/%2e%2e/secret")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn decodes_chunked_proxy_response() {
        let response = parse_proxy_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            false,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"hello");
        assert!(!response.headers().contains_key(TRANSFER_ENCODING));
    }

    #[tokio::test]
    async fn proxy_rewrites_target_and_forwards_client_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let length = stream.read(&mut buffer).await.unwrap();
                assert!(length > 0);
                request.extend_from_slice(&buffer[..length]);
                if find_bytes(&request, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let target = ProxyTarget::parse(&format!("http://{address}/base?token=a")).unwrap();
        let handler = ProxyHandler::new(target, true, SystemDialer::default());
        let response = handler
            .handle(
                "192.0.2.10:12345".parse().unwrap(),
                Request::get("https://decoy.example/asset?q=b")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"hello");

        let request = server.await.unwrap();
        assert!(request.starts_with("GET /base/asset?token=a&q=b HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Host: {address}\r\n")));
        assert!(request.contains("x-forwarded-for: 192.0.2.10\r\n"));
    }
}
