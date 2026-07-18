use std::io::Cursor;

use anyhow::{Context, Result};
use rustls::RootCertStore;

const CLOUDFLARE_CA_PEM: &[u8] = include_bytes!("cloudflare_ca.pem");

/// Builds the trust store used by Cloudflare edge and origin TLS sessions.
///
/// Cloudflare Tunnel edges use certificates issued by the Cloudflare Origin
/// SSL CA, which is not part of every public web root bundle.
pub(crate) fn root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut reader = Cursor::new(CLOUDFLARE_CA_PEM);
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots
            .add(certificate.context("parse embedded Cloudflare CA")?)
            .context("add embedded Cloudflare CA")?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_embedded_cloudflare_roots() {
        let roots = root_store().unwrap();
        assert!(roots.len() >= 2);
    }
}
