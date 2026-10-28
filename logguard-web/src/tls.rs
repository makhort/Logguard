//! The console's TLS: TLS 1.3 only, with a certificate and key from PEM files that are read
//! again when they change (a renewed Let's Encrypt certificate needs no restart). `gen-cert`
//! makes a self-signed one; the browser then shows its fingerprint to compare with
//! `logguard-web fingerprint`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::say;

/// How often the files are looked at for a renewal.
const CHECK_EVERY: Duration = Duration::from_secs(60);

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Reads a certificate chain and its key.
pub fn load(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("{}: not a PEM certificate", cert.display()))?;
    if chain.is_empty() {
        bail!("{}: no certificate in it", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("{}: no PEM private key in it", key.display()))?;
    let ck = CertifiedKey::from_der(chain, key, &provider()).map_err(|e| anyhow!("certificate and key: {e}"))?;
    Ok(Arc::new(ck))
}

fn modified(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Hands out the current certificate; reloads it when its files change.
#[derive(Debug)]
pub struct Reloading {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<(Option<SystemTime>, Option<SystemTime>, Arc<CertifiedKey>)>,
    checked: Mutex<Instant>,
}

impl Reloading {
    pub fn new(cert: PathBuf, key: PathBuf) -> Result<Self> {
        let ck = load(&cert, &key)?;
        let stamps = (modified(&cert), modified(&key));
        Ok(Reloading { current: RwLock::new((stamps.0, stamps.1, ck)), cert, key, checked: Mutex::new(Instant::now()) })
    }

    fn maybe_reload(&self) {
        {
            let mut checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
            if checked.elapsed() < CHECK_EVERY {
                return;
            }
            *checked = Instant::now();
        }
        let stamps = (modified(&self.cert), modified(&self.key));
        let changed = {
            let cur = self.current.read().unwrap_or_else(|e| e.into_inner());
            (cur.0, cur.1) != stamps
        };
        if !changed {
            return;
        }
        match load(&self.cert, &self.key) {
            Ok(ck) => {
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = (stamps.0, stamps.1, ck);
                say!("console: certificate reloaded from {}", self.cert.display());
            }
            // a renewal half written (the certificate before its key): kept, tried again later
            Err(e) => say!("console: certificate not reloaded, keeping the old one: {e:#}"),
        }
    }
}

impl ResolvesServerCert for Reloading {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.maybe_reload();
        Some(Arc::clone(&self.current.read().unwrap_or_else(|e| e.into_inner()).2))
    }
}

/// The server's TLS settings: TLS 1.3, HTTP/1.1.
pub fn server_config(cert: PathBuf, key: PathBuf) -> Result<Arc<rustls::ServerConfig>> {
    let resolver = Reloading::new(cert, key)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A certificate's SHA-256 fingerprint as browsers show it (`AB:CD:...`).
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// The fingerprint of the first certificate in a PEM file.
pub fn file_fingerprint(cert: &Path) -> Result<String> {
    let first = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .next()
        .with_context(|| format!("{}: no certificate in it", cert.display()))?
        .with_context(|| format!("{}: not a PEM certificate", cert.display()))?;
    Ok(fingerprint(&first))
}

/// A self-signed certificate (ECDSA P-256, five years) for `names` (host names or
/// addresses): `(certificate PEM, key PEM, fingerprint)`.
pub fn self_signed(names: &[String]) -> Result<(String, String, String)> {
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| anyhow!("certificate names: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("logguard-web {}", names.first().map_or("", String::as_str)));
    let day = |offset_days: i64| {
        let (y, m, d) = crate::time::ymd(crate::time::now() + offset_days * 86_400 * crate::time::SEC);
        rcgen::date_time_ymd(y as i32, m as u8, d as u8)
    };
    params.not_before = day(-1);
    params.not_after = day(5 * 365);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| anyhow!("key: {e}"))?;
    let cert = params.self_signed(&key).map_err(|e| anyhow!("certificate: {e}"))?;
    Ok((cert.pem(), key.serialize_pem(), fingerprint(cert.der())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_loads() {
        let (cert, key, fp) = self_signed(&["console.example.org".into(), "192.0.2.10".into()]).unwrap();
        let dir = std::env::temp_dir().join(format!("lgw-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("c.pem"), &cert).unwrap();
        std::fs::write(dir.join("k.pem"), &key).unwrap();
        load(&dir.join("c.pem"), &dir.join("k.pem")).unwrap();
        assert_eq!(file_fingerprint(&dir.join("c.pem")).unwrap(), fp);
        assert_eq!(fp.len(), 32 * 3 - 1);
        server_config(dir.join("c.pem"), dir.join("k.pem")).unwrap();
        // a key that isn't the certificate's
        let (_, other, _) = self_signed(&["x".into()]).unwrap();
        std::fs::write(dir.join("k2.pem"), other).unwrap();
        assert!(load(&dir.join("c.pem"), &dir.join("k2.pem")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
