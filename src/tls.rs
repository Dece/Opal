//! Trying desperately to not implement a security colander.

use std::sync::Arc;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Supported signature verification mechanisms; copied from Rustls source.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// A `ClientCertVerifier` for Gemini.
///
/// Client certificate is optional. When provided, we check that it is valid for use by a client.
/// No certificate chain is verified as client certs in Gemini are mostly self-signed anyway.
/// Signature verification is left to the default implementation.
pub struct GeminiClientCertVerifier {}

impl GeminiClientCertVerifier {
    pub fn new() -> Arc<dyn rustls::server::ClientCertVerifier> {
        Arc::new(Self {})
    }
}

impl rustls::server::ClientCertVerifier for GeminiClientCertVerifier {
    /// Make client certificate optional.
    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(false)
    }

    /// Do not provide CA names.
    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        Some(vec![])
    }

    /// “Verify” client certificates.
    ///
    /// Actually do not verify much, mostly that the certificate is well-formed. Like Rustls, we
    /// rely on the WebPKI crate to verify the certificate. It rejects self-signed client
    /// certificates early in the verification stage (we can't do much against that), and we ignore
    /// that error because Gemini clients mostly use self-signed certificates, so we can miss other
    /// WebPKI verifications errors. We should use a validation process that reports all issues
    /// found or provide a way to filter acceptable issues, but we can't blame anyone on this…
    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificateEncoding)?;
        let now = webpki::Time::try_from(now).map_err(|_| rustls::Error::FailedToGetCurrentTime)?;
        let verified = rustls::server::ClientCertVerified::assertion();
        match cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TlsClientTrustAnchors(&vec![]),
            &intermediates
                .iter()
                .map(|c| c.0.as_ref())
                .collect::<Vec<&[u8]>>(),
            now,
        ) {
            Ok(()) => Ok(verified),
            Err(e) => match e {
                // It's OK for client certs to be self-signed.
                webpki::Error::CaUsedAsEndEntity => Ok(verified),
                // Any other error is fatal.
                _ => Err(rustls::Error::InvalidCertificateData(format!(
                    "invalid client cert: {}",
                    e
                ))),
            },
        }
    }
}
