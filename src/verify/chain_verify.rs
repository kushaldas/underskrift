//! Certificate chain and revocation validation.
//!
//! Validates the signer's certificate chain against a trust store.
//! Builds the chain from embedded CMS certificates and verifies it
//! leads to a trusted root.
//!
//! # Online Path Validation
//!
//! When the `ltv` feature is enabled, [`validate_certificate_path`] performs
//! full path validation with per-certificate revocation checking (OCSP + CRL)
//! and X.509 extension validation. The original [`verify_chain`] function
//! remains available for offline-only validation.

use x509_cert::Certificate;

use crate::trust::TrustStore;

#[cfg(feature = "ltv")]
use chrono::{DateTime, Utc};

#[cfg(feature = "ltv")]
use crate::ltv::crl::CrlClient;
#[cfg(feature = "ltv")]
use crate::ltv::ocsp::OcspClient;
#[cfg(feature = "ltv")]
use crate::ltv::revocation::{check_certificate_revocation, RevocationConfig};
#[cfg(feature = "ltv")]
use crate::ltv::status::ValidationStatus;
#[cfg(feature = "ltv")]
use crate::ltv::x509_ext::{validate_extensions_for_role, CertRole};

/// Result of certificate chain validation.
#[derive(Debug)]
pub struct ChainVerifyResult {
    /// Whether the chain is valid and leads to a trusted root
    pub trusted: bool,
    /// The certificate chain in order: [leaf, intermediate..., root]
    /// Only populated if chain building succeeds
    pub chain: Vec<Certificate>,
    /// Name of the trust anchor that validated the chain, if any
    pub trust_anchor_subject: Option<String>,
    /// Certificate validity status
    pub cert_validity: CertValidity,
    /// Human-readable issues
    pub issues: Vec<String>,
}

/// Certificate validity status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertValidity {
    /// Certificate and chain are valid
    Valid,
    /// Certificate has expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Certificate is revoked (placeholder — full revocation checking in ltv module)
    Revoked(String),
    /// Certificate chain is incomplete (cannot build path to trust anchor)
    ChainIncomplete,
    /// Root certificate is not in the trust store
    UntrustedRoot,
    /// Validation error
    ValidationError(String),
}

/// Validate a signer certificate's chain against a trust store.
///
/// Attempts to build a certificate chain from the signer's certificate
/// through any intermediates to a trust anchor, then verifies the
/// cryptographic chain of signatures and time validity.
///
/// `signer_cert` is the end-entity certificate from the CMS signer info.
/// `embedded_certs` are all certificates from the CMS SignedData.
/// `trust_store` is the trust store containing root CA certificates.
pub fn verify_chain(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
    trust_store: &TrustStore,
) -> ChainVerifyResult {
    let mut issues = Vec::new();

    // Build the certificate chain from signer cert to root
    let chain = match build_chain(signer_cert, embedded_certs) {
        Ok(chain) => chain,
        Err(e) => {
            issues.push(format!("chain building failed: {e}"));
            return ChainVerifyResult {
                trusted: false,
                chain: vec![signer_cert.clone()],
                trust_anchor_subject: None,
                cert_validity: CertValidity::ChainIncomplete,
                issues,
            };
        }
    };

    // Verify the chain against the trust store
    // Use the current system time for validation
    let now = {
        let utc = chrono::Utc::now();
        der::DateTime::new(
            utc.format("%Y").to_string().parse().unwrap_or(2026),
            utc.format("%m").to_string().parse().unwrap_or(1),
            utc.format("%d").to_string().parse().unwrap_or(1),
            utc.format("%H").to_string().parse().unwrap_or(0),
            utc.format("%M").to_string().parse().unwrap_or(0),
            utc.format("%S").to_string().parse().unwrap_or(0),
        )
        .ok()
    };
    match trust_store.verify_chain(&chain, now) {
        Ok(anchor) => {
            let anchor_subject = format!("{}", anchor.tbs_certificate.subject);
            ChainVerifyResult {
                trusted: true,
                chain,
                trust_anchor_subject: Some(anchor_subject),
                cert_validity: CertValidity::Valid,
                issues,
            }
        }
        Err(e) => {
            let cert_validity = match &e {
                crate::error::TrustError::Expired { .. } => CertValidity::Expired,
                crate::error::TrustError::NotYetValid { .. } => CertValidity::NotYetValid,
                crate::error::TrustError::UntrustedRoot { .. } => CertValidity::UntrustedRoot,
                crate::error::TrustError::ChainBroken { .. } => CertValidity::ChainIncomplete,
                other => CertValidity::ValidationError(format!("{other}")),
            };
            issues.push(format!("chain verification failed: {e}"));
            ChainVerifyResult {
                trusted: false,
                chain,
                trust_anchor_subject: None,
                cert_validity,
                issues,
            }
        }
    }
}

// ── Online path validation (ltv feature) ──────────────────────────

/// Result of full path validation with per-certificate revocation checking.
///
/// This extends the basic [`ChainVerifyResult`] with per-certificate revocation
/// status information from OCSP and CRL checks.
///
/// Only available with the `ltv` feature.
#[cfg(feature = "ltv")]
#[derive(Debug)]
pub struct PathValidationResult {
    /// Overall status of the certificate path validation.
    ///
    /// - `Valid` if chain is trusted, all certs are time-valid, extensions
    ///   are correct, and no certificate is revoked.
    /// - `Revoked` if any certificate in the chain is revoked.
    /// - `Unknown` if revocation status could not be determined but
    ///   `require_revocation_check` is true.
    /// - `Invalid` on structural/crypto failures.
    pub overall_status: ValidationStatus,

    /// The certificate chain in order: [leaf, intermediate..., root].
    pub chain: Vec<Certificate>,

    /// Per-certificate validation details, in the same order as `chain`.
    pub per_cert_status: Vec<CertPathEntry>,

    /// Subject of the trust anchor that validated the chain, if any.
    pub trust_anchor: Option<String>,

    /// Human-readable issues encountered during validation.
    pub issues: Vec<String>,
}

/// Per-certificate status within a path validation.
///
/// Only available with the `ltv` feature.
#[cfg(feature = "ltv")]
#[derive(Debug)]
pub struct CertPathEntry {
    /// Certificate subject name (DN).
    pub subject: String,

    /// Whether the certificate's issuer chain is cryptographically valid.
    pub chain_valid: bool,

    /// Whether the certificate is within its validity period.
    pub time_valid: bool,

    /// Whether X.509 extensions pass role validation.
    pub extensions_valid: bool,

    /// Revocation status from OCSP/CRL checking.
    pub revocation_status: ValidationStatus,
}

/// Perform full path validation with per-certificate revocation checking.
///
/// This is the online-capable path validation entry point. It:
///
/// 1. Builds the certificate chain from the signer cert through intermediates
/// 2. Verifies the chain against the trust store (signatures + time)
/// 3. Validates X.509 extensions for each certificate's role
/// 4. Checks revocation status of each certificate via OCSP and CRL concurrently
/// 5. Aggregates per-cert results into an overall status
///
/// # Arguments
///
/// - `signer_cert` — end-entity certificate from the CMS signer info
/// - `embedded_certs` — all certificates from the CMS SignedData
/// - `trust_store` — trust store containing root CA certificates
/// - `revocation_config` — timeout/behavior configuration for OCSP/CRL
/// - `crl_client` — CRL fetching client
/// - `ocsp_client` — OCSP querying client
/// - `validation_time` — if `None`, uses the current time
///
/// # Returns
///
/// A [`PathValidationResult`] with per-certificate details and an overall status.
#[cfg(feature = "ltv")]
pub async fn validate_certificate_path(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
    trust_store: &TrustStore,
    revocation_config: &RevocationConfig,
    crl_client: &CrlClient,
    ocsp_client: &OcspClient,
    validation_time: Option<DateTime<Utc>>,
) -> PathValidationResult {
    let mut issues = Vec::new();
    let mut per_cert_status = Vec::new();

    // Step 1: Build the certificate chain
    let chain = match build_chain(signer_cert, embedded_certs) {
        Ok(chain) => chain,
        Err(e) => {
            issues.push(format!("chain building failed: {e}"));
            return PathValidationResult {
                overall_status: ValidationStatus::Invalid {
                    reason: format!("chain building failed: {e}"),
                },
                chain: vec![signer_cert.clone()],
                per_cert_status: vec![CertPathEntry {
                    subject: format!("{}", signer_cert.tbs_certificate.subject),
                    chain_valid: false,
                    time_valid: false,
                    extensions_valid: false,
                    revocation_status: ValidationStatus::Unknown {
                        reason: "chain building failed".into(),
                    },
                }],
                trust_anchor: None,
                issues,
            };
        }
    };

    // Step 2: Verify the chain against the trust store (signatures + time)
    // Use the provided validation_time (e.g. from a verified timestamp) or fall back to now.
    let check_time = {
        let utc = validation_time.unwrap_or_else(chrono::Utc::now);
        der::DateTime::new(
            utc.format("%Y").to_string().parse().unwrap_or(2026),
            utc.format("%m").to_string().parse().unwrap_or(1),
            utc.format("%d").to_string().parse().unwrap_or(1),
            utc.format("%H").to_string().parse().unwrap_or(0),
            utc.format("%M").to_string().parse().unwrap_or(0),
            utc.format("%S").to_string().parse().unwrap_or(0),
        )
        .ok()
    };

    let (chain_valid, trust_anchor_subject, anchor_cert) =
        match trust_store.verify_chain(&chain, check_time) {
            Ok(anchor) => {
                let anchor_subject = format!("{}", anchor.tbs_certificate.subject);
                (true, Some(anchor_subject), Some(anchor))
            }
            Err(e) => {
                issues.push(format!("chain verification failed: {e}"));
                (false, None, None)
            }
        };

    // Step 3: Per-certificate validation (extensions + revocation)
    for (i, cert) in chain.iter().enumerate() {
        let subject = format!("{}", cert.tbs_certificate.subject);

        // Time validity: check against validation time
        let time_valid = if let Some(ref vt) = check_time {
            let validity = &cert.tbs_certificate.validity;
            *vt >= validity.not_before.to_date_time()
                && *vt <= validity.not_after.to_date_time()
        } else {
            true // No time to check against
        };

        // Extension validation: determine role
        let role = if i == 0 {
            CertRole::EndEntity
        } else {
            CertRole::IntermediateCa
        };

        let extensions_valid = match validate_extensions_for_role(cert, role) {
            Ok(()) => true,
            Err(e) => {
                issues.push(format!("cert[{i}] ({subject}): extension validation failed: {e}"));
                false
            }
        };

        // Revocation checking: find the issuer for this cert
        let issuer = if i + 1 < chain.len() {
            // Issuer is the next cert in the chain
            Some(&chain[i + 1])
        } else {
            // Last cert in chain — issuer is the trust anchor
            anchor_cert
        };

        let revocation_status = if let Some(issuer_cert) = issuer {
            check_certificate_revocation(
                cert,
                issuer_cert,
                revocation_config,
                crl_client,
                ocsp_client,
                validation_time,
            )
            .await
        } else {
            ValidationStatus::Unknown {
                reason: "no issuer available for revocation checking".into(),
            }
        };

        if revocation_status.is_revoked() {
            issues.push(format!("cert[{i}] ({subject}): {revocation_status}"));
        } else if revocation_status.is_unknown() && revocation_config.require_revocation_check {
            issues.push(format!(
                "cert[{i}] ({subject}): revocation status unknown: {revocation_status}"
            ));
        }

        per_cert_status.push(CertPathEntry {
            subject,
            chain_valid,
            time_valid,
            extensions_valid,
            revocation_status,
        });
    }

    // Step 4: Compute overall status
    let overall_status = compute_path_status(&per_cert_status, chain_valid, revocation_config);

    PathValidationResult {
        overall_status,
        chain,
        per_cert_status,
        trust_anchor: trust_anchor_subject,
        issues,
    }
}

/// Compute the overall path validation status from per-certificate results.
#[cfg(feature = "ltv")]
fn compute_path_status(
    entries: &[CertPathEntry],
    chain_valid: bool,
    config: &RevocationConfig,
) -> ValidationStatus {
    // If chain itself is invalid, the whole path is invalid
    if !chain_valid {
        return ValidationStatus::Invalid {
            reason: "certificate chain verification failed".into(),
        };
    }

    // Check for any revoked certificate — REVOKED wins
    for entry in entries {
        if entry.revocation_status.is_revoked() {
            return entry.revocation_status.clone();
        }
    }

    // Check for structural failures (time, extensions)
    for entry in entries {
        if !entry.time_valid {
            return ValidationStatus::Invalid {
                reason: format!("certificate {} is not time-valid", entry.subject),
            };
        }
        if !entry.extensions_valid {
            return ValidationStatus::Invalid {
                reason: format!(
                    "certificate {} failed extension validation",
                    entry.subject
                ),
            };
        }
    }

    // Check for unknown revocation when required
    if config.require_revocation_check {
        for entry in entries {
            if entry.revocation_status.is_unknown() {
                return ValidationStatus::Unknown {
                    reason: format!(
                        "revocation status unknown for {}",
                        entry.subject
                    ),
                };
            }
        }
    }

    // All checks passed
    ValidationStatus::Valid {
        source: crate::ltv::status::RevocationSource::Ocsp, // placeholder source
        checked_at: Utc::now(),
    }
}

/// Sync wrapper for [`validate_certificate_path`].
///
/// Available when both the `ltv` and `blocking` features are enabled.
/// Uses `tokio::runtime::Runtime::block_on()` to execute the async
/// function synchronously.
#[cfg(all(feature = "ltv", feature = "blocking"))]
pub fn validate_certificate_path_blocking(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
    trust_store: &TrustStore,
    revocation_config: &RevocationConfig,
    crl_client: &CrlClient,
    ocsp_client: &OcspClient,
    validation_time: Option<DateTime<Utc>>,
) -> PathValidationResult {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");
    rt.block_on(validate_certificate_path(
        signer_cert,
        embedded_certs,
        trust_store,
        revocation_config,
        crl_client,
        ocsp_client,
        validation_time,
    ))
}

// ── Chain building (shared) ──────────────────────────────────────

/// Build a certificate chain from a leaf certificate through intermediates.
///
/// Starting from the signer's certificate, finds each issuer in the
/// embedded certificates set, building a chain [leaf, intermediate_0, ..., intermediate_n].
/// The root CA is NOT included in the chain (it's found in the trust store).
///
/// Stops when:
/// - A self-signed certificate is found (root CA in the embedded set)
/// - No issuer is found in the embedded set (issuer should be in the trust store)
/// - Maximum chain depth is exceeded (prevents loops)
pub(crate) fn build_chain(
    signer_cert: &Certificate,
    embedded_certs: &[Certificate],
) -> Result<Vec<Certificate>, String> {
    const MAX_CHAIN_DEPTH: usize = 10;

    let mut chain = vec![signer_cert.clone()];
    let mut current = signer_cert.clone();

    for _ in 0..MAX_CHAIN_DEPTH {
        let issuer_name = &current.tbs_certificate.issuer;
        let subject_name = &current.tbs_certificate.subject;

        // Check if this is a self-signed cert (issuer == subject)
        if issuer_name == subject_name {
            // Self-signed — this is a root CA. Don't include it in the chain
            // if it's not the leaf (the trust store should have it).
            if chain.len() > 1 {
                // Remove the self-signed cert from the chain — trust store verifies against it
                // Actually, keep it — the trust store's verify_chain expects [leaf, ..., last_intermediate]
                // and the last intermediate's issuer should match a trust anchor.
                // A self-signed cert IS the root, so remove it from the chain.
                chain.pop();
            }
            break;
        }

        // Find the issuer in the embedded certificates
        let issuer_cert = embedded_certs.iter().find(|cert| {
            cert.tbs_certificate.subject == *issuer_name
                // Don't match ourselves
                && cert.tbs_certificate.serial_number != current.tbs_certificate.serial_number
        });

        match issuer_cert {
            Some(cert) => {
                chain.push(cert.clone());
                current = cert.clone();
            }
            None => {
                // Issuer not in embedded certs — should be in the trust store
                break;
            }
        }
    }

    if chain.is_empty() {
        Err("empty chain".to_string())
    } else {
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_validity_enum() {
        assert_eq!(CertValidity::Valid, CertValidity::Valid);
        assert_ne!(CertValidity::Valid, CertValidity::Expired);
    }

    // ── Path validation tests (require ltv feature) ───────────────

    #[cfg(feature = "ltv")]
    mod path_validation {
        use super::*;
        use crate::ltv::crl::CrlClient;
        use crate::ltv::ocsp::OcspClient;
        use crate::ltv::revocation::RevocationConfig;
        use crate::trust::TrustStore;
        use der::Decode;

        fn load_cert(pem: &str) -> Certificate {
            let (_, der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
            Certificate::from_der(&der).unwrap()
        }

        fn _ca_cert() -> Certificate {
            load_cert(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ca_cert.pem"
            )))
        }

        fn intermediate_cert() -> Certificate {
            load_cert(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/intermediate_ca_cert.pem"
            )))
        }

        fn signer_cert() -> Certificate {
            load_cert(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signer_cert.pem"
            )))
        }

        fn make_trust_store() -> TrustStore {
            TrustStore::from_pem_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ca_cert.pem"
            ))
            .unwrap()
        }

        #[tokio::test]
        async fn test_path_validation_trusted_chain_unknown_revocation() {
            // Our test certs have no OCSP/CRL endpoints, so revocation will
            // be Unknown. With require_revocation_check = true, overall should
            // be Unknown.
            let signer = signer_cert();
            let intermediate = intermediate_cert();
            let embedded = vec![signer.clone(), intermediate.clone()];
            let trust_store = make_trust_store();
            let config = RevocationConfig::default(); // require_revocation_check = true
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            // Chain should be trusted (trust anchor found)
            assert!(
                result.trust_anchor.is_some(),
                "should find trust anchor, got: {:?}",
                result.issues
            );

            // But overall status should be Unknown because revocation
            // could not be checked (no endpoints)
            assert!(
                result.overall_status.is_unknown(),
                "overall should be Unknown when revocation is required but \
                 certs have no OCSP/CRL endpoints, got: {}",
                result.overall_status
            );

            // Per-cert entries should exist for signer + intermediate
            assert_eq!(
                result.per_cert_status.len(),
                2,
                "should have 2 per-cert entries"
            );

            // Each cert should have chain_valid=true, time_valid=true
            for entry in &result.per_cert_status {
                assert!(entry.chain_valid, "chain should be valid for {}", entry.subject);
                assert!(entry.time_valid, "time should be valid for {}", entry.subject);
                assert!(
                    entry.revocation_status.is_unknown(),
                    "revocation should be unknown for {} (no endpoints)",
                    entry.subject
                );
            }
        }

        #[tokio::test]
        async fn test_path_validation_disabled_revocation_check() {
            // When require_revocation_check = false, Unknown revocation
            // should still result in overall Valid (chain is trusted).
            let signer = signer_cert();
            let intermediate = intermediate_cert();
            let embedded = vec![signer.clone(), intermediate.clone()];
            let trust_store = make_trust_store();
            let config = RevocationConfig::disabled(); // require_revocation_check = false
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            assert!(
                result.trust_anchor.is_some(),
                "should find trust anchor"
            );
            assert!(
                result.overall_status.is_valid(),
                "overall should be Valid when revocation checking is not \
                 required, got: {}",
                result.overall_status
            );
        }

        #[tokio::test]
        async fn test_path_validation_untrusted_root() {
            // Use an empty trust store — chain should be untrusted.
            let signer = signer_cert();
            let intermediate = intermediate_cert();
            let embedded = vec![signer.clone(), intermediate.clone()];
            let trust_store = TrustStore::new(); // empty
            let config = RevocationConfig::disabled();
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            assert!(
                result.trust_anchor.is_none(),
                "should NOT find trust anchor with empty store"
            );
            assert!(
                result.overall_status.is_invalid(),
                "overall should be Invalid with untrusted root, got: {}",
                result.overall_status
            );
        }

        #[tokio::test]
        async fn test_path_validation_signer_only_no_intermediate() {
            // Signer cert without intermediate in embedded certs.
            // Chain building should produce [signer] only.
            // Trust store has root CA but signer was issued by intermediate,
            // so chain verification should fail.
            let signer = signer_cert();
            let embedded = vec![signer.clone()];
            let trust_store = make_trust_store();
            let config = RevocationConfig::disabled();
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            // The chain will be [signer] and the trust store won't find the
            // intermediate CA as issuer, so it should fail
            assert!(
                result.overall_status.is_invalid(),
                "should be Invalid when intermediate is missing, got: {}",
                result.overall_status
            );
        }

        #[tokio::test]
        async fn test_path_validation_per_cert_extensions_validated() {
            // Verify that per-cert extension validation is done correctly.
            // Our test signer cert should pass EndEntity validation,
            // our intermediate should pass IntermediateCa validation.
            let signer = signer_cert();
            let intermediate = intermediate_cert();
            let embedded = vec![signer.clone(), intermediate.clone()];
            let trust_store = make_trust_store();
            let config = RevocationConfig::disabled();
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            // Both certs should pass extension validation
            for entry in &result.per_cert_status {
                assert!(
                    entry.extensions_valid,
                    "extensions should be valid for {}",
                    entry.subject
                );
            }
        }

        #[tokio::test]
        async fn test_path_validation_result_has_correct_chain() {
            let signer = signer_cert();
            let intermediate = intermediate_cert();
            let embedded = vec![signer.clone(), intermediate.clone()];
            let trust_store = make_trust_store();
            let config = RevocationConfig::disabled();
            let crl_client = CrlClient::new();
            let ocsp_client = OcspClient::new();

            let result = validate_certificate_path(
                &signer,
                &embedded,
                &trust_store,
                &config,
                &crl_client,
                &ocsp_client,
                None,
            )
            .await;

            // Chain should be [signer, intermediate]
            assert_eq!(result.chain.len(), 2, "chain should have 2 certs");
            assert_eq!(
                result.chain[0].tbs_certificate.subject,
                signer.tbs_certificate.subject,
                "first cert should be the signer"
            );
            assert_eq!(
                result.chain[1].tbs_certificate.subject,
                intermediate.tbs_certificate.subject,
                "second cert should be the intermediate"
            );
        }
    }
}
