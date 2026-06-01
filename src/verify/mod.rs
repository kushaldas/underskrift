//! Signature verification and validation.
//!
//! Extracts signatures from PDFs, verifies CMS cryptographic integrity,
//! validates certificate chains, and checks ByteRange integrity.
//!
//! # Usage
//!
//! ```no_run
//! use underskrift::verify::{SignatureVerifier, VerificationReport};
//! use underskrift::trust::{TrustStore, TrustStoreSet};
//!
//! # fn example() -> Result<(), underskrift::PdfSignError> {
//! // Load the PDF and set up trust store
//! let pdf = std::fs::read("signed.pdf")?;
//! let trust = TrustStore::from_pem_file("ca-cert.pem")?;
//! let trust_set = TrustStoreSet::new().with_sig_store(trust);
//!
//! // Verify all signatures
//! let verifier = SignatureVerifier::new(&trust_set);
//! let report = verifier.verify_pdf(&pdf)?;
//!
//! for sig in &report.signatures {
//!     println!("{}: {:?}", sig.field_name, sig.status);
//! }
//! # Ok(())
//! # }
//! ```

pub mod chain_verify;
pub mod cms_verify;
pub mod extractor;
pub mod integrity;
pub mod report;

// Re-export key types for convenience
#[cfg(all(feature = "ltv", feature = "blocking"))]
pub use chain_verify::validate_certificate_path_blocking;
pub use chain_verify::CertValidity;
#[cfg(feature = "ltv")]
pub use chain_verify::{validate_certificate_path, CertPathEntry, PathValidationResult};
pub use extractor::{ExtractedSignature, SignatureType};
pub use report::{
    CryptoValidity, DetectedPadesLevel, SignatureStatus, SignatureVerificationResult,
    VerificationReport,
};

use crate::core::revision::{DefaultSafeObjectClassifier, RevisionAnalysis};
use crate::crypto::algorithm::DigestAlgorithm;
use crate::error::{PdfSignError, VerifyError};
use crate::policy::SignatureValidationPolicy;
use crate::trust::TrustStoreSet;

#[cfg(feature = "ltv")]
use crate::ltv::crl::CrlClient;
#[cfg(feature = "ltv")]
use crate::ltv::ocsp::OcspClient;
#[cfg(feature = "ltv")]
use crate::ltv::revocation::RevocationConfig;

/// PDF signature verifier.
///
/// Orchestrates the full verification pipeline:
/// 1. Extract signatures from the PDF
/// 2. For each signature:
///    a. Verify ByteRange integrity
///    b. Verify CMS cryptographic signature
///    c. Validate the certificate chain
/// 3. Return a structured verification report
pub struct SignatureVerifier<'a> {
    /// Trust stores (signature, TSA, SVT)
    trust_stores: &'a TrustStoreSet,
    /// Whether to allow online validation (OCSP/CRL fetching).
    /// When false, only embedded validation data is used.
    /// Defaults to false (offline-only for now; online comes in Phase 4).
    allow_online: bool,
    /// Validation policy to apply after verification.
    ///
    /// When set, the policy is evaluated for each signature after all
    /// sub-verifications are complete. The result is stored in
    /// `SignatureVerificationResult.policy_result`.
    policy: Option<Box<dyn SignatureValidationPolicy>>,
    /// Revocation checking configuration (requires `ltv` feature).
    #[cfg(feature = "ltv")]
    revocation_config: Option<RevocationConfig>,
    /// CRL client for fetching CRLs (requires `ltv` feature).
    #[cfg(feature = "ltv")]
    crl_client: Option<CrlClient>,
    /// OCSP client for querying OCSP responders (requires `ltv` feature).
    #[cfg(feature = "ltv")]
    ocsp_client: Option<OcspClient>,
}

impl<'a> SignatureVerifier<'a> {
    /// Create a new verifier with the given trust store set.
    pub fn new(trust_stores: &'a TrustStoreSet) -> Self {
        Self {
            trust_stores,
            allow_online: false,
            policy: None,
            #[cfg(feature = "ltv")]
            revocation_config: None,
            #[cfg(feature = "ltv")]
            crl_client: None,
            #[cfg(feature = "ltv")]
            ocsp_client: None,
        }
    }

    /// Set whether online validation (OCSP/CRL) is allowed.
    pub fn allow_online(mut self, allow: bool) -> Self {
        self.allow_online = allow;
        self
    }

    /// Set a validation policy to apply after verification.
    ///
    /// When set, the policy is evaluated for each signature after all
    /// sub-verifications are complete. The three-valued conclusion
    /// (PASSED / FAILED / INDETERMINATE) is stored in
    /// `SignatureVerificationResult.policy_result`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use underskrift::verify::SignatureVerifier;
    /// use underskrift::policy::BasicPdfSignaturePolicy;
    /// use underskrift::trust::TrustStoreSet;
    ///
    /// let trust_set = TrustStoreSet::new();
    /// let verifier = SignatureVerifier::new(&trust_set)
    ///     .policy(Box::new(BasicPdfSignaturePolicy::new()));
    /// ```
    pub fn policy(mut self, policy: Box<dyn SignatureValidationPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the revocation checking configuration.
    ///
    /// When set together with `allow_online(true)`, the verifier will perform
    /// per-certificate OCSP and CRL revocation checks during chain validation.
    ///
    /// Requires the `ltv` feature.
    #[cfg(feature = "ltv")]
    pub fn revocation_config(mut self, config: RevocationConfig) -> Self {
        self.revocation_config = Some(config);
        self
    }

    /// Set the CRL client for fetching CRLs.
    ///
    /// Requires the `ltv` feature.
    #[cfg(feature = "ltv")]
    pub fn crl_client(mut self, client: CrlClient) -> Self {
        self.crl_client = Some(client);
        self
    }

    /// Set the OCSP client for querying OCSP responders.
    ///
    /// Requires the `ltv` feature.
    #[cfg(feature = "ltv")]
    pub fn ocsp_client(mut self, client: OcspClient) -> Self {
        self.ocsp_client = Some(client);
        self
    }

    /// Verify all signatures in a PDF document.
    ///
    /// Returns a `VerificationReport` with per-signature results and
    /// an overall document status.
    pub fn verify_pdf(&self, pdf_data: &[u8]) -> Result<VerificationReport, PdfSignError> {
        // Step 1: Extract all signatures
        let extracted = extractor::extract_signatures(pdf_data)?;

        if extracted.is_empty() {
            return Err(VerifyError::NoSignatures.into());
        }

        // Step 1b: Run revision analysis (best-effort; if it fails, fall back
        // to simple byte-range checks, but record a warning)
        let revision_analysis =
            RevisionAnalysis::analyze(pdf_data, &DefaultSafeObjectClassifier).ok();
        let revision_analysis_failed = revision_analysis.is_none();

        let mut results = Vec::with_capacity(extracted.len());
        let num_sigs = extracted.len();

        for (idx, sig) in extracted.iter().enumerate() {
            let is_last = idx == num_sigs - 1;
            let mut result =
                self.verify_single_signature(pdf_data, sig, is_last, revision_analysis.as_ref());

            // If revision analysis failed, record a warning in each signature's
            // integrity_issues so consumers know that shadow-attack and
            // incremental-save-attack detection was not available.
            if revision_analysis_failed {
                result.integrity_issues.push(
                    "revision analysis failed; shadow attack detection was not available"
                        .to_string(),
                );
            }

            results.push(result);
        }

        // Compute summary stats
        let valid_count = results
            .iter()
            .filter(|r| r.status == SignatureStatus::Valid)
            .count();
        let invalid_count = results.len() - valid_count;
        let document_modified = results
            .last()
            .map(|r| r.modifications_after_signing)
            .unwrap_or(false);

        // Policy stats
        let mut policy_passed_count = 0;
        let mut policy_failed_count = 0;
        let mut policy_indeterminate_count = 0;
        for r in &results {
            if let Some(ref pr) = r.policy_result {
                match pr.conclusion {
                    crate::policy::PolicyConclusion::Passed => policy_passed_count += 1,
                    crate::policy::PolicyConclusion::Failed => policy_failed_count += 1,
                    crate::policy::PolicyConclusion::Indeterminate => {
                        policy_indeterminate_count += 1
                    }
                }
            }
        }

        let summary = if valid_count == results.len() {
            format!("all {} signatures valid and trusted", results.len())
        } else if valid_count > 0 {
            format!(
                "{} of {} signatures valid; {} invalid/indeterminate",
                valid_count,
                results.len(),
                invalid_count
            )
        } else {
            format!("no valid signatures found ({} checked)", results.len())
        };

        Ok(VerificationReport {
            signatures: results,
            document_modified,
            valid_count,
            invalid_count,
            policy_passed_count,
            policy_failed_count,
            policy_indeterminate_count,
            summary,
        })
    }

    /// Verify a single extracted signature.
    fn verify_single_signature(
        &self,
        pdf_data: &[u8],
        sig: &ExtractedSignature,
        is_last: bool,
        revision_analysis: Option<&RevisionAnalysis>,
    ) -> SignatureVerificationResult {
        // Dispatch: DocTimestamp uses a completely different verification path
        if sig.signature_type == SignatureType::DocTimestamp {
            return self.verify_doc_timestamp_signature(pdf_data, sig, is_last, revision_analysis);
        }

        let mut all_issues = Vec::new();

        // --- Step A: ByteRange integrity ---
        // Determine digest algorithm: we'll try to get it from CMS first,
        // but we need to parse CMS for that. Use SHA-256 as default for
        // integrity check; we'll re-hash if CMS says otherwise.
        let default_digest = DigestAlgorithm::Sha256;

        let integrity_result =
            integrity::verify_byte_range(pdf_data, &sig.byte_range, default_digest);
        let integrity_ok = integrity_result.valid;
        let covers_whole_document = integrity_result.covers_whole_file;
        let integrity_issues = integrity_result.issues.clone();
        all_issues.extend(integrity_result.issues);

        // --- Step B: CMS cryptographic verification ---
        let (
            crypto_validity,
            digest_matches,
            signer_cert,
            embedded_certs,
            _cms_digest_alg,
            cms_signing_time,
            ess_cert_id_match,
            signature_timestamp_token,
            signature_value,
            dtbsr_hash,
            signature_algorithm_oid,
        ) = match cms_verify::verify_cms(&sig.cms_bytes, &integrity_result.data_hash) {
            Ok(cms_result) => {
                all_issues.extend(cms_result.issues.clone());

                let crypto_validity = if !cms_result.signature_valid {
                    let reason = cms_result
                        .issues
                        .iter()
                        .find(|i| i.contains("signature"))
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    CryptoValidity::Invalid(reason)
                } else if !cms_result.algorithm_protection_ok {
                    CryptoValidity::Invalid(
                        "CMS Algorithm Protection mismatch (RFC 6211)".to_string(),
                    )
                } else {
                    CryptoValidity::Valid
                };

                // If CMS says a different digest algorithm than our default,
                // we should re-hash. For now, this only matters if they differ.
                let actual_digest = cms_result.digest_algorithm.unwrap_or(default_digest);
                let final_digest_matches = if actual_digest != default_digest {
                    // Re-compute hash with the correct algorithm
                    let rehash = integrity::compute_byte_range_hash(
                        pdf_data,
                        &sig.byte_range,
                        actual_digest,
                    );
                    // Re-verify CMS with correct hash
                    match cms_verify::verify_cms(&sig.cms_bytes, &rehash) {
                        Ok(r2) => r2.digest_matches,
                        Err(_) => false,
                    }
                } else {
                    cms_result.digest_matches
                };

                (
                    crypto_validity,
                    final_digest_matches,
                    cms_result.signer_certificate,
                    cms_result.embedded_certificates,
                    Some(actual_digest),
                    cms_result.cms_signing_time,
                    cms_result.ess_cert_id_match,
                    cms_result.signature_timestamp_token,
                    cms_result.signature_value,
                    cms_result.dtbsr_hash,
                    cms_result.signature_algorithm_oid,
                )
            }
            Err(e) => {
                all_issues.push(format!("CMS verification error: {e}"));
                (
                    CryptoValidity::Invalid(e.to_string()),
                    false,
                    None,
                    Vec::new(),
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    None,
                )
            }
        };

        // --- Step B2: Verify signature timestamp token ---
        // If the CMS contains a signature timestamp (id-aa-signatureTimeStampToken),
        // verify it against the TSA trust store and extract the verified time.
        let (timestamp_time, validation_time_used) = if let Some(ref token_der) =
            signature_timestamp_token
        {
            if let Some(tsa_store) = self.trust_stores.tsa() {
                match cms_verify::verify_timestamp_token(token_der, &signature_value, tsa_store) {
                    Ok(ts_result) => {
                        all_issues.extend(ts_result.issues);
                        if ts_result.tsa_signature_valid
                            && ts_result.message_imprint_valid
                            && ts_result.tsa_chain_trusted
                        {
                            // Fully verified timestamp — use it for validation time
                            let ts_str = ts_result.gen_time.to_rfc3339();
                            (Some(ts_str), Some(ts_result.gen_time))
                        } else {
                            // Timestamp token present but verification incomplete
                            let ts_str = ts_result.gen_time.to_rfc3339();
                            all_issues.push(
                                "signature timestamp present but not fully verified".to_string(),
                            );
                            (Some(ts_str), None)
                        }
                    }
                    Err(e) => {
                        all_issues.push(format!("signature timestamp verification failed: {e}"));
                        (None, None)
                    }
                }
            } else {
                all_issues.push(
                    "signature timestamp present but no TSA trust store configured".to_string(),
                );
                (None, None)
            }
        } else {
            (None, None)
        };

        // --- Step C: Certificate chain validation ---
        // When allow_online + ltv feature: full path validation with revocation
        // When offline: basic chain verification only
        #[cfg(feature = "ltv")]
        let (
            certificate_validity,
            chain_trusted,
            trust_anchor,
            revocation_status,
            per_cert_revocation,
        ) = if let Some(ref signer_cert) = signer_cert {
            if let Some(sig_store) = self.trust_stores.sig() {
                if self.allow_online {
                    // Online path validation with per-cert revocation checking
                    self.verify_chain_online(
                        signer_cert,
                        &embedded_certs,
                        sig_store,
                        validation_time_used,
                    )
                } else {
                    // Offline-only chain verification
                    let chain_result =
                        chain_verify::verify_chain(signer_cert, &embedded_certs, sig_store);
                    all_issues.extend(chain_result.issues);
                    (
                        chain_result.cert_validity,
                        chain_result.trusted,
                        chain_result.trust_anchor_subject,
                        None,
                        Vec::new(),
                    )
                }
            } else {
                all_issues.push("no signature trust store configured".to_string());
                (
                    CertValidity::ValidationError("no trust store".to_string()),
                    false,
                    None,
                    None,
                    Vec::new(),
                )
            }
        } else {
            all_issues.push("no signer certificate found — cannot validate chain".to_string());
            (CertValidity::ChainIncomplete, false, None, None, Vec::new())
        };

        #[cfg(not(feature = "ltv"))]
        let (
            certificate_validity,
            chain_trusted,
            trust_anchor,
            revocation_status,
            per_cert_revocation,
        ) = if let Some(ref signer_cert) = signer_cert {
            if let Some(sig_store) = self.trust_stores.sig() {
                let chain_result =
                    chain_verify::verify_chain(signer_cert, &embedded_certs, sig_store);
                all_issues.extend(chain_result.issues);
                (
                    chain_result.cert_validity,
                    chain_result.trusted,
                    chain_result.trust_anchor_subject,
                    None::<()>,
                    Vec::<(String, ())>::new(),
                )
            } else {
                all_issues.push("no signature trust store configured".to_string());
                (
                    CertValidity::ValidationError("no trust store".to_string()),
                    false,
                    None,
                    None,
                    Vec::new(),
                )
            }
        } else {
            all_issues.push("no signer certificate found — cannot validate chain".to_string());
            (CertValidity::ChainIncomplete, false, None, None, Vec::new())
        };

        // --- Step D: Extract signer name and DER bytes for report ---
        let signer_name = signer_cert
            .as_ref()
            .map(|cert| format!("{}", cert.tbs_certificate.subject));

        // DER-encode the signer cert and chain certs for ETSI report Validation Objects
        let signer_cert_der = signer_cert
            .as_ref()
            .and_then(|cert| der::Encode::to_der(cert).ok());
        let chain_certs_der: Vec<Vec<u8>> = embedded_certs
            .iter()
            .filter(|c| {
                // Exclude the signer cert itself from the chain certs
                signer_cert.as_ref().map_or(true, |sc| {
                    c.tbs_certificate.serial_number != sc.tbs_certificate.serial_number
                        || c.tbs_certificate.issuer != sc.tbs_certificate.issuer
                })
            })
            .filter_map(|c| der::Encode::to_der(c).ok())
            .collect();

        // --- Step E: Check post-signature modifications (revision analysis) ---
        let (modifications_after_signing, covers_whole_doc_rev, extended_by_non_safe) =
            if let Some(analysis) = revision_analysis {
                let covers = analysis.covers_whole_document(&sig.byte_range);
                let extended = analysis.is_extended_by_non_safe_updates(&sig.byte_range);
                // modifications_after_signing = the signature doesn't cover everything
                // AND there are non-safe extensions
                let modified = !covers;
                (modified, Some(covers), Some(extended))
            } else {
                // Fallback: simple byte offset check
                let modified = if is_last {
                    integrity::check_post_signature_modifications(pdf_data, &sig.byte_range)
                } else {
                    true
                };
                (modified, None, None)
            };

        // --- Step F: Determine PAdES level ---
        let pades_level = match sig.signature_type {
            SignatureType::Pades => {
                if signature_timestamp_token.is_some() {
                    // Has a signature timestamp → at least B-T
                    // TODO: check for DSS/VRI to detect B-LT, doc timestamps for B-LTA
                    DetectedPadesLevel::BT
                } else {
                    DetectedPadesLevel::BB
                }
            }
            SignatureType::DocTimestamp => DetectedPadesLevel::Unknown,
            _ => DetectedPadesLevel::NotPades,
        };

        // --- Step G: Compute overall status ---
        let status = compute_overall_status(
            integrity_ok,
            &crypto_validity,
            digest_matches,
            chain_trusted,
        );

        let summary = build_summary(&status, &all_issues);

        // Build the result (policy_result is filled in Step H)
        let mut sig_result = SignatureVerificationResult {
            field_name: sig.field_name.clone(),
            status,
            signature_type: sig.signature_type.clone(),
            signer_name,
            signing_time: sig.signing_time.clone(),
            cms_signing_time,
            timestamp_time,
            ess_cert_id_match,
            validation_time_used,
            integrity_ok,
            covers_whole_document,
            integrity_issues,
            cryptographic_validity: crypto_validity,
            digest_matches,
            certificate_validity,
            chain_trusted,
            trust_anchor,
            revocation_status,
            per_cert_revocation,
            pades_level,
            modifications_after_signing,
            covers_whole_document_revision: covers_whole_doc_rev,
            extended_by_non_safe_updates: extended_by_non_safe,
            policy_result: None,
            signer_cert_der,
            chain_certs_der,
            signature_value_bytes: signature_value,
            dtbsr_hash,
            signature_algorithm_oid,
            timestamp_token_der: signature_timestamp_token.clone(),
            summary,
        };

        // --- Step H: Policy evaluation ---
        if let Some(ref policy) = self.policy {
            sig_result.policy_result = Some(policy.evaluate(&sig_result));
        }

        sig_result
    }

    /// Verify a document timestamp signature (SubFilter ETSI.RFC3161).
    ///
    /// Document timestamps differ from regular signatures:
    /// - The CMS `/Contents` IS the timestamp token (not a detached signature)
    /// - The `messageDigest` signed attr = hash of encapsulated TSTInfo DER
    /// - The TSTInfo `messageImprint` = hash of the byte-range data
    /// - Chain validation uses the TSA trust store (not the signature trust store)
    /// - No signingTime, no ESSCertIDv2, no signature timestamp in unsigned attrs
    fn verify_doc_timestamp_signature(
        &self,
        pdf_data: &[u8],
        sig: &ExtractedSignature,
        is_last: bool,
        revision_analysis: Option<&RevisionAnalysis>,
    ) -> SignatureVerificationResult {
        let mut all_issues = Vec::new();
        let default_digest = DigestAlgorithm::Sha256;

        // --- Step A: ByteRange integrity ---
        let integrity_result =
            integrity::verify_byte_range(pdf_data, &sig.byte_range, default_digest);
        let integrity_ok = integrity_result.valid;
        let covers_whole_document = integrity_result.covers_whole_file;
        let integrity_issues = integrity_result.issues.clone();
        all_issues.extend(integrity_result.issues);

        // --- Step B: Verify document timestamp ---
        // For DocTimestamp, use verify_doc_timestamp() which:
        //   1. Verifies TSA CMS signature (messageDigest = hash of TSTInfo)
        //   2. Verifies TSA certificate chain against TSA trust store
        //   3. Validates TSTInfo messageImprint against byte-range hash
        //   4. Extracts genTime
        let (
            crypto_validity,
            digest_matches,
            timestamp_time,
            validation_time_used,
            signer_name,
            chain_trusted,
            trust_anchor,
        ) = if let Some(tsa_store) = self.trust_stores.tsa() {
            match cms_verify::verify_doc_timestamp(
                &sig.cms_bytes,
                &integrity_result.data_hash,
                default_digest,
                tsa_store,
            ) {
                Ok(ts_result) => {
                    // If the TSTInfo uses a different hash algorithm than our default,
                    // re-hash the byte range with the correct algorithm and retry.
                    let (final_result, _used_rehash) = if !ts_result.message_imprint_valid {
                        if let Some(tst_alg) = ts_result.tst_hash_algorithm {
                            if tst_alg != default_digest {
                                let rehash = integrity::compute_byte_range_hash(
                                    pdf_data,
                                    &sig.byte_range,
                                    tst_alg,
                                );
                                match cms_verify::verify_doc_timestamp(
                                    &sig.cms_bytes,
                                    &rehash,
                                    tst_alg,
                                    tsa_store,
                                ) {
                                    Ok(retry_result) => (retry_result, true),
                                    Err(_) => (ts_result, false),
                                }
                            } else {
                                (ts_result, false)
                            }
                        } else {
                            (ts_result, false)
                        }
                    } else {
                        (ts_result, false)
                    };

                    all_issues.extend(final_result.issues.clone());

                    let crypto_valid = if final_result.tsa_signature_valid {
                        CryptoValidity::Valid
                    } else {
                        CryptoValidity::Invalid("TSA signature verification failed".to_string())
                    };

                    let digest_ok = final_result.message_imprint_valid;
                    let chain_ok = final_result.tsa_chain_trusted;

                    // If all checks pass, the genTime is the verified timestamp
                    let (ts_time, val_time) = if final_result.tsa_signature_valid
                        && final_result.message_imprint_valid
                        && final_result.tsa_chain_trusted
                    {
                        let ts_str = final_result.gen_time.to_rfc3339();
                        (Some(ts_str), Some(final_result.gen_time))
                    } else {
                        let ts_str = final_result.gen_time.to_rfc3339();
                        all_issues.push("doc timestamp present but not fully verified".to_string());
                        (Some(ts_str), None)
                    };

                    // For trust anchor, we got it from the TSA chain verification
                    // inside verify_doc_timestamp. We don't have it directly here,
                    // so we report the TSA signer name.
                    (
                        crypto_valid,
                        digest_ok,
                        ts_time,
                        val_time,
                        final_result.tsa_signer_name,
                        chain_ok,
                        None::<String>, // trust anchor not directly available
                    )
                }
                Err(e) => {
                    all_issues.push(format!("doc timestamp verification error: {e}"));
                    (
                        CryptoValidity::Invalid(e.to_string()),
                        false,
                        None,
                        None,
                        None,
                        false,
                        None,
                    )
                }
            }
        } else {
            all_issues.push("doc timestamp present but no TSA trust store configured".to_string());
            (
                CryptoValidity::Invalid("no TSA trust store configured".to_string()),
                false,
                None,
                None,
                None,
                false,
                None,
            )
        };

        // --- Step C: Certificate validity ---
        // For DocTimestamp, the "certificate validity" reflects the TSA chain status.
        // The chain was already verified inside verify_doc_timestamp().
        let certificate_validity = if chain_trusted {
            CertValidity::Valid
        } else if signer_name.is_some() {
            CertValidity::UntrustedRoot
        } else {
            CertValidity::ChainIncomplete
        };

        // --- Step D: Check post-signature modifications (revision analysis) ---
        let (modifications_after_signing, covers_whole_doc_rev, extended_by_non_safe) =
            if let Some(analysis) = revision_analysis {
                let covers = analysis.covers_whole_document(&sig.byte_range);
                let extended = analysis.is_extended_by_non_safe_updates(&sig.byte_range);
                let modified = !covers;
                (modified, Some(covers), Some(extended))
            } else {
                let modified = if is_last {
                    integrity::check_post_signature_modifications(pdf_data, &sig.byte_range)
                } else {
                    true
                };
                (modified, None, None)
            };

        // --- Step E: Compute overall status ---
        let status = compute_overall_status(
            integrity_ok,
            &crypto_validity,
            digest_matches,
            chain_trusted,
        );

        let summary = build_summary(&status, &all_issues);

        // Build the result
        let mut sig_result = SignatureVerificationResult {
            field_name: sig.field_name.clone(),
            status,
            signature_type: sig.signature_type.clone(),
            signer_name,
            signing_time: sig.signing_time.clone(),
            cms_signing_time: None, // DocTimestamps don't have signingTime
            timestamp_time,
            ess_cert_id_match: None, // DocTimestamps don't have ESSCertIDv2
            validation_time_used,
            integrity_ok,
            covers_whole_document,
            integrity_issues,
            cryptographic_validity: crypto_validity,
            digest_matches,
            certificate_validity,
            chain_trusted,
            trust_anchor,
            #[cfg(feature = "ltv")]
            revocation_status: None, // TSA revocation not checked here (yet)
            #[cfg(not(feature = "ltv"))]
            revocation_status: None,
            #[cfg(feature = "ltv")]
            per_cert_revocation: Vec::new(),
            #[cfg(not(feature = "ltv"))]
            per_cert_revocation: Vec::new(),
            pades_level: DetectedPadesLevel::Unknown, // DocTimestamp is not a PAdES level itself
            modifications_after_signing,
            covers_whole_document_revision: covers_whole_doc_rev,
            extended_by_non_safe_updates: extended_by_non_safe,
            policy_result: None,
            // DocTimestamp: no signer cert, chain, or signature value in the traditional sense
            signer_cert_der: None,
            chain_certs_der: Vec::new(),
            signature_value_bytes: Vec::new(),
            dtbsr_hash: Vec::new(),
            signature_algorithm_oid: None,
            timestamp_token_der: None,
            summary,
        };

        // --- Step F: Policy evaluation ---
        if let Some(ref policy) = self.policy {
            sig_result.policy_result = Some(policy.evaluate(&sig_result));
        }

        sig_result
    }

    /// Perform online path validation with revocation checking.
    ///
    /// Uses `validate_certificate_path_blocking` to run the async revocation
    /// checks synchronously. Falls back to basic chain verification if
    /// the required clients are not configured.
    #[cfg(feature = "ltv")]
    #[allow(clippy::type_complexity)]
    fn verify_chain_online(
        &self,
        signer_cert: &x509_cert::Certificate,
        embedded_certs: &[x509_cert::Certificate],
        trust_store: &crate::trust::TrustStore,
        validation_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> (
        CertValidity,
        bool,
        Option<String>,
        Option<crate::ltv::status::ValidationStatus>,
        Vec<(String, crate::ltv::status::ValidationStatus)>,
    ) {
        let config = self.revocation_config.clone().unwrap_or_default();
        let crl = self.crl_client.clone().unwrap_or_default();
        let ocsp = self.ocsp_client.clone().unwrap_or_default();

        // Run the full async path validation using block_on
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
        let path_result = rt.block_on(chain_verify::validate_certificate_path(
            signer_cert,
            embedded_certs,
            trust_store,
            &config,
            &crl,
            &ocsp,
            validation_time,
        ));

        // Convert PathValidationResult to the tuple format expected by verify_single_signature
        let chain_trusted = path_result.trust_anchor.is_some()
            && !path_result.overall_status.is_revoked()
            && !path_result.overall_status.is_invalid();

        let cert_validity = if path_result.overall_status.is_revoked() {
            CertValidity::Revoked(format!("{}", path_result.overall_status))
        } else if path_result.overall_status.is_invalid() {
            CertValidity::ValidationError(format!("{}", path_result.overall_status))
        } else if path_result.trust_anchor.is_none() {
            CertValidity::UntrustedRoot
        } else {
            CertValidity::Valid
        };

        let per_cert: Vec<(String, crate::ltv::status::ValidationStatus)> = path_result
            .per_cert_status
            .into_iter()
            .map(|e| (e.subject, e.revocation_status))
            .collect();

        (
            cert_validity,
            chain_trusted,
            path_result.trust_anchor,
            Some(path_result.overall_status),
            per_cert,
        )
    }
}

/// Compute the overall signature status from sub-results.
fn compute_overall_status(
    integrity_ok: bool,
    crypto_validity: &CryptoValidity,
    digest_matches: bool,
    chain_trusted: bool,
) -> SignatureStatus {
    if !integrity_ok {
        return SignatureStatus::Invalid;
    }

    match crypto_validity {
        CryptoValidity::Valid => {
            if !digest_matches {
                SignatureStatus::Invalid
            } else if chain_trusted {
                SignatureStatus::Valid
            } else {
                SignatureStatus::ValidButUntrusted
            }
        }
        CryptoValidity::Invalid(_) => SignatureStatus::Invalid,
        CryptoValidity::UnknownAlgorithm(_) => SignatureStatus::Indeterminate,
    }
}

/// Build a human-readable summary string.
fn build_summary(status: &SignatureStatus, issues: &[String]) -> String {
    let status_str = match status {
        SignatureStatus::Valid => "VALID",
        SignatureStatus::ValidButUntrusted => "VALID (untrusted)",
        SignatureStatus::Invalid => "INVALID",
        SignatureStatus::Indeterminate => "INDETERMINATE",
    };

    if issues.is_empty() {
        status_str.to_string()
    } else {
        format!("{}: {}", status_str, issues.join("; "))
    }
}
