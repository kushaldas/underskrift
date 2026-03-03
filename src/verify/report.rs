//! Verification result types and signature status reporting.
//!
//! Provides structured types for representing the outcome of verifying
//! each signature in a PDF document. Follows the plan's specification
//! for rich validation results.

use chrono::{DateTime, Utc};

use crate::policy::PolicyResult;
use crate::verify::chain_verify::CertValidity;
use crate::verify::extractor::SignatureType;

/// Overall status of a signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature is cryptographically valid and trusted
    Valid,
    /// Signature is cryptographically valid but chain is not trusted
    ValidButUntrusted,
    /// Signature is cryptographically invalid
    Invalid,
    /// Signature could not be verified (missing data, unsupported algorithm, etc.)
    Indeterminate,
}

/// Cryptographic validity of the signature itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoValidity {
    /// Cryptographic signature is valid
    Valid,
    /// Cryptographic signature is invalid
    Invalid(String),
    /// Algorithm is unknown or unsupported
    UnknownAlgorithm(String),
}

/// Detected PAdES conformance level of a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedPadesLevel {
    /// PAdES B-B (basic)
    BB,
    /// PAdES B-T (with timestamp)
    BT,
    /// PAdES B-LT (with LTV data)
    BLT,
    /// PAdES B-LTA (with archive timestamp)
    BLTA,
    /// Not a PAdES signature
    NotPades,
    /// Cannot determine level
    Unknown,
}

/// Result of verifying a single signature in a PDF.
#[derive(Debug)]
pub struct SignatureVerificationResult {
    /// The signature field name
    pub field_name: String,
    /// Overall status
    pub status: SignatureStatus,
    /// Type of signature (PAdES, PKCS#7, DocTimestamp, etc.)
    pub signature_type: SignatureType,
    /// Signer's common name or subject, if extracted
    pub signer_name: Option<String>,
    /// Signing time from the PDF `/M` dictionary field (unsigned, easily forgeable).
    ///
    /// For authenticated signing time, prefer `cms_signing_time` (from CMS signed
    /// attributes) or `timestamp_time` (from an RFC 3161 timestamp).
    pub signing_time: Option<String>,
    /// CMS signing-time from the `signingTime` signed attribute (OID 1.2.840.113549.1.9.5).
    ///
    /// Present in traditional PKCS#7 / CMS signatures. Absent in PAdES signatures
    /// (which use timestamps instead). This value is authenticated by the CMS
    /// signature but represents an unverified claim by the signer's clock.
    pub cms_signing_time: Option<DateTime<Utc>>,
    /// Timestamp time (from embedded RFC 3161 timestamp), if present
    pub timestamp_time: Option<String>,

    /// Whether the ESS `signingCertificateV2` attribute (RFC 5035) matched the signer cert.
    ///
    /// - `Some(true)` — attribute present and cert hash verified successfully
    /// - `Some(false)` — attribute present but hash mismatch (potential substitution attack)
    /// - `None` — attribute not present (expected for traditional CMS, required for PAdES)
    pub ess_cert_id_match: Option<bool>,

    /// The actual time used for certificate path validation.
    ///
    /// When a verified signature timestamp is available, this is the timestamp time
    /// (enabling long-term validation). Otherwise, the current time is used.
    /// `None` if validation time could not be determined.
    pub validation_time_used: Option<DateTime<Utc>>,

    /// Integrity check: ByteRange is structurally valid
    pub integrity_ok: bool,
    /// Integrity check: ByteRange covers the entire file
    pub covers_whole_document: bool,
    /// ByteRange integrity issues (empty if none)
    pub integrity_issues: Vec<String>,

    /// CMS cryptographic verification result
    pub cryptographic_validity: CryptoValidity,
    /// Whether the messageDigest attribute matches the data hash
    pub digest_matches: bool,

    /// Certificate chain validation result
    pub certificate_validity: CertValidity,
    /// Whether the chain leads to a trusted root
    pub chain_trusted: bool,
    /// Trust anchor subject, if chain is trusted
    pub trust_anchor: Option<String>,

    /// Overall revocation status from path validation.
    ///
    /// `Some(...)` when online path validation was performed (requires `ltv` feature
    /// and `allow_online(true)`). `None` for offline-only validation.
    #[cfg(feature = "ltv")]
    pub revocation_status: Option<crate::ltv::status::ValidationStatus>,
    /// Placeholder when `ltv` feature is not enabled.
    #[cfg(not(feature = "ltv"))]
    pub revocation_status: Option<()>,

    /// Per-certificate revocation status from path validation.
    ///
    /// Each entry is `(subject_name, revocation_status)` for each certificate
    /// in the chain. Empty when online path validation was not performed.
    #[cfg(feature = "ltv")]
    pub per_cert_revocation: Vec<(String, crate::ltv::status::ValidationStatus)>,
    /// Placeholder when `ltv` feature is not enabled.
    #[cfg(not(feature = "ltv"))]
    pub per_cert_revocation: Vec<(String, ())>,

    /// Detected PAdES conformance level
    pub pades_level: DetectedPadesLevel,

    /// Whether the document was modified after this signature
    pub modifications_after_signing: bool,

    /// Whether the signature covers the whole document (revision analysis).
    ///
    /// `true` if the signature is the last revision, or if all subsequent
    /// revisions are safe (DSS updates, timestamps, etc.).
    /// `None` if revision analysis was not performed.
    pub covers_whole_document_revision: Option<bool>,

    /// Whether the signature has been extended by non-safe updates.
    ///
    /// `true` if there are subsequent revisions that are neither signatures
    /// nor valid DSS-only updates. `None` if revision analysis was not performed.
    pub extended_by_non_safe_updates: Option<bool>,

    /// Validation policy result, if a policy was configured.
    ///
    /// Contains the three-valued conclusion (PASSED / FAILED / INDETERMINATE),
    /// the policy identifier, and individual check results.
    /// `None` if no policy was configured on the verifier.
    pub policy_result: Option<PolicyResult>,

    /// Human-readable summary
    pub summary: String,
}

/// Result of verifying all signatures in a PDF.
#[derive(Debug)]
pub struct VerificationReport {
    /// Results for each signature, in document order
    pub signatures: Vec<SignatureVerificationResult>,
    /// Whether the document has been modified after the last signature
    pub document_modified: bool,
    /// Number of valid signatures
    pub valid_count: usize,
    /// Number of invalid/indeterminate signatures
    pub invalid_count: usize,
    /// Number of signatures that passed the configured policy
    pub policy_passed_count: usize,
    /// Number of signatures that failed the configured policy
    pub policy_failed_count: usize,
    /// Number of signatures with indeterminate policy result
    pub policy_indeterminate_count: usize,
    /// Overall document status summary
    pub summary: String,
}

impl VerificationReport {
    /// Whether all signatures are valid and trusted.
    pub fn all_valid(&self) -> bool {
        self.invalid_count == 0 && self.valid_count > 0
    }

    /// Whether any signature is valid (even if not all are).
    pub fn any_valid(&self) -> bool {
        self.valid_count > 0
    }

    /// Whether all signatures passed the configured policy.
    ///
    /// Returns `true` if at least one policy was evaluated and all concluded PASSED.
    /// Returns `false` if no policy was configured or any policy concluded
    /// FAILED/INDETERMINATE.
    pub fn all_policies_passed(&self) -> bool {
        self.policy_passed_count > 0
            && self.policy_failed_count == 0
            && self.policy_indeterminate_count == 0
    }
}
