//! PKIX-based PDF signature validation policy.
//!
//! A revocation-aware policy that extends the basic pre-checks with
//! certificate revocation status verification and configurable grace
//! period logic.
//!
//! Corresponds to the Java stack's `PkixPdfSignaturePolicyValidator` with
//! policy identifier `pkix/01`.
//!
//! # Grace period logic
//!
//! When a certificate is revoked, the policy checks whether the signature
//! was created *before* the revocation time, allowing for a configurable
//! grace period:
//!
//! ```text
//! earliest_verified_timestamp + grace_period < revocation_time → PASSED
//! ```
//!
//! This means a signature made before a certificate was revoked can still
//! be considered valid if verified within the grace period.
//!
//! # Enforcement modes
//!
//! - **Strict** (`enforce_current_time_validation = true`): Certificates must
//!   be valid at the current time, not just at signing time. Default: `false`.
//! - **Require revocation** (`require_revocation_check = true`): If revocation
//!   status is unknown for any cert, conclude INDETERMINATE. Default: `true`.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::policy::{PolicyCheckResult, PolicyConclusion, PolicyResult};
#[cfg(feature = "verify")]
use crate::verify::report::{CryptoValidity, SignatureVerificationResult};

/// Policy identifier for the PKIX policy.
pub const PKIX_POLICY_ID: &str = "pkix/01";

/// Policy identifier for the timestamp-aware PKIX policy variant.
pub const TS_PKIX_POLICY_ID: &str = "ts-pkix/01";

/// PKIX-based PDF signature validation policy.
///
/// Extends the basic policy checks with revocation-awareness and
/// configurable grace period logic.
///
/// # Example
///
/// ```rust
/// use underskrift::policy::PkixPdfSignaturePolicy;
/// use std::time::Duration;
///
/// let policy = PkixPdfSignaturePolicy::new()
///     .grace_period(Duration::from_secs(48 * 3600))  // 48 hours
///     .require_revocation_check(true);
/// ```
#[derive(Debug, Clone)]
pub struct PkixPdfSignaturePolicy {
    /// Revocation grace period.
    ///
    /// If a certificate was revoked, but the signature was made before
    /// `revocation_time - grace_period`, the signature may still be PASSED.
    ///
    /// Default: 24 hours (86400 seconds), matching the Java stack.
    pub grace_period: Duration,

    /// Whether revocation status must be definitively known.
    ///
    /// When `true`, if revocation status is Unknown for any certificate,
    /// the conclusion is INDETERMINATE rather than PASSED.
    /// Default: `true`.
    pub require_revocation_check: bool,

    /// Whether to require no non-safe modifications after signing.
    ///
    /// Default: `true`.
    pub require_no_modifications: bool,

    /// Whether to enforce current-time certificate validity.
    ///
    /// When `true`, certificates must be valid at the current time,
    /// not just at the signing/timestamp time.
    /// Default: `false` (lenient mode — timestamp time is sufficient).
    pub enforce_current_time_validation: bool,

    /// Whether to use a timestamp-aware policy variant.
    ///
    /// When `true` and a timestamp is present, the policy uses the
    /// timestamp time as the validation reference point instead of
    /// the signing time. This changes the policy ID to `ts-pkix/01`.
    /// Default: `true`.
    pub use_timestamp_time: bool,
}

impl PkixPdfSignaturePolicy {
    /// Create a new PKIX policy with default settings.
    pub fn new() -> Self {
        Self {
            grace_period: Duration::from_secs(24 * 3600), // 24 hours
            require_revocation_check: true,
            require_no_modifications: true,
            enforce_current_time_validation: false,
            use_timestamp_time: true,
        }
    }

    /// Set the revocation grace period.
    pub fn grace_period(mut self, period: Duration) -> Self {
        self.grace_period = period;
        self
    }

    /// Set whether revocation status must be known.
    pub fn require_revocation_check(mut self, require: bool) -> Self {
        self.require_revocation_check = require;
        self
    }

    /// Set whether to require no non-safe modifications.
    pub fn require_no_modifications(mut self, require: bool) -> Self {
        self.require_no_modifications = require;
        self
    }

    /// Set whether to enforce current-time certificate validity.
    pub fn enforce_current_time_validation(mut self, enforce: bool) -> Self {
        self.enforce_current_time_validation = enforce;
        self
    }

    /// Set whether to use timestamp time as validation reference.
    pub fn use_timestamp_time(mut self, use_ts: bool) -> Self {
        self.use_timestamp_time = use_ts;
        self
    }

    /// Determine the effective policy ID based on configuration.
    fn effective_policy_id(&self, has_timestamp: bool) -> &str {
        if self.use_timestamp_time && has_timestamp {
            TS_PKIX_POLICY_ID
        } else {
            PKIX_POLICY_ID
        }
    }

    /// Parse an RFC 3339 / ISO 8601 timestamp string.
    fn parse_time(s: &str) -> Option<DateTime<Utc>> {
        // Try parsing with chrono
        s.parse::<DateTime<Utc>>().ok()
    }

    /// Determine the validation reference time.
    ///
    /// Priority:
    /// 1. Timestamp time (if available and `use_timestamp_time` is true)
    /// 2. Signing time
    /// 3. Current time (fallback)
    #[cfg(feature = "verify")]
    fn determine_validation_time(&self, result: &SignatureVerificationResult) -> DateTime<Utc> {
        if self.use_timestamp_time {
            if let Some(ref ts_time) = result.timestamp_time {
                if let Some(parsed) = Self::parse_time(ts_time) {
                    return parsed;
                }
            }
        }
        if let Some(ref sign_time) = result.signing_time {
            if let Some(parsed) = Self::parse_time(sign_time) {
                return parsed;
            }
        }
        Utc::now()
    }
}

impl Default for PkixPdfSignaturePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "verify")]
impl crate::policy::SignatureValidationPolicy for PkixPdfSignaturePolicy {
    fn policy_id(&self) -> &str {
        // Return the base policy ID; effective ID may vary per evaluation
        PKIX_POLICY_ID
    }

    fn evaluate(&self, result: &SignatureVerificationResult) -> PolicyResult {
        let has_timestamp = result.timestamp_time.is_some();
        let effective_id = self.effective_policy_id(has_timestamp).to_string();
        let _validation_time = self.determine_validation_time(result);

        let mut checks = Vec::with_capacity(7);
        let mut has_failure = false;
        let mut has_indeterminate = false;

        // ── Check 1: Cryptographic validity ──
        match &result.cryptographic_validity {
            CryptoValidity::Valid => {
                checks.push(PolicyCheckResult::pass("signature_crypto"));
            }
            CryptoValidity::Invalid(reason) => {
                checks.push(PolicyCheckResult::fail(
                    "signature_crypto",
                    format!("cryptographic signature invalid: {reason}"),
                ));
                has_failure = true;
            }
            CryptoValidity::UnknownAlgorithm(alg) => {
                checks.push(PolicyCheckResult::fail(
                    "signature_crypto",
                    format!("unknown/unsupported algorithm: {alg}"),
                ));
                has_indeterminate = true;
            }
        }

        // ── Check 2: Digest match ──
        if result.digest_matches {
            checks.push(PolicyCheckResult::pass("digest_match"));
        } else {
            checks.push(PolicyCheckResult::fail(
                "digest_match",
                "messageDigest attribute does not match computed hash",
            ));
            has_failure = true;
        }

        // ── Check 3: Integrity ──
        if result.integrity_ok {
            checks.push(PolicyCheckResult::pass("integrity"));
        } else {
            let issues = result.integrity_issues.join("; ");
            checks.push(PolicyCheckResult::fail(
                "integrity",
                format!("ByteRange integrity failed: {issues}"),
            ));
            has_failure = true;
        }

        // ── Check 4: Chain trusted ──
        if result.chain_trusted {
            let msg = match &result.trust_anchor {
                Some(anchor) => format!("chain trusted, anchor: {anchor}"),
                None => "chain trusted".into(),
            };
            checks.push(PolicyCheckResult::pass_with("chain_trusted", msg));
        } else {
            checks.push(PolicyCheckResult::fail(
                "chain_trusted",
                format!(
                    "certificate chain not trusted: {:?}",
                    result.certificate_validity
                ),
            ));
            has_failure = true;
        }

        // ── Check 5: Revocation status ──
        // This is the key addition over BasicPdfSignaturePolicy
        #[cfg(feature = "ltv")]
        {
            if let Some(ref revocation) = result.revocation_status {
                if revocation.is_valid() {
                    checks.push(PolicyCheckResult::pass("revocation"));
                } else if revocation.is_revoked() {
                    // Check grace period logic
                    let grace_result =
                        self.check_revocation_grace_period(revocation, &_validation_time);
                    match grace_result {
                        GracePeriodResult::StillValid(msg) => {
                            checks.push(PolicyCheckResult::pass_with("revocation", msg));
                        }
                        GracePeriodResult::Revoked(msg) => {
                            checks.push(PolicyCheckResult::fail("revocation", msg));
                            has_failure = true;
                        }
                    }
                } else if revocation.is_unknown() {
                    if self.require_revocation_check {
                        checks.push(PolicyCheckResult::fail(
                            "revocation",
                            format!("revocation status unknown: {revocation}"),
                        ));
                        has_indeterminate = true;
                    } else {
                        checks.push(PolicyCheckResult::pass_with(
                            "revocation",
                            "revocation status unknown but not required",
                        ));
                    }
                } else {
                    // Invalid status from revocation check
                    checks.push(PolicyCheckResult::fail(
                        "revocation",
                        format!("revocation check returned invalid: {revocation}"),
                    ));
                    has_failure = true;
                }
            } else {
                // No revocation status available (offline validation)
                if self.require_revocation_check {
                    checks.push(PolicyCheckResult::fail(
                        "revocation",
                        "no revocation status available (offline validation)",
                    ));
                    has_indeterminate = true;
                } else {
                    checks.push(PolicyCheckResult::pass_with(
                        "revocation",
                        "revocation check not performed (not required)",
                    ));
                }
            }
        }

        #[cfg(not(feature = "ltv"))]
        {
            // Without LTV feature, revocation checking is not available
            if self.require_revocation_check {
                checks.push(PolicyCheckResult::fail(
                    "revocation",
                    "revocation checking requires ltv feature",
                ));
                has_indeterminate = true;
            } else {
                checks.push(PolicyCheckResult::pass_with(
                    "revocation",
                    "revocation check skipped (ltv feature not enabled)",
                ));
            }
        }

        // ── Check 6: No non-safe modifications ──
        if self.require_no_modifications {
            match result.extended_by_non_safe_updates {
                Some(true) => {
                    checks.push(PolicyCheckResult::fail(
                        "no_modifications",
                        "document has non-safe modifications after this signature",
                    ));
                    has_failure = true;
                }
                Some(false) => {
                    checks.push(PolicyCheckResult::pass("no_modifications"));
                }
                None => {
                    checks.push(PolicyCheckResult::pass_with(
                        "no_modifications",
                        "revision analysis not available; skipping modification check",
                    ));
                }
            }
        }

        // ── Check 7: Current-time validity (strict mode) ──
        if self.enforce_current_time_validation {
            // In strict mode, we check if certificates are currently valid.
            // This is approximated by checking the overall cert validity.
            use crate::verify::chain_verify::CertValidity;
            match &result.certificate_validity {
                CertValidity::Expired => {
                    checks.push(PolicyCheckResult::fail(
                        "current_time_validity",
                        "certificate has expired (strict time validation)",
                    ));
                    has_failure = true;
                }
                CertValidity::NotYetValid => {
                    checks.push(PolicyCheckResult::fail(
                        "current_time_validity",
                        "certificate not yet valid (strict time validation)",
                    ));
                    has_failure = true;
                }
                _ => {
                    checks.push(PolicyCheckResult::pass("current_time_validity"));
                }
            }
        }

        // ── Determine conclusion ──
        let conclusion = if has_failure {
            PolicyConclusion::Failed
        } else if has_indeterminate {
            PolicyConclusion::Indeterminate
        } else {
            PolicyConclusion::Passed
        };

        let message = match conclusion {
            PolicyConclusion::Passed => Some("all PKIX checks passed".into()),
            PolicyConclusion::Failed => {
                let failed: Vec<&str> = checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| c.check_name)
                    .collect();
                Some(format!("failed checks: {}", failed.join(", ")))
            }
            PolicyConclusion::Indeterminate => {
                let indeterminate: Vec<&str> = checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| c.check_name)
                    .collect();
                Some(format!("inconclusive checks: {}", indeterminate.join(", ")))
            }
        };

        PolicyResult {
            policy_id: effective_id,
            conclusion,
            message,
            checks,
        }
    }
}

// ── Grace period logic ────────────────────────────────────────────

/// Result of grace period evaluation.
#[cfg(feature = "ltv")]
enum GracePeriodResult {
    /// Certificate was revoked but signature was made within grace period.
    StillValid(String),
    /// Certificate was revoked and grace period does not save it.
    Revoked(String),
}

#[cfg(feature = "ltv")]
impl PkixPdfSignaturePolicy {
    /// Check whether a revoked certificate's signature is still within grace period.
    ///
    /// The grace period logic:
    /// - If `validation_time + grace_period < revocation_time`, the signature
    ///   was made well before revocation → PASSED
    /// - Otherwise → FAILED
    fn check_revocation_grace_period(
        &self,
        revocation: &crate::ltv::status::ValidationStatus,
        validation_time: &DateTime<Utc>,
    ) -> GracePeriodResult {
        if let crate::ltv::status::ValidationStatus::Revoked {
            revocation_time,
            reason,
            ..
        } = revocation
        {
            let grace = chrono::Duration::from_std(self.grace_period)
                .unwrap_or(chrono::Duration::hours(24));
            let deadline = *validation_time + grace;

            if deadline < *revocation_time {
                GracePeriodResult::StillValid(format!(
                    "certificate revoked at {revocation_time} (reason: {reason}), \
                     but signature at {validation_time} + grace period is before revocation"
                ))
            } else {
                GracePeriodResult::Revoked(format!(
                    "certificate revoked at {revocation_time} (reason: {reason}), \
                     signature at {validation_time} is not within grace period"
                ))
            }
        } else {
            // Not actually revoked — shouldn't be called, but handle gracefully
            GracePeriodResult::Revoked(format!("unexpected revocation status: {revocation}"))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "verify")]
mod tests {
    use super::*;
    use crate::policy::SignatureValidationPolicy;
    use crate::verify::chain_verify::CertValidity;
    use crate::verify::extractor::SignatureType;
    use crate::verify::report::{
        CryptoValidity, DetectedPadesLevel, SignatureStatus, SignatureVerificationResult,
    };

    /// Helper to create a basic valid result for testing.
    fn make_valid_result() -> SignatureVerificationResult {
        SignatureVerificationResult {
            field_name: "Signature1".into(),
            status: SignatureStatus::Valid,
            signature_type: SignatureType::Pades,
            signer_name: Some("CN=Test Signer".into()),
            signing_time: Some("2025-06-01T12:00:00Z".into()),
            cms_signing_time: None,
            timestamp_time: None,
            ess_cert_id_match: None,
            validation_time_used: None,
            integrity_ok: true,
            covers_whole_document: true,
            integrity_issues: vec![],
            cryptographic_validity: CryptoValidity::Valid,
            digest_matches: true,
            certificate_validity: CertValidity::Valid,
            chain_trusted: true,
            trust_anchor: Some("CN=Test CA".into()),
            #[cfg(feature = "ltv")]
            revocation_status: None,
            #[cfg(not(feature = "ltv"))]
            revocation_status: None,
            #[cfg(feature = "ltv")]
            per_cert_revocation: vec![],
            #[cfg(not(feature = "ltv"))]
            per_cert_revocation: vec![],
            pades_level: DetectedPadesLevel::BB,
            modifications_after_signing: false,
            covers_whole_document_revision: Some(true),
            extended_by_non_safe_updates: Some(false),
            policy_result: None,
            summary: "test".into(),
        }
    }

    #[test]
    fn test_pkix_policy_defaults() {
        let p = PkixPdfSignaturePolicy::new();
        assert_eq!(p.grace_period, Duration::from_secs(24 * 3600));
        assert!(p.require_revocation_check);
        assert!(p.require_no_modifications);
        assert!(!p.enforce_current_time_validation);
        assert!(p.use_timestamp_time);
    }

    #[test]
    fn test_pkix_policy_builder() {
        let p = PkixPdfSignaturePolicy::new()
            .grace_period(Duration::from_secs(48 * 3600))
            .require_revocation_check(false)
            .require_no_modifications(false)
            .enforce_current_time_validation(true)
            .use_timestamp_time(false);

        assert_eq!(p.grace_period, Duration::from_secs(48 * 3600));
        assert!(!p.require_revocation_check);
        assert!(!p.require_no_modifications);
        assert!(p.enforce_current_time_validation);
        assert!(!p.use_timestamp_time);
    }

    #[test]
    fn test_pkix_policy_id_without_timestamp() {
        let p = PkixPdfSignaturePolicy::new();
        assert_eq!(p.effective_policy_id(false), "pkix/01");
    }

    #[test]
    fn test_pkix_policy_id_with_timestamp() {
        let p = PkixPdfSignaturePolicy::new();
        assert_eq!(p.effective_policy_id(true), "ts-pkix/01");
    }

    #[test]
    fn test_pkix_all_pass_no_revocation_not_required() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(false);
        let result = make_valid_result();
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
    }

    #[test]
    fn test_pkix_crypto_invalid() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(false);
        let mut result = make_valid_result();
        result.cryptographic_validity = CryptoValidity::Invalid("bad sig".into());
        result.status = SignatureStatus::Invalid;
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
    }

    #[test]
    fn test_pkix_chain_untrusted() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(false);
        let mut result = make_valid_result();
        result.chain_trusted = false;
        result.certificate_validity = CertValidity::UntrustedRoot;
        result.status = SignatureStatus::ValidButUntrusted;
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
    }

    #[test]
    fn test_pkix_revocation_required_but_missing() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(true);
        let result = make_valid_result();
        // revocation_status is None → INDETERMINATE
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Indeterminate);
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_pkix_revocation_valid() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(true);
        let mut result = make_valid_result();
        result.revocation_status = Some(crate::ltv::status::ValidationStatus::Valid {
            source: crate::ltv::status::RevocationSource::Ocsp,
            checked_at: Utc::now(),
        });
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_pkix_revocation_revoked_outside_grace() {
        let policy = PkixPdfSignaturePolicy::new().grace_period(Duration::from_secs(3600)); // 1 hour grace

        let mut result = make_valid_result();
        // Signing time is 2025-06-01T12:00:00Z
        // Revocation time is 2025-06-01T12:30:00Z (30 min after signing)
        // signing_time + grace_period(1h) = 13:00 > revocation_time(12:30) → FAILED
        result.revocation_status = Some(crate::ltv::status::ValidationStatus::Revoked {
            source: crate::ltv::status::RevocationSource::Crl,
            reason: crate::ltv::status::RevocationReason::KeyCompromise,
            revocation_time: "2025-06-01T12:30:00Z".parse().unwrap(),
        });
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "revocation" && !c.passed));
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_pkix_revocation_within_grace_period() {
        let policy = PkixPdfSignaturePolicy::new().grace_period(Duration::from_secs(3600)); // 1 hour grace

        let mut result = make_valid_result();
        // Signing time is 2025-06-01T12:00:00Z
        // Revocation time is 2025-06-01T20:00:00Z (8 hours after signing)
        // signing_time + grace_period(1h) = 13:00 < revocation_time(20:00) → PASSED (grace period saves it)
        result.revocation_status = Some(crate::ltv::status::ValidationStatus::Revoked {
            source: crate::ltv::status::RevocationSource::Crl,
            reason: crate::ltv::status::RevocationReason::Unspecified,
            revocation_time: "2025-06-01T20:00:00Z".parse().unwrap(),
        });
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "revocation" && c.passed));
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_pkix_revocation_unknown_required() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(true);
        let mut result = make_valid_result();
        result.revocation_status = Some(crate::ltv::status::ValidationStatus::Unknown {
            reason: "no OCSP endpoints".into(),
        });
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Indeterminate);
    }

    #[cfg(feature = "ltv")]
    #[test]
    fn test_pkix_revocation_unknown_not_required() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(false);
        let mut result = make_valid_result();
        result.revocation_status = Some(crate::ltv::status::ValidationStatus::Unknown {
            reason: "no OCSP endpoints".into(),
        });
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
    }

    #[test]
    fn test_pkix_non_safe_modifications() {
        let policy = PkixPdfSignaturePolicy::new().require_revocation_check(false);
        let mut result = make_valid_result();
        result.extended_by_non_safe_updates = Some(true);
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
    }

    #[test]
    fn test_pkix_strict_mode_expired() {
        let policy = PkixPdfSignaturePolicy::new()
            .require_revocation_check(false)
            .enforce_current_time_validation(true);
        let mut result = make_valid_result();
        result.certificate_validity = CertValidity::Expired;
        // chain_trusted is still true in this scenario (was trusted at signing time)
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "current_time_validity" && !c.passed));
    }

    #[test]
    fn test_pkix_timestamp_time_used_for_policy_id() {
        let policy = PkixPdfSignaturePolicy::new()
            .require_revocation_check(false)
            .use_timestamp_time(true);
        let mut result = make_valid_result();
        result.timestamp_time = Some("2025-06-01T13:00:00Z".into());
        let pr = policy.evaluate(&result);
        assert_eq!(pr.policy_id, "ts-pkix/01");
    }

    #[test]
    fn test_pkix_no_timestamp_uses_base_id() {
        let policy = PkixPdfSignaturePolicy::new()
            .require_revocation_check(false)
            .use_timestamp_time(true);
        let result = make_valid_result();
        let pr = policy.evaluate(&result);
        assert_eq!(pr.policy_id, "pkix/01");
    }

    #[test]
    fn test_parse_time_valid() {
        let t = PkixPdfSignaturePolicy::parse_time("2025-06-01T12:00:00Z");
        assert!(t.is_some());
    }

    #[test]
    fn test_parse_time_invalid() {
        let t = PkixPdfSignaturePolicy::parse_time("not-a-date");
        assert!(t.is_none());
    }
}
