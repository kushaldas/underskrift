//! Basic PDF signature validation policy.
//!
//! The simplest built-in policy. Performs pre-checks on the raw verification
//! results and concludes PASSED if all pass, FAILED if any definitively fail,
//! or INDETERMINATE if results are inconclusive.
//!
//! Corresponds to the Java stack's `BasicPdfSignaturePolicyValidator` with
//! policy identifier `basic/01`.
//!
//! # Checks performed
//!
//! 1. **Signature crypto** — CMS signature must be cryptographically valid
//! 2. **Digest match** — messageDigest attribute must match computed hash
//! 3. **Integrity** — ByteRange must be structurally valid
//! 4. **Chain trusted** — certificate chain must lead to a trust anchor
//! 5. **No non-safe modifications** — no non-safe updates after signing (optional, configurable)

use crate::policy::{PolicyCheckResult, PolicyConclusion, PolicyResult};
#[cfg(feature = "verify")]
use crate::verify::report::{CryptoValidity, SignatureStatus, SignatureVerificationResult};

/// Policy identifier for the basic policy.
pub const BASIC_POLICY_ID: &str = "basic/01";

/// Basic PDF signature validation policy.
///
/// Concludes:
/// - **PASSED** if the signature is cryptographically valid, the digest matches,
///   integrity is OK, and the chain is trusted
/// - **FAILED** if any of those checks definitively fail
/// - **INDETERMINATE** if the algorithm is unknown or results are inconclusive
///
/// # Configuration
///
/// - `require_no_modifications`: When `true` (default), the policy also checks
///   that there are no non-safe modifications after the signature.
///
/// # Example
///
/// ```rust
/// use underskrift::policy::BasicPdfSignaturePolicy;
///
/// let policy = BasicPdfSignaturePolicy::new();
/// // Use with SignatureVerifier:
/// // let verifier = SignatureVerifier::new(&trust_set).policy(Box::new(policy));
/// ```
#[derive(Debug, Clone)]
pub struct BasicPdfSignaturePolicy {
    /// Whether to require no non-safe modifications after signing.
    ///
    /// When `true`, a signature followed by non-safe updates results in FAILED.
    /// Default: `true`.
    pub require_no_modifications: bool,
}

impl BasicPdfSignaturePolicy {
    /// Create a new basic policy with default settings.
    pub fn new() -> Self {
        Self {
            require_no_modifications: true,
        }
    }

    /// Set whether to require no non-safe modifications after signing.
    pub fn require_no_modifications(mut self, require: bool) -> Self {
        self.require_no_modifications = require;
        self
    }
}

impl Default for BasicPdfSignaturePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "verify")]
impl crate::policy::SignatureValidationPolicy for BasicPdfSignaturePolicy {
    fn policy_id(&self) -> &str {
        BASIC_POLICY_ID
    }

    fn evaluate(&self, result: &SignatureVerificationResult) -> PolicyResult {
        let mut checks = Vec::with_capacity(5);

        // Check 1: Cryptographic validity
        let crypto_ok = match &result.cryptographic_validity {
            CryptoValidity::Valid => {
                checks.push(PolicyCheckResult::pass("signature_crypto"));
                true
            }
            CryptoValidity::Invalid(reason) => {
                checks.push(PolicyCheckResult::fail(
                    "signature_crypto",
                    format!("cryptographic signature invalid: {reason}"),
                ));
                false
            }
            CryptoValidity::UnknownAlgorithm(alg) => {
                checks.push(PolicyCheckResult::fail(
                    "signature_crypto",
                    format!("unknown/unsupported algorithm: {alg}"),
                ));
                // Unknown algorithm → INDETERMINATE, not FAILED
                // (we can't say it's bad, we just can't verify it)
                return build_indeterminate_result(
                    checks,
                    format!("cannot verify: unknown algorithm {alg}"),
                );
            }
        };

        // Check 2: Digest match
        let digest_ok = if result.digest_matches {
            checks.push(PolicyCheckResult::pass("digest_match"));
            true
        } else {
            checks.push(PolicyCheckResult::fail(
                "digest_match",
                "messageDigest attribute does not match computed hash",
            ));
            false
        };

        // Check 3: Integrity
        let integrity_ok = if result.integrity_ok {
            checks.push(PolicyCheckResult::pass("integrity"));
            true
        } else {
            let issues = result.integrity_issues.join("; ");
            checks.push(PolicyCheckResult::fail(
                "integrity",
                format!("ByteRange integrity failed: {issues}"),
            ));
            false
        };

        // Check 4: Chain trusted
        let chain_ok = if result.chain_trusted {
            let msg = match &result.trust_anchor {
                Some(anchor) => format!("chain trusted, anchor: {anchor}"),
                None => "chain trusted".into(),
            };
            checks.push(PolicyCheckResult::pass_with("chain_trusted", msg));
            true
        } else {
            checks.push(PolicyCheckResult::fail(
                "chain_trusted",
                format!(
                    "certificate chain not trusted: {:?}",
                    result.certificate_validity
                ),
            ));
            false
        };

        // Check 5: No non-safe modifications (optional)
        let modifications_ok = if self.require_no_modifications {
            match result.extended_by_non_safe_updates {
                Some(true) => {
                    checks.push(PolicyCheckResult::fail(
                        "no_modifications",
                        "document has non-safe modifications after this signature",
                    ));
                    false
                }
                Some(false) => {
                    checks.push(PolicyCheckResult::pass("no_modifications"));
                    true
                }
                None => {
                    // Revision analysis not available — treat as indeterminate
                    // for this check, but don't fail the whole policy
                    checks.push(PolicyCheckResult::pass_with(
                        "no_modifications",
                        "revision analysis not available; skipping modification check",
                    ));
                    true
                }
            }
        } else {
            // Not required — skip this check
            true
        };

        // Determine conclusion
        let all_pass = crypto_ok && digest_ok && integrity_ok && chain_ok && modifications_ok;

        if all_pass {
            PolicyResult {
                policy_id: BASIC_POLICY_ID.into(),
                conclusion: PolicyConclusion::Passed,
                message: Some("all basic checks passed".into()),
                checks,
            }
        } else {
            // Determine if it's definitively FAILED or just INDETERMINATE
            // For the basic policy, if any hard check fails, it's FAILED
            let conclusion = if result.status == SignatureStatus::Indeterminate {
                PolicyConclusion::Indeterminate
            } else {
                PolicyConclusion::Failed
            };

            let failed_checks: Vec<&str> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.check_name)
                .collect();
            let msg = format!("failed checks: {}", failed_checks.join(", "));

            PolicyResult {
                policy_id: BASIC_POLICY_ID.into(),
                conclusion,
                message: Some(msg),
                checks,
            }
        }
    }
}

/// Build an INDETERMINATE result (used when we can't determine pass/fail).
fn build_indeterminate_result(checks: Vec<PolicyCheckResult>, reason: String) -> PolicyResult {
    PolicyResult {
        policy_id: BASIC_POLICY_ID.into(),
        conclusion: PolicyConclusion::Indeterminate,
        message: Some(reason),
        checks,
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

    /// Helper to create a minimal SignatureVerificationResult for testing.
    fn make_result(
        crypto: CryptoValidity,
        digest_matches: bool,
        integrity_ok: bool,
        chain_trusted: bool,
        status: SignatureStatus,
    ) -> SignatureVerificationResult {
        SignatureVerificationResult {
            field_name: "Signature1".into(),
            status,
            signature_type: SignatureType::Pades,
            signer_name: Some("CN=Test Signer".into()),
            signing_time: Some("2025-01-01T00:00:00Z".into()),
            cms_signing_time: None,
            timestamp_time: None,
            ess_cert_id_match: None,
            validation_time_used: None,
            integrity_ok,
            covers_whole_document: true,
            integrity_issues: if integrity_ok {
                vec![]
            } else {
                vec!["ByteRange invalid".into()]
            },
            cryptographic_validity: crypto,
            digest_matches,
            certificate_validity: if chain_trusted {
                CertValidity::Valid
            } else {
                CertValidity::UntrustedRoot
            },
            chain_trusted,
            trust_anchor: if chain_trusted {
                Some("CN=Test CA".into())
            } else {
                None
            },
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
    fn test_basic_policy_all_pass() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Valid,
            true,
            true,
            true,
            SignatureStatus::Valid,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
        assert_eq!(pr.policy_id, "basic/01");
        assert!(pr.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn test_basic_policy_crypto_invalid() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Invalid("bad sig".into()),
            true,
            true,
            true,
            SignatureStatus::Invalid,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "signature_crypto" && !c.passed));
    }

    #[test]
    fn test_basic_policy_unknown_algorithm() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::UnknownAlgorithm("1.2.3.4".into()),
            true,
            true,
            true,
            SignatureStatus::Indeterminate,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Indeterminate);
    }

    #[test]
    fn test_basic_policy_digest_mismatch() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Valid,
            false,
            true,
            true,
            SignatureStatus::Invalid,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "digest_match" && !c.passed));
    }

    #[test]
    fn test_basic_policy_integrity_failed() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Valid,
            true,
            false,
            true,
            SignatureStatus::Invalid,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "integrity" && !c.passed));
    }

    #[test]
    fn test_basic_policy_chain_untrusted() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Valid,
            true,
            true,
            false,
            SignatureStatus::ValidButUntrusted,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "chain_trusted" && !c.passed));
    }

    #[test]
    fn test_basic_policy_non_safe_modifications() {
        let policy = BasicPdfSignaturePolicy::new();
        let mut result = make_result(
            CryptoValidity::Valid,
            true,
            true,
            true,
            SignatureStatus::Valid,
        );
        result.extended_by_non_safe_updates = Some(true);
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        assert!(pr
            .checks
            .iter()
            .any(|c| c.check_name == "no_modifications" && !c.passed));
    }

    #[test]
    fn test_basic_policy_modifications_not_required() {
        let policy = BasicPdfSignaturePolicy::new().require_no_modifications(false);
        let mut result = make_result(
            CryptoValidity::Valid,
            true,
            true,
            true,
            SignatureStatus::Valid,
        );
        result.extended_by_non_safe_updates = Some(true);
        let pr = policy.evaluate(&result);
        // Should pass because modifications check is disabled
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
    }

    #[test]
    fn test_basic_policy_revision_not_available() {
        let policy = BasicPdfSignaturePolicy::new();
        let mut result = make_result(
            CryptoValidity::Valid,
            true,
            true,
            true,
            SignatureStatus::Valid,
        );
        result.extended_by_non_safe_updates = None;
        let pr = policy.evaluate(&result);
        // Should still pass — revision analysis unavailable is not a failure
        assert_eq!(pr.conclusion, PolicyConclusion::Passed);
    }

    #[test]
    fn test_basic_policy_multiple_failures() {
        let policy = BasicPdfSignaturePolicy::new();
        let result = make_result(
            CryptoValidity::Invalid("bad".into()),
            false,
            false,
            false,
            SignatureStatus::Invalid,
        );
        let pr = policy.evaluate(&result);
        assert_eq!(pr.conclusion, PolicyConclusion::Failed);
        let failed_count = pr.checks.iter().filter(|c| !c.passed).count();
        assert!(
            failed_count >= 3,
            "expected at least 3 failures, got {failed_count}"
        );
    }
}
