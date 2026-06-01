//! Signature validation policy framework.
//!
//! Policies evaluate the raw verification sub-results (crypto validity,
//! chain trust, revocation status, timestamps, post-signing modifications)
//! and produce a higher-level **conclusion**: `PASSED`, `FAILED`, or
//! `INDETERMINATE`.
//!
//! This is the compliance/regulatory layer — it answers "does this
//! signature meet our trust requirements?" rather than just "is it
//! cryptographically valid?"
//!
//! # Built-in policies
//!
//! | Policy | ID | Description |
//! |--------|----|-------------|
//! | [`BasicPdfSignaturePolicy`] | `basic/01` | Pre-checks only; PASSED if crypto + chain + integrity all pass |
//! | [`PkixPdfSignaturePolicy`] | `pkix/01` | Revocation-aware with configurable grace period |
//!
//! # Custom policies
//!
//! Implement the [`SignatureValidationPolicy`] trait:
//!
//! ```rust
//! use underskrift::policy::{
//!     SignatureValidationPolicy, PolicyResult, PolicyConclusion, PolicyCheckResult,
//! };
//! use underskrift::verify::SignatureVerificationResult;
//!
//! struct MyPolicy;
//!
//! impl SignatureValidationPolicy for MyPolicy {
//!     fn policy_id(&self) -> &str {
//!         "my-org/custom/01"
//!     }
//!
//!     fn evaluate(&self, result: &SignatureVerificationResult) -> PolicyResult {
//!         // Your custom logic here
//!         PolicyResult {
//!             policy_id: self.policy_id().to_string(),
//!             conclusion: PolicyConclusion::Passed,
//!             message: None,
//!             checks: Vec::new(),
//!         }
//!     }
//! }
//! ```

pub mod basic;
pub mod pkix;

pub use basic::BasicPdfSignaturePolicy;
pub use pkix::PkixPdfSignaturePolicy;

use std::fmt;

#[cfg(feature = "verify")]
use crate::verify::SignatureVerificationResult;

// ── Policy conclusion ─────────────────────────────────────────────

/// Three-valued validation conclusion.
///
/// Matches the SVT `ValidationConclusion` (RFC 9321) and the Java
/// stack's policy framework semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyConclusion {
    /// Signature meets all policy requirements.
    Passed,
    /// Signature definitively fails policy requirements.
    Failed,
    /// Cannot determine — missing data, revocation unknown, etc.
    Indeterminate,
}

impl fmt::Display for PolicyConclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyConclusion::Passed => write!(f, "PASSED"),
            PolicyConclusion::Failed => write!(f, "FAILED"),
            PolicyConclusion::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

// ── Individual check result ───────────────────────────────────────

/// Result of a single sub-check within a policy evaluation.
///
/// Each policy runs several checks (e.g., "signature crypto valid",
/// "chain trusted", "revocation ok"). This type records the outcome
/// of each check for auditability.
#[derive(Debug, Clone)]
pub struct PolicyCheckResult {
    /// Short name of the check (e.g., "signature_crypto", "chain_trusted").
    pub check_name: &'static str,
    /// Whether this check passed.
    pub passed: bool,
    /// Optional human-readable message explaining the result.
    pub message: Option<String>,
}

impl PolicyCheckResult {
    /// Create a passing check result.
    pub fn pass(name: &'static str) -> Self {
        Self {
            check_name: name,
            passed: true,
            message: None,
        }
    }

    /// Create a passing check result with a message.
    pub fn pass_with(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            check_name: name,
            passed: true,
            message: Some(msg.into()),
        }
    }

    /// Create a failing check result with a message.
    pub fn fail(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            check_name: name,
            passed: false,
            message: Some(msg.into()),
        }
    }
}

// ── Policy result ─────────────────────────────────────────────────

/// Result of evaluating a validation policy against a signature.
///
/// Carries the overall conclusion, the policy identifier, a human-readable
/// message, and the individual sub-check results.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    /// URI identifying which policy was applied (e.g., `"basic/01"`).
    pub policy_id: String,
    /// Overall conclusion.
    pub conclusion: PolicyConclusion,
    /// Optional human-readable summary.
    pub message: Option<String>,
    /// Individual check results for auditability.
    pub checks: Vec<PolicyCheckResult>,
}

impl PolicyResult {
    /// Whether the policy concluded PASSED.
    pub fn is_passed(&self) -> bool {
        self.conclusion == PolicyConclusion::Passed
    }

    /// Whether the policy concluded FAILED.
    pub fn is_failed(&self) -> bool {
        self.conclusion == PolicyConclusion::Failed
    }

    /// Whether the policy concluded INDETERMINATE.
    pub fn is_indeterminate(&self) -> bool {
        self.conclusion == PolicyConclusion::Indeterminate
    }
}

impl fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "policy={} conclusion={}",
            self.policy_id, self.conclusion
        )?;
        if let Some(ref msg) = self.message {
            write!(f, " ({})", msg)?;
        }
        Ok(())
    }
}

// ── Policy trait ──────────────────────────────────────────────────

/// Trait for signature validation policies.
///
/// A policy evaluates the raw verification results (crypto, chain,
/// revocation, timestamps, integrity) and produces a [`PolicyResult`]
/// with a three-valued conclusion: PASSED, FAILED, or INDETERMINATE.
///
/// Policies are used by [`SignatureVerifier`](crate::verify::SignatureVerifier)
/// after all sub-verifications are complete.
///
/// # Thread Safety
///
/// Policies must be `Send + Sync` so they can be shared across verification
/// calls.
#[cfg(feature = "verify")]
pub trait SignatureValidationPolicy: Send + Sync {
    /// The policy identifier URI (e.g., `"basic/01"`, `"pkix/01"`).
    fn policy_id(&self) -> &str;

    /// Evaluate this policy against a signature verification result.
    fn evaluate(&self, result: &SignatureVerificationResult) -> PolicyResult;
}

// ── Helper: convert PolicyConclusion to/from SVT ValidationConclusion ──

#[cfg(feature = "svt")]
impl From<PolicyConclusion> for crate::svt::claims::ValidationConclusion {
    fn from(c: PolicyConclusion) -> Self {
        match c {
            PolicyConclusion::Passed => crate::svt::claims::ValidationConclusion::Passed,
            PolicyConclusion::Failed => crate::svt::claims::ValidationConclusion::Failed,
            PolicyConclusion::Indeterminate => {
                crate::svt::claims::ValidationConclusion::Indeterminate
            }
        }
    }
}

#[cfg(feature = "svt")]
impl From<crate::svt::claims::ValidationConclusion> for PolicyConclusion {
    fn from(c: crate::svt::claims::ValidationConclusion) -> Self {
        match c {
            crate::svt::claims::ValidationConclusion::Passed => PolicyConclusion::Passed,
            crate::svt::claims::ValidationConclusion::Failed => PolicyConclusion::Failed,
            crate::svt::claims::ValidationConclusion::Indeterminate => {
                PolicyConclusion::Indeterminate
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_conclusion_display() {
        assert_eq!(PolicyConclusion::Passed.to_string(), "PASSED");
        assert_eq!(PolicyConclusion::Failed.to_string(), "FAILED");
        assert_eq!(PolicyConclusion::Indeterminate.to_string(), "INDETERMINATE");
    }

    #[test]
    fn test_policy_conclusion_equality() {
        assert_eq!(PolicyConclusion::Passed, PolicyConclusion::Passed);
        assert_ne!(PolicyConclusion::Passed, PolicyConclusion::Failed);
    }

    #[test]
    fn test_check_result_pass() {
        let c = PolicyCheckResult::pass("test");
        assert!(c.passed);
        assert_eq!(c.check_name, "test");
        assert!(c.message.is_none());
    }

    #[test]
    fn test_check_result_pass_with_message() {
        let c = PolicyCheckResult::pass_with("test", "all good");
        assert!(c.passed);
        assert_eq!(c.message.as_deref(), Some("all good"));
    }

    #[test]
    fn test_check_result_fail() {
        let c = PolicyCheckResult::fail("test", "bad signature");
        assert!(!c.passed);
        assert_eq!(c.message.as_deref(), Some("bad signature"));
    }

    #[test]
    fn test_policy_result_predicates() {
        let r = PolicyResult {
            policy_id: "test/01".into(),
            conclusion: PolicyConclusion::Passed,
            message: None,
            checks: vec![],
        };
        assert!(r.is_passed());
        assert!(!r.is_failed());
        assert!(!r.is_indeterminate());
    }

    #[test]
    fn test_policy_result_display() {
        let r = PolicyResult {
            policy_id: "basic/01".into(),
            conclusion: PolicyConclusion::Failed,
            message: Some("chain not trusted".into()),
            checks: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("basic/01"));
        assert!(s.contains("FAILED"));
        assert!(s.contains("chain not trusted"));
    }

    #[test]
    fn test_policy_result_display_no_message() {
        let r = PolicyResult {
            policy_id: "pkix/01".into(),
            conclusion: PolicyConclusion::Indeterminate,
            message: None,
            checks: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("pkix/01"));
        assert!(s.contains("INDETERMINATE"));
        assert!(!s.contains("("));
    }
}
