//! Long-term validation (LTV) support.
//!
//! Embeds revocation information (OCSP responses, CRLs) and certificates
//! into the PDF's Document Security Store (DSS) for offline validation.
//!
//! Most LTV infrastructure (OCSP, CRL, chain building, trust stores) lives
//! in the shared [`tsp_ltv`] crate. This module adds the PDF-specific DSS
//! dictionary builder on top.
//!
//! # PAdES Levels
//!
//! | Level | LTV Data |
//! |-------|----------|
//! | B-B   | None |
//! | B-T   | Timestamp only |
//! | B-LT  | DSS with certs, OCSP, CRLs |
//! | B-LTA | DSS + document timestamp |

// PDF-specific module (stays in underskrift)
pub mod dss;

// Re-export everything from tsp-ltv so `crate::ltv::*` still works
pub use tsp_ltv::ltv::chain;
pub use tsp_ltv::ltv::crl;
pub use tsp_ltv::ltv::ocsp;
pub use tsp_ltv::ltv::revocation;
pub use tsp_ltv::ltv::status;
pub use tsp_ltv::ltv::x509_ext;

// Re-export key types
#[cfg(feature = "blocking")]
pub use tsp_ltv::ltv::check_certificate_revocation_blocking;
pub use tsp_ltv::ltv::ChainBuilder;
pub use tsp_ltv::ltv::CrlClient;
pub use tsp_ltv::ltv::OcspClient;
pub use tsp_ltv::ltv::{
    build_ocsp_request_with_nonce, extract_aia_urls, has_ocsp_nocheck_extension,
    ocsp_check_revocation, parse_ocsp_response, AiaAccessMethod, CertStatus,
    ParsedBasicOcspResponse, ResponderId, SingleResponse,
};
pub use tsp_ltv::ltv::{
    check_basic_constraints, check_extended_key_usage, check_key_usage, has_extension,
    validate_extensions_for_role, CertRole, KeyUsageBits,
};
pub use tsp_ltv::ltv::{check_certificate_revocation, RevocationConfig};
pub use tsp_ltv::ltv::{resolve_priority, RevocationReason, RevocationSource, ValidationStatus};

// DSS re-exports (local)
pub use dss::{compute_vri_key, DssBuilder, VriEntry};
