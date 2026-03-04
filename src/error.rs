//! Unified error types for the underskrift crate.
//!
//! Each module defines its own focused error enum. The top-level [`PdfSignError`]
//! wraps them all via `#[from]` for ergonomic use at the signer/public API level.

use thiserror::Error;

/// Top-level error type unifying all module errors.
#[derive(Debug, Error)]
pub enum PdfSignError {
    #[error("PDF core error: {0}")]
    Core(#[from] CoreError),

    #[error("CMS error: {0}")]
    Cms(#[from] CmsError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),

    #[cfg(feature = "tsp")]
    #[error("TSP error: {0}")]
    Tsp(#[from] TspError),

    #[cfg(feature = "ltv")]
    #[error("LTV error: {0}")]
    Ltv(#[from] LtvError),

    #[cfg(feature = "verify")]
    #[error("Verification error: {0}")]
    Verify(#[from] VerifyError),

    #[error("Trust error: {0}")]
    Trust(#[from] TrustError),

    #[cfg(feature = "saci")]
    #[error("SACI error: {0}")]
    Saci(#[from] SaciError),

    #[cfg(feature = "svt")]
    #[error("SVT error: {0}")]
    Svt(#[from] SvtError),

    #[cfg(feature = "report")]
    #[error("Report error: {0}")]
    Report(#[from] ReportError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Algorithm not allowed: {0}")]
    AlgorithmNotAllowed(String),

    #[error("Visual signature error: {0}")]
    Visual(#[from] VisualError),
}

/// Errors from the `core` module — PDF structure manipulation.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("lopdf error: {0}")]
    Lopdf(#[from] lopdf::Error),

    #[error("PDF does not contain a valid cross-reference table")]
    InvalidXref,

    #[error("ByteRange placeholder not found at expected offset")]
    ByteRangePlaceholderMissing,

    #[error("Signature /Contents placeholder not found at expected offset")]
    ContentsPlaceholderMissing,

    #[error("Signature exceeds allocated /Contents placeholder size ({actual} > {allocated})")]
    SignatureTooLarge { actual: usize, allocated: usize },

    #[error("AcroForm dictionary error: {0}")]
    AcroForm(String),

    #[error("invalid PDF structure: {0}")]
    InvalidStructure(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the `cms` module — CMS/PKCS#7 construction.
#[derive(Debug, Error)]
pub enum CmsError {
    #[error("DER encoding error: {0}")]
    Der(String),

    #[error("CMS builder error: {0}")]
    Builder(String),

    #[error("missing required attribute: {0}")]
    MissingAttribute(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Errors from the `crypto` module — signing key operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("PKCS#12 loading error: {0}")]
    Pkcs12(String),

    #[error("PEM parsing error: {0}")]
    Pem(String),

    #[error("PKCS#8 key error: {0}")]
    Pkcs8(String),

    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("signing operation failed: {0}")]
    SigningFailed(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the `signer` orchestrator.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("no signing certificate provided")]
    NoCertificate,

    #[error("estimated signature size insufficient — try increasing content_size")]
    ContentSizeInsufficient,

    #[error("configuration error: {0}")]
    Config(String),
}

/// Errors from the `tsp` module — RFC 3161 timestamping.
#[cfg(feature = "tsp")]
#[derive(Debug, Error)]
pub enum TspError {
    #[error("TSA HTTP request failed: {0}")]
    HttpError(String),

    #[error("TSA returned error status: {0}")]
    TsaError(String),

    #[error("invalid timestamp response: {0}")]
    InvalidResponse(String),
}

/// Errors from the `ltv` module — long-term validation.
#[cfg(feature = "ltv")]
#[derive(Debug, Error)]
pub enum LtvError {
    #[error("OCSP error: {0}")]
    Ocsp(String),

    #[error("CRL error: {0}")]
    Crl(String),

    #[error("certificate chain error: {0}")]
    Chain(String),

    #[error("DSS construction error: {0}")]
    Dss(String),

    #[error("revocation check error: {0}")]
    Revocation(String),

    #[error("X.509 extension validation error: {0}")]
    X509Extension(String),
}

/// Errors from the `verify` module — signature verification.
#[cfg(feature = "verify")]
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("no signatures found in PDF")]
    NoSignatures,

    #[error("ByteRange integrity check failed")]
    IntegrityFailed,

    #[error("CMS verification failed: {0}")]
    CmsVerification(String),

    #[error("certificate chain validation failed: {0}")]
    ChainValidation(String),

    #[error("signature is expired or not yet valid")]
    TimeValidity,

    #[error("certificate has been revoked: {0}")]
    Revoked(String),
}

/// Errors from the `trust` module — trust store management.
#[derive(Debug, Error)]
pub enum TrustError {
    #[error("certificate parse error: {0}")]
    CertificateParse(String),

    #[error("path is not a directory: {0}")]
    NotADirectory(String),

    #[error("certificate chain is empty")]
    EmptyChain,

    #[error("chain broken at index {index}: expected issuer {expected_issuer}, found subject {found_subject}")]
    ChainBroken {
        index: usize,
        expected_issuer: String,
        found_subject: String,
    },

    #[error("certificate at index {index} is not yet valid (not_before: {not_before})")]
    NotYetValid {
        index: usize,
        not_before: der::DateTime,
    },

    #[error("certificate at index {index} is expired (not_after: {not_after})")]
    Expired {
        index: usize,
        not_after: der::DateTime,
    },

    #[error("untrusted root: no trust anchor found for issuer {issuer}")]
    UntrustedRoot { issuer: String },

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("trust store not configured for {0}")]
    StoreNotConfigured(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the `saci` module — SACI AuthnContext extension parsing.
#[cfg(feature = "saci")]
#[derive(Debug, Error)]
pub enum SaciError {
    #[error("AuthnContext extension not found (OID 1.2.752.201.5.1)")]
    ExtensionNotFound,

    #[error("ASN.1 decode error: {0}")]
    Asn1(String),

    #[error("XML parse error: {0}")]
    Xml(String),

    #[error("missing required element: {0}")]
    MissingElement(String),

    #[error("missing required attribute: {0}")]
    MissingAttribute(String),

    #[error("unsupported context type: {0}")]
    UnsupportedContextType(String),
}

/// Errors from the `svt` module — RFC 9321 Signature Validation Tokens.
#[cfg(feature = "svt")]
#[derive(Debug, Error)]
pub enum SvtError {
    #[error("JWT signing error: {0}")]
    JwtSigning(String),

    #[error("JWT verification error: {0}")]
    JwtVerification(String),

    #[error("JWT parsing error: {0}")]
    JwtParsing(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid SVT claims: {0}")]
    InvalidClaims(String),

    #[error("signature reference mismatch: {0}")]
    SignatureReferenceMismatch(String),

    #[error("certificate reference mismatch: {0}")]
    CertificateReferenceMismatch(String),

    #[error("SVT expired at {0}")]
    Expired(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("hash computation error: {0}")]
    HashError(String),

    #[error("SVT embedding error: {0}")]
    Embedding(String),

    #[error("TSTInfo construction error: {0}")]
    TstInfoBuild(String),
}

/// Errors from the `report` module — ETSI TS 119 102-2 validation reports.
#[cfg(feature = "report")]
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("XML generation error: {0}")]
    XmlGeneration(String),

    #[error("no verification data: {0}")]
    NoData(String),

    #[error("unsupported report option: {0}")]
    UnsupportedOption(String),
}

/// Errors from the `visual` module — visible signature appearance generation.
#[derive(Debug, Error)]
pub enum VisualError {
    #[error("invalid signature dimensions: {0}")]
    InvalidDimensions(String),

    #[error("image processing error: {0}")]
    ImageError(String),

    #[error("font error: {0}")]
    FontError(String),

    #[error("font parsing error: {0}")]
    FontParsing(String),

    #[error("font subsetting error: {0}")]
    FontSubsetting(String),

    #[error("glyph not found for character U+{0:04X}")]
    GlyphNotFound(u32),

    #[error("appearance generation error: {0}")]
    AppearanceError(String),
}
