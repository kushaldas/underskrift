//! # Underskrift
//!
//! Production-grade PDF digital signing library for Rust.
//!
//! Supports PAdES Baseline profiles (B-B through B-LTA), traditional PKCS#7
//! signatures, visible and invisible signatures, multiple signatures,
//! certification signatures, long-term validation (LTV), and verification.
//!
//! ## Quick Start
//!
//! ```no_run
//! use underskrift::{PdfSigner, SigningOptions, SoftwareSigner};
//!
//! # async fn example() -> Result<(), underskrift::PdfSignError> {
//! let pdf_bytes = std::fs::read("document.pdf")?;
//! let signer = SoftwareSigner::from_pkcs12_file("identity.p12", "password")?;
//!
//! let signed_pdf = PdfSigner::new()
//!     .options(SigningOptions::default())
//!     .sign(&pdf_bytes, &signer)
//!     .await?;
//!
//! std::fs::write("signed.pdf", signed_pdf)?;
//! # Ok(())
//! # }
//! ```

// Modules — always compiled
pub mod core;
pub mod cms;
pub mod crypto;
pub mod der_utils;
pub mod error;
pub mod remote;
pub mod signer;
pub mod trust;

// Policy module — always compiled (core types don't need features;
// the SignatureValidationPolicy trait requires `verify`)
pub mod policy;

// Feature-gated modules
#[cfg(feature = "tsp")]
pub mod tsp;

#[cfg(feature = "ltv")]
pub mod ltv;

#[cfg(feature = "visual")]
pub mod visual;

#[cfg(feature = "verify")]
pub mod verify;

#[cfg(feature = "saci")]
pub mod saci;

#[cfg(feature = "svt")]
pub mod svt;

#[cfg(feature = "report")]
pub mod report;

// Public re-exports for convenience
pub use error::PdfSignError;
pub use signer::{PdfSigner, SigningOptions, PadesLevel, SubFilter};
pub use crypto::traits::CryptoSigner;
pub use crypto::software::SoftwareSigner;
pub use crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm, SignatureAlgorithm};
pub use core::doc_timestamp::DocTimestampOptions;

pub use remote::{
    prepare_signature, finalize_signature,
    PreparedSignature, RemoteSignerInfo, RemoteSigningOptions,
};

#[cfg(feature = "tsp")]
pub use core::doc_timestamp::{add_document_timestamp, add_document_timestamp_pool};

#[cfg(feature = "verify")]
pub use verify::SignatureVerifier;

#[cfg(feature = "visual")]
pub use visual::{
    VisibleSignatureConfig, SignatureRect, SignatureLayout, TextConfig,
    TextLine, FontSpec, Standard14Font, Measurement, TextAlignment,
    Color, Border, Arrangement, AppearanceStream,
    build_appearance, build_default_text_appearance, build_text_appearance,
    ImageConfig, ImageFormat, ImageScale,
    prepare_image, EmbeddedImage,
};
