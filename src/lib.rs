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
pub mod cms;
pub mod core;
pub mod crypto;
pub mod error;
pub mod remote;
pub mod signer;

// Re-export shared infrastructure from tsp-ltv
pub use tsp_ltv::der_utils;
pub use tsp_ltv::trust;

// Policy module — always compiled (core types don't need features;
// the SignatureValidationPolicy trait requires `verify`)
pub mod policy;

// Feature-gated modules
#[cfg(feature = "tsp")]
pub use tsp_ltv::tsp;

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

#[cfg(feature = "inspect")]
pub mod inspect;

// Public re-exports for convenience
pub use cms::builder::{CmsProfile, SigningTimePlacement};
pub use core::doc_timestamp::DocTimestampOptions;
pub use crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm, SignatureAlgorithm};
pub use crypto::software::SoftwareSigner;
pub use crypto::traits::CryptoSigner;
pub use error::PdfSignError;
pub use signer::{PadesLevel, PdfSigner, SigningOptions, SubFilter};

pub use remote::{
    finalize_signature, prepare_signature, PreparedSignature, RemoteSignerInfo,
    RemoteSigningOptions,
};

#[cfg(feature = "tsp")]
pub use core::doc_timestamp::{add_document_timestamp, add_document_timestamp_pool};

#[cfg(feature = "verify")]
pub use verify::SignatureVerifier;

#[cfg(feature = "visual")]
pub use visual::{
    build_appearance, build_appearance_with_context, build_default_text_appearance,
    build_text_appearance, build_tounicode_cmap, build_w_array, embedded_ascent_1000,
    embedded_descent_1000, encode_cid_text, prepare_embedded_font, prepare_image,
    AppearanceContext, AppearanceRenderer, AppearanceStream, Arrangement, Border, Color,
    CustomAppearanceResult, EmbeddedFontInfo, EmbeddedImage, FontSpec, ImageConfig, ImageFormat,
    ImageResource, ImageScale, Measurement, PreparedEmbeddedFont, SignatureLayout, SignatureRect,
    SignatureTemplate, Standard14Font, TextAlignment, TextConfig, TextLine, VisibleSignatureConfig,
};

#[cfg(feature = "inspect")]
pub use inspect::{
    extract_cms_by_object, inspect_pdf, inspect_signatures, DssInfo, DssVriEntry, ObjectKind,
    PdfInspection, PdfObjectInfo, PdfSignatureInspection, SignatureFieldInfo,
};
