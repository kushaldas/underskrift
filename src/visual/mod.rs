//! Visible signature appearance generation.
//!
//! Creates PDF appearance streams for visible signatures, supporting
//! text, images, and composite layouts with font subsetting.
//!
//! # Feature Flags
//!
//! The `visual` feature flag enables image embedding (JPEG/PNG) and
//! font subsetting. Without it, only text-based appearances using
//! the PDF standard 14 fonts are available.
//!
//! # Example
//!
//! ```rust
//! use underskrift::visual::layout::*;
//! use underskrift::visual::appearance::build_default_text_appearance;
//!
//! // Create a default text appearance
//! let appearance = build_default_text_appearance(
//!     "John Doe",
//!     Some("Approval"),
//!     Some("Stockholm"),
//!     None,
//!     200.0,
//!     60.0,
//! ).unwrap();
//!
//! // The appearance.content contains the PDF content stream
//! // The appearance.font_resources lists fonts needed
//! assert!(!appearance.content.is_empty());
//! ```

pub mod appearance;
pub mod font;
pub mod image;
pub mod layout;

// Re-export key types for convenience
pub use appearance::{
    build_appearance, build_default_text_appearance, build_text_appearance, AppearanceStream,
};
pub use layout::{
    Arrangement, Border, Color, FontSpec, Measurement, SignatureLayout, SignatureRect,
    Standard14Font, TextAlignment, TextConfig, TextLine, VisibleSignatureConfig,
};

#[cfg(feature = "visual")]
pub use layout::{ImageConfig, ImageFormat, ImageScale};

pub use font::{encode_pdf_text, FontMetrics};

#[cfg(feature = "visual")]
pub use image::{prepare_image, EmbeddedImage};
