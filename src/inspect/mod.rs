//! PDF inspection module — enumerate objects, extract signature metadata, and read DSS.
//!
//! Provides high-level functions for inspecting PDF structure without
//! modifying the document. Designed to replace pikepdf-based inspection
//! in downstream applications.

pub mod objects;
pub mod signatures;
pub mod cms;

// Re-export public API
pub use objects::{PdfInspection, PdfObjectInfo, ObjectKind, inspect_pdf};
pub use signatures::{
    PdfSignatureInspection, SignatureFieldInfo, DssInfo, VriEntry as DssVriEntry,
    inspect_signatures,
};
pub use cms::extract_cms_by_object;
