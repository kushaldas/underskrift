//! PDF inspection module — enumerate objects, extract signature metadata, and read DSS.
//!
//! Provides high-level functions for inspecting PDF structure without
//! modifying the document. Designed to replace pikepdf-based inspection
//! in downstream applications.

pub mod cms;
pub mod objects;
pub mod signatures;

// Re-export public API
pub use cms::extract_cms_by_object;
pub use objects::{inspect_pdf, ObjectKind, PdfInspection, PdfObjectInfo};
pub use signatures::{
    inspect_signatures, DssInfo, PdfSignatureInspection, SignatureFieldInfo,
    VriEntry as DssVriEntry,
};
