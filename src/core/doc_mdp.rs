//! DocMDP and FieldMDP — certification and modification detection.
//!
//! Handles `/DocMDP` transform method for certification signatures and
//! `/FieldMDP` for field-level locking.

/// Permitted changes level for a certification signature (DocMDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DocMdpPermissions {
    /// No changes allowed
    NoChanges = 1,
    /// Form filling and signing only
    #[default]
    FormFillingAndSigning = 2,
    /// Form filling, signing, and annotation
    FormFillingSigningAndAnnotation = 3,
}
