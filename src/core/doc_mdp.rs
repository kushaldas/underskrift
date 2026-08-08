//! DocMDP and FieldMDP — certification and modification detection.
//!
//! Handles `/DocMDP` transform method for certification signatures and
//! `/FieldMDP` for field-level locking.

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::error::CoreError;

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

impl DocMdpPermissions {
    /// The `/P` value used in the DocMDP `TransformParams` dictionary.
    pub fn as_p(self) -> i64 {
        self as i64
    }
}

/// Build the `/Reference` array for a certification (DocMDP) signature.
///
/// This goes in the signature dictionary. Per PDF 32000-1 §12.8.2.2 it carries
/// a single signature-reference dictionary using the `DocMDP` transform method
/// with a `TransformParams` `/P` permission level and `/V 1.2`:
///
/// ```text
/// /Reference [ << /Type /SigRef
///                 /TransformMethod /DocMDP
///                 /TransformParams << /Type /TransformParams /P n /V /1.2 >> >> ]
/// ```
///
/// The catalog must additionally carry `/Perms << /DocMDP <sig dict ref> >>`
/// pointing back at the signature dictionary (see [`set_docmdp_perms`]).
pub fn build_docmdp_reference(perms: DocMdpPermissions) -> Object {
    let mut transform_params = Dictionary::new();
    transform_params.set("Type", Object::Name(b"TransformParams".to_vec()));
    transform_params.set("P", Object::Integer(perms.as_p()));
    transform_params.set("V", Object::Name(b"1.2".to_vec()));

    let mut sig_ref = Dictionary::new();
    sig_ref.set("Type", Object::Name(b"SigRef".to_vec()));
    sig_ref.set("TransformMethod", Object::Name(b"DocMDP".to_vec()));
    sig_ref.set("TransformParams", Object::Dictionary(transform_params));

    Object::Array(vec![Object::Dictionary(sig_ref)])
}

/// Point the document catalog's `/Perms` at the certifying signature.
///
/// The `/Reference` entry in the signature dictionary is inert on its own — the
/// catalog is what tells a reader which signature certifies the document.
///
/// Per PDF 32000-1 §12.8.2.2 a document may carry only one certification
/// signature, and it must be the first one applied. Certifying an
/// already-certified document is rejected here rather than producing a file
/// that readers report as tampered with. Any other `/Perms` entries (such as
/// `/UR3`) are left in place.
pub fn set_docmdp_perms(
    doc: &mut Document,
    catalog_id: ObjectId,
    sig_dict_id: ObjectId,
) -> Result<(), CoreError> {
    let catalog = doc
        .get_dictionary_mut(catalog_id)
        .map_err(|e| CoreError::InvalidStructure(format!("cannot read catalog: {e}")))?;

    let mut perms = match catalog.get(b"Perms") {
        Ok(Object::Dictionary(existing)) => existing.clone(),
        _ => Dictionary::new(),
    };

    if perms.has(b"DocMDP") {
        return Err(CoreError::InvalidStructure(
            "document already has a certification signature; only one is allowed and it must be \
             the first signature applied"
                .into(),
        ));
    }

    perms.set("DocMDP", Object::Reference(sig_dict_id));
    catalog.set("Perms", Object::Dictionary(perms));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal document with an empty catalog and an empty signature dict.
    fn doc_with_catalog() -> (Document, ObjectId, ObjectId) {
        let mut doc = Document::with_version("1.7");
        let catalog_id = doc.add_object(Object::Dictionary(Dictionary::new()));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let sig_dict_id = doc.add_object(Object::Dictionary(Dictionary::new()));
        (doc, catalog_id, sig_dict_id)
    }

    #[test]
    fn reference_carries_the_requested_permission_level() {
        let reference = build_docmdp_reference(DocMdpPermissions::NoChanges);
        let entries = reference.as_array().unwrap();
        assert_eq!(entries.len(), 1);

        let sig_ref = entries[0].as_dict().unwrap();
        assert_eq!(
            sig_ref.get(b"TransformMethod").unwrap().as_name().unwrap(),
            b"DocMDP"
        );

        let params = sig_ref.get(b"TransformParams").unwrap().as_dict().unwrap();
        assert_eq!(params.get(b"V").unwrap().as_name().unwrap(), b"1.2");
        assert_eq!(params.get(b"P").unwrap().as_i64().unwrap(), 1);
    }

    #[test]
    fn permission_levels_match_the_pdf_p_values() {
        assert_eq!(DocMdpPermissions::NoChanges.as_p(), 1);
        assert_eq!(DocMdpPermissions::FormFillingAndSigning.as_p(), 2);
        assert_eq!(DocMdpPermissions::FormFillingSigningAndAnnotation.as_p(), 3);
    }

    #[test]
    fn perms_points_at_the_signature_dictionary() {
        let (mut doc, catalog_id, sig_dict_id) = doc_with_catalog();
        set_docmdp_perms(&mut doc, catalog_id, sig_dict_id).unwrap();

        let perms = doc
            .catalog()
            .unwrap()
            .get(b"Perms")
            .unwrap()
            .as_dict()
            .unwrap();
        assert_eq!(
            perms.get(b"DocMDP").unwrap().as_reference().unwrap(),
            sig_dict_id
        );
    }

    #[test]
    fn certifying_an_already_certified_document_is_rejected() {
        let (mut doc, catalog_id, sig_dict_id) = doc_with_catalog();
        set_docmdp_perms(&mut doc, catalog_id, sig_dict_id).unwrap();
        assert!(set_docmdp_perms(&mut doc, catalog_id, sig_dict_id).is_err());
    }

    #[test]
    fn other_perms_entries_survive() {
        let (mut doc, catalog_id, sig_dict_id) = doc_with_catalog();
        let mut perms = Dictionary::new();
        perms.set("UR3", Object::Reference(sig_dict_id));
        doc.get_dictionary_mut(catalog_id)
            .unwrap()
            .set("Perms", Object::Dictionary(perms));

        set_docmdp_perms(&mut doc, catalog_id, sig_dict_id).unwrap();

        let perms = doc
            .catalog()
            .unwrap()
            .get(b"Perms")
            .unwrap()
            .as_dict()
            .unwrap();
        assert!(perms.has(b"UR3"));
        assert!(perms.has(b"DocMDP"));
    }
}
