//! CMS extraction by object number.
//!
//! Given a PDF and an object number, extracts the raw /Contents bytes
//! (CMS/PKCS#7 DER data) from that signature dictionary object.

use lopdf::Document;

use crate::error::InspectError;

/// Extract the raw CMS/PKCS#7 bytes from a signature dictionary at the given object number.
///
/// The object at `obj_num` must be a dictionary with a /Contents entry containing
/// the hex-encoded CMS SignedData. Returns the decoded raw DER bytes.
///
/// # Errors
///
/// Returns `InspectError` if:
/// - The PDF cannot be parsed
/// - The object number doesn't exist
/// - The object has no /Contents entry
pub fn extract_cms_by_object(pdf_data: &[u8], obj_num: u32) -> Result<Vec<u8>, InspectError> {
    let doc = Document::load_mem(pdf_data).map_err(|e| InspectError::PdfParse(format!("{e}")))?;

    // Try to find the object — lopdf uses (obj_num, gen_num) as key.
    // We try gen 0 first (most common), then search all generations.
    let object = doc
        .get_object((obj_num, 0))
        .or_else(|_| {
            // Search all generations for this object number
            doc.objects
                .iter()
                .find(|(&(n, _), _)| n == obj_num)
                .map(|(_, obj)| obj)
                .ok_or(lopdf::Error::ObjectNotFound)
        })
        .map_err(|_| InspectError::ObjectNotFound(obj_num))?;

    let dict = object
        .as_dict()
        .map_err(|_| InspectError::NotADictionary(obj_num))?;

    let contents = dict
        .get(b"Contents")
        .map_err(|_| InspectError::NoContents(obj_num))?
        .as_str()
        .map_err(|_| InspectError::NoContents(obj_num))?;

    // lopdf already decodes the hex string to raw bytes.
    // Strip trailing zero-padding.
    let mut data = contents.to_vec();
    while data.last() == Some(&0) {
        data.pop();
    }

    if data.is_empty() {
        return Err(InspectError::EmptyContents(obj_num));
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonexistent_object() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = extract_cms_by_object(&pdf_data, 99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_object_without_contents() {
        // Object 1 in a typical PDF is the catalog — no /Contents
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = extract_cms_by_object(&pdf_data, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pdf() {
        let result = extract_cms_by_object(b"not a pdf", 1);
        assert!(result.is_err());
    }
}
