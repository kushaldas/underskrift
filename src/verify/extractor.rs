//! Extract signatures and byte ranges from PDF.
//!
//! Uses lopdf to parse the PDF structure and locate signature dictionaries,
//! then extracts the raw CMS/PKCS#7 bytes and byte range information needed
//! for verification.

use lopdf::{Document, Object};

use crate::error::VerifyError;

/// Type of signature found in the PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureType {
    /// PAdES signature (ETSI.CAdES.detached)
    Pades,
    /// Traditional PKCS#7 signature (adbe.pkcs7.detached)
    Pkcs7Detached,
    /// PKCS#7 SHA-1 signature (adbe.pkcs7.sha1) — legacy
    Pkcs7Sha1,
    /// Document timestamp (ETSI.RFC3161)
    DocTimestamp,
    /// Unknown SubFilter value
    Unknown(String),
}

impl SignatureType {
    /// Parse a SubFilter PDF name value into a SignatureType.
    pub fn from_sub_filter(name: &[u8]) -> Self {
        match name {
            b"ETSI.CAdES.detached" => SignatureType::Pades,
            b"adbe.pkcs7.detached" => SignatureType::Pkcs7Detached,
            b"adbe.pkcs7.sha1" => SignatureType::Pkcs7Sha1,
            b"ETSI.RFC3161" => SignatureType::DocTimestamp,
            other => SignatureType::Unknown(String::from_utf8_lossy(other).into_owned()),
        }
    }
}

/// An extracted signature from a PDF document.
#[derive(Debug)]
pub struct ExtractedSignature {
    /// The signature field name (from /T in the field dict)
    pub field_name: String,
    /// The type of signature (derived from /SubFilter)
    pub signature_type: SignatureType,
    /// Raw ByteRange values [offset1, length1, offset2, length2]
    pub byte_range: [usize; 4],
    /// The raw CMS/PKCS#7 DER bytes from /Contents (padding stripped)
    pub cms_bytes: Vec<u8>,
    /// The /Reason field, if present
    pub reason: Option<String>,
    /// The /Location field, if present
    pub location: Option<String>,
    /// The /ContactInfo field, if present
    pub contact_info: Option<String>,
    /// The /Name field (signer name), if present
    pub signer_name: Option<String>,
    /// The /M field (signing time from dict, not CMS), if present
    pub signing_time: Option<String>,
}

/// Extract all signatures from a PDF document's raw bytes.
///
/// Parses the PDF with lopdf, walks the AcroForm fields looking for
/// signature fields (/FT /Sig), and extracts the CMS bytes, byte range,
/// and metadata from each signature dictionary.
///
/// Returns signatures in document order (field order in AcroForm).
pub fn extract_signatures(pdf_data: &[u8]) -> Result<Vec<ExtractedSignature>, VerifyError> {
    let doc = Document::load_mem(pdf_data)
        .map_err(|e| VerifyError::CmsVerification(format!("failed to parse PDF: {e}")))?;

    extract_signatures_from_doc(&doc)
}

/// Extract signatures from an already-parsed lopdf Document.
pub fn extract_signatures_from_doc(doc: &Document) -> Result<Vec<ExtractedSignature>, VerifyError> {
    let mut signatures = Vec::new();

    // Get the catalog
    let catalog = doc
        .catalog()
        .map_err(|e| VerifyError::CmsVerification(format!("failed to get catalog: {e}")))?;

    // Check for AcroForm
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_dict).ok(),
        Ok(Object::Dictionary(d)) => Some(d),
        _ => None,
    };

    let acroform = match acroform {
        Some(af) => af,
        None => return Ok(signatures), // No AcroForm means no signatures
    };

    // Get the Fields array
    let fields = match acroform.get(b"Fields") {
        Ok(Object::Array(arr)) => arr.clone(),
        _ => return Ok(signatures),
    };

    // Walk each field looking for signature fields
    for field_ref in &fields {
        let field_id = match field_ref.as_reference() {
            Ok(id) => id,
            Err(_) => continue,
        };

        let field = match doc.get_object(field_id).and_then(Object::as_dict) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Check if this is a signature field (/FT /Sig)
        let ft = match field.get(b"FT").and_then(Object::as_name) {
            Ok(name) => name,
            Err(_) => continue,
        };
        if ft != b"Sig" {
            continue;
        }

        // Get the field name
        let field_name = field
            .get(b"T")
            .and_then(Object::as_str)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();

        // Get the signature dictionary (may be inline or referenced via /V)
        let sig_dict = match field.get(b"V") {
            Ok(Object::Reference(sig_id)) => {
                match doc.get_object(*sig_id).and_then(Object::as_dict) {
                    Ok(d) => d,
                    Err(_) => continue,
                }
            }
            Ok(Object::Dictionary(d)) => d,
            _ => continue, // No /V means unsigned field
        };

        // Extract ByteRange
        let byte_range = match extract_byte_range_values(sig_dict) {
            Some(br) => br,
            None => continue, // No ByteRange = not a proper signature
        };

        // Extract SubFilter
        let signature_type = sig_dict
            .get(b"SubFilter")
            .and_then(Object::as_name)
            .map(SignatureType::from_sub_filter)
            .unwrap_or(SignatureType::Unknown("missing".to_string()));

        // Extract Contents (the CMS/PKCS#7 bytes)
        // lopdf parses the hex string into raw bytes for us.
        // We strip trailing zero padding to get the actual DER.
        let cms_bytes = match sig_dict.get(b"Contents").and_then(Object::as_str) {
            Ok(bytes) => {
                let mut data = bytes.to_vec();
                // Trim trailing zeros (padding from the hex placeholder)
                while data.last() == Some(&0) {
                    data.pop();
                }
                data
            }
            Err(_) => continue,
        };

        if cms_bytes.is_empty() {
            continue; // Empty contents = unsigned placeholder
        }

        // Extract optional metadata fields
        let reason = extract_string_field(sig_dict, b"Reason");
        let location = extract_string_field(sig_dict, b"Location");
        let contact_info = extract_string_field(sig_dict, b"ContactInfo");
        let signer_name = extract_string_field(sig_dict, b"Name");
        let signing_time = extract_string_field(sig_dict, b"M");

        signatures.push(ExtractedSignature {
            field_name,
            signature_type,
            byte_range,
            cms_bytes,
            reason,
            location,
            contact_info,
            signer_name,
            signing_time,
        });
    }

    Ok(signatures)
}

/// Extract ByteRange values from a signature dictionary.
fn extract_byte_range_values(sig_dict: &lopdf::Dictionary) -> Option<[usize; 4]> {
    let arr = sig_dict.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let values: Vec<usize> = arr
        .iter()
        .filter_map(|obj| {
            obj.as_i64().ok().and_then(|v| {
                if v < 0 {
                    None // Reject negative ByteRange values
                } else {
                    Some(v as usize)
                }
            })
        })
        .collect();
    if values.len() == 4 {
        Some([values[0], values[1], values[2], values[3]])
    } else {
        None
    }
}

/// Extract a string field from a signature dictionary.
fn extract_string_field(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .and_then(Object::as_str)
        .ok()
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_type_from_sub_filter() {
        assert_eq!(
            SignatureType::from_sub_filter(b"ETSI.CAdES.detached"),
            SignatureType::Pades
        );
        assert_eq!(
            SignatureType::from_sub_filter(b"adbe.pkcs7.detached"),
            SignatureType::Pkcs7Detached
        );
        assert_eq!(
            SignatureType::from_sub_filter(b"ETSI.RFC3161"),
            SignatureType::DocTimestamp
        );
        assert_eq!(
            SignatureType::from_sub_filter(b"unknown"),
            SignatureType::Unknown("unknown".to_string())
        );
    }

    #[test]
    fn test_extract_from_unsigned_pdf() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");
        let sigs = extract_signatures(&pdf_data).expect("extraction failed");
        assert!(sigs.is_empty(), "unsigned PDF should have no signatures");
    }
}
