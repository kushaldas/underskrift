//! Extended signature metadata extraction and DSS reading.
//!
//! Provides detailed signature field information including DocMDP permissions,
//! Prop_Build application name, contents length, and full DSS content extraction
//! (returning actual DER bytes for certs, OCSPs, CRLs).

use lopdf::{Document, Object};

use crate::error::InspectError;

/// Information about a single signature field.
#[derive(Debug, Clone)]
pub struct SignatureFieldInfo {
    /// Field name from /T.
    pub field_name: Option<String>,
    /// Object number of the signature value dictionary.
    pub obj_num: Option<u32>,
    /// /Filter value (e.g. "Adobe.PPKLite").
    pub filter: Option<String>,
    /// /SubFilter value (e.g. "adbe.pkcs7.detached", "ETSI.CAdES.detached").
    pub sub_filter: Option<String>,
    /// /Name (signer name).
    pub name: Option<String>,
    /// /Reason.
    pub reason: Option<String>,
    /// /Location.
    pub location: Option<String>,
    /// /ContactInfo.
    pub contact_info: Option<String>,
    /// /M signing time string.
    pub signing_time: Option<String>,
    /// ByteRange array [offset1, length1, offset2, length2].
    pub byte_range: Option<[i64; 4]>,
    /// Coverage info: signed_bytes, file_size, percentage, gap info.
    pub coverage: Option<CoverageInfo>,
    /// Length of the raw /Contents bytes.
    pub contents_length: Option<usize>,
    /// First 32 bytes of /Contents as hex string.
    pub contents_hex_preview: Option<String>,
    /// DocMDP permissions (1=no changes, 2=form fill, 3=annotations+form).
    pub doc_mdp_permissions: Option<i64>,
    /// Application name from /Prop_Build /App /Name.
    pub build_app_name: Option<String>,
}

/// ByteRange coverage information.
#[derive(Debug, Clone)]
pub struct CoverageInfo {
    /// Total signed bytes.
    pub signed_bytes: i64,
    /// Total file size.
    pub file_size: i64,
    /// Percentage of file signed.
    pub percentage: f64,
    /// Start of the unsigned gap (Contents).
    pub gap_start: i64,
    /// End of the unsigned gap.
    pub gap_end: i64,
    /// Size of the unsigned gap.
    pub gap_size: i64,
}

/// A VRI (Validation Related Information) entry from the DSS.
#[derive(Debug, Clone)]
pub struct VriEntry {
    /// The hash key (uppercase hex SHA-1 of signature /Contents).
    pub hash_key: String,
    /// Number of certificates.
    pub num_certs: usize,
    /// Number of OCSP responses.
    pub num_ocsps: usize,
    /// Number of CRLs.
    pub num_crls: usize,
    /// DER-encoded certificates.
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses.
    pub ocsps: Vec<Vec<u8>>,
    /// DER-encoded CRLs.
    pub crls: Vec<Vec<u8>>,
}

/// Document Security Store (DSS) information.
#[derive(Debug, Clone)]
pub struct DssInfo {
    /// Object number of the DSS dictionary.
    pub obj_num: Option<u32>,
    /// Number of top-level certificates.
    pub num_certs: usize,
    /// Number of top-level OCSP responses.
    pub num_ocsps: usize,
    /// Number of top-level CRLs.
    pub num_crls: usize,
    /// DER-encoded top-level certificates.
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded top-level OCSP responses.
    pub ocsps: Vec<Vec<u8>>,
    /// DER-encoded top-level CRLs.
    pub crls: Vec<Vec<u8>>,
    /// Per-signature VRI entries.
    pub vri: Vec<VriEntry>,
}

/// A detected PDF revision (bounded by %%EOF).
#[derive(Debug, Clone)]
pub struct RevisionInfo {
    /// 0-based index.
    pub index: usize,
    /// Byte offset of the %%EOF marker end.
    pub eof_offset: usize,
    /// Start byte of this revision's incremental section.
    pub byte_start: usize,
    /// End byte (after trailing newlines past %%EOF).
    pub byte_end: usize,
}

/// Result of inspecting a PDF's signature-related structures.
#[derive(Debug, Clone)]
pub struct PdfSignatureInspection {
    /// Whether the PDF has any signatures.
    pub has_signatures: bool,
    /// Number of signatures found.
    pub num_signatures: usize,
    /// Signature field details.
    pub signatures: Vec<SignatureFieldInfo>,
    /// Document Security Store, if present.
    pub dss: Option<DssInfo>,
    /// Detected revisions.
    pub revisions: Vec<RevisionInfo>,
    /// Total file size in bytes.
    pub file_size: usize,
}

/// Inspect all signature-related data in a PDF.
///
/// Extracts signature fields, DSS (with full DER content), and revision info.
pub fn inspect_signatures(pdf_data: &[u8]) -> Result<PdfSignatureInspection, InspectError> {
    let file_size = pdf_data.len();

    let doc = Document::load_mem(pdf_data).map_err(|e| InspectError::PdfParse(format!("{e}")))?;

    let mut signatures = Vec::new();

    // Get catalog
    let catalog = doc
        .catalog()
        .map_err(|e| InspectError::PdfParse(format!("failed to get catalog: {e}")))?;

    // Find AcroForm
    let acroform = match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => doc.get_object(*id).and_then(Object::as_dict).ok(),
        Ok(Object::Dictionary(d)) => Some(d),
        _ => None,
    };

    if let Some(af) = acroform {
        let fields = match af.get(b"Fields") {
            Ok(Object::Array(arr)) => arr.clone(),
            _ => vec![],
        };

        for field_ref in &fields {
            let field_id = match field_ref.as_reference() {
                Ok(id) => id,
                Err(_) => continue,
            };

            let field = match doc.get_object(field_id).and_then(Object::as_dict) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Check if this is a signature field
            let ft = match field.get(b"FT").and_then(Object::as_name) {
                Ok(name) => name,
                Err(_) => continue,
            };
            if ft != b"Sig" {
                continue;
            }

            let field_name = field
                .get(b"T")
                .and_then(Object::as_str)
                .ok()
                .map(|s| String::from_utf8_lossy(s).into_owned());

            // Get the signature value dict
            let (sig_dict, sig_obj_num) = match field.get(b"V") {
                Ok(Object::Reference(sig_id)) => {
                    match doc.get_object(*sig_id).and_then(Object::as_dict) {
                        Ok(d) => (d, Some(sig_id.0)),
                        Err(_) => continue,
                    }
                }
                Ok(Object::Dictionary(d)) => (d, None),
                _ => continue,
            };

            let mut sig_info = SignatureFieldInfo {
                field_name,
                obj_num: sig_obj_num,
                filter: extract_name_field(sig_dict, b"Filter"),
                sub_filter: extract_name_field(sig_dict, b"SubFilter"),
                name: extract_string_field(sig_dict, b"Name"),
                reason: extract_string_field(sig_dict, b"Reason"),
                location: extract_string_field(sig_dict, b"Location"),
                contact_info: extract_string_field(sig_dict, b"ContactInfo"),
                signing_time: extract_string_field(sig_dict, b"M"),
                byte_range: None,
                coverage: None,
                contents_length: None,
                contents_hex_preview: None,
                doc_mdp_permissions: None,
                build_app_name: None,
            };

            // ByteRange
            if let Some(br) = extract_byte_range(sig_dict) {
                sig_info.coverage = Some(compute_coverage(&br, file_size as i64));
                sig_info.byte_range = Some(br);
            }

            // Contents
            if let Ok(contents) = sig_dict.get(b"Contents").and_then(Object::as_str) {
                sig_info.contents_length = Some(contents.len());
                let preview_len = std::cmp::min(32, contents.len());
                sig_info.contents_hex_preview = Some(hex::encode(&contents[..preview_len]));
            }

            // DocMDP
            if let Ok(Object::Array(refs)) = sig_dict.get(b"Reference") {
                for ref_obj in refs {
                    let ref_dict = match ref_obj {
                        Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
                        Object::Dictionary(d) => Some(d),
                        _ => None,
                    };
                    if let Some(rd) = ref_dict {
                        let transform = rd.get(b"TransformMethod").and_then(Object::as_name).ok();
                        if transform == Some(b"DocMDP") {
                            if let Ok(params) = rd.get(b"TransformParams") {
                                let params_dict = match params {
                                    Object::Reference(id) => {
                                        doc.get_object(*id).and_then(Object::as_dict).ok()
                                    }
                                    Object::Dictionary(d) => Some(d),
                                    _ => None,
                                };
                                if let Some(pd) = params_dict {
                                    sig_info.doc_mdp_permissions =
                                        pd.get(b"P").and_then(Object::as_i64).ok().or(Some(2));
                                    // default is 2
                                }
                            }
                        }
                    }
                }
            }

            // Prop_Build
            if let Ok(build_obj) = sig_dict.get(b"Prop_Build") {
                let build_dict = match build_obj {
                    Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
                    Object::Dictionary(d) => Some(d),
                    _ => None,
                };
                if let Some(bd) = build_dict {
                    if let Ok(app_obj) = bd.get(b"App") {
                        let app_dict = match app_obj {
                            Object::Reference(id) => {
                                doc.get_object(*id).and_then(Object::as_dict).ok()
                            }
                            Object::Dictionary(d) => Some(d),
                            _ => None,
                        };
                        if let Some(ad) = app_dict {
                            sig_info.build_app_name = extract_name_field(ad, b"Name")
                                .or_else(|| extract_string_field(ad, b"Name"));
                        }
                    }
                }
            }

            signatures.push(sig_info);
        }
    }

    // DSS
    let dss = extract_dss(&doc, catalog);

    // Revisions
    let revisions = detect_revisions(pdf_data);

    Ok(PdfSignatureInspection {
        has_signatures: !signatures.is_empty(),
        num_signatures: signatures.len(),
        signatures,
        dss,
        revisions,
        file_size,
    })
}

/// Extract ByteRange from a signature dictionary.
fn extract_byte_range(sig_dict: &lopdf::Dictionary) -> Option<[i64; 4]> {
    let arr = sig_dict.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let values: Vec<i64> = arr.iter().filter_map(|o| o.as_i64().ok()).collect();
    if values.len() == 4 {
        Some([values[0], values[1], values[2], values[3]])
    } else {
        None
    }
}

/// Compute coverage from ByteRange and file size.
fn compute_coverage(br: &[i64; 4], file_size: i64) -> CoverageInfo {
    let signed_bytes = br[1] + br[3];
    let percentage = if file_size > 0 {
        (100.0 * signed_bytes as f64 / file_size as f64 * 10.0).round() / 10.0
    } else {
        0.0
    };
    CoverageInfo {
        signed_bytes,
        file_size,
        percentage,
        gap_start: br[0] + br[1],
        gap_end: br[2],
        gap_size: br[2] - (br[0] + br[1]),
    }
}

/// Extract a /Name value as a string from a dictionary.
fn extract_name_field(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .and_then(Object::as_name)
        .ok()
        .map(|n| format!("/{}", std::str::from_utf8(n).unwrap_or("?")))
}

/// Extract a string value from a dictionary.
fn extract_string_field(dict: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .and_then(Object::as_str)
        .ok()
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

/// Extract the DSS (Document Security Store) with full DER content.
fn extract_dss(doc: &Document, catalog: &lopdf::Dictionary) -> Option<DssInfo> {
    let dss_obj = catalog.get(b"DSS").ok()?;
    let (dss_dict, dss_obj_num) = match dss_obj {
        Object::Reference(id) => {
            let d = doc.get_object(*id).and_then(Object::as_dict).ok()?;
            (d, Some(id.0))
        }
        Object::Dictionary(d) => (d, None),
        _ => return None,
    };

    let certs = extract_stream_array(doc, dss_dict, b"Certs");
    let ocsps = extract_stream_array(doc, dss_dict, b"OCSPs");
    let crls = extract_stream_array(doc, dss_dict, b"CRLs");

    // VRI
    let mut vri_entries = Vec::new();
    if let Ok(vri_obj) = dss_dict.get(b"VRI") {
        let vri_dict = match vri_obj {
            Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
            Object::Dictionary(d) => Some(d),
            _ => None,
        };
        if let Some(vd) = vri_dict {
            for (key, val) in vd.iter() {
                let hash_key = String::from_utf8_lossy(key).into_owned();
                let entry_dict = match val {
                    Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
                    Object::Dictionary(d) => Some(d),
                    _ => None,
                };
                if let Some(ed) = entry_dict {
                    let entry_certs = extract_stream_array(doc, ed, b"Cert");
                    let entry_ocsps = extract_stream_array(doc, ed, b"OCSP");
                    let entry_crls = extract_stream_array(doc, ed, b"CRL");
                    vri_entries.push(VriEntry {
                        hash_key,
                        num_certs: entry_certs.len(),
                        num_ocsps: entry_ocsps.len(),
                        num_crls: entry_crls.len(),
                        certs: entry_certs,
                        ocsps: entry_ocsps,
                        crls: entry_crls,
                    });
                }
            }
        }
    }

    Some(DssInfo {
        obj_num: dss_obj_num,
        num_certs: certs.len(),
        num_ocsps: ocsps.len(),
        num_crls: crls.len(),
        certs,
        ocsps,
        crls,
        vri: vri_entries,
    })
}

/// Extract an array of stream contents (DER bytes) from a dictionary key.
///
/// The key (e.g. "Certs") points to an array of references to stream objects.
/// Each stream's raw content is extracted and returned.
fn extract_stream_array(doc: &Document, dict: &lopdf::Dictionary, key: &[u8]) -> Vec<Vec<u8>> {
    let arr = match dict.get(key) {
        Ok(Object::Array(a)) => a,
        _ => return vec![],
    };

    let mut result = Vec::new();
    for item in arr {
        let stream_id = match item.as_reference() {
            Ok(id) => id,
            Err(_) => continue,
        };

        if let Ok(Object::Stream(stream)) = doc.get_object(stream_id) {
            // Try to decompress; fall back to raw content
            let mut stream_clone = stream.clone();
            let data = if stream_clone.decompress().is_ok() {
                stream_clone.content.clone()
            } else {
                stream.content.clone()
            };
            if !data.is_empty() {
                result.push(data);
            }
        }
    }
    result
}

/// Detect document revisions by finding %%EOF markers.
fn detect_revisions(pdf_data: &[u8]) -> Vec<RevisionInfo> {
    let eof_marker = b"%%EOF";
    let mut revisions: Vec<RevisionInfo> = Vec::new();
    let mut search_start = 0;

    while let Some(pos) = find_bytes(pdf_data, eof_marker, search_start) {
        let eof_end = pos + eof_marker.len();

        // Skip trailing newlines
        let mut actual_end = eof_end;
        while actual_end < pdf_data.len()
            && (pdf_data[actual_end] == b'\r' || pdf_data[actual_end] == b'\n')
        {
            actual_end += 1;
        }

        let index = revisions.len();
        let byte_start = if index == 0 {
            0
        } else {
            revisions[index - 1].byte_end
        };

        revisions.push(RevisionInfo {
            index,
            eof_offset: eof_end,
            byte_start,
            byte_end: actual_end,
        });

        search_start = eof_end;
    }

    revisions
}

/// Find a byte pattern in a slice starting at a given offset.
fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start + needle.len() > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_unsigned_pdf() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = inspect_signatures(&pdf_data).expect("inspection failed");
        assert!(!result.has_signatures);
        assert_eq!(result.num_signatures, 0);
        assert!(result.signatures.is_empty());
        assert!(result.dss.is_none());
        assert!(result.file_size > 0);
    }

    #[test]
    fn test_detect_revisions() {
        let data = b"%PDF-1.7\n%%EOF\nmore data\n%%EOF\n";
        let revisions = detect_revisions(data);
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].index, 0);
        assert_eq!(revisions[1].index, 1);
        assert!(revisions[1].byte_start > 0);
    }

    #[test]
    fn test_compute_coverage() {
        let br = [0, 1000, 2000, 500];
        let cov = compute_coverage(&br, 3000);
        assert_eq!(cov.signed_bytes, 1500);
        assert_eq!(cov.file_size, 3000);
        assert!((cov.percentage - 50.0).abs() < 0.1);
        assert_eq!(cov.gap_start, 1000);
        assert_eq!(cov.gap_end, 2000);
        assert_eq!(cov.gap_size, 1000);
    }

    #[test]
    fn test_find_bytes() {
        assert_eq!(find_bytes(b"hello world", b"world", 0), Some(6));
        assert_eq!(find_bytes(b"hello world", b"world", 7), None);
        assert_eq!(find_bytes(b"hello", b"", 0), None);
    }

    #[test]
    fn test_invalid_pdf() {
        let result = inspect_signatures(b"not a pdf");
        assert!(result.is_err());
    }
}
