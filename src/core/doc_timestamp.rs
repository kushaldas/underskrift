//! Document timestamp creation for PAdES-B-LTA.
//!
//! A `/DocTimeStamp` is a special signature-like dictionary that contains an
//! RFC 3161 timestamp token covering the entire PDF at the point it was applied.
//! It uses `/SubFilter /ETSI.RFC3161` and `/Type /DocTimeStamp`.
//!
//! Unlike a regular signature, no signing key is needed — just a TSA URL.
//! The timestamp covers the entire document up to the timestamp's own `/Contents`,
//! enabling indefinite archival when chained (PAdES-B-LTA).
//!
//! ## Workflow
//!
//! 1. Build a `/DocTimeStamp` dictionary with ByteRange/Contents placeholders
//! 2. Add it as an incremental update (new signature field + annotation)
//! 3. Compute the hash of the ByteRange-selected bytes
//! 4. Send the hash to a TSA, get back an RFC 3161 timestamp token
//! 5. Inject the token into `/Contents` and backpatch ByteRange
//!
//! This produces a PDF with a document-level timestamp that covers all prior
//! content, including any existing signatures and DSS dictionaries.

use lopdf::{Dictionary, Document, Object};

use crate::core::acroform;
use crate::core::incremental::IncrementalWriter;
use crate::core::parser;
use crate::core::sig_field::{self, SignatureFieldOptions};
use crate::error::{CoreError, PdfSignError};

#[cfg(feature = "tsp")]
use crate::tsp::{TsaClient, TsaClientPool};

/// Build a `/DocTimeStamp` signature dictionary.
///
/// This is similar to a regular signature dictionary but uses:
/// - `/Type /DocTimeStamp`
/// - `/SubFilter /ETSI.RFC3161`
/// - `/Filter /Adobe.PPKLite`
///
/// The `/Contents` will hold the DER-encoded RFC 3161 `TimeStampToken`
/// (which is a CMS `ContentInfo` wrapping `SignedData` with `TSTInfo`).
///
/// `contents_size` is the number of bytes to reserve for the hex-encoded
/// timestamp token. 8192 bytes (16384 hex chars) is usually sufficient.
pub fn build_doc_timestamp_dict(contents_size: usize) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"DocTimeStamp".to_vec()));
    dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    dict.set("SubFilter", Object::Name(b"ETSI.RFC3161".to_vec()));

    // ByteRange placeholder — will be backpatched after serialization
    dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );

    // Contents placeholder — hex-encoded zeroes, sized to `contents_size`
    let placeholder = vec![0u8; contents_size];
    dict.set(
        "Contents",
        Object::String(placeholder, lopdf::StringFormat::Hexadecimal),
    );

    dict
}

/// Options for adding a document timestamp.
#[derive(Debug, Clone)]
pub struct DocTimestampOptions {
    /// Size to reserve for the timestamp token in /Contents (bytes, not hex chars).
    /// Default: 8192 bytes (16384 hex chars). Should be enough for most TSA tokens.
    pub content_size: usize,
    /// Signature field name for the timestamp.
    /// Default: "DocTimeStamp1"
    pub field_name: String,
    /// Page to attach the annotation to (0-indexed).
    /// Default: 0 (first page)
    pub page: u32,
}

impl Default for DocTimestampOptions {
    fn default() -> Self {
        Self {
            content_size: 8192,
            field_name: "DocTimeStamp1".to_string(),
            page: 0,
        }
    }
}

/// Prepare a PDF with a DocTimeStamp placeholder, ready for timestamp injection.
///
/// Returns `(output_bytes, byte_range)` where:
/// - `output_bytes` is the full PDF with the placeholder
/// - `byte_range` contains the offsets needed for hash computation and injection
///
/// After calling this, the caller should:
/// 1. Compute the hash of the ByteRange-selected bytes
/// 2. Send the hash to a TSA
/// 3. Call [`inject_timestamp_token`] to finalize
pub fn prepare_doc_timestamp(
    pdf_data: &[u8],
    options: &DocTimestampOptions,
) -> Result<(Vec<u8>, crate::core::byte_range::ByteRange), PdfSignError> {
    let mut doc = Document::load_mem(pdf_data).map_err(CoreError::Lopdf)?;

    let meta = parser::extract_metadata(&doc)?;
    log::debug!(
        "DocTimeStamp: PDF metadata: xref_offset={}, trailer_size={}, root={:?}",
        meta.xref_offset,
        meta.trailer_size,
        meta.root_id,
    );

    // Build the DocTimeStamp dictionary
    let contents_hex_size = options.content_size * 2;
    let ts_dict = build_doc_timestamp_dict(options.content_size);

    // Add as new object
    let ts_dict_id = doc.add_object(Object::Dictionary(ts_dict));

    // Build a signature field pointing to the timestamp dict
    let field_opts = SignatureFieldOptions {
        name: options.field_name.clone(),
        page: options.page,
        rect: [0.0, 0.0, 0.0, 0.0], // invisible
    };
    let sig_field_dict = sig_field::build_sig_field(&field_opts, ts_dict_id);
    let sig_field_id = doc.add_object(Object::Dictionary(sig_field_dict));

    // Update AcroForm and page annotations
    acroform::ensure_acroform(&mut doc, sig_field_id, options.page)?;

    // Build the incremental update
    let mut writer = IncrementalWriter::new(
        pdf_data.to_vec(),
        meta.trailer_size,
        meta.xref_offset,
        meta.root_id,
        contents_hex_size,
    );

    // The DocTimeStamp dict is the "sig dict" for ByteRange tracking
    writer.set_sig_dict_id(ts_dict_id);

    // Add new objects
    if let Ok(obj) = doc.get_object(ts_dict_id) {
        writer.add_object(ts_dict_id, obj.clone());
    }
    if let Ok(obj) = doc.get_object(sig_field_id) {
        writer.add_object(sig_field_id, obj.clone());
    }

    // Add modified catalog
    let catalog_id = meta.root_id;
    if let Ok(obj) = doc.get_object(catalog_id) {
        writer.add_object(catalog_id, obj.clone());
    }

    // Add AcroForm if indirect
    if let Ok(catalog_dict) = doc.get_object(catalog_id).and_then(|o| o.as_dict()) {
        if let Ok(Object::Reference(af_id)) = catalog_dict.get(b"AcroForm") {
            if let Ok(obj) = doc.get_object(*af_id) {
                writer.add_object(*af_id, obj.clone());
            }
        }
    }

    // Add the modified page
    let pages = doc.get_pages();
    let page_num = options.page + 1;
    if let Some(&page_id) = pages.get(&page_num) {
        if let Ok(obj) = doc.get_object(page_id) {
            writer.add_object(page_id, obj.clone());
        }
    }

    // Write the incremental update
    let (output, byte_range) = writer.write()?;

    Ok((output, byte_range))
}

/// Inject a timestamp token into a prepared DocTimeStamp placeholder.
///
/// `pdf_data` should be the output from [`prepare_doc_timestamp`].
/// `byte_range` should be the ByteRange returned by that function.
/// `token_der` is the DER-encoded RFC 3161 TimeStampToken.
///
/// Returns the finalized PDF bytes.
pub fn inject_timestamp_token(
    mut pdf_data: Vec<u8>,
    byte_range: &crate::core::byte_range::ByteRange,
    token_der: &[u8],
    content_size: usize,
) -> Result<Vec<u8>, PdfSignError> {
    if token_der.len() > content_size {
        return Err(PdfSignError::Core(CoreError::SignatureTooLarge {
            actual: token_der.len(),
            allocated: content_size,
        }));
    }

    // Hex-encode the token
    let hex_token = hex::encode_upper(token_der);
    let hex_bytes = hex_token.as_bytes();

    // Write into the Contents placeholder
    let start = byte_range.contents_offset;
    let end = byte_range.contents_offset + byte_range.contents_length;
    pdf_data[start..start + hex_bytes.len()].copy_from_slice(hex_bytes);
    // Zero-pad the rest
    for b in &mut pdf_data[start + hex_bytes.len()..end] {
        *b = b'0';
    }

    Ok(pdf_data)
}

/// Add a document timestamp to a PDF using a TSA client.
///
/// This is the high-level function that combines preparation, hashing,
/// TSA request, and injection into a single async call.
///
/// Requires the `tsp` feature.
///
/// # Arguments
///
/// - `pdf_data`: The PDF to timestamp (may already be signed)
/// - `tsa`: A TSA client to obtain the timestamp token
/// - `options`: Configuration for the timestamp
///
/// # Returns
///
/// The PDF with the document timestamp appended as an incremental update.
#[cfg(feature = "tsp")]
pub async fn add_document_timestamp(
    pdf_data: &[u8],
    tsa: &TsaClient,
    options: &DocTimestampOptions,
) -> Result<Vec<u8>, PdfSignError> {
    use crate::crypto::algorithm::DigestAlgorithm;

    // Step 1: Prepare the PDF with a DocTimeStamp placeholder
    let (output, byte_range) = prepare_doc_timestamp(pdf_data, options)?;

    // Step 2: Compute hash of the ByteRange-selected bytes
    let br_values = byte_range.compute(output.len());
    let range1 = &output[br_values[0]..br_values[0] + br_values[1]];
    let range2 = &output[br_values[2]..br_values[2] + br_values[3]];

    let digest_alg = DigestAlgorithm::Sha256;
    let mut hasher = digest_alg.new_hasher();
    hasher.update(range1);
    hasher.update(range2);
    let data_hash = hasher.finalize();

    log::debug!(
        "DocTimeStamp: computed hash over {} + {} = {} bytes",
        br_values[1],
        br_values[3],
        br_values[1] + br_values[3],
    );

    // Step 3: Request timestamp from TSA
    let token_der = tsa.timestamp(&data_hash).await.map_err(PdfSignError::Tsp)?;

    log::debug!(
        "DocTimeStamp: received timestamp token ({} bytes)",
        token_der.len(),
    );

    // Step 4: Inject the timestamp token
    inject_timestamp_token(output, &byte_range, &token_der, options.content_size)
}

/// Add a document timestamp using a TSA client pool (with fallback).
///
/// Same as [`add_document_timestamp`] but uses a [`TsaClientPool`] which
/// tries multiple TSA servers in order.
#[cfg(feature = "tsp")]
pub async fn add_document_timestamp_pool(
    pdf_data: &[u8],
    tsa_pool: &TsaClientPool,
    options: &DocTimestampOptions,
) -> Result<Vec<u8>, PdfSignError> {
    use crate::crypto::algorithm::DigestAlgorithm;

    let (output, byte_range) = prepare_doc_timestamp(pdf_data, options)?;

    let br_values = byte_range.compute(output.len());
    let range1 = &output[br_values[0]..br_values[0] + br_values[1]];
    let range2 = &output[br_values[2]..br_values[2] + br_values[3]];

    let digest_alg = DigestAlgorithm::Sha256;
    let mut hasher = digest_alg.new_hasher();
    hasher.update(range1);
    hasher.update(range2);
    let data_hash = hasher.finalize();

    let token_der = tsa_pool
        .timestamp(&data_hash)
        .await
        .map_err(PdfSignError::Tsp)?;

    inject_timestamp_token(output, &byte_range, &token_der, options.content_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_doc_timestamp_dict() {
        let dict = build_doc_timestamp_dict(4096);

        // Check /Type
        let type_val = dict.get(b"Type").unwrap();
        assert_eq!(type_val, &Object::Name(b"DocTimeStamp".to_vec()));

        // Check /Filter
        let filter = dict.get(b"Filter").unwrap();
        assert_eq!(filter, &Object::Name(b"Adobe.PPKLite".to_vec()));

        // Check /SubFilter
        let sub_filter = dict.get(b"SubFilter").unwrap();
        assert_eq!(sub_filter, &Object::Name(b"ETSI.RFC3161".to_vec()));

        // Check /ByteRange exists and is an array of 4 elements
        let byte_range = dict.get(b"ByteRange").unwrap();
        if let Object::Array(arr) = byte_range {
            assert_eq!(arr.len(), 4);
        } else {
            panic!("ByteRange should be an array");
        }

        // Check /Contents exists and has correct size
        let contents = dict.get(b"Contents").unwrap();
        if let Object::String(data, lopdf::StringFormat::Hexadecimal) = contents {
            assert_eq!(data.len(), 4096);
        } else {
            panic!("Contents should be a hex string");
        }
    }

    #[test]
    fn test_doc_timestamp_options_default() {
        let opts = DocTimestampOptions::default();
        assert_eq!(opts.content_size, 8192);
        assert_eq!(opts.field_name, "DocTimeStamp1");
        assert_eq!(opts.page, 0);
    }

    #[test]
    fn test_prepare_doc_timestamp() {
        let pdf_data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ));

        let options = DocTimestampOptions {
            content_size: 4096,
            field_name: "TestTimestamp".to_string(),
            page: 0,
        };

        let (output, byte_range) = prepare_doc_timestamp(pdf_data, &options).unwrap();

        // Output should be larger than input (incremental update added)
        assert!(output.len() > pdf_data.len());

        // ByteRange should have valid offsets
        assert!(byte_range.contents_offset > 0);
        assert!(byte_range.contents_length > 0);
        assert_eq!(byte_range.contents_length, 4096 * 2); // hex doubles the size

        // The output should still end with %%EOF
        let as_str = String::from_utf8_lossy(&output);
        assert!(as_str.contains("%%EOF"));

        // The output should contain DocTimeStamp
        assert!(as_str.contains("DocTimeStamp"));

        // The output should contain ETSI.RFC3161
        assert!(as_str.contains("ETSI.RFC3161"));
    }

    #[test]
    fn test_inject_timestamp_token() {
        let pdf_data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ));

        let options = DocTimestampOptions {
            content_size: 4096,
            field_name: "TestTimestamp2".to_string(),
            page: 0,
        };

        let (output, byte_range) = prepare_doc_timestamp(pdf_data, &options).unwrap();

        // Create a fake "timestamp token" (not a real one, just for testing injection)
        let fake_token = vec![0x30, 0x82, 0x01, 0x00]; // 4 bytes

        let result =
            inject_timestamp_token(output, &byte_range, &fake_token, options.content_size).unwrap();

        // The injected hex should appear in the output
        let hex_token = hex::encode_upper(&fake_token);
        let as_str = String::from_utf8_lossy(&result);
        assert!(as_str.contains(&hex_token));
    }

    #[test]
    fn test_inject_token_too_large() {
        let pdf_data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ));

        let options = DocTimestampOptions {
            content_size: 16, // Very small
            field_name: "TestTimestamp3".to_string(),
            page: 0,
        };

        let (output, byte_range) = prepare_doc_timestamp(pdf_data, &options).unwrap();

        // Create a token larger than the allocated space
        let big_token = vec![0xAA; 32];

        let result = inject_timestamp_token(output, &byte_range, &big_token, options.content_size);

        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_on_already_signed_pdf() {
        // First sign a PDF, then add a timestamp placeholder
        // This simulates the B-LTA workflow
        let pdf_data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ));

        // Prepare first timestamp
        let opts1 = DocTimestampOptions {
            content_size: 4096,
            field_name: "TS1".to_string(),
            page: 0,
        };
        let (pdf_with_ts1, _br1) = prepare_doc_timestamp(pdf_data, &opts1).unwrap();

        // Prepare second timestamp on top
        let opts2 = DocTimestampOptions {
            content_size: 4096,
            field_name: "TS2".to_string(),
            page: 0,
        };
        let (pdf_with_ts2, _br2) = prepare_doc_timestamp(&pdf_with_ts1, &opts2).unwrap();

        // Both should be present
        let as_str = String::from_utf8_lossy(&pdf_with_ts2);
        // Should have multiple %%EOF (one per incremental update)
        let eof_count = as_str.matches("%%EOF").count();
        assert!(eof_count >= 2, "Expected multiple %%EOF, got {eof_count}");
    }
}
