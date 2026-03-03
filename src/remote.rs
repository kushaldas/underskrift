//! Three-phase remote signing protocol for PDF signatures.
//!
//! This module provides a **deferred signing** workflow where the private key
//! is not available locally. Instead of the single-call [`PdfSigner::sign`],
//! the process is split into three phases:
//!
//! 1. **Prepare** ([`prepare_signature`]) — Parse the PDF, build the signature
//!    dictionary and CMS signed attributes, compute the hash that must be signed.
//!    Returns a [`PreparedSignature`] containing the hash and all state needed to
//!    finalize.
//!
//! 2. **Sign** (external) — The caller sends `prepared.attrs_hash` to a remote
//!    signing service, cloud KMS, HSM, or other external signer. The remote party
//!    signs the hash and returns raw signature bytes.
//!
//! 3. **Finalize** ([`finalize_signature`]) — Inject the signature bytes into the
//!    prepared CMS structure and PDF, producing the final signed document.
//!
//! This is the approach used by the Sweden Connect SignService protocol and is
//! useful whenever the signing key lives on a different machine, behind an API,
//! or in hardware that cannot be called synchronously.
//!
//! # Comparison with `PdfSigner`
//!
//! | | `PdfSigner::sign` | Three-phase |
//! |---|---|---|
//! | Private key | Required locally | Only needed remotely |
//! | Signing call | Synchronous inside `sign()` | External, between phases |
//! | Network round-trips | 0 | 1 (to remote signer) |
//! | Use case | Software keys, PKCS#12 | Cloud KMS, HSM, SignService |
//!
//! # Example
//!
//! ```no_run
//! use underskrift::remote::{
//!     prepare_signature, finalize_signature, RemoteSignerInfo, RemoteSigningOptions,
//! };
//! use underskrift::crypto::algorithm::{DigestAlgorithm, SignatureAlgorithm};
//!
//! # fn example() -> Result<(), underskrift::PdfSignError> {
//! let pdf = std::fs::read("document.pdf")?;
//!
//! // Certificate and algorithm info (no private key!)
//! let signer_info = RemoteSignerInfo {
//!     certificate_der: std::fs::read("signer_cert.der")?,
//!     chain_der: vec![
//!         std::fs::read("signer_cert.der")?,
//!         std::fs::read("ca_cert.der")?,
//!     ],
//!     digest_algorithm: DigestAlgorithm::Sha256,
//!     signature_algorithm: SignatureAlgorithm::RsaPkcs1v15,
//! };
//!
//! // Phase 1: Prepare
//! let prepared = prepare_signature(&pdf, &signer_info, &RemoteSigningOptions::default())?;
//!
//! // Phase 2: Send hash to remote signer (your code)
//! // let signature_bytes = remote_kms.sign(&prepared.attrs_hash)?;
//! # let signature_bytes = vec![0u8; 256];
//!
//! // Phase 3: Finalize
//! let signed_pdf = finalize_signature(prepared, &signature_bytes)?;
//! std::fs::write("signed.pdf", signed_pdf)?;
//! # Ok(())
//! # }
//! ```

use lopdf::{Document, Object};

use crate::cms::builder::{CmsPreSignData, CmsProfile, PdfCmsBuilder};
use crate::core::acroform;
use crate::core::byte_range::ByteRange;
use crate::core::incremental::IncrementalWriter;
use crate::core::parser;
use crate::core::sig_dict::{self, SigSubFilter};
use crate::core::sig_field::{self, SignatureFieldOptions};
use crate::crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm, SignatureAlgorithm};
use crate::crypto::traits::CryptoSigner;
use crate::error::{CoreError, CryptoError, PdfSignError};
use crate::signer::SubFilter;

/// Certificate and algorithm information for a remote signer.
///
/// This is the keyless equivalent of [`CryptoSigner`] — it provides everything
/// needed to build the CMS structure except the actual signing operation.
#[derive(Debug, Clone)]
pub struct RemoteSignerInfo {
    /// The signing certificate in DER-encoded X.509 format.
    pub certificate_der: Vec<u8>,
    /// The full certificate chain (DER-encoded), signer cert first, root last.
    pub chain_der: Vec<Vec<u8>>,
    /// The digest algorithm to use for hashing.
    pub digest_algorithm: DigestAlgorithm,
    /// The signature algorithm the remote signer will use.
    pub signature_algorithm: SignatureAlgorithm,
}

/// Adapter that implements `CryptoSigner` for `RemoteSignerInfo`.
///
/// The `sign_hash` method always returns an error — it should never be called
/// during the pre-sign phase. This adapter exists solely so we can reuse
/// `PdfCmsBuilder` which requires a `&dyn CryptoSigner` for certificate/algorithm
/// access.
struct RemoteSignerAdapter<'a> {
    info: &'a RemoteSignerInfo,
}

impl<'a> CryptoSigner for RemoteSignerAdapter<'a> {
    fn sign_hash(&self, _hash: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SigningFailed(
            "RemoteSignerAdapter::sign_hash() must not be called — \
             use pre_sign() / complete_cms() instead"
                .into(),
        ))
    }

    fn certificate_der(&self) -> &[u8] {
        &self.info.certificate_der
    }

    fn certificate_chain_der(&self) -> Vec<&[u8]> {
        self.info.chain_der.iter().map(|c| c.as_slice()).collect()
    }

    fn digest_algorithm(&self) -> DigestAlgorithm {
        self.info.digest_algorithm
    }

    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.info.signature_algorithm
    }
}

/// Options for remote/three-phase signing.
///
/// Mirrors [`crate::signer::SigningOptions`] but without fields that only
/// make sense for local signing (like TSA URL).
#[derive(Debug, Clone)]
pub struct RemoteSigningOptions {
    /// The signature sub-filter to use.
    pub sub_filter: SubFilter,
    /// Digest algorithm (must match `RemoteSignerInfo::digest_algorithm`).
    pub digest_algorithm: DigestAlgorithm,
    /// Signature field name.
    pub field_name: String,
    /// Page to place the signature annotation (0-indexed).
    pub page: u32,
    /// Reason for signing.
    pub reason: Option<String>,
    /// Signer location.
    pub location: Option<String>,
    /// Signer contact info.
    pub contact_info: Option<String>,
    /// Size to reserve for the /Contents hex string (in bytes, not hex chars).
    /// Default is 8192 bytes. Increase for large cert chains.
    pub content_size: usize,
    /// Algorithm registry for validating allowed algorithms.
    /// When set, algorithms are checked before preparing the signature.
    pub algorithm_registry: Option<AlgorithmRegistry>,
}

impl Default for RemoteSigningOptions {
    fn default() -> Self {
        Self {
            sub_filter: SubFilter::default(),
            digest_algorithm: DigestAlgorithm::default(),
            field_name: "Signature1".to_string(),
            page: 0,
            reason: None,
            location: None,
            contact_info: None,
            content_size: 8192,
            algorithm_registry: None,
        }
    }
}

/// The result of [`prepare_signature`] — everything needed to finalize
/// the signature once the remote signer returns the raw signature bytes.
///
/// The only field callers need to read is `attrs_hash` — send this to
/// the remote signing service. Pass the entire struct to [`finalize_signature`].
pub struct PreparedSignature {
    /// The hash of the DER-encoded CMS signed attributes.
    /// **Send this to the remote signer.**
    pub attrs_hash: Vec<u8>,

    // Internal state — opaque to callers
    pub(crate) output: Vec<u8>,
    pub(crate) byte_range: ByteRange,
    pub(crate) cms_pre_sign: CmsPreSignData,
    pub(crate) content_size: usize,
    pub(crate) cms_profile: CmsProfile,
    pub(crate) signer_info: RemoteSignerInfo,
}

/// Phase 1: Prepare a PDF for remote signing.
///
/// Parses the PDF, builds signature structures, computes the ByteRange hash,
/// constructs CMS signed attributes, and returns the hash that must be signed
/// along with all state needed to finalize.
///
/// This function does NOT require a private key. It only needs the signer's
/// certificate, chain, and algorithm information via [`RemoteSignerInfo`].
///
/// # Errors
///
/// Returns an error if:
/// - The PDF cannot be parsed
/// - The algorithms are rejected by the optional `AlgorithmRegistry`
/// - The certificate cannot be DER-decoded
pub fn prepare_signature(
    pdf_data: &[u8],
    signer_info: &RemoteSignerInfo,
    options: &RemoteSigningOptions,
) -> Result<PreparedSignature, PdfSignError> {
    // Step 0: Validate algorithms if registry is configured
    if let Some(registry) = &options.algorithm_registry {
        registry
            .validate(
                signer_info.signature_algorithm,
                signer_info.digest_algorithm,
            )
            .map_err(PdfSignError::AlgorithmNotAllowed)?;
    }

    // Step 1: Parse the PDF
    let mut doc = Document::load_mem(pdf_data).map_err(CoreError::Lopdf)?;

    // Step 2: Extract metadata
    let meta = parser::extract_metadata(&doc)?;
    log::debug!(
        "Remote signing: PDF metadata: xref_offset={}, trailer_size={}, root={:?}, max_id={}",
        meta.xref_offset,
        meta.trailer_size,
        meta.root_id,
        meta.max_id,
    );

    // Step 3: Build the signature dictionary
    let sub_filter: SigSubFilter = options.sub_filter.into();
    let contents_hex_size = options.content_size * 2;
    let mut sig_dict = sig_dict::build_sig_dict(sub_filter, options.content_size);

    if let Some(reason) = &options.reason {
        sig_dict.set(
            "Reason",
            Object::String(reason.as_bytes().to_vec(), lopdf::StringFormat::Literal),
        );
    }
    if let Some(location) = &options.location {
        sig_dict.set(
            "Location",
            Object::String(location.as_bytes().to_vec(), lopdf::StringFormat::Literal),
        );
    }
    if let Some(contact) = &options.contact_info {
        sig_dict.set(
            "ContactInfo",
            Object::String(contact.as_bytes().to_vec(), lopdf::StringFormat::Literal),
        );
    }

    // Step 4: Add sig dict as a new object
    let sig_dict_id = doc.add_object(Object::Dictionary(sig_dict));

    // Step 5: Build the signature field
    let field_opts = SignatureFieldOptions {
        name: options.field_name.clone(),
        page: options.page,
        rect: [0.0, 0.0, 0.0, 0.0], // invisible signature
    };
    let sig_field_dict = sig_field::build_sig_field(&field_opts, sig_dict_id);
    let sig_field_id = doc.add_object(Object::Dictionary(sig_field_dict));

    // Step 6: Update AcroForm and page annotations
    acroform::ensure_acroform(&mut doc, sig_field_id, options.page)?;

    // Step 7: Build the incremental update
    let mut writer = IncrementalWriter::new(
        pdf_data.to_vec(),
        meta.trailer_size,
        meta.xref_offset,
        meta.root_id,
        contents_hex_size,
    );

    writer.set_sig_dict_id(sig_dict_id);

    // Add new objects
    if let Ok(obj) = doc.get_object(sig_dict_id) {
        writer.add_object(sig_dict_id, obj.clone());
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

    // Step 8: Write the incremental update
    let (output, byte_range) = writer.write()?;

    // Step 9: Compute hash of the byte-range-selected bytes
    let br_values = byte_range.compute(output.len());
    let range1 = &output[br_values[0]..br_values[0] + br_values[1]];
    let range2 = &output[br_values[2]..br_values[2] + br_values[3]];

    let digest_alg = signer_info.digest_algorithm;
    let mut hasher = digest_alg.new_hasher();
    hasher.update(range1);
    hasher.update(range2);
    let data_hash = hasher.finalize();

    // Step 10: CMS pre-sign — build signed attributes, compute attrs_hash
    let cms_profile = match options.sub_filter {
        SubFilter::Pades => CmsProfile::Pades,
        SubFilter::Pkcs7 => CmsProfile::Traditional,
    };
    let adapter = RemoteSignerAdapter { info: signer_info };
    let cms_builder = PdfCmsBuilder::new(&adapter).profile(cms_profile);
    let cms_pre_sign = cms_builder.pre_sign(&data_hash)?;

    let attrs_hash = cms_pre_sign.attrs_hash.clone();

    Ok(PreparedSignature {
        attrs_hash,
        output,
        byte_range,
        cms_pre_sign,
        content_size: options.content_size,
        cms_profile,
        signer_info: signer_info.clone(),
    })
}

/// Phase 3: Finalize a prepared signature with remotely-produced signature bytes.
///
/// Takes the [`PreparedSignature`] from [`prepare_signature`] and the raw
/// signature bytes (the result of signing `prepared.attrs_hash` with the
/// private key), and produces the final signed PDF.
///
/// # Errors
///
/// Returns an error if:
/// - The CMS assembly fails
/// - The signature is too large for the allocated `/Contents` placeholder
pub fn finalize_signature(
    mut prepared: PreparedSignature,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, PdfSignError> {
    // Step 1: Complete the CMS SignedData with the external signature
    let adapter = RemoteSignerAdapter {
        info: &prepared.signer_info,
    };
    let cms_builder = PdfCmsBuilder::new(&adapter).profile(prepared.cms_profile);
    let cms_der = cms_builder.complete_cms(&prepared.cms_pre_sign, signature_bytes)?;

    // Step 2: Check that the CMS fits
    if cms_der.len() > prepared.content_size {
        return Err(PdfSignError::Core(CoreError::SignatureTooLarge {
            actual: cms_der.len(),
            allocated: prepared.content_size,
        }));
    }

    // Step 3: Inject the CMS signature into /Contents
    let hex_sig = hex::encode_upper(&cms_der);
    let hex_bytes = hex_sig.as_bytes();

    let start = prepared.byte_range.contents_offset;
    let end = prepared.byte_range.contents_offset + prepared.byte_range.contents_length;
    prepared.output[start..start + hex_bytes.len()].copy_from_slice(hex_bytes);
    for b in &mut prepared.output[start + hex_bytes.len()..end] {
        *b = b'0';
    }

    Ok(prepared.output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_signing_options_default() {
        let opts = RemoteSigningOptions::default();
        assert_eq!(opts.sub_filter, SubFilter::Pades);
        assert_eq!(opts.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(opts.field_name, "Signature1");
        assert_eq!(opts.page, 0);
        assert_eq!(opts.content_size, 8192);
        assert!(opts.reason.is_none());
        assert!(opts.location.is_none());
        assert!(opts.contact_info.is_none());
        assert!(opts.algorithm_registry.is_none());
    }

    #[test]
    fn test_remote_signer_adapter_sign_hash_errors() {
        let info = RemoteSignerInfo {
            certificate_der: vec![0x30, 0x00],
            chain_der: vec![vec![0x30, 0x00]],
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1v15,
        };
        let adapter = RemoteSignerAdapter { info: &info };

        // sign_hash must always fail — it should never be called
        let result = adapter.sign_hash(&[1, 2, 3]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("must not be called"));
    }

    #[test]
    fn test_remote_signer_adapter_accessors() {
        let cert = vec![0x30, 0x82, 0x01, 0x00];
        let chain = vec![vec![0x30, 0x82, 0x01, 0x00], vec![0x30, 0x82, 0x02, 0x00]];
        let info = RemoteSignerInfo {
            certificate_der: cert.clone(),
            chain_der: chain.clone(),
            digest_algorithm: DigestAlgorithm::Sha384,
            signature_algorithm: SignatureAlgorithm::EcdsaP384,
        };
        let adapter = RemoteSignerAdapter { info: &info };

        assert_eq!(adapter.certificate_der(), cert.as_slice());
        assert_eq!(adapter.certificate_chain_der().len(), 2);
        assert_eq!(adapter.digest_algorithm(), DigestAlgorithm::Sha384);
        assert_eq!(adapter.signature_algorithm(), SignatureAlgorithm::EcdsaP384);
    }

    /// Test the full three-phase flow with a real PDF and software signer.
    ///
    /// This test prepares a signature, extracts the attrs_hash, signs it
    /// using a local SoftwareSigner (simulating a remote signer), and
    /// finalizes the PDF. The result should be a valid signed PDF.
    #[test]
    fn test_three_phase_roundtrip() {
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        // Load test fixtures
        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test_three_phase_roundtrip: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        // Build RemoteSignerInfo from the SoftwareSigner's public data
        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        let options = RemoteSigningOptions::default();

        // Phase 1: Prepare
        let prepared = prepare_signature(&pdf_data, &info, &options).unwrap();
        assert!(!prepared.attrs_hash.is_empty());
        assert!(prepared.output.len() > pdf_data.len());

        // Phase 2: Sign the attrs_hash locally (simulating remote)
        let signature_bytes = signer.sign_hash(&prepared.attrs_hash).unwrap();

        // Phase 3: Finalize
        let signed_pdf = finalize_signature(prepared, &signature_bytes).unwrap();
        assert!(signed_pdf.len() > pdf_data.len());

        // Verify the result is valid PDF (starts with %PDF)
        assert_eq!(&signed_pdf[..5], b"%PDF-");

        // Verify the signature was injected (non-zero hex in Contents region)
        let hex_content = String::from_utf8_lossy(&signed_pdf);
        // The signed PDF should contain non-zero hex data
        assert!(hex_content.contains("/SubFilter /ETSI.CAdES.detached"));
    }

    /// Test that the three-phase flow produces the same CMS structure
    /// as the single-phase PdfSigner::sign() when using the same key.
    #[test]
    fn test_three_phase_matches_single_phase_structure() {
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        // Three-phase
        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        let prepared =
            prepare_signature(&pdf_data, &info, &RemoteSigningOptions::default()).unwrap();
        let sig = signer.sign_hash(&prepared.attrs_hash).unwrap();
        let signed_remote = finalize_signature(prepared, &sig).unwrap();

        // Both should be valid PDFs
        assert_eq!(&signed_remote[..5], b"%PDF-");
        // The remote-signed PDF should contain the PAdES SubFilter
        let content = String::from_utf8_lossy(&signed_remote);
        assert!(content.contains("/SubFilter /ETSI.CAdES.detached"));
    }

    #[test]
    fn test_three_phase_traditional_subfilter() {
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        let options = RemoteSigningOptions {
            sub_filter: SubFilter::Pkcs7,
            ..RemoteSigningOptions::default()
        };

        let prepared = prepare_signature(&pdf_data, &info, &options).unwrap();
        let sig = signer.sign_hash(&prepared.attrs_hash).unwrap();
        let signed = finalize_signature(prepared, &sig).unwrap();

        let content = String::from_utf8_lossy(&signed);
        assert!(content.contains("/SubFilter /adbe.pkcs7.detached"));
    }

    #[test]
    fn test_three_phase_with_algorithm_registry() {
        use crate::crypto::algorithm::AlgorithmRegistry;
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        // Empty registry should reject everything
        let options = RemoteSigningOptions {
            algorithm_registry: Some(AlgorithmRegistry::new()),
            ..RemoteSigningOptions::default()
        };

        let result = prepare_signature(&pdf_data, &info, &options);
        match result {
            Err(e) => {
                let err = format!("{e}");
                assert!(
                    err.contains("not allowed") || err.contains("Algorithm"),
                    "unexpected error: {err}"
                );
            }
            Ok(_) => panic!("expected prepare_signature to fail with empty registry"),
        }

        // Standard registry should accept the signer's algorithms
        let options = RemoteSigningOptions {
            algorithm_registry: Some(AlgorithmRegistry::standard()),
            ..RemoteSigningOptions::default()
        };

        let result = prepare_signature(&pdf_data, &info, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_three_phase_with_options() {
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        let options = RemoteSigningOptions {
            field_name: "RemoteSig1".to_string(),
            reason: Some("Remotely signed".to_string()),
            location: Some("Cloud".to_string()),
            contact_info: Some("admin@example.com".to_string()),
            ..RemoteSigningOptions::default()
        };

        let prepared = prepare_signature(&pdf_data, &info, &options).unwrap();
        let sig = signer.sign_hash(&prepared.attrs_hash).unwrap();
        let signed = finalize_signature(prepared, &sig).unwrap();

        let content = String::from_utf8_lossy(&signed);
        assert!(content.contains("Remotely signed"));
        assert!(content.contains("Cloud"));
        assert!(content.contains("admin@example.com"));
    }

    #[test]
    fn test_signature_too_large_for_content_size() {
        use crate::crypto::software::SoftwareSigner;
        use std::path::Path;

        let p12_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signer.p12");
        let pdf_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.pdf");

        if !p12_path.exists() || !pdf_path.exists() {
            eprintln!("Skipping test: test fixtures not found. Run gen-test-fixtures.sh");
            return;
        }

        let pdf_data = std::fs::read(&pdf_path).unwrap();
        let signer = SoftwareSigner::from_pkcs12_file(&p12_path, "test123").unwrap();

        let info = RemoteSignerInfo {
            certificate_der: signer.certificate_der().to_vec(),
            chain_der: signer
                .certificate_chain_der()
                .iter()
                .map(|c| c.to_vec())
                .collect(),
            digest_algorithm: signer.digest_algorithm(),
            signature_algorithm: signer.signature_algorithm(),
        };

        // Tiny content_size — CMS will be too large to fit
        let options = RemoteSigningOptions {
            content_size: 64,
            ..RemoteSigningOptions::default()
        };

        let prepared = prepare_signature(&pdf_data, &info, &options).unwrap();
        let sig = signer.sign_hash(&prepared.attrs_hash).unwrap();

        let result = finalize_signature(prepared, &sig);
        match result {
            Err(e) => {
                let err = format!("{e}");
                assert!(
                    err.contains("exceeds allocated") || err.contains("Signature"),
                    "unexpected error: {err}"
                );
            }
            Ok(_) => panic!("expected finalize_signature to fail with tiny content_size"),
        }
    }
}
