//! SVT Document Timestamp Embedding.
//!
//! Bridges the SVT JWT issuance (`svt/issuer.rs`) with PDF document timestamp
//! embedding (`core/doc_timestamp.rs`). An SVT JWT is placed inside a TSTInfo
//! extension (OID `1.2.752.201.5.2`) within a self-signed CMS timestamp token,
//! then embedded as a `/DocTimeStamp` in the PDF via incremental save.
//!
//! ## Architecture
//!
//! The embedding follows the Sweden Connect reference implementation:
//!
//! 1. **TSTInfo with extension**: Build a TSTInfo DER that carries the SVT JWT
//!    as an X.509 extension with OID `1.2.752.201.5.2`.
//! 2. **CMS wrapping**: Wrap the TSTInfo in a CMS `ContentInfo → SignedData`
//!    with content type `id-ct-TSTInfo`.
//! 3. **PDF embedding**: Use the existing DocTimeStamp infrastructure to
//!    prepare a placeholder and inject the CMS token.
//!
//! ## Detection & Extraction
//!
//! - [`is_svt_doc_timestamp`] checks if a CMS token carries the SVT extension.
//! - [`extract_svt_jwt_from_token`] extracts the JWT string from a CMS token.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::CmsVersion;
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::Certificate;

use crate::core::byte_range::ByteRange;
use crate::core::doc_timestamp::{self, DocTimestampOptions};
use crate::crypto::algorithm::DigestAlgorithm;
use crate::crypto::traits::CryptoSigner;
use crate::der_utils;
use crate::error::SvtError;

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// SVT extension OID inside TSTInfo: `1.2.752.201.5.2`
pub const OID_SVT_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.752.201.5.2");

/// SVT timestamp policy OID: `1.2.752.201.2.1`
pub const OID_SVT_TS_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.752.201.2.1");

/// id-ct-TSTInfo OID: `1.2.840.113549.1.9.16.1.4`
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// id-signedData OID: `1.2.840.113549.1.7.2`
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// id-contentType OID: `1.2.840.113549.1.9.3`
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// id-messageDigest OID: `1.2.840.113549.1.9.4`
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for creating an SVT-sealed PDF.
#[derive(Debug, Clone)]
pub struct SvtSealOptions {
    /// Size to reserve for the CMS token in `/Contents` (bytes, not hex chars).
    ///
    /// Must be large enough for: SVT JWT + cert chain + CMS overhead.
    /// Default: computed from JWT + chain size + 2000 bytes overhead.
    pub content_size: Option<usize>,

    /// Signature field name for the timestamp.
    /// Default: "SVTDocTimeStamp"
    pub field_name: String,

    /// Page to attach the annotation to (0-indexed).
    /// Default: 0 (first page)
    pub page: u32,
}

impl Default for SvtSealOptions {
    fn default() -> Self {
        Self {
            content_size: None,
            field_name: "SVTDocTimeStamp".to_string(),
            page: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TSTInfo DER construction
// ---------------------------------------------------------------------------

/// Build a DER-encoded TSTInfo that carries an SVT JWT as an extension.
///
/// The TSTInfo structure:
/// ```text
/// TSTInfo ::= SEQUENCE {
///    version        INTEGER { v1(1) },
///    policy         TSAPolicyId,            -- 1.2.752.201.2.1
///    messageImprint MessageImprint,
///    serialNumber   INTEGER,
///    genTime        GeneralizedTime,
///    extensions [1] IMPLICIT Extensions OPTIONAL  -- SVT JWT here
/// }
/// ```
///
/// # Arguments
///
/// - `svt_jwt`: The signed SVT JWT string to embed.
/// - `message_hash`: The hash of the PDF ByteRange-selected bytes.
/// - `digest_alg`: The digest algorithm used for the hash.
///
/// # Returns
///
/// The DER-encoded TSTInfo bytes.
pub fn build_tst_info_with_svt(
    svt_jwt: &str,
    message_hash: &[u8],
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>, SvtError> {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    // version INTEGER { v1(1) }
    parts.push(der_utils::encode_integer_u64(1));

    // policy TSAPolicyId — OID 1.2.752.201.2.1
    let policy_der = OID_SVT_TS_POLICY
        .to_der()
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to encode policy OID: {e}")))?;
    parts.push(policy_der);

    // messageImprint MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
    let hash_alg_id = AlgorithmIdentifierOwned {
        oid: digest_alg.oid(),
        parameters: None,
    };
    let hash_alg_der = hash_alg_id
        .to_der()
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to encode hash algorithm: {e}")))?;
    let hashed_message = OctetString::new(message_hash.to_vec())
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to create hash octet string: {e}")))?;
    let hashed_message_der = hashed_message
        .to_der()
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to encode hash: {e}")))?;
    let msg_imprint = der_utils::encode_sequence_from_parts(&[&hash_alg_der, &hashed_message_der]);
    parts.push(msg_imprint);

    // serialNumber INTEGER — use current time nanos for uniqueness
    let serial = generate_serial();
    parts.push(der_utils::encode_integer_u64(serial));

    // genTime GeneralizedTime — current UTC time
    let gen_time_der = encode_generalized_time_now()
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to encode genTime: {e}")))?;
    parts.push(gen_time_der);

    // extensions [1] IMPLICIT Extensions
    // Extensions ::= SEQUENCE OF Extension
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    let svt_extension = build_svt_extension(svt_jwt)?;
    let extensions_seq = der_utils::encode_sequence_raw(&svt_extension);
    // Tag as [1] IMPLICIT (replace SEQUENCE tag 0x30 with 0xA1)
    let mut tagged_extensions = extensions_seq;
    tagged_extensions[0] = 0xA1;
    parts.push(tagged_extensions);

    // Assemble the TSTInfo SEQUENCE
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    Ok(der_utils::encode_sequence_raw(&body))
}

/// Build a single SVT Extension DER.
///
/// ```text
/// Extension ::= SEQUENCE {
///    extnID    OBJECT IDENTIFIER,  -- 1.2.752.201.5.2
///    critical  BOOLEAN DEFAULT FALSE, -- omitted (default is false)
///    extnValue OCTET STRING          -- UTF-8 bytes of JWT string
/// }
/// ```
fn build_svt_extension(svt_jwt: &str) -> Result<Vec<u8>, SvtError> {
    let oid_der = OID_SVT_EXTENSION
        .to_der()
        .map_err(|e| SvtError::TstInfoBuild(format!("failed to encode SVT extension OID: {e}")))?;

    // extnValue is OCTET STRING wrapping the raw UTF-8 JWT bytes
    let jwt_bytes = svt_jwt.as_bytes();
    let extn_value = der_utils::encode_tlv(0x04, jwt_bytes);

    Ok(der_utils::encode_sequence_from_parts(&[
        &oid_der,
        &extn_value,
    ]))
}

/// Encode current UTC time as DER GeneralizedTime.
fn encode_generalized_time_now() -> Result<Vec<u8>, String> {
    let now = chrono::Utc::now();
    let time_str = now.format("%Y%m%d%H%M%SZ").to_string();
    // GeneralizedTime tag = 0x18
    Ok(der_utils::encode_tlv(0x18, time_str.as_bytes()))
}

/// Generate a unique serial number for the TSTInfo.
fn generate_serial() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_nanos() as u64
}

// ---------------------------------------------------------------------------
// CMS timestamp token construction
// ---------------------------------------------------------------------------

/// Build a CMS ContentInfo wrapping a SignedData that contains the TSTInfo.
///
/// This creates a self-signed timestamp token (not from an external TSA).
/// The CMS structure:
/// ```text
/// ContentInfo ::= SEQUENCE {
///    contentType  id-signedData,
///    content [0] EXPLICIT SignedData
/// }
/// SignedData ::= SEQUENCE {
///    version          CMSVersion (3),
///    digestAlgorithms SET OF AlgorithmIdentifier,
///    encapContentInfo EncapsulatedContentInfo,  -- id-ct-TSTInfo + TSTInfo
///    certificates [0] IMPLICIT CertificateSet,
///    signerInfos      SET OF SignerInfo
/// }
/// ```
///
/// # Arguments
///
/// - `tst_info_der`: DER-encoded TSTInfo (from [`build_tst_info_with_svt`]).
/// - `signer`: The signing key for the timestamp token.
///
/// # Returns
///
/// DER-encoded CMS ContentInfo bytes.
pub fn build_svt_timestamp_token(
    tst_info_der: &[u8],
    signer: &dyn CryptoSigner,
) -> Result<Vec<u8>, SvtError> {
    // Parse the signer certificate
    let cert_der = signer.certificate_der();
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| SvtError::Embedding(format!("failed to parse signer certificate: {e}")))?;

    // Build SignerIdentifier (IssuerAndSerialNumber)
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });

    // Digest algorithm identifier
    let digest_alg = build_digest_alg_id(signer.digest_algorithm());

    // Signature algorithm identifier
    let sig_alg = build_sig_alg_id(signer)?;

    // Digest algorithm set (just one)
    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms
        .insert(digest_alg.clone())
        .map_err(|e| SvtError::Embedding(format!("failed to build digest algorithm set: {e}")))?;

    // EncapsulatedContentInfo with id-ct-TSTInfo and the TSTInfo as eContent
    let tst_octet = OctetString::new(tst_info_der.to_vec())
        .map_err(|e| SvtError::Embedding(format!("failed to create TSTInfo octet string: {e}")))?;
    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_CT_TST_INFO,
        econtent: Some(
            Any::new(Tag::OctetString, tst_octet.as_bytes().to_vec())
                .map_err(|e| SvtError::Embedding(format!("failed to wrap TSTInfo as Any: {e}")))?,
        ),
    };

    // Build signed attributes
    let signed_attrs = build_timestamp_signed_attrs(tst_info_der, signer)?;

    // Sign the signed attributes
    let attrs_der = signed_attrs
        .to_der()
        .map_err(|e| SvtError::Embedding(format!("failed to DER-encode signed attributes: {e}")))?;
    let attrs_hash = signer.digest_algorithm().digest(&attrs_der);
    let signature_bytes = signer
        .sign_hash(&attrs_hash)
        .map_err(|e| SvtError::Embedding(format!("signing failed: {e}")))?;

    // Build SignerInfo
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg,
        signed_attrs: Some(signed_attrs),
        signature_algorithm: sig_alg,
        signature: OctetString::new(signature_bytes)
            .map_err(|e| SvtError::Embedding(format!("failed to create signature octet: {e}")))?,
        unsigned_attrs: None,
    };

    let mut signer_infos_set = SetOfVec::new();
    signer_infos_set
        .insert(signer_info)
        .map_err(|e| SvtError::Embedding(format!("failed to build signer infos set: {e}")))?;

    // Build certificate set
    let cert_set = build_cert_set(signer)?;

    // Assemble SignedData
    // Version 3 is used for timestamps (encapContentInfo has non-id-data content type)
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms,
        encap_content_info: encap_content_info,
        certificates: Some(cert_set),
        crls: None,
        signer_infos: SignerInfos(signer_infos_set),
    };

    // Wrap in ContentInfo
    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| SvtError::Embedding(format!("failed to DER-encode SignedData: {e}")))?;

    let content = Any::from_der(&signed_data_der)
        .map_err(|e| SvtError::Embedding(format!("failed to re-parse SignedData as Any: {e}")))?;

    let content_info = cms::content_info::ContentInfo {
        content_type: ID_SIGNED_DATA,
        content,
    };

    content_info
        .to_der()
        .map_err(|e| SvtError::Embedding(format!("failed to DER-encode ContentInfo: {e}")))
}

/// Build signed attributes for the timestamp signer info.
///
/// Includes:
/// - `contentType` = id-ct-TSTInfo
/// - `messageDigest` = hash of the TSTInfo DER
fn build_timestamp_signed_attrs(
    tst_info_der: &[u8],
    signer: &dyn CryptoSigner,
) -> Result<SetOfVec<Attribute>, SvtError> {
    let mut attrs: Vec<Attribute> = Vec::new();

    // contentType = id-ct-TSTInfo
    let ct_oid_der = ID_CT_TST_INFO
        .to_der()
        .map_err(|e| SvtError::Embedding(format!("failed to encode id-ct-TSTInfo OID: {e}")))?;
    let ct_value = AttributeValue::from_der(&ct_oid_der)
        .map_err(|e| SvtError::Embedding(format!("failed to parse content-type value: {e}")))?;
    let mut ct_values = SetOfVec::new();
    ct_values
        .insert(ct_value)
        .map_err(|e| SvtError::Embedding(format!("failed to insert content-type: {e}")))?;
    attrs.push(Attribute {
        oid: ID_CONTENT_TYPE,
        values: ct_values,
    });

    // messageDigest = hash of TSTInfo
    let digest = signer.digest_algorithm().digest(tst_info_der);
    let digest_octet = OctetString::new(digest)
        .map_err(|e| SvtError::Embedding(format!("failed to create digest octet: {e}")))?;
    let digest_der = digest_octet
        .to_der()
        .map_err(|e| SvtError::Embedding(format!("failed to encode digest: {e}")))?;
    let md_value = AttributeValue::from_der(&digest_der)
        .map_err(|e| SvtError::Embedding(format!("failed to parse message-digest value: {e}")))?;
    let mut md_values = SetOfVec::new();
    md_values
        .insert(md_value)
        .map_err(|e| SvtError::Embedding(format!("failed to insert message-digest: {e}")))?;
    attrs.push(Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: md_values,
    });

    SetOfVec::try_from(attrs)
        .map_err(|e| SvtError::Embedding(format!("failed to build signed attributes set: {e}")))
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn build_digest_alg_id(alg: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: alg.oid(),
        parameters: None,
    }
}

fn build_sig_alg_id(signer: &dyn CryptoSigner) -> Result<AlgorithmIdentifierOwned, SvtError> {
    use crate::crypto::algorithm::{SignatureAlgorithm, OID_ED25519, OID_RSASSA_PSS};
    use const_oid::db::rfc5912;

    let (oid, parameters) = match (signer.signature_algorithm(), signer.digest_algorithm()) {
        // RSA PKCS#1 v1.5 with SHA-2
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256) => {
            let null_any = Any::new(Tag::Null, Vec::new())
                .map_err(|e| SvtError::Embedding(format!("failed to create NULL Any: {e}")))?;
            (rfc5912::SHA_256_WITH_RSA_ENCRYPTION, Some(null_any))
        }
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha384) => {
            let null_any = Any::new(Tag::Null, Vec::new())
                .map_err(|e| SvtError::Embedding(format!("failed to create NULL Any: {e}")))?;
            (rfc5912::SHA_384_WITH_RSA_ENCRYPTION, Some(null_any))
        }
        (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha512) => {
            let null_any = Any::new(Tag::Null, Vec::new())
                .map_err(|e| SvtError::Embedding(format!("failed to create NULL Any: {e}")))?;
            (rfc5912::SHA_512_WITH_RSA_ENCRYPTION, Some(null_any))
        }
        // RSA PKCS#1 v1.5 with SHA-3 → fall back to RSA-PSS (no combined OIDs exist)
        (SignatureAlgorithm::RsaPkcs1v15, digest) if digest.is_sha3() => {
            let params = crate::cms::builder::rsassa_pss_params_any(digest)
                .map_err(|e| SvtError::Embedding(format!("RSA-PSS params: {e}")))?;
            (OID_RSASSA_PSS, Some(params))
        }
        // RSA-PSS (explicit)
        (SignatureAlgorithm::RsaPss, digest) => {
            let params = crate::cms::builder::rsassa_pss_params_any(digest)
                .map_err(|e| SvtError::Embedding(format!("RSA-PSS params: {e}")))?;
            (OID_RSASSA_PSS, Some(params))
        }
        // ECDSA
        (SignatureAlgorithm::EcdsaP256, _) => (rfc5912::ECDSA_WITH_SHA_256, None),
        (SignatureAlgorithm::EcdsaP384, _) => (rfc5912::ECDSA_WITH_SHA_384, None),
        // Ed25519
        (SignatureAlgorithm::Ed25519, _) => (OID_ED25519, None),
        (alg, digest) => {
            return Err(SvtError::Embedding(format!(
                "unsupported algorithm combination: {alg:?} with {digest:?}"
            )));
        }
    };

    Ok(AlgorithmIdentifierOwned { oid, parameters })
}

fn build_cert_set(signer: &dyn CryptoSigner) -> Result<CertificateSet, SvtError> {
    let mut cert_set = SetOfVec::new();
    for cert_der in signer.certificate_chain_der() {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| SvtError::Embedding(format!("failed to parse chain certificate: {e}")))?;
        cert_set
            .insert(CertificateChoices::Certificate(cert))
            .map_err(|e| {
                SvtError::Embedding(format!("failed to insert certificate into set: {e}"))
            })?;
    }
    Ok(CertificateSet(cert_set))
}

// ---------------------------------------------------------------------------
// High-level PDF embedding
// ---------------------------------------------------------------------------

/// Create an SVT-sealed PDF by embedding an SVT JWT as a DocTimeStamp.
///
/// This is the high-level function that:
/// 1. Prepares the PDF with a DocTimeStamp placeholder (incremental save)
/// 2. Computes the hash of the ByteRange-selected bytes
/// 3. Builds a TSTInfo carrying the SVT JWT as an extension
/// 4. Wraps it in a CMS SignedData timestamp token
/// 5. Injects the token into the `/Contents` placeholder
///
/// # Arguments
///
/// - `pdf_data`: The PDF to seal (may already be signed)
/// - `svt_jwt`: The signed SVT JWT string (from `SvtIssuer::issue()`)
/// - `signer`: The signing key for the self-signed CMS timestamp token
/// - `options`: Optional embedding configuration
///
/// # Returns
///
/// The PDF with the SVT document timestamp appended as an incremental update.
pub fn create_svt_sealed_pdf(
    pdf_data: &[u8],
    svt_jwt: &str,
    signer: &dyn CryptoSigner,
    options: Option<&SvtSealOptions>,
) -> Result<Vec<u8>, SvtError> {
    let defaults = SvtSealOptions::default();
    let opts = options.unwrap_or(&defaults);

    // Compute content size: JWT + cert chain + CMS overhead
    let chain_size: usize = signer.certificate_chain_der().iter().map(|c| c.len()).sum();
    let content_size = opts.content_size.unwrap_or_else(|| {
        svt_jwt.len() + chain_size + 4000 // generous overhead for CMS + TSTInfo + signed attrs
    });

    let ts_opts = DocTimestampOptions {
        content_size,
        field_name: opts.field_name.clone(),
        page: opts.page,
    };

    // Step 1: Prepare PDF with placeholder
    let (output, byte_range) = doc_timestamp::prepare_doc_timestamp(pdf_data, &ts_opts)
        .map_err(|e| SvtError::Embedding(format!("failed to prepare PDF: {e}")))?;

    // Step 2: Compute hash of ByteRange-selected bytes
    let digest_alg = signer.digest_algorithm();
    let data_hash = compute_byte_range_hash(&output, &byte_range, digest_alg)?;

    // Step 3: Build TSTInfo with SVT extension
    let tst_info_der = build_tst_info_with_svt(svt_jwt, &data_hash, digest_alg)?;

    // Step 4: Build CMS timestamp token
    let token_der = build_svt_timestamp_token(&tst_info_der, signer)?;

    log::debug!(
        "SVT seal: JWT={} bytes, TSTInfo={} bytes, CMS token={} bytes, content_size={} bytes",
        svt_jwt.len(),
        tst_info_der.len(),
        token_der.len(),
        content_size,
    );

    if token_der.len() > content_size {
        return Err(SvtError::Embedding(format!(
            "CMS token ({} bytes) exceeds allocated space ({} bytes)",
            token_der.len(),
            content_size,
        )));
    }

    // Step 5: Inject the token
    doc_timestamp::inject_timestamp_token(output, &byte_range, &token_der, content_size)
        .map_err(|e| SvtError::Embedding(format!("failed to inject timestamp token: {e}")))
}

/// Compute the hash of the ByteRange-selected bytes from the prepared PDF.
fn compute_byte_range_hash(
    pdf_data: &[u8],
    byte_range: &ByteRange,
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>, SvtError> {
    let br_values = byte_range.compute(pdf_data.len());

    let range1_start = br_values[0];
    let range1_len = br_values[1];
    let range2_start = br_values[2];
    let range2_len = br_values[3];

    if range1_start + range1_len > pdf_data.len() || range2_start + range2_len > pdf_data.len() {
        return Err(SvtError::Embedding(
            "ByteRange extends beyond PDF data".into(),
        ));
    }

    let mut hasher = digest_alg.new_hasher();
    hasher.update(&pdf_data[range1_start..range1_start + range1_len]);
    hasher.update(&pdf_data[range2_start..range2_start + range2_len]);
    Ok(hasher.finalize())
}

// ---------------------------------------------------------------------------
// SVT detection & extraction
// ---------------------------------------------------------------------------

/// Check if a CMS token is an SVA/SVT document timestamp.
///
/// A CMS token is an SVT doc timestamp if:
/// 1. It is a CMS `ContentInfo` wrapping `SignedData`
/// 2. The `EncapsulatedContentInfo` has content type `id-ct-TSTInfo`
/// 3. The TSTInfo contains an extension with OID `1.2.752.201.5.2`
///
/// # Arguments
///
/// - `cms_der`: The DER-encoded CMS `ContentInfo` bytes (typically from
///   a PDF `/DocTimeStamp` `/Contents` field).
///
/// # Returns
///
/// `true` if the token carries an SVT extension.
pub fn is_svt_doc_timestamp(cms_der: &[u8]) -> bool {
    extract_svt_jwt_from_token(cms_der).is_ok()
}

/// Extract the SVT JWT string from a CMS timestamp token.
///
/// Navigates:
/// ```text
/// ContentInfo → [0] SignedData → encapContentInfo
///   → [0] eContent OCTET STRING → TSTInfo SEQUENCE
///   → extensions [1] IMPLICIT → SEQUENCE OF Extension
///   → Extension with OID 1.2.752.201.5.2 → extnValue OCTET STRING → UTF-8 string
/// ```
///
/// # Arguments
///
/// - `cms_der`: The DER-encoded CMS `ContentInfo` bytes.
///
/// # Returns
///
/// The SVT JWT string, or an error if the token doesn't carry an SVT.
pub fn extract_svt_jwt_from_token(cms_der: &[u8]) -> Result<String, SvtError> {
    // Parse ContentInfo SEQUENCE
    let (tag, ci_body) = der_utils::parse_tlv(cms_der)
        .map_err(|e| SvtError::Embedding(format!("failed to parse ContentInfo: {e}")))?;
    if tag != 0x30 {
        return Err(SvtError::Embedding("ContentInfo: expected SEQUENCE".into()));
    }

    // contentType OID — should be id-signedData
    let (oid_tag, oid_body, ci_rest) = der_utils::parse_tlv_with_rest(&ci_body)
        .map_err(|e| SvtError::Embedding(format!("failed to parse contentType: {e}")))?;
    if oid_tag != 0x06 {
        return Err(SvtError::Embedding(format!(
            "expected OID tag 0x06, got 0x{oid_tag:02x}"
        )));
    }
    // Verify it's id-signedData
    let ct_oid = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, &oid_body))
        .map_err(|e| SvtError::Embedding(format!("invalid contentType OID: {e}")))?;
    if ct_oid != ID_SIGNED_DATA {
        return Err(SvtError::Embedding(format!(
            "contentType is not id-signedData: {ct_oid}"
        )));
    }

    // content [0] EXPLICIT — the SignedData
    let (ctx_tag, sd_inner, _) = der_utils::parse_tlv_with_rest(ci_rest)
        .map_err(|e| SvtError::Embedding(format!("failed to parse content [0]: {e}")))?;
    if ctx_tag != 0xA0 {
        return Err(SvtError::Embedding(format!(
            "expected [0] EXPLICIT tag 0xA0, got 0x{ctx_tag:02x}"
        )));
    }

    // SignedData SEQUENCE
    let (sd_tag, sd_body) = der_utils::parse_tlv(&sd_inner)
        .map_err(|e| SvtError::Embedding(format!("failed to parse SignedData: {e}")))?;
    if sd_tag != 0x30 {
        return Err(SvtError::Embedding("SignedData: expected SEQUENCE".into()));
    }

    // version INTEGER
    let (_ver_tag, _ver_body, sd_rest) = der_utils::parse_tlv_with_rest(&sd_body)
        .map_err(|e| SvtError::Embedding(format!("failed to parse SD version: {e}")))?;

    // digestAlgorithms SET OF
    let (_da_tag, _da_body, sd_rest2) = der_utils::parse_tlv_with_rest(sd_rest)
        .map_err(|e| SvtError::Embedding(format!("failed to parse digestAlgorithms: {e}")))?;

    // encapContentInfo SEQUENCE
    let (_eci_tag, eci_body, _sd_rest3) = der_utils::parse_tlv_with_rest(sd_rest2)
        .map_err(|e| SvtError::Embedding(format!("failed to parse encapContentInfo: {e}")))?;

    // eContentType OID — should be id-ct-TSTInfo
    let (ect_tag, ect_body, eci_rest) = der_utils::parse_tlv_with_rest(&eci_body)
        .map_err(|e| SvtError::Embedding(format!("failed to parse eContentType: {e}")))?;
    if ect_tag != 0x06 {
        return Err(SvtError::Embedding(format!(
            "expected eContentType OID tag 0x06, got 0x{ect_tag:02x}"
        )));
    }
    let ect_oid = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, &ect_body))
        .map_err(|e| SvtError::Embedding(format!("invalid eContentType OID: {e}")))?;
    if ect_oid != ID_CT_TST_INFO {
        return Err(SvtError::Embedding(format!(
            "eContentType is not id-ct-TSTInfo: {ect_oid}"
        )));
    }

    // eContent [0] EXPLICIT
    let (ec_tag, ec_inner, _) = der_utils::parse_tlv_with_rest(eci_rest)
        .map_err(|e| SvtError::Embedding(format!("failed to parse eContent [0]: {e}")))?;
    if ec_tag != 0xA0 {
        return Err(SvtError::Embedding(format!(
            "expected eContent [0] tag 0xA0, got 0x{ec_tag:02x}"
        )));
    }

    // OCTET STRING containing TSTInfo
    let (os_tag, tst_info_der, _) = der_utils::parse_tlv_with_rest(&ec_inner)
        .map_err(|e| SvtError::Embedding(format!("failed to parse eContent OCTET STRING: {e}")))?;
    if os_tag != 0x04 {
        return Err(SvtError::Embedding(format!(
            "expected OCTET STRING 0x04, got 0x{os_tag:02x}"
        )));
    }

    // Parse TSTInfo SEQUENCE
    let (tst_tag, tst_body) = der_utils::parse_tlv(&tst_info_der)
        .map_err(|e| SvtError::Embedding(format!("failed to parse TSTInfo SEQUENCE: {e}")))?;
    if tst_tag != 0x30 {
        return Err(SvtError::Embedding("TSTInfo: expected SEQUENCE".into()));
    }

    // Walk through TSTInfo fields to find extensions [1] IMPLICIT (tag 0xA1)
    let extensions_body = find_tst_info_extensions(&tst_body)?;

    // extensions is SEQUENCE OF Extension — iterate to find OID 1.2.752.201.5.2
    extract_jwt_from_extensions(&extensions_body)
}

/// Walk the TSTInfo body to find the extensions [1] IMPLICIT field.
fn find_tst_info_extensions(tst_body: &[u8]) -> Result<Vec<u8>, SvtError> {
    let mut pos = tst_body;
    while !pos.is_empty() {
        let (tag, body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| SvtError::Embedding(format!("TSTInfo field parse error: {e}")))?;
        if tag == 0xA1 {
            // Found extensions [1] IMPLICIT
            return Ok(body.to_vec());
        }
        pos = rest;
    }
    Err(SvtError::Embedding(
        "no extensions [1] found in TSTInfo".into(),
    ))
}

/// Iterate over extensions to find the SVT extension and extract the JWT.
fn extract_jwt_from_extensions(extensions_body: &[u8]) -> Result<String, SvtError> {
    let svt_oid_der = OID_SVT_EXTENSION.to_der().map_err(|e| {
        SvtError::Embedding(format!("failed to encode SVT OID for comparison: {e}"))
    })?;

    let mut pos: &[u8] = extensions_body;
    while !pos.is_empty() {
        let (ext_tag, ext_body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| SvtError::Embedding(format!("Extension parse error: {e}")))?;

        if ext_tag == 0x30 {
            // Extension SEQUENCE — first element is OID
            if let Ok((oid_tag, oid_body, ext_rest)) = der_utils::parse_tlv_with_rest(&ext_body) {
                if oid_tag == 0x06 {
                    let this_oid_der = der_utils::encode_tlv(0x06, &oid_body);
                    if this_oid_der == svt_oid_der {
                        // Found SVT extension — next is either BOOLEAN (critical) or OCTET STRING (extnValue)
                        return extract_jwt_value(ext_rest);
                    }
                }
            }
        }
        pos = rest;
    }

    Err(SvtError::Embedding(
        "SVT extension OID 1.2.752.201.5.2 not found in TSTInfo extensions".into(),
    ))
}

/// Extract the JWT string from the extension value fields (after the OID).
///
/// The remaining fields after the OID are:
/// - Optional: BOOLEAN (critical) — DEFAULT FALSE so typically absent
/// - Required: OCTET STRING (extnValue) containing the JWT UTF-8 bytes
fn extract_jwt_value(ext_rest: &[u8]) -> Result<String, SvtError> {
    let mut pos = ext_rest;
    while !pos.is_empty() {
        let (tag, body, rest) = der_utils::parse_tlv_with_rest(pos)
            .map_err(|e| SvtError::Embedding(format!("extnValue parse error: {e}")))?;
        match tag {
            0x01 => {
                // BOOLEAN (critical) — skip
                pos = rest;
            }
            0x04 => {
                // OCTET STRING — this is the JWT bytes
                let jwt = String::from_utf8(body.to_vec())
                    .map_err(|e| SvtError::Embedding(format!("SVT JWT is not valid UTF-8: {e}")))?;
                return Ok(jwt);
            }
            _ => {
                pos = rest;
            }
        }
    }
    Err(SvtError::Embedding(
        "no OCTET STRING extnValue found in SVT extension".into(),
    ))
}

/// Estimate the content size needed for an SVT timestamp token.
///
/// This is useful for pre-allocating the `/Contents` placeholder.
///
/// # Arguments
///
/// - `svt_jwt`: The SVT JWT string.
/// - `signer`: The signer that will sign the CMS token.
///
/// # Returns
///
/// A conservative size estimate in bytes.
pub fn estimate_svt_token_size(svt_jwt: &str, signer: &dyn CryptoSigner) -> usize {
    let jwt_len = svt_jwt.len();
    let chain_size: usize = signer.certificate_chain_der().iter().map(|c| c.len()).sum();
    // TSTInfo overhead: ~100 bytes for version, policy, messageImprint, serialNumber, genTime
    // Extension overhead: ~20 bytes for OID, tag, length
    // CMS overhead: ~500 bytes for SignedData, SignerInfo, signed attrs
    // Signature: up to 512 bytes for RSA
    jwt_len + chain_size + 100 + 20 + 500 + 512 + 256 // ~1388 bytes overhead
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_svt_extension() {
        let jwt = "eyJhbGciOiJSUzI1NiJ9.test.signature";
        let ext_der = build_svt_extension(jwt).unwrap();

        // Should be a SEQUENCE
        let (tag, body) = der_utils::parse_tlv(&ext_der).unwrap();
        assert_eq!(tag, 0x30, "Extension should be a SEQUENCE");

        // First element: OID
        let (oid_tag, oid_body, rest) = der_utils::parse_tlv_with_rest(&body).unwrap();
        assert_eq!(oid_tag, 0x06, "First element should be OID");
        let oid = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, &oid_body)).unwrap();
        assert_eq!(oid, OID_SVT_EXTENSION);

        // Second element: OCTET STRING containing JWT
        let (os_tag, os_body, _) = der_utils::parse_tlv_with_rest(rest).unwrap();
        assert_eq!(os_tag, 0x04, "Second element should be OCTET STRING");
        let extracted = String::from_utf8(os_body.to_vec()).unwrap();
        assert_eq!(extracted, jwt);
    }

    #[test]
    fn test_build_tst_info_with_svt() {
        let jwt = "eyJhbGciOiJSUzI1NiJ9.test_payload.test_sig";
        let hash = vec![0xAA; 32]; // SHA-256 hash
        let tst_der = build_tst_info_with_svt(jwt, &hash, DigestAlgorithm::Sha256).unwrap();

        // Should be a SEQUENCE
        let (tag, body) = der_utils::parse_tlv(&tst_der).unwrap();
        assert_eq!(tag, 0x30, "TSTInfo should be a SEQUENCE");

        // Walk the fields
        let mut pos = &body[..];
        let mut field_count = 0;
        let mut found_extensions = false;

        while !pos.is_empty() {
            let (ftag, _fbody, rest) = der_utils::parse_tlv_with_rest(pos).unwrap();
            field_count += 1;
            if ftag == 0xA1 {
                found_extensions = true;
            }
            pos = rest;
        }

        assert!(field_count >= 5, "TSTInfo should have at least 5 fields");
        assert!(found_extensions, "TSTInfo should have extensions [1]");
    }

    #[test]
    fn test_encode_generalized_time() {
        let gt = encode_generalized_time_now().unwrap();
        // Should be tag 0x18 (GeneralizedTime)
        assert_eq!(gt[0], 0x18);
        // The body should be 15 bytes: YYYYMMDDHHMMSSZ
        let (tag, body) = der_utils::parse_tlv(&gt).unwrap();
        assert_eq!(tag, 0x18);
        assert_eq!(body.len(), 15, "GeneralizedTime should be 15 bytes");
        assert_eq!(body.last(), Some(&b'Z'), "Should end with Z");
    }

    #[test]
    fn test_svt_extension_roundtrip() {
        let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        let hash = vec![0xBB; 32];
        let tst_der = build_tst_info_with_svt(jwt, &hash, DigestAlgorithm::Sha256).unwrap();

        // Parse the TSTInfo to find extensions
        let (_, tst_body) = der_utils::parse_tlv(&tst_der).unwrap();
        let ext_body = find_tst_info_extensions(&tst_body).unwrap();

        // Extract JWT from extensions
        let extracted = extract_jwt_from_extensions(&ext_body).unwrap();
        assert_eq!(extracted, jwt);
    }

    #[test]
    fn test_build_and_detect_svt_token() {
        // This test requires the test fixture PKCS#12 file
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        if !std::path::Path::new(p12_path).exists() {
            eprintln!("Skipping test: signer.p12 not found (run gen-test-fixtures.sh)");
            return;
        }

        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let jwt = "eyJhbGciOiJSUzI1NiJ9.test_payload.test_signature";
        let hash = vec![0xCC; 32];

        // Build TSTInfo
        let tst_der = build_tst_info_with_svt(jwt, &hash, DigestAlgorithm::Sha256).unwrap();

        // Build CMS token
        let token_der = build_svt_timestamp_token(&tst_der, &signer).unwrap();

        // Detect SVT
        assert!(is_svt_doc_timestamp(&token_der));

        // Extract JWT
        let extracted = extract_svt_jwt_from_token(&token_der).unwrap();
        assert_eq!(extracted, jwt);
    }

    #[test]
    fn test_non_svt_token_not_detected() {
        // A minimal non-SVT CMS structure should not be detected
        // Just test with garbage data
        assert!(!is_svt_doc_timestamp(&[0x30, 0x00]));
        assert!(!is_svt_doc_timestamp(&[]));
        assert!(!is_svt_doc_timestamp(&[0xFF]));
    }

    #[test]
    fn test_estimate_svt_token_size() {
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        if !std::path::Path::new(p12_path).exists() {
            eprintln!("Skipping test: signer.p12 not found (run gen-test-fixtures.sh)");
            return;
        }

        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let jwt = "eyJhbGciOiJSUzI1NiJ9.a_somewhat_realistic_jwt_payload_that_is_longer.signature_value_here";
        let estimate = estimate_svt_token_size(jwt, &signer);

        // Should be reasonable
        assert!(estimate > jwt.len(), "estimate should be larger than JWT");
        assert!(estimate < 100_000, "estimate should not be absurdly large");
    }

    #[test]
    fn test_create_svt_sealed_pdf() {
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        if !std::path::Path::new(p12_path).exists() {
            eprintln!("Skipping test: signer.p12 not found (run gen-test-fixtures.sh)");
            return;
        }

        let pdf_data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ));

        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let jwt = "eyJhbGciOiJSUzI1NiJ9.test_svt_payload.test_svt_signature";

        let options = SvtSealOptions {
            content_size: Some(16384),
            field_name: "TestSVTSeal".to_string(),
            page: 0,
        };

        let sealed_pdf = create_svt_sealed_pdf(pdf_data, jwt, &signer, Some(&options)).unwrap();

        // Sealed PDF should be larger
        assert!(sealed_pdf.len() > pdf_data.len());

        // Should contain DocTimeStamp markers
        let as_str = String::from_utf8_lossy(&sealed_pdf);
        assert!(as_str.contains("DocTimeStamp"));
        assert!(as_str.contains("ETSI.RFC3161"));
    }

    #[test]
    fn test_svt_seal_options_default() {
        let opts = SvtSealOptions::default();
        assert_eq!(opts.field_name, "SVTDocTimeStamp");
        assert_eq!(opts.page, 0);
        assert!(opts.content_size.is_none());
    }
}
