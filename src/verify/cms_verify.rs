//! CMS SignedData cryptographic verification.
//!
//! Parses a CMS `SignedData` structure (RFC 5652) from a PDF signature's
//! `/Contents` value, verifies the cryptographic signature over the signed
//! attributes, and checks that the `messageDigest` attribute matches the
//! hash of the PDF byte ranges.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::db::rfc5911;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use x509_cert::Certificate;

use chrono::{DateTime, Utc};

use crate::cms::builder::ID_AA_CMS_ALGORITHM_PROTECTION;
use crate::crypto::algorithm::DigestAlgorithm;
use crate::error::VerifyError;

/// Result of CMS Algorithm Protection attribute extraction.
#[derive(Debug, Clone)]
pub struct CmsAlgorithmProtection {
    /// The digest algorithm OID declared inside the CMS-AP attribute
    pub digest_algorithm: ObjectIdentifier,
    /// The signature algorithm OID declared inside the CMS-AP attribute
    pub signature_algorithm: ObjectIdentifier,
}

/// OID for `id-aa-signatureTimeStampToken` (1.2.840.113549.1.9.16.2.14).
///
/// This identifies the unsigned attribute that carries an RFC 3161
/// timestamp token proving the signature existed at a specific time.
pub const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Result of CMS cryptographic verification.
#[derive(Debug)]
pub struct CmsVerifyResult {
    /// Whether the CMS signature is cryptographically valid
    pub signature_valid: bool,
    /// Whether the messageDigest attribute matches the provided data hash
    pub digest_matches: bool,
    /// The signer's certificate extracted from the CMS certificates set
    pub signer_certificate: Option<Certificate>,
    /// All certificates embedded in the CMS structure (for chain building)
    pub embedded_certificates: Vec<Certificate>,
    /// The digest algorithm used
    pub digest_algorithm: Option<DigestAlgorithm>,
    /// Whether the CMS Algorithm Protection attribute was present and consistent
    pub algorithm_protection_ok: bool,
    /// The parsed CMS-AP data, if present
    pub algorithm_protection: Option<CmsAlgorithmProtection>,
    /// CMS signing-time from the signingTime signed attribute (OID 1.2.840.113549.1.9.5).
    ///
    /// This is the time the signer claims to have produced the signature,
    /// as embedded in the CMS signed attributes. Distinct from the PDF `/M`
    /// dictionary field (which is unsigned and trivially forgeable).
    pub cms_signing_time: Option<DateTime<Utc>>,
    /// CMS signing-time from the signingTime unsigned attribute (OID 1.2.840.113549.1.9.5).
    ///
    /// Some signing workflows place `signingTime` in unsigned attributes instead of
    /// (or in addition to) signed attributes. In PAdES mode the signed copy is always
    /// omitted, so this may be the only CMS-level timestamp available.
    ///
    /// `None` if the attribute is absent from unsigned attributes.
    pub cms_signing_time_unsigned: Option<DateTime<Utc>>,
    /// Whether the ESS signingCertificateV2 attribute (RFC 5035) matches the signer cert.
    ///
    /// `Some(true)` — attribute present and cert hash matches.
    /// `Some(false)` — attribute present but cert hash does NOT match (certificate
    ///   substitution attack or corrupted attribute).
    /// `None` — attribute not present (expected for traditional PKCS#7 / CMS,
    ///   but REQUIRED for PAdES).
    pub ess_cert_id_match: Option<bool>,
    /// Raw DER of the signature timestamp token (`id-aa-signatureTimeStampToken`,
    /// OID 1.2.840.113549.1.9.16.2.14) from CMS unsigned attributes.
    ///
    /// This is the RFC 3161 timestamp token embedded by the signing application
    /// to prove that the signature existed at the timestamp's time. The caller
    /// is responsible for verifying the token (TSA signature, TSTInfo hash match).
    /// `None` if no signature timestamp was embedded.
    pub signature_timestamp_token: Option<Vec<u8>>,
    /// Raw signature value bytes from the CMS SignerInfo.
    ///
    /// These are the bytes that an RFC 3161 signature timestamp covers
    /// (the timestamp's messageImprint is the hash of these bytes).
    /// Needed for verifying the signature timestamp token.
    pub signature_value: Vec<u8>,
    /// Hash of the DER-encoded signed attributes (Data To Be Signed Representation).
    ///
    /// This is the DTBSR — the hash that is actually signed by the signer's private key.
    /// The signed attributes are re-encoded as a SET OF (tag 0x31) before hashing.
    /// Needed for ETSI TS 119 102-2 `<SignatureIdentifier>`.
    pub dtbsr_hash: Vec<u8>,
    /// The signature algorithm OID from the CMS SignerInfo.
    ///
    /// Needed for ETSI TS 119 102-2 `<ds:SignatureMethod>` in reports.
    pub signature_algorithm_oid: Option<String>,
    /// Human-readable issues
    pub issues: Vec<String>,
}

/// Verify a CMS SignedData structure against the provided data hash.
///
/// This performs the core cryptographic verification per RFC 5652 §5.6:
/// 1. Parse the DER-encoded ContentInfo/SignedData
/// 2. Extract the signer info (first signer — PDF signatures have exactly one)
/// 3. Extract the messageDigest signed attribute and compare to `data_hash`
/// 4. Re-encode the signed attributes as a SET OF for signature verification
/// 5. Verify the signature over the signed attributes using the signer's public key
///
/// `cms_bytes` is the raw DER from the PDF /Contents field.
/// `data_hash` is the hash of the byte-range-selected PDF data.
pub fn verify_cms(cms_bytes: &[u8], data_hash: &[u8]) -> Result<CmsVerifyResult, VerifyError> {
    let mut issues = Vec::new();

    // Step 1: Parse ContentInfo
    let content_info = ContentInfo::from_der(cms_bytes).map_err(|e| {
        VerifyError::CmsVerification(format!("failed to parse CMS ContentInfo: {e}"))
    })?;

    if content_info.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(VerifyError::CmsVerification(format!(
            "unexpected content type: {} (expected signedData)",
            content_info.content_type
        )));
    }

    // Step 2: Parse SignedData
    let sd_bytes = content_info.content.to_der().map_err(|e| {
        VerifyError::CmsVerification(format!("failed to re-encode SignedData content: {e}"))
    })?;
    let signed_data = SignedData::from_der(&sd_bytes)
        .map_err(|e| VerifyError::CmsVerification(format!("failed to parse SignedData: {e}")))?;

    // Step 3: Extract all embedded certificates
    let embedded_certificates = extract_certificates(&signed_data);

    // Step 4: Get the first (and typically only) SignerInfo
    let signer_infos: Vec<&SignerInfo> = signed_data.signer_infos.0.iter().collect();
    if signer_infos.is_empty() {
        return Err(VerifyError::CmsVerification(
            "no signer infos in SignedData".to_string(),
        ));
    }
    if signer_infos.len() > 1 {
        issues.push(format!(
            "multiple signer infos found ({}); using first",
            signer_infos.len()
        ));
    }
    let signer_info = signer_infos[0];

    // Step 5: Determine digest algorithm from SignerInfo
    let digest_algorithm = oid_to_digest_algorithm(&signer_info.digest_alg.oid);

    // Step 6: Find the signer's certificate
    let signer_certificate = find_signer_certificate(signer_info, &embedded_certificates);
    if signer_certificate.is_none() {
        issues.push("signer certificate not found in embedded certificates".to_string());
    }

    // Step 7: Check messageDigest attribute
    let digest_matches = match extract_message_digest(signer_info) {
        Some(cms_digest) => {
            if cms_digest == data_hash {
                true
            } else {
                issues.push("messageDigest does not match data hash".to_string());
                false
            }
        }
        None => {
            issues.push("messageDigest attribute not found in signed attributes".to_string());
            false
        }
    };

    // Step 8: Check CMS Algorithm Protection attribute (RFC 6211)
    let (algorithm_protection_ok, algorithm_protection) =
        check_cms_algorithm_protection(signer_info, &mut issues);

    // Step 8b: Extract CMS signingTime from signed attributes
    let cms_signing_time = extract_signing_time(signer_info);

    // Step 8b2: Extract CMS signingTime from unsigned attributes
    let cms_signing_time_unsigned = extract_signing_time_unsigned(signer_info);

    // Step 8c: Verify ESSCertIDv2 (signingCertificateV2) if present
    let ess_cert_id_match = verify_ess_cert_id_v2(signer_info, &signer_certificate, &mut issues);

    // Step 8d: Extract signature timestamp token from unsigned attributes
    let signature_timestamp_token = extract_signature_timestamp_token(signer_info);

    // Step 8e: Extract raw signature value bytes (needed for timestamp verification)
    let signature_value = signer_info.signature.as_bytes().to_vec();

    // Step 8f: Compute DTBSR hash (hash of DER-encoded signed attributes as SET OF)
    let dtbsr_hash = compute_dtbsr_hash(signer_info, &digest_algorithm);

    // Step 8g: Extract signature algorithm OID
    let signature_algorithm_oid = Some(signer_info.signature_algorithm.oid.to_string());

    // Step 9: Verify the cryptographic signature
    let signature_valid = if let Some(ref cert) = signer_certificate {
        match verify_signer_info_signature(signer_info, cert, cms_bytes) {
            Ok(()) => true,
            Err(e) => {
                issues.push(format!("signature verification failed: {e}"));
                false
            }
        }
    } else {
        issues.push("cannot verify signature: signer certificate not found".to_string());
        false
    };

    Ok(CmsVerifyResult {
        signature_valid,
        digest_matches,
        signer_certificate,
        embedded_certificates,
        digest_algorithm,
        algorithm_protection_ok,
        algorithm_protection,
        cms_signing_time,
        cms_signing_time_unsigned,
        ess_cert_id_match,
        signature_timestamp_token,
        signature_value,
        dtbsr_hash,
        signature_algorithm_oid,
        issues,
    })
}

/// Extract all certificates from a SignedData's certificate set.
fn extract_certificates(signed_data: &SignedData) -> Vec<Certificate> {
    let mut certs = Vec::new();
    if let Some(ref cert_set) = signed_data.certificates {
        for choice in cert_set.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                certs.push(cert.clone());
            }
        }
    }
    certs
}

/// Find the signer's certificate by matching the SignerIdentifier.
fn find_signer_certificate(
    signer_info: &SignerInfo,
    certificates: &[Certificate],
) -> Option<Certificate> {
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certificates
            .iter()
            .find(|cert| {
                cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Find by Subject Key Identifier extension
            certificates
                .iter()
                .find(|cert| {
                    if let Some(ref extensions) = cert.tbs_certificate.extensions {
                        for ext in extensions.iter() {
                            if ext.extn_id == const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER {
                                if let Ok(ski_val) =
                                    OctetString::from_der(ext.extn_value.as_bytes())
                                {
                                    return ski_val.as_bytes() == ski.0.as_bytes();
                                }
                            }
                        }
                    }
                    false
                })
                .cloned()
        }
    }
}

/// Extract the messageDigest value from signed attributes.
fn extract_message_digest(signer_info: &SignerInfo) -> Option<Vec<u8>> {
    let signed_attrs = signer_info.signed_attrs.as_ref()?;
    for attr in signed_attrs.iter() {
        if attr.oid == rfc5911::ID_MESSAGE_DIGEST {
            // The attribute value is an OCTET STRING
            if let Some(value) = attr.values.iter().next() {
                let value_der = value.to_der().ok()?;
                let octet_string = OctetString::from_der(&value_der).ok()?;
                return Some(octet_string.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Extract the CMS `signingTime` attribute value from signed attributes.
///
/// Per RFC 5652 §11.3, the signingTime attribute (OID 1.2.840.113549.1.9.5)
/// contains either a UTCTime or GeneralizedTime value representing when
/// the signer claims to have performed the signing.
///
/// Returns `None` if the attribute is absent or cannot be parsed.
fn extract_signing_time(signer_info: &SignerInfo) -> Option<DateTime<Utc>> {
    let signed_attrs = signer_info.signed_attrs.as_ref()?;
    for attr in signed_attrs.iter() {
        if attr.oid == rfc5911::ID_SIGNING_TIME {
            if let Some(value) = attr.values.iter().next() {
                let value_der = value.to_der().ok()?;
                return parse_cms_time(&value_der);
            }
        }
    }
    None
}

/// Extract the CMS `signingTime` attribute value from unsigned attributes.
///
/// Some signing workflows place `signingTime` in unsigned attributes (e.g.,
/// when `SigningTimePlacement::Unsigned` or `Both` is used). In PAdES mode,
/// `signingTime` is omitted from signed attributes per ETSI EN 319 122-1,
/// so the unsigned copy may be the only CMS-level timestamp.
///
/// Returns `None` if the attribute is absent from unsigned attributes or cannot be parsed.
fn extract_signing_time_unsigned(signer_info: &SignerInfo) -> Option<DateTime<Utc>> {
    let unsigned_attrs = signer_info.unsigned_attrs.as_ref()?;
    for attr in unsigned_attrs.iter() {
        if attr.oid == rfc5911::ID_SIGNING_TIME {
            if let Some(value) = attr.values.iter().next() {
                let value_der = value.to_der().ok()?;
                return parse_cms_time(&value_der);
            }
        }
    }
    None
}

/// Parse a DER-encoded CMS time value (UTCTime or GeneralizedTime)
/// into a `DateTime<Utc>`.
fn parse_cms_time(der: &[u8]) -> Option<DateTime<Utc>> {
    if der.is_empty() {
        return None;
    }

    let tag = der[0];
    match tag {
        // UTCTime (tag 0x17)
        0x17 => {
            let utc_time = der::asn1::UtcTime::from_der(der).ok()?;
            let dt = utc_time.to_date_time();
            der_datetime_to_chrono(&dt)
        }
        // GeneralizedTime (tag 0x18)
        0x18 => {
            let gen_time = der::asn1::GeneralizedTime::from_der(der).ok()?;
            let dt = gen_time.to_date_time();
            der_datetime_to_chrono(&dt)
        }
        _ => None,
    }
}

/// Convert a `der::DateTime` to `chrono::DateTime<Utc>`.
fn der_datetime_to_chrono(dt: &der::DateTime) -> Option<DateTime<Utc>> {
    let date =
        chrono::NaiveDate::from_ymd_opt(dt.year() as i32, dt.month() as u32, dt.day() as u32)?;
    let time = chrono::NaiveTime::from_hms_opt(
        dt.hour() as u32,
        dt.minutes() as u32,
        dt.seconds() as u32,
    )?;
    let naive = chrono::NaiveDateTime::new(date, time);
    Some(naive.and_utc())
}

/// Verify the ESS `signingCertificateV2` attribute (RFC 5035) against the signer certificate.
///
/// PAdES signatures MUST include this attribute binding the signer certificate
/// to the signature, preventing certificate substitution attacks. The attribute
/// contains a hash of the signer's certificate which we recompute and compare.
///
/// Returns:
/// - `Some(true)` — attribute present, hash matches the signer certificate
/// - `Some(false)` — attribute present but hash does NOT match
/// - `None` — attribute not present
fn verify_ess_cert_id_v2(
    signer_info: &SignerInfo,
    signer_cert: &Option<Certificate>,
    issues: &mut Vec<String>,
) -> Option<bool> {
    let signed_attrs = signer_info.signed_attrs.as_ref()?;

    // Find the signingCertificateV2 attribute
    let mut attr_value = None;
    for attr in signed_attrs.iter() {
        if attr.oid == rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2 {
            if let Some(value) = attr.values.iter().next() {
                attr_value = Some(value.to_der().ok()?);
            }
        }
    }

    let attr_der = attr_value?; // Return None if attribute not present

    // Parse: SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
    let (hash_alg, cert_hash) = match parse_ess_cert_id_v2(&attr_der) {
        Some(result) => result,
        None => {
            issues.push("signingCertificateV2 attribute present but malformed".to_string());
            return Some(false);
        }
    };

    // If no signer cert was found, we can't verify
    let cert = match signer_cert {
        Some(c) => c,
        None => {
            issues.push(
                "signingCertificateV2 present but signer certificate not found for verification"
                    .to_string(),
            );
            return Some(false);
        }
    };

    // Determine digest algorithm from the ESSCertIDv2 hashAlgorithm field
    let digest_alg = match hash_alg {
        Some(oid) => match oid_to_digest_algorithm(&oid) {
            Some(alg) => alg,
            None => {
                issues.push(format!(
                    "signingCertificateV2 uses unsupported hash algorithm: {oid}"
                ));
                return Some(false);
            }
        },
        // Default is SHA-256 per RFC 5035
        None => DigestAlgorithm::Sha256,
    };

    // Recompute the hash over the signer certificate's DER encoding
    let cert_der = match cert.to_der() {
        Ok(d) => d,
        Err(e) => {
            issues.push(format!(
                "failed to DER-encode signer certificate for ESSCertIDv2 check: {e}"
            ));
            return Some(false);
        }
    };
    let computed_hash = digest_alg.digest(&cert_der);

    if computed_hash == cert_hash {
        Some(true)
    } else {
        issues.push("signingCertificateV2 cert hash does NOT match signer certificate — possible certificate substitution".to_string());
        Some(false)
    }
}

/// Parse an ESSCertIDv2 from a DER-encoded `SigningCertificateV2` attribute value.
///
/// Returns `(hash_algorithm_oid, cert_hash_bytes)` for the first ESSCertIDv2 entry.
/// The hash algorithm OID is `None` when the DEFAULT (SHA-256) is used and omitted.
///
/// ASN.1 structure:
/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs SEQUENCE OF ESSCertIDv2,
///     policies SEQUENCE OF PolicyInformation OPTIONAL
/// }
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///     certHash Hash (OCTET STRING),
///     issuerSerial IssuerSerial OPTIONAL
/// }
/// ```
fn parse_ess_cert_id_v2(der: &[u8]) -> Option<(Option<ObjectIdentifier>, Vec<u8>)> {
    // Outer: SigningCertificateV2 SEQUENCE
    if der.is_empty() || der[0] != 0x30 {
        return None;
    }
    let (sc_offset, _sc_len) = parse_der_tl(der)?;
    let sc_content = &der[sc_offset..];

    // First element: certs SEQUENCE OF ESSCertIDv2
    if sc_content.is_empty() || sc_content[0] != 0x30 {
        return None;
    }
    let (certs_offset, certs_len) = parse_der_tl(sc_content)?;
    let certs_content = &sc_content[certs_offset..certs_offset + certs_len];

    // First ESSCertIDv2 in the SEQUENCE OF
    if certs_content.is_empty() || certs_content[0] != 0x30 {
        return None;
    }
    let (ess_offset, ess_len) = parse_der_tl(certs_content)?;
    let ess_content = &certs_content[ess_offset..ess_offset + ess_len];

    // Parse elements of ESSCertIDv2
    if ess_content.is_empty() {
        return None;
    }

    let mut pos = 0;
    let mut hash_alg_oid: Option<ObjectIdentifier> = None;
    let mut cert_hash: Option<Vec<u8>> = None;

    // First element could be either:
    // - AlgorithmIdentifier (SEQUENCE, tag 0x30) — hashAlgorithm
    // - OCTET STRING (tag 0x04) — certHash (when hashAlgorithm is DEFAULT/omitted)
    while pos < ess_content.len() {
        let tag = ess_content[pos];
        let (tl_len, elem_len) = parse_der_tl(&ess_content[pos..])?;
        let elem_total = tl_len + elem_len;

        match tag {
            0x30 if hash_alg_oid.is_none() && cert_hash.is_none() => {
                // AlgorithmIdentifier SEQUENCE — extract the OID
                let alg_der = &ess_content[pos..pos + elem_total];
                hash_alg_oid = extract_first_oid_from_alg_id(alg_der);
            }
            0x04 if cert_hash.is_none() => {
                // OCTET STRING — certHash
                let hash_bytes = &ess_content[pos + tl_len..pos + elem_total];
                cert_hash = Some(hash_bytes.to_vec());
            }
            _ => {
                // issuerSerial or other — skip
            }
        }

        pos += elem_total;
    }

    let hash = cert_hash?;
    Some((hash_alg_oid, hash))
}

/// Result of verifying a signature timestamp token.
#[derive(Debug)]
pub struct TimestampVerifyResult {
    /// The verified timestamp (genTime from TSTInfo).
    pub gen_time: DateTime<Utc>,
    /// Whether the TSA's CMS signature is cryptographically valid.
    pub tsa_signature_valid: bool,
    /// Whether the messageImprint hash matches the expected signature value hash.
    pub message_imprint_valid: bool,
    /// The TSA signer's certificate subject, if extracted.
    pub tsa_signer_name: Option<String>,
    /// Whether the TSA certificate chain is trusted.
    pub tsa_chain_trusted: bool,
    /// The hash algorithm used in the TSTInfo messageImprint.
    ///
    /// This is useful for callers that need to re-hash data with the correct
    /// algorithm when the initially provided hash used a different algorithm.
    /// `None` if the TSTInfo could not be parsed.
    pub tst_hash_algorithm: Option<DigestAlgorithm>,
    /// Human-readable issues encountered during verification.
    pub issues: Vec<String>,
}

/// Verify a signature timestamp token (RFC 3161) embedded in CMS unsigned attributes.
///
/// This performs full verification of the timestamp token:
/// 1. Parse the CMS ContentInfo/SignedData wrapping the timestamp
/// 2. Verify the TSA's CMS signature over the signed attributes
/// 3. Verify the TSA's certificate chain against the TSA trust store
/// 4. Extract and parse TSTInfo from the encapsulated content
/// 5. Validate the messageImprint hash matches the expected hash
///    (hash of the original signature value bytes)
/// 6. Extract genTime as the verified timestamp
///
/// `token_der` is the raw DER of the timestamp token (ContentInfo).
/// `signature_value_bytes` is the raw signature value from the CMS SignerInfo
///   (the bytes that were timestamped).
/// `tsa_trust_store` is the trust store for validating TSA certificates.
pub fn verify_timestamp_token(
    token_der: &[u8],
    signature_value_bytes: &[u8],
    tsa_trust_store: &crate::trust::TrustStore,
) -> Result<TimestampVerifyResult, VerifyError> {
    let mut issues = Vec::new();

    // Step 1: Parse ContentInfo
    let content_info = ContentInfo::from_der(token_der).map_err(|e| {
        VerifyError::CmsVerification(format!("failed to parse timestamp token ContentInfo: {e}"))
    })?;

    if content_info.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(VerifyError::CmsVerification(format!(
            "timestamp token: unexpected content type: {} (expected signedData)",
            content_info.content_type
        )));
    }

    // Step 2: Parse SignedData
    let sd_bytes = content_info.content.to_der().map_err(|e| {
        VerifyError::CmsVerification(format!(
            "timestamp token: failed to re-encode SignedData: {e}"
        ))
    })?;
    let signed_data = SignedData::from_der(&sd_bytes).map_err(|e| {
        VerifyError::CmsVerification(format!("timestamp token: failed to parse SignedData: {e}"))
    })?;

    // Step 3: Extract TSA certificates and signer info
    let tsa_certs = extract_certificates(&signed_data);
    let signer_infos: Vec<&SignerInfo> = signed_data.signer_infos.0.iter().collect();
    if signer_infos.is_empty() {
        return Err(VerifyError::CmsVerification(
            "timestamp token: no signer infos".to_string(),
        ));
    }
    let tsa_signer_info = signer_infos[0];

    // Step 4: Find TSA signer certificate
    let tsa_signer_cert = find_signer_certificate(tsa_signer_info, &tsa_certs);
    let tsa_signer_name = tsa_signer_cert
        .as_ref()
        .map(|c| format!("{}", c.tbs_certificate.subject));

    // Step 5: Verify TSA CMS signature
    let tsa_signature_valid = if let Some(ref cert) = tsa_signer_cert {
        match verify_signer_info_signature(tsa_signer_info, cert, token_der) {
            Ok(()) => true,
            Err(e) => {
                issues.push(format!("TSA signature verification failed: {e}"));
                false
            }
        }
    } else {
        issues.push("TSA signer certificate not found in timestamp token".to_string());
        false
    };

    // Step 6: Verify TSA certificate chain against TSA trust store
    let tsa_chain_trusted = if let Some(ref cert) = tsa_signer_cert {
        let chain = super::chain_verify::build_chain(cert, &tsa_certs)
            .unwrap_or_else(|_| vec![cert.clone()]);
        // Use current time for TSA cert validity (TSA cert must be valid now)
        let now = chrono_to_der_datetime(&chrono::Utc::now());
        match tsa_trust_store.verify_chain(&chain, now) {
            Ok(_) => true,
            Err(e) => {
                issues.push(format!("TSA certificate chain verification failed: {e}"));
                false
            }
        }
    } else {
        false
    };

    // Step 7: Extract TSTInfo and validate messageImprint
    let tst_info = crate::tsp::token::extract_tst_info(token_der).map_err(|e| {
        VerifyError::CmsVerification(format!("timestamp token: failed to extract TSTInfo: {e}"))
    })?;

    // Compute hash of the signature value using the TSTInfo's hash algorithm
    let expected_hash = tst_info.hash_algorithm.digest(signature_value_bytes);
    let message_imprint_valid = if tst_info.message_hash == expected_hash {
        true
    } else {
        issues.push(format!(
            "TSTInfo messageImprint hash mismatch: expected {}, got {} (algorithm: {:?})",
            hex::encode(&expected_hash),
            hex::encode(&tst_info.message_hash),
            tst_info.hash_algorithm,
        ));
        false
    };

    // Step 8: Parse genTime into DateTime<Utc>
    let gen_time = parse_generalized_time_bytes(&tst_info.gen_time_der).ok_or_else(|| {
        VerifyError::CmsVerification("timestamp token: failed to parse genTime".to_string())
    })?;

    Ok(TimestampVerifyResult {
        gen_time,
        tsa_signature_valid,
        message_imprint_valid,
        tsa_signer_name,
        tsa_chain_trusted,
        tst_hash_algorithm: Some(tst_info.hash_algorithm),
        issues,
    })
}

/// Convert a `chrono::DateTime<Utc>` to an `Option<der::DateTime>`.
fn chrono_to_der_datetime(dt: &DateTime<Utc>) -> Option<der::DateTime> {
    use chrono::Datelike;
    use chrono::Timelike;
    der::DateTime::new(
        dt.year() as u16,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .ok()
}

/// Parse raw GeneralizedTime body bytes (without ASN.1 tag+length) into `DateTime<Utc>`.
///
/// GeneralizedTime format: "YYYYMMDDHHMMSSZ" or "YYYYMMDDHHMMSS.fffZ"
fn parse_generalized_time_bytes(raw: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(raw).ok()?;
    // Strip trailing 'Z'
    let s = s.strip_suffix('Z').unwrap_or(s);
    // Strip fractional seconds if present
    let base = if let Some(dot_pos) = s.find('.') {
        &s[..dot_pos]
    } else {
        s
    };

    if base.len() < 14 {
        return None;
    }

    let year: i32 = base[0..4].parse().ok()?;
    let month: u32 = base[4..6].parse().ok()?;
    let day: u32 = base[6..8].parse().ok()?;
    let hour: u32 = base[8..10].parse().ok()?;
    let minute: u32 = base[10..12].parse().ok()?;
    let second: u32 = base[12..14].parse().ok()?;

    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    let time = chrono::NaiveTime::from_hms_opt(hour, minute, second)?;
    let naive = chrono::NaiveDateTime::new(date, time);
    Some(naive.and_utc())
}

/// Verify a document timestamp (SubFilter ETSI.RFC3161) from a PDF signature.
///
/// A document timestamp differs from a signature timestamp in that:
/// - The CMS `/Contents` itself IS the timestamp token (not embedded in unsigned attrs)
/// - The TSTInfo `messageImprint` covers the byte-range data (not a signature value)
/// - The `messageDigest` signed attribute in the CMS = hash of encapsulated TSTInfo DER
///   (NOT the byte-range hash)
///
/// This function performs:
/// 1. Parse the CMS ContentInfo/SignedData (same as `verify_timestamp_token`)
/// 2. Verify the TSA's CMS signature
/// 3. Verify the TSA's certificate chain against the TSA trust store
/// 4. Extract TSTInfo and validate the messageImprint against the byte-range hash
/// 5. Extract genTime as the verified document timestamp
///
/// `token_der` is the raw DER of the document timestamp CMS (from `/Contents`).
/// `byte_range_hash` is the pre-computed hash of the byte-range data.
/// `hash_algorithm` is the digest algorithm used to compute `byte_range_hash`.
/// `tsa_trust_store` is the trust store for validating TSA certificates.
pub fn verify_doc_timestamp(
    token_der: &[u8],
    byte_range_hash: &[u8],
    hash_algorithm: DigestAlgorithm,
    tsa_trust_store: &crate::trust::TrustStore,
) -> Result<TimestampVerifyResult, VerifyError> {
    let mut issues = Vec::new();

    // Step 1: Parse ContentInfo
    let content_info = ContentInfo::from_der(token_der).map_err(|e| {
        VerifyError::CmsVerification(format!("doc timestamp: failed to parse ContentInfo: {e}"))
    })?;

    if content_info.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(VerifyError::CmsVerification(format!(
            "doc timestamp: unexpected content type: {} (expected signedData)",
            content_info.content_type
        )));
    }

    // Step 2: Parse SignedData
    let sd_bytes = content_info.content.to_der().map_err(|e| {
        VerifyError::CmsVerification(format!(
            "doc timestamp: failed to re-encode SignedData: {e}"
        ))
    })?;
    let signed_data = SignedData::from_der(&sd_bytes).map_err(|e| {
        VerifyError::CmsVerification(format!("doc timestamp: failed to parse SignedData: {e}"))
    })?;

    // Step 3: Extract TSA certificates and signer info
    let tsa_certs = extract_certificates(&signed_data);
    let signer_infos: Vec<&SignerInfo> = signed_data.signer_infos.0.iter().collect();
    if signer_infos.is_empty() {
        return Err(VerifyError::CmsVerification(
            "doc timestamp: no signer infos".to_string(),
        ));
    }
    let tsa_signer_info = signer_infos[0];

    // Step 4: Find TSA signer certificate
    let tsa_signer_cert = find_signer_certificate(tsa_signer_info, &tsa_certs);
    let tsa_signer_name = tsa_signer_cert
        .as_ref()
        .map(|c| format!("{}", c.tbs_certificate.subject));

    // Step 5: Verify TSA CMS signature over the signed attributes
    // Note: For a document timestamp, the messageDigest signed attribute contains
    // the hash of the encapsulated TSTInfo DER, NOT the byte-range hash.
    // The CMS signature verification checks this internally.
    let tsa_signature_valid = if let Some(ref cert) = tsa_signer_cert {
        match verify_signer_info_signature(tsa_signer_info, cert, token_der) {
            Ok(()) => true,
            Err(e) => {
                issues.push(format!(
                    "doc timestamp: TSA signature verification failed: {e}"
                ));
                false
            }
        }
    } else {
        issues.push("doc timestamp: TSA signer certificate not found".to_string());
        false
    };

    // Step 6: Verify TSA certificate chain against TSA trust store
    let tsa_chain_trusted = if let Some(ref cert) = tsa_signer_cert {
        let chain = super::chain_verify::build_chain(cert, &tsa_certs)
            .unwrap_or_else(|_| vec![cert.clone()]);
        let now = chrono_to_der_datetime(&chrono::Utc::now());
        match tsa_trust_store.verify_chain(&chain, now) {
            Ok(_) => true,
            Err(e) => {
                issues.push(format!(
                    "doc timestamp: TSA certificate chain verification failed: {e}"
                ));
                false
            }
        }
    } else {
        false
    };

    // Step 7: Extract TSTInfo and validate messageImprint against byte-range hash
    let tst_info = crate::tsp::token::extract_tst_info(token_der).map_err(|e| {
        VerifyError::CmsVerification(format!("doc timestamp: failed to extract TSTInfo: {e}"))
    })?;

    // Validate that the TSTInfo's hash algorithm matches what we used for byte-range
    let message_imprint_valid = if tst_info.hash_algorithm != hash_algorithm {
        // The TSTInfo uses a different hash algorithm than what we computed.
        // We need to report this but can't validate the imprint.
        issues.push(format!(
            "doc timestamp: TSTInfo hash algorithm {:?} differs from byte-range hash algorithm {:?}",
            tst_info.hash_algorithm, hash_algorithm,
        ));
        false
    } else if tst_info.message_hash == byte_range_hash {
        true
    } else {
        issues.push(format!(
            "doc timestamp: TSTInfo messageImprint mismatch: \
             expected {} (byte-range hash), got {} (algorithm: {:?})",
            hex::encode(byte_range_hash),
            hex::encode(&tst_info.message_hash),
            tst_info.hash_algorithm,
        ));
        false
    };

    // Step 8: Parse genTime into DateTime<Utc>
    let gen_time = parse_generalized_time_bytes(&tst_info.gen_time_der).ok_or_else(|| {
        VerifyError::CmsVerification("doc timestamp: failed to parse genTime".to_string())
    })?;

    Ok(TimestampVerifyResult {
        gen_time,
        tsa_signature_valid,
        message_imprint_valid,
        tsa_signer_name,
        tsa_chain_trusted,
        tst_hash_algorithm: Some(tst_info.hash_algorithm),
        issues,
    })
}

/// Extract the signature timestamp token from CMS unsigned attributes.
///
/// Looks for the `id-aa-signatureTimeStampToken` attribute
/// (OID 1.2.840.113549.1.9.16.2.14) in the unsigned attributes of
/// the SignerInfo. Returns the raw DER of the timestamp token
/// (a ContentInfo wrapping a SignedData containing a TSTInfo).
fn extract_signature_timestamp_token(signer_info: &SignerInfo) -> Option<Vec<u8>> {
    let unsigned_attrs = signer_info.unsigned_attrs.as_ref()?;
    for attr in unsigned_attrs.iter() {
        if attr.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN {
            if let Some(value) = attr.values.iter().next() {
                return value.to_der().ok();
            }
        }
    }
    None
}

/// Extract the CMS Algorithm Protection attribute (RFC 6211) from signed attributes.
///
/// Parses the `CMSAlgorithmProtection` SEQUENCE to extract the digest algorithm
/// and signature algorithm OIDs. The signature algorithm is stored under IMPLICIT
/// tag `[1]`.
///
/// Returns `None` if the attribute is not present or cannot be parsed.
fn extract_cms_algorithm_protection(signer_info: &SignerInfo) -> Option<CmsAlgorithmProtection> {
    let signed_attrs = signer_info.signed_attrs.as_ref()?;
    for attr in signed_attrs.iter() {
        if attr.oid == ID_AA_CMS_ALGORITHM_PROTECTION {
            if let Some(value) = attr.values.iter().next() {
                let value_der = value.to_der().ok()?;
                return parse_cms_algorithm_protection(&value_der);
            }
        }
    }
    None
}

/// Parse a DER-encoded CMSAlgorithmProtection SEQUENCE.
///
/// ```text
/// CMSAlgorithmProtection ::= SEQUENCE {
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
///     macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL
/// }
/// ```
///
/// We need to extract:
/// - The first element as an `AlgorithmIdentifier` (digest algorithm OID)
/// - Any element with IMPLICIT tag `[1]` as an `AlgorithmIdentifier` (signature algorithm OID)
fn parse_cms_algorithm_protection(der: &[u8]) -> Option<CmsAlgorithmProtection> {
    // Must be a SEQUENCE (tag 0x30)
    if der.is_empty() || der[0] != 0x30 {
        return None;
    }

    // Skip the outer SEQUENCE tag + length to get to contents
    let (content_offset, _content_len) = parse_der_tl(der)?;
    let content = &der[content_offset..];

    // First element: digestAlgorithm (a SEQUENCE = AlgorithmIdentifier)
    if content.is_empty() || content[0] != 0x30 {
        return None;
    }
    let (digest_tl_len, digest_content_len) = parse_der_tl(content)?;
    let digest_alg_total = digest_tl_len + digest_content_len;
    let digest_alg_der = &content[..digest_alg_total];
    let digest_oid = extract_first_oid_from_alg_id(digest_alg_der)?;

    // Remaining elements: look for tag [1] (0xA1) for signatureAlgorithm
    let mut pos = digest_alg_total;
    let mut sig_oid = None;
    while pos < content.len() {
        let tag = content[pos];
        let (tl_len, elem_content_len) = parse_der_tl(&content[pos..])?;
        let elem_total = tl_len + elem_content_len;

        if tag == 0xA1 {
            // IMPLICIT [1] — the content is the AlgorithmIdentifier's inner content.
            // To parse the OID, we reconstruct it as a SEQUENCE.
            let inner = &content[pos + tl_len..pos + elem_total];
            // Reconstruct as a SEQUENCE for OID extraction
            let mut reconstructed =
                Vec::with_capacity(1 + der_length_bytes(inner.len()) + inner.len());
            reconstructed.push(0x30); // SEQUENCE tag
            encode_der_length(&mut reconstructed, inner.len());
            reconstructed.extend_from_slice(inner);
            sig_oid = extract_first_oid_from_alg_id(&reconstructed);
        }

        pos += elem_total;
    }

    let signature_algorithm = sig_oid?;
    Some(CmsAlgorithmProtection {
        digest_algorithm: digest_oid,
        signature_algorithm,
    })
}

/// Parse DER tag + length, returning (total header bytes, content length).
fn parse_der_tl(der: &[u8]) -> Option<(usize, usize)> {
    if der.len() < 2 {
        return None;
    }
    let len_byte = der[1];
    if len_byte < 0x80 {
        Some((2, len_byte as usize))
    } else {
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if der.len() < 2 + num_len_bytes {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (der[2 + i] as usize);
        }
        Some((2 + num_len_bytes, len))
    }
}

/// Extract the first OID from a DER-encoded AlgorithmIdentifier SEQUENCE.
fn extract_first_oid_from_alg_id(der: &[u8]) -> Option<ObjectIdentifier> {
    // Must be SEQUENCE
    if der.is_empty() || der[0] != 0x30 {
        return None;
    }
    let (content_offset, _) = parse_der_tl(der)?;
    let content = &der[content_offset..];

    // First element should be OID (tag 0x06)
    if content.is_empty() || content[0] != 0x06 {
        return None;
    }
    let (oid_tl_len, oid_content_len) = parse_der_tl(content)?;
    let oid_total = oid_tl_len + oid_content_len;
    let oid_der = &content[..oid_total];
    ObjectIdentifier::from_der(oid_der).ok()
}

/// How many bytes a DER length encoding takes.
fn der_length_bytes(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else if len <= 0xFFFF {
        3
    } else {
        4
    }
}

/// Encode DER definite-form length.
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Check the CMS Algorithm Protection attribute against the SignerInfo fields.
///
/// If the CMS-AP attribute is present, compares the digest and signature algorithm
/// OIDs in the attribute against the corresponding fields in the `SignerInfo`.
/// A mismatch indicates a potential algorithm substitution attack.
///
/// If the attribute is absent, a warning is added to issues (not a hard failure,
/// since CMS-AP is optional per RFC 6211 but strongly recommended).
///
/// Returns `(ok, protection)` where `ok` is `true` if either the attribute is absent
/// or present and consistent, and `false` if present but inconsistent.
fn check_cms_algorithm_protection(
    signer_info: &SignerInfo,
    issues: &mut Vec<String>,
) -> (bool, Option<CmsAlgorithmProtection>) {
    match extract_cms_algorithm_protection(signer_info) {
        Some(cmsap) => {
            let mut ok = true;

            // Check digest algorithm consistency
            if cmsap.digest_algorithm != signer_info.digest_alg.oid {
                issues.push(format!(
                    "CMS-AP digest algorithm mismatch: attribute has {}, SignerInfo has {}",
                    cmsap.digest_algorithm, signer_info.digest_alg.oid
                ));
                ok = false;
            }

            // Check signature algorithm consistency
            if cmsap.signature_algorithm != signer_info.signature_algorithm.oid {
                issues.push(format!(
                    "CMS-AP signature algorithm mismatch: attribute has {}, SignerInfo has {}",
                    cmsap.signature_algorithm, signer_info.signature_algorithm.oid
                ));
                ok = false;
            }

            (ok, Some(cmsap))
        }
        None => {
            // CMS-AP is optional — absence is not a failure, but note it
            issues.push("CMS Algorithm Protection attribute not present (RFC 6211)".to_string());
            (true, None)
        }
    }
}

/// Verify the cryptographic signature in a SignerInfo against the signer's certificate.
///
/// Per RFC 5652 §5.4: The signature is computed over the DER-encoded
/// signed attributes, re-encoded as a SET OF (tag 0x31).
///
/// `raw_cms_bytes` is the original DER-encoded CMS ContentInfo — we need it
/// to extract the *exact* signed-attributes bytes as they appeared on the wire
/// because `SetOfVec::to_der()` may re-sort elements, producing a different
/// encoding from what the signer actually signed.
fn verify_signer_info_signature(
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
    raw_cms_bytes: &[u8],
) -> Result<(), VerifyError> {
    // Try to extract the raw signed attributes bytes from the original DER.
    // This preserves the original attribute ordering, which is critical because
    // SetOfVec::to_der() may re-sort elements in DER canonical order, but the
    // signer signed the attributes in their original order.
    let attrs_bytes = extract_raw_signed_attrs(raw_cms_bytes).unwrap_or_else(|| {
        // Fallback: re-encode from parsed structure (may fail for some signers)
        let signed_attrs = signer_info.signed_attrs.as_ref().unwrap();
        let attrs_der = signed_attrs.to_der().unwrap_or_default();
        if !attrs_der.is_empty() && attrs_der[0] == 0xA0 {
            let mut fixed = attrs_der;
            fixed[0] = 0x31;
            fixed
        } else {
            attrs_der
        }
    });

    if attrs_bytes.is_empty() {
        return Err(VerifyError::CmsVerification(
            "no signed attributes found for signature verification".to_string(),
        ));
    }

    // Get signature algorithm OID
    let sig_alg_oid = &signer_info.signature_algorithm.oid;

    // Get the signer's public key
    let spki = &signer_cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki
        .to_der()
        .map_err(|e| VerifyError::CmsVerification(format!("failed to encode signer SPKI: {e}")))?;

    // Get the raw signature bytes
    let signature_bytes = signer_info.signature.as_bytes();

    // Verify using the appropriate algorithm
    verify_cms_signature(sig_alg_oid, &attrs_bytes, signature_bytes, &spki_der)
}

/// Extract the raw signed attributes bytes from the original CMS DER,
/// replacing the IMPLICIT [0] tag (0xA0) with SET OF (0x31).
///
/// This is necessary because the `cms` crate's `SetOfVec::to_der()` re-sorts
/// attribute elements in DER canonical order, which may differ from the order
/// the signer used when computing the signature.
///
/// We navigate the ASN.1 structure:
///   ContentInfo → SignedData → SignerInfos → SignerInfo → signedAttrs [0]
fn extract_raw_signed_attrs(cms_bytes: &[u8]) -> Option<Vec<u8>> {
    // We need to navigate the DER manually to find the signed attrs.
    // Structure:
    //   ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    //   SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //                             certificates [0] IMPLICIT OPTIONAL,
    //                             crls [1] IMPLICIT OPTIONAL,
    //                             signerInfos SET OF SignerInfo }
    //   SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
    //                             signedAttrs [0] IMPLICIT SET OF Attribute, ... }

    let reader = DerReader::new(cms_bytes);

    // Parse ContentInfo SEQUENCE
    let (_, content_info_body) = reader.read_sequence(0)?;

    // Skip contentType OID
    let ci_reader = DerReader::new(content_info_body);
    let (oid_end, _) = ci_reader.read_tlv(0)?;

    // Parse [0] EXPLICIT content
    let (_, explicit_body) = ci_reader.read_tlv(oid_end)?;

    // Parse SignedData SEQUENCE inside the explicit wrapper
    let sd_reader = DerReader::new(explicit_body);
    let (_, sd_body) = sd_reader.read_sequence(0)?;

    // Navigate SignedData fields:
    let field_reader = DerReader::new(sd_body);

    // 1. version INTEGER
    let (pos, _) = field_reader.read_tlv(0)?;
    // 2. digestAlgorithms SET OF
    let (pos, _) = field_reader.read_tlv(pos)?;
    // 3. encapContentInfo SEQUENCE
    let (pos, _) = field_reader.read_tlv(pos)?;

    // 4. Next fields are optional: certificates [0], crls [1], then signerInfos SET OF
    let mut pos = pos;
    loop {
        if pos >= sd_body.len() {
            return None;
        }
        let tag = sd_body[pos];
        if tag == 0x31 {
            // Found signerInfos SET OF
            let (_, signer_infos_body) = field_reader.read_tlv(pos)?;
            // signer_infos_body contains the value of SET OF, which is one or more SignerInfo SEQUENCEs
            // Parse first SignerInfo SEQUENCE
            let si_reader = DerReader::new(signer_infos_body);
            let (_, si_body) = si_reader.read_sequence(0)?;

            // Navigate SignerInfo fields:
            let si_field_reader = DerReader::new(si_body);
            // 1. version INTEGER
            let (si_pos, _) = si_field_reader.read_tlv(0)?;
            // 2. sid CHOICE (IssuerAndSerialNumber SEQUENCE or [0] SubjectKeyIdentifier)
            let (si_pos, _) = si_field_reader.read_tlv(si_pos)?;
            // 3. digestAlgorithm AlgorithmIdentifier SEQUENCE
            let (si_pos, _) = si_field_reader.read_tlv(si_pos)?;

            // 4. signedAttrs [0] IMPLICIT — tag should be 0xA0
            if si_pos < si_body.len() && si_body[si_pos] == 0xA0 {
                // Extract the full TLV (tag + length + value)
                let (_, raw_bytes) = si_field_reader.read_tlv_raw(si_pos)?;
                // Replace 0xA0 with 0x31
                let mut result = raw_bytes.to_vec();
                result[0] = 0x31;
                return Some(result);
            }
            return None;
        } else {
            // Skip this field (could be certificates [0] = 0xA0, crls [1] = 0xA1)
            let (next_pos, _) = field_reader.read_tlv(pos)?;
            pos = next_pos;
        }
    }
}

/// Minimal DER reader for navigating ASN.1 structures without re-encoding.
struct DerReader<'a> {
    data: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Read a TLV at the given offset, returning (end_offset, value_slice).
    fn read_tlv(&self, offset: usize) -> Option<(usize, &'a [u8])> {
        if offset >= self.data.len() {
            return None;
        }
        let _tag = self.data[offset];
        let (len, header_len) = self.read_length(offset + 1)?;
        let value_start = offset + 1 + header_len;
        let value_end = value_start + len;
        if value_end > self.data.len() {
            return None;
        }
        Some((value_end, &self.data[value_start..value_end]))
    }

    /// Read a TLV at the given offset, returning (end_offset, full_tlv_slice).
    fn read_tlv_raw(&self, offset: usize) -> Option<(usize, &'a [u8])> {
        if offset >= self.data.len() {
            return None;
        }
        let _tag = self.data[offset];
        let (len, header_len) = self.read_length(offset + 1)?;
        let value_end = offset + 1 + header_len + len;
        if value_end > self.data.len() {
            return None;
        }
        Some((value_end, &self.data[offset..value_end]))
    }

    /// Read a SEQUENCE, returning (end_offset, sequence_body).
    fn read_sequence(&self, offset: usize) -> Option<(usize, &'a [u8])> {
        if offset >= self.data.len() || self.data[offset] != 0x30 {
            return None;
        }
        self.read_tlv(offset)
    }

    /// Read a DER length field, returning (length_value, num_bytes_consumed).
    fn read_length(&self, offset: usize) -> Option<(usize, usize)> {
        if offset >= self.data.len() {
            return None;
        }
        let first = self.data[offset] as usize;
        if first < 0x80 {
            // Short form
            Some((first, 1))
        } else if first == 0x80 {
            // Indefinite length — not valid DER
            None
        } else {
            // Long form: first byte = 0x80 | num_length_bytes
            let num_bytes = first & 0x7F;
            if num_bytes > 4 || offset + 1 + num_bytes > self.data.len() {
                return None;
            }
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | (self.data[offset + 1 + i] as usize);
            }
            Some((len, 1 + num_bytes))
        }
    }
}

/// Verify a CMS signature given the algorithm OID, data, signature, and public key.
fn verify_cms_signature(
    sig_alg_oid: &const_oid::ObjectIdentifier,
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use crate::crypto::algorithm::{OID_ED25519, OID_RSASSA_PSS};
    use const_oid::db;

    if *sig_alg_oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha256>(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha384>(data, signature, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_cms::<sha2::Sha512>(data, signature, spki_der)
    } else if *sig_alg_oid == OID_RSASSA_PSS {
        // RSA-PSS: try SHA-256 first (most common), then SHA-384, SHA-512.
        verify_rsa_pss_cms::<sha2::Sha256>(data, signature, spki_der)
            .or_else(|_| verify_rsa_pss_cms::<sha2::Sha384>(data, signature, spki_der))
            .or_else(|_| verify_rsa_pss_cms::<sha2::Sha512>(data, signature, spki_der))
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        // ECDSA-SHA256: try P-256 first, then P-384, then P-521
        // P-521 with SHA-256 is unusual but occurs with self-signed certs
        verify_ecdsa_p256_cms(data, signature, spki_der)
            .or_else(|_| verify_ecdsa_p384_cms(data, signature, spki_der))
            .or_else(|_| verify_ecdsa_p521_sha256_cms(data, signature, spki_der))
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        // ECDSA-SHA384: try P-384 first, then P-256, then P-521
        verify_ecdsa_p384_cms(data, signature, spki_der)
            .or_else(|_| verify_ecdsa_p256_cms(data, signature, spki_der))
            .or_else(|_| verify_ecdsa_p521_sha384_cms(data, signature, spki_der))
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_512 {
        // ECDSA-SHA512: try P-521 first, then P-384
        verify_ecdsa_p521_cms(data, signature, spki_der)
            .or_else(|_| verify_ecdsa_p384_cms(data, signature, spki_der))
    } else if *sig_alg_oid == OID_ED25519 {
        verify_ed25519_cms(data, signature, spki_der)
    } else {
        Err(VerifyError::CmsVerification(format!(
            "unsupported signature algorithm: {sig_alg_oid}"
        )))
    }
}

fn verify_rsa_cms<D: digest::Digest + const_oid::AssociatedOid>(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(data);
    let scheme = Pkcs1v15Sign::new::<D>();
    pub_key
        .verify(scheme, &hash, signature)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA signature invalid: {e}")))
}

fn verify_ecdsa_p256_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-256 key decode failed: {e}")))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-256 signature decode failed: {e}")))?;

    vk.verify(data, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-256 invalid: {e}")))
}

fn verify_ecdsa_p384_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-384 key decode failed: {e}")))?;
    let sig = Signature::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-384 signature decode failed: {e}")))?;

    vk.verify(data, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-384 invalid: {e}")))
}

fn verify_ecdsa_p521_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 key decode failed: {e}")))?;
    let sig = ecdsa::Signature::<p521::NistP521>::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 signature decode failed: {e}")))?;

    // P-521 doesn't implement DigestPrimitive, so we prehash with SHA-512
    let hash = sha2::Sha512::digest(data);
    vk.verify_prehash(&hash, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-521 invalid: {e}")))
}

/// Verify an ECDSA P-521 CMS signature where the algorithm specified SHA-256.
///
/// Note: The `ecdsa` crate's `bits2field` requires the hash to be at least
/// half the field size (33 bytes for P-521). Since SHA-256 produces 32 bytes,
/// we left-pad with zeros to field size (66 bytes) to satisfy this constraint.
fn verify_ecdsa_p521_sha256_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 key decode failed: {e}")))?;
    let sig = ecdsa::Signature::<p521::NistP521>::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 signature decode failed: {e}")))?;

    let hash = sha2::Sha256::digest(data);
    // SHA-256 produces 32 bytes, but ecdsa crate's bits2field requires >= 33 bytes
    // (half of P-521's 66-byte field size). Left-pad to 66 bytes (field size).
    let mut padded = vec![0u8; 66];
    padded[66 - 32..].copy_from_slice(&hash);
    vk.verify_prehash(&padded, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-521/SHA-256 invalid: {e}")))
}

/// Verify an ECDSA P-521 CMS signature where the algorithm specified SHA-384.
fn verify_ecdsa_p521_sha384_cms(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest as _;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let vk = ecdsa::VerifyingKey::<p521::NistP521>::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 key decode failed: {e}")))?;
    let sig = ecdsa::Signature::<p521::NistP521>::from_der(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("P-521 signature decode failed: {e}")))?;

    let hash = sha2::Sha384::digest(data);
    vk.verify_prehash(&hash, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("ECDSA P-521/SHA-384 invalid: {e}")))
}

fn verify_rsa_pss_cms<
    D: digest::Digest + digest::FixedOutputReset + Default + Clone + Send + Sync + 'static,
>(
    data: &[u8],
    signature: &[u8],
    spki_der: &[u8],
) -> Result<(), VerifyError> {
    use rsa::pss::Pss;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(data);
    let scheme = Pss::new::<D>();
    pub_key
        .verify(scheme, &hash, signature)
        .map_err(|e| VerifyError::CmsVerification(format!("RSA-PSS signature invalid: {e}")))
}

fn verify_ed25519_cms(data: &[u8], signature: &[u8], spki_der: &[u8]) -> Result<(), VerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Ed25519 public key is 32 bytes; extract from SPKI
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| VerifyError::CmsVerification(format!("SPKI decode failed: {e}")))?;
    let key_bytes = spki.subject_public_key.raw_bytes();
    let vk = VerifyingKey::try_from(key_bytes)
        .map_err(|e| VerifyError::CmsVerification(format!("Ed25519 key decode failed: {e}")))?;
    let sig = Signature::from_slice(signature)
        .map_err(|e| VerifyError::CmsVerification(format!("Ed25519 sig decode failed: {e}")))?;

    vk.verify(data, &sig)
        .map_err(|e| VerifyError::CmsVerification(format!("Ed25519 signature invalid: {e}")))
}

/// Map an OID to our DigestAlgorithm enum.
fn oid_to_digest_algorithm(oid: &const_oid::ObjectIdentifier) -> Option<DigestAlgorithm> {
    DigestAlgorithm::from_oid(oid)
}

/// Compute the DTBSR (Data To Be Signed Representation) hash.
///
/// The DTBSR is the hash of the DER-encoded signed attributes, re-encoded
/// as a SET OF (tag 0x31) per RFC 5652 §5.4. This is the data that was
/// actually signed by the signer's private key.
///
/// Returns the hash bytes, or an empty Vec if signed attributes are absent.
fn compute_dtbsr_hash(signer_info: &SignerInfo, digest_alg: &Option<DigestAlgorithm>) -> Vec<u8> {
    let signed_attrs = match signer_info.signed_attrs.as_ref() {
        Some(attrs) => attrs,
        None => return Vec::new(),
    };

    let attrs_der = match signed_attrs.to_der() {
        Ok(der) => der,
        Err(_) => return Vec::new(),
    };

    // Re-encode: the cms crate stores signed attrs with IMPLICIT [0] tag (0xA0).
    // We need SET OF tag (0x31) per RFC 5652 §5.4.
    let attrs_bytes = if !attrs_der.is_empty() && attrs_der[0] == 0xA0 {
        let mut fixed = attrs_der;
        fixed[0] = 0x31;
        fixed
    } else {
        attrs_der
    };

    let alg = digest_alg.unwrap_or(DigestAlgorithm::Sha256);
    alg.digest(&attrs_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};
    use const_oid::db::rfc5912;

    #[test]
    fn test_oid_to_digest_algorithm() {
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_256),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_384),
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(
            oid_to_digest_algorithm(&rfc5912::ID_SHA_512),
            Some(DigestAlgorithm::Sha512)
        );
        // Unknown OID
        assert_eq!(
            oid_to_digest_algorithm(&const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5")),
            None
        );
    }

    #[test]
    fn test_parse_der_tl_short_form() {
        // SEQUENCE of length 3: 0x30 0x03 ...
        let der = [0x30, 0x03, 0x01, 0x02, 0x03];
        let (header_len, content_len) = parse_der_tl(&der).unwrap();
        assert_eq!(header_len, 2);
        assert_eq!(content_len, 3);
    }

    #[test]
    fn test_parse_der_tl_long_form() {
        // Length 0x80 in long form: 0x30 0x81 0x80 ...
        let mut der = vec![0x30, 0x81, 0x80];
        der.extend(vec![0x00; 128]);
        let (header_len, content_len) = parse_der_tl(&der).unwrap();
        assert_eq!(header_len, 3);
        assert_eq!(content_len, 128);
    }

    #[test]
    fn test_parse_der_tl_too_short() {
        assert!(parse_der_tl(&[0x30]).is_none());
        assert!(parse_der_tl(&[]).is_none());
    }

    #[test]
    fn test_extract_first_oid_from_alg_id() {
        use spki::AlgorithmIdentifierOwned;
        // Build a real AlgorithmIdentifier for SHA-256
        let alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_256,
            parameters: None,
        };
        let der = alg.to_der().unwrap();
        let oid = extract_first_oid_from_alg_id(&der).unwrap();
        assert_eq!(oid, rfc5912::ID_SHA_256);
    }

    #[test]
    fn test_extract_first_oid_from_alg_id_with_null() {
        use der::{Any, Tag};
        use spki::AlgorithmIdentifierOwned;
        // RSA with NULL parameters
        let null_any = Any::new(Tag::Null, Vec::new()).unwrap();
        let alg = AlgorithmIdentifierOwned {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(null_any),
        };
        let der = alg.to_der().unwrap();
        let oid = extract_first_oid_from_alg_id(&der).unwrap();
        assert_eq!(oid, rfc5912::SHA_256_WITH_RSA_ENCRYPTION);
    }

    #[test]
    fn test_parse_cms_algorithm_protection_roundtrip() {
        use der::{Any, Tag};
        use spki::AlgorithmIdentifierOwned;

        // Build a CMS-AP attribute using the builder's function
        let digest_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_256,
            parameters: None,
        };
        let null_any = Any::new(Tag::Null, Vec::new()).unwrap();
        let sig_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(null_any),
        };

        // Use the builder to create the attribute
        let attr = crate::cms::builder::tests::build_cmsap_for_test(&digest_alg, &sig_alg);

        // Parse the attribute value
        let value = attr.values.iter().next().unwrap();
        let value_der = value.to_der().unwrap();
        let parsed = parse_cms_algorithm_protection(&value_der).unwrap();

        assert_eq!(parsed.digest_algorithm, rfc5912::ID_SHA_256);
        assert_eq!(
            parsed.signature_algorithm,
            rfc5912::SHA_256_WITH_RSA_ENCRYPTION
        );
    }

    #[test]
    fn test_parse_cms_algorithm_protection_ecdsa() {
        use spki::AlgorithmIdentifierOwned;

        // Build CMS-AP with ECDSA
        let digest_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_384,
            parameters: None,
        };
        let sig_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ECDSA_WITH_SHA_384,
            parameters: None,
        };

        let attr = crate::cms::builder::tests::build_cmsap_for_test(&digest_alg, &sig_alg);

        let value = attr.values.iter().next().unwrap();
        let value_der = value.to_der().unwrap();
        let parsed = parse_cms_algorithm_protection(&value_der).unwrap();

        assert_eq!(parsed.digest_algorithm, rfc5912::ID_SHA_384);
        assert_eq!(parsed.signature_algorithm, rfc5912::ECDSA_WITH_SHA_384);
    }

    #[test]
    fn test_check_cmsap_consistent() {
        // Build a real CMS and verify the CMS-AP check passes
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        // Parse back and check
        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let mut issues = Vec::new();
        let (ok, protection) = check_cms_algorithm_protection(si, &mut issues);
        assert!(ok, "CMS-AP check should pass: {:?}", issues);
        assert!(protection.is_some(), "CMS-AP should be present");

        let cmsap = protection.unwrap();
        assert_eq!(cmsap.digest_algorithm, si.digest_alg.oid);
        assert_eq!(cmsap.signature_algorithm, si.signature_algorithm.oid);
        // No mismatch issues
        assert!(
            !issues.iter().any(|i| i.contains("mismatch")),
            "should have no mismatch issues"
        );
    }

    #[test]
    fn test_verify_cms_includes_algorithm_protection() {
        // Sign a PDF and verify CMS, checking that CMS-AP fields are populated
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let result = verify_cms(&cms_der, &fake_hash).unwrap();
        assert!(result.algorithm_protection_ok);
        assert!(result.algorithm_protection.is_some());

        let ap = result.algorithm_protection.unwrap();
        assert_eq!(ap.digest_algorithm, rfc5912::ID_SHA_256);
    }

    #[test]
    fn test_parse_cmsap_invalid_data() {
        // Not a SEQUENCE
        assert!(parse_cms_algorithm_protection(&[0x04, 0x02, 0x01, 0x02]).is_none());
        // Empty
        assert!(parse_cms_algorithm_protection(&[]).is_none());
        // SEQUENCE but empty content
        assert!(parse_cms_algorithm_protection(&[0x30, 0x00]).is_none());
    }

    #[test]
    fn test_parse_cms_time_utctime() {
        // Build a UTCTime for 2025-03-15 10:30:00 UTC
        let dt = der::DateTime::new(2025, 3, 15, 10, 30, 0).unwrap();
        let utc_time = der::asn1::UtcTime::from_date_time(dt).unwrap();
        let der_bytes = utc_time.to_der().unwrap();

        let parsed = parse_cms_time(&der_bytes).unwrap();
        assert_eq!(parsed.year(), 2025);
        assert_eq!(parsed.month(), 3);
        assert_eq!(parsed.day(), 15);
        assert_eq!(parsed.hour(), 10);
        assert_eq!(parsed.minute(), 30);
        assert_eq!(parsed.second(), 0);
    }

    #[test]
    fn test_parse_cms_time_generalized_time() {
        // Build a GeneralizedTime for 2050-12-31 23:59:59 UTC
        let dt = der::DateTime::new(2050, 12, 31, 23, 59, 59).unwrap();
        let gen_time = der::asn1::GeneralizedTime::from_date_time(dt);
        let der_bytes = gen_time.to_der().unwrap();

        let parsed = parse_cms_time(&der_bytes).unwrap();
        assert_eq!(parsed.year(), 2050);
        assert_eq!(parsed.month(), 12);
        assert_eq!(parsed.day(), 31);
        assert_eq!(parsed.hour(), 23);
        assert_eq!(parsed.minute(), 59);
        assert_eq!(parsed.second(), 59);
    }

    #[test]
    fn test_parse_cms_time_invalid() {
        // Empty
        assert!(parse_cms_time(&[]).is_none());
        // Wrong tag (OCTET STRING)
        assert!(parse_cms_time(&[0x04, 0x02, 0x01, 0x02]).is_none());
    }

    #[test]
    fn test_der_datetime_to_chrono_roundtrip() {
        let dt = der::DateTime::new(2025, 6, 15, 14, 30, 45).unwrap();
        let chrono_dt = der_datetime_to_chrono(&dt).unwrap();
        assert_eq!(chrono_dt.year(), 2025);
        assert_eq!(chrono_dt.month(), 6);
        assert_eq!(chrono_dt.day(), 15);
        assert_eq!(chrono_dt.hour(), 14);
        assert_eq!(chrono_dt.minute(), 30);
        assert_eq!(chrono_dt.second(), 45);
    }

    #[test]
    fn test_extract_signing_time_from_traditional_cms() {
        // Traditional CMS includes signingTime; PAdES does NOT
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(
                chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
                    .unwrap()
                    .and_hms_opt(14, 30, 0)
                    .unwrap(),
            );
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        // Parse CMS and extract signing time
        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let signing_time = extract_signing_time(si);
        assert!(
            signing_time.is_some(),
            "signing time should be present in traditional CMS"
        );
        let st = signing_time.unwrap();
        assert_eq!(st.year(), 2025);
        assert_eq!(st.month(), 6);
        assert_eq!(st.day(), 15);
        assert_eq!(st.hour(), 14);
        assert_eq!(st.minute(), 30);
    }

    #[test]
    fn test_pades_cms_has_no_signing_time() {
        // PAdES profile should NOT include signingTime (per RFC 5126 / ETSI EN 319 122)
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let signing_time = extract_signing_time(si);
        assert!(
            signing_time.is_none(),
            "PAdES should NOT have signingTime attribute"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_matches_in_pades() {
        // PAdES CMS includes signingCertificateV2; verify it matches
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        // Extract the signer certificate
        let certs = extract_certificates(&signed_data);
        let signer_cert = find_signer_certificate(si, &certs);
        assert!(signer_cert.is_some());

        let mut issues = Vec::new();
        let result = verify_ess_cert_id_v2(si, &signer_cert, &mut issues);
        assert_eq!(result, Some(true), "ESSCertIDv2 should match: {:?}", issues);
        assert!(
            !issues.iter().any(|i| i.contains("does NOT match")),
            "should have no mismatch issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_ess_cert_id_v2_not_present_in_traditional() {
        // Traditional CMS does NOT include signingCertificateV2
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let certs = extract_certificates(&signed_data);
        let signer_cert = find_signer_certificate(si, &certs);

        let mut issues = Vec::new();
        let result = verify_ess_cert_id_v2(si, &signer_cert, &mut issues);
        assert_eq!(
            result, None,
            "Traditional CMS should not have signingCertificateV2"
        );
    }

    #[test]
    fn test_verify_cms_new_fields_pades() {
        // Full verify_cms() roundtrip checking all new fields for PAdES
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let result = verify_cms(&cms_der, &fake_hash).unwrap();
        assert!(result.signature_valid);
        assert!(result.digest_matches);

        // PAdES: no signingTime, but has ESSCertIDv2
        assert!(
            result.cms_signing_time.is_none(),
            "PAdES should not have CMS signingTime"
        );
        assert_eq!(
            result.ess_cert_id_match,
            Some(true),
            "PAdES should have matching ESSCertIDv2"
        );

        // No signature timestamp (we didn't embed one)
        assert!(result.signature_timestamp_token.is_none());
    }

    #[test]
    fn test_verify_cms_new_fields_traditional() {
        // Full verify_cms() roundtrip checking all new fields for Traditional
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(
                chrono::NaiveDate::from_ymd_opt(2025, 1, 1)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap(),
            );
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let result = verify_cms(&cms_der, &fake_hash).unwrap();
        assert!(result.signature_valid);
        assert!(result.digest_matches);

        // Traditional: has signingTime, no ESSCertIDv2
        assert!(
            result.cms_signing_time.is_some(),
            "Traditional should have CMS signingTime"
        );
        let st = result.cms_signing_time.unwrap();
        assert_eq!(st.year(), 2025);
        assert_eq!(st.month(), 1);
        assert_eq!(st.day(), 1);

        assert_eq!(
            result.ess_cert_id_match, None,
            "Traditional should not have ESSCertIDv2"
        );
        assert!(result.signature_timestamp_token.is_none());
    }

    #[test]
    fn test_parse_ess_cert_id_v2_invalid() {
        // Empty
        assert!(parse_ess_cert_id_v2(&[]).is_none());
        // Not a SEQUENCE
        assert!(parse_ess_cert_id_v2(&[0x04, 0x02, 0x01, 0x02]).is_none());
        // SEQUENCE but empty
        assert!(parse_ess_cert_id_v2(&[0x30, 0x00]).is_none());
    }

    // ── parse_generalized_time_bytes tests ──────────────────────────

    #[test]
    fn test_parse_generalized_time_bytes_basic() {
        // "20250315103000Z" → 2025-03-15 10:30:00 UTC
        let raw = b"20250315103000Z";
        let dt = parse_generalized_time_bytes(raw).unwrap();
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 10);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_parse_generalized_time_bytes_with_fraction() {
        // "20501231235959.123Z" → 2050-12-31 23:59:59 UTC (fraction ignored)
        let raw = b"20501231235959.123Z";
        let dt = parse_generalized_time_bytes(raw).unwrap();
        assert_eq!(dt.year(), 2050);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 31);
        assert_eq!(dt.hour(), 23);
        assert_eq!(dt.minute(), 59);
        assert_eq!(dt.second(), 59);
    }

    #[test]
    fn test_parse_generalized_time_bytes_no_z_suffix() {
        // Without trailing Z (some implementations)
        let raw = b"20250101000000";
        let dt = parse_generalized_time_bytes(raw).unwrap();
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 0);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_parse_generalized_time_bytes_too_short() {
        // Less than 14 chars → None
        let raw = b"202503151030Z";
        assert!(parse_generalized_time_bytes(raw).is_none());
    }

    #[test]
    fn test_parse_generalized_time_bytes_empty() {
        assert!(parse_generalized_time_bytes(b"").is_none());
    }

    #[test]
    fn test_parse_generalized_time_bytes_invalid_date() {
        // Month 13 is invalid
        let raw = b"20251315103000Z";
        assert!(parse_generalized_time_bytes(raw).is_none());
    }

    #[test]
    fn test_parse_generalized_time_bytes_invalid_utf8() {
        // Non-UTF-8 bytes
        let raw = &[0xFF, 0xFE, 0xFD, 0xFC];
        assert!(parse_generalized_time_bytes(raw).is_none());
    }

    #[test]
    fn test_parse_generalized_time_bytes_midnight() {
        // Edge case: midnight
        let raw = b"20260101000000Z";
        let dt = parse_generalized_time_bytes(raw).unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 0);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    // ── chrono_to_der_datetime tests ────────────────────────────────

    #[test]
    fn test_chrono_to_der_datetime_basic() {
        use chrono::TimeZone;
        let dt = chrono::Utc
            .with_ymd_and_hms(2025, 6, 15, 14, 30, 45)
            .unwrap();
        let der_dt = chrono_to_der_datetime(&dt).unwrap();
        assert_eq!(der_dt.year(), 2025);
        assert_eq!(der_dt.month(), 6);
        assert_eq!(der_dt.day(), 15);
        assert_eq!(der_dt.hour(), 14);
        assert_eq!(der_dt.minutes(), 30);
        assert_eq!(der_dt.seconds(), 45);
    }

    #[test]
    fn test_chrono_to_der_datetime_epoch() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let der_dt = chrono_to_der_datetime(&dt).unwrap();
        assert_eq!(der_dt.year(), 1970);
        assert_eq!(der_dt.month(), 1);
        assert_eq!(der_dt.day(), 1);
    }

    #[test]
    fn test_chrono_to_der_datetime_roundtrip() {
        // chrono → der → chrono should preserve values
        use chrono::TimeZone;
        let original = chrono::Utc
            .with_ymd_and_hms(2030, 12, 31, 23, 59, 59)
            .unwrap();
        let der_dt = chrono_to_der_datetime(&original).unwrap();
        let back = der_datetime_to_chrono(&der_dt).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn test_no_unsigned_attrs_means_no_timestamp() {
        // CMS built by our builder has no unsigned attrs → no timestamp token
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let token = extract_signature_timestamp_token(si);
        assert!(
            token.is_none(),
            "should be None when no unsigned attrs present"
        );
    }

    // ── verify_timestamp_token tests ────────────────────────────────

    #[test]
    fn test_verify_timestamp_token_invalid_der() {
        // Garbage bytes should fail with a parse error
        let trust_store = crate::trust::TrustStore::new();
        let result = verify_timestamp_token(&[0xFF, 0xFE, 0xFD], &[0xAA; 32], &trust_store);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("ContentInfo"),
            "error should mention ContentInfo parse failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_timestamp_token_empty_input() {
        let trust_store = crate::trust::TrustStore::new();
        let result = verify_timestamp_token(&[], &[0xAA; 32], &trust_store);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_timestamp_token_wrong_content_type() {
        // Build a ContentInfo with id-data instead of id-signedData
        use der::Encode;
        let content_info = cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA,
            content: der::Any::new(der::Tag::OctetString, vec![0x00]).unwrap(),
        };
        let der = content_info.to_der().unwrap();

        let trust_store = crate::trust::TrustStore::new();
        let result = verify_timestamp_token(&der, &[0xAA; 32], &trust_store);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("unexpected content type"),
            "error should mention wrong content type, got: {err}"
        );
    }

    #[test]
    fn test_verify_timestamp_token_no_signer_infos() {
        // Build a minimal SignedData with no signer infos
        use cms::content_info::CmsVersion;
        use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
        use der::asn1::SetOfVec;
        use der::Encode;

        let encap = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        };
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: encap,
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let sd_der = sd.to_der().unwrap();
        let sd_any = der::Any::from_der(&sd_der).unwrap();

        let ci = cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: sd_any,
        };
        let ci_der = ci.to_der().unwrap();

        let trust_store = crate::trust::TrustStore::new();
        let result = verify_timestamp_token(&ci_der, &[0xAA; 32], &trust_store);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("no signer infos"),
            "error should mention no signer infos, got: {err}"
        );
    }

    #[test]
    fn test_verify_cms_result_has_signature_value() {
        // Verify that verify_cms populates the signature_value field
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Pades);
        let fake_hash = vec![0xBB; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let result = verify_cms(&cms_der, &fake_hash).unwrap();
        assert!(
            !result.signature_value.is_empty(),
            "signature_value should not be empty"
        );
        // For RSA, signature value should be at least 128 bytes (1024-bit key minimum)
        assert!(
            result.signature_value.len() >= 128,
            "RSA signature value should be at least 128 bytes, got {}",
            result.signature_value.len()
        );
    }

    // ── verify_doc_timestamp tests ────────────────────────────────

    #[test]
    fn test_verify_doc_timestamp_invalid_der() {
        // Garbage bytes should fail with a parse error
        let trust_store = crate::trust::TrustStore::new();
        let result = verify_doc_timestamp(
            &[0xFF, 0xFE, 0xFD],
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            &trust_store,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("ContentInfo"),
            "error should mention ContentInfo parse failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_doc_timestamp_empty_input() {
        let trust_store = crate::trust::TrustStore::new();
        let result = verify_doc_timestamp(&[], &[0xAA; 32], DigestAlgorithm::Sha256, &trust_store);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_doc_timestamp_wrong_content_type() {
        // Build a ContentInfo with id-data instead of id-signedData
        use der::Encode;
        let content_info = cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA,
            content: der::Any::new(der::Tag::OctetString, vec![0x00]).unwrap(),
        };
        let der = content_info.to_der().unwrap();

        let trust_store = crate::trust::TrustStore::new();
        let result = verify_doc_timestamp(&der, &[0xAA; 32], DigestAlgorithm::Sha256, &trust_store);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("unexpected content type"),
            "error should mention wrong content type, got: {err}"
        );
    }

    #[test]
    fn test_verify_doc_timestamp_no_signer_infos() {
        // Build a minimal SignedData with no signer infos
        use cms::content_info::CmsVersion;
        use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
        use der::asn1::SetOfVec;
        use der::Encode;

        let encap = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        };
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: encap,
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let sd_der = sd.to_der().unwrap();
        let sd_any = der::Any::from_der(&sd_der).unwrap();

        let ci = cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: sd_any,
        };
        let ci_der = ci.to_der().unwrap();

        let trust_store = crate::trust::TrustStore::new();
        let result =
            verify_doc_timestamp(&ci_der, &[0xAA; 32], DigestAlgorithm::Sha256, &trust_store);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("no signer infos"),
            "error should mention no signer infos, got: {err}"
        );
    }

    #[test]
    fn test_extract_signing_time_unsigned_from_cms() {
        // Build CMS with signing_time_placement = Unsigned, then verify
        // extract_signing_time_unsigned finds the time.
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();
        let cms_der = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(crate::cms::builder::SigningTimePlacement::Unsigned)
            .build(&[0xBB; 32])
            .expect("build");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        // Signed attrs should NOT have signingTime
        let signed_time = extract_signing_time(si);
        assert!(
            signed_time.is_none(),
            "signingTime should NOT be in signed attrs with Unsigned placement"
        );

        // Unsigned attrs SHOULD have signingTime
        let unsigned_time = extract_signing_time_unsigned(si);
        assert!(
            unsigned_time.is_some(),
            "signingTime should be in unsigned attrs with Unsigned placement"
        );
        let ut = unsigned_time.unwrap();
        assert_eq!(ut.year(), 2025);
        assert_eq!(ut.month(), 6);
        assert_eq!(ut.day(), 15);
        assert_eq!(ut.hour(), 14);
        assert_eq!(ut.minute(), 30);
    }

    #[test]
    fn test_extract_signing_time_unsigned_absent() {
        // Default placement (Signed): unsigned attrs are None, so extract_signing_time_unsigned
        // should return None.
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();
        let cms_der = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(time)
            // default placement = Signed
            .build(&[0xBB; 32])
            .expect("build");

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let sd_bytes = content_info.content.to_der().unwrap();
        let signed_data = SignedData::from_der(&sd_bytes).unwrap();
        let si = &signed_data.signer_infos.0.as_slice()[0];

        let unsigned_time = extract_signing_time_unsigned(si);
        assert!(
            unsigned_time.is_none(),
            "unsigned signing time should be None with default Signed placement"
        );
    }

    #[test]
    fn test_verify_cms_result_has_unsigned_signing_time() {
        // End-to-end: verify_cms should populate cms_signing_time_unsigned field
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();

        // Build CMS with Both placement: signed + unsigned both have signingTime
        let fake_hash = vec![0xBB; 32];
        let cms_der = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(crate::cms::builder::SigningTimePlacement::Both)
            .build(&fake_hash)
            .expect("build");

        // verify_cms uses the same fake_hash as data_hash
        let result = verify_cms(&cms_der, &fake_hash).expect("verify_cms");

        // Signed signing time should be present
        assert!(
            result.cms_signing_time.is_some(),
            "cms_signing_time should be Some with Both placement"
        );

        // Unsigned signing time should also be present
        assert!(
            result.cms_signing_time_unsigned.is_some(),
            "cms_signing_time_unsigned should be Some with Both placement"
        );

        // Both should have the same time
        let signed_t = result.cms_signing_time.unwrap();
        let unsigned_t = result.cms_signing_time_unsigned.unwrap();
        assert_eq!(
            signed_t, unsigned_t,
            "signed and unsigned signing times should match"
        );
        assert_eq!(signed_t.year(), 2025);
    }

    #[test]
    fn test_verify_cms_result_unsigned_only() {
        // verify_cms with Unsigned placement: cms_signing_time is None,
        // cms_signing_time_unsigned is Some.
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();

        let fake_hash = vec![0xBB; 32];
        let cms_der = crate::cms::builder::PdfCmsBuilder::new(&signer)
            .profile(crate::cms::builder::CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(crate::cms::builder::SigningTimePlacement::Unsigned)
            .build(&fake_hash)
            .expect("build");

        let result = verify_cms(&cms_der, &fake_hash).expect("verify_cms");

        assert!(
            result.cms_signing_time.is_none(),
            "cms_signing_time should be None with Unsigned placement"
        );
        assert!(
            result.cms_signing_time_unsigned.is_some(),
            "cms_signing_time_unsigned should be Some with Unsigned placement"
        );
        let ut = result.cms_signing_time_unsigned.unwrap();
        assert_eq!(ut.year(), 2025);
        assert_eq!(ut.month(), 6);
        assert_eq!(ut.hour(), 14);
    }
}
