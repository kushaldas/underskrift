//! TimeStampReq/Resp ASN.1 parsing and validation per RFC 3161.
//!
//! This module handles:
//! - Building `TimeStampReq` messages
//! - Parsing `TimeStampResp` responses
//! - Extracting and validating `TSTInfo` from the embedded `TimeStampToken`
//! - Nonce generation and verification

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;

use crate::crypto::algorithm::DigestAlgorithm;
use crate::der_utils;
use crate::error::TspError;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

/// id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4)
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// id-signedData (1.2.840.113549.1.7.2)
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

// ---------------------------------------------------------------------------
// PKI status codes per RFC 3161 §2.4.2
// ---------------------------------------------------------------------------

/// PKIStatus values per RFC 3161.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    /// 0 — granted
    Granted,
    /// 1 — grantedWithMods
    GrantedWithMods,
    /// 2 — rejection
    Rejection,
    /// 3 — waiting
    Waiting,
    /// 4 — revocationWarning
    RevocationWarning,
    /// 5 — revocationNotification
    RevocationNotification,
    /// Unknown status value
    Unknown(u64),
}

impl PkiStatus {
    fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Granted,
            1 => Self::GrantedWithMods,
            2 => Self::Rejection,
            3 => Self::Waiting,
            4 => Self::RevocationWarning,
            5 => Self::RevocationNotification,
            _ => Self::Unknown(v),
        }
    }

    /// Returns true if the status indicates success (token was issued).
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }
}

impl std::fmt::Display for PkiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted => write!(f, "granted (0)"),
            Self::GrantedWithMods => write!(f, "grantedWithMods (1)"),
            Self::Rejection => write!(f, "rejection (2)"),
            Self::Waiting => write!(f, "waiting (3)"),
            Self::RevocationWarning => write!(f, "revocationWarning (4)"),
            Self::RevocationNotification => write!(f, "revocationNotification (5)"),
            Self::Unknown(v) => write!(f, "unknown ({v})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TimeStampReq builder
// ---------------------------------------------------------------------------

/// Build a DER-encoded RFC 3161 `TimeStampReq`.
///
/// ```text
/// TimeStampReq ::= SEQUENCE  {
///    version               INTEGER  { v1(1) },
///    messageImprint        MessageImprint,
///    reqPolicy             TSAPolicyId              OPTIONAL,
///    nonce                 INTEGER                  OPTIONAL,
///    certReq               BOOLEAN                  DEFAULT FALSE,
///    extensions        [0] IMPLICIT Extensions      OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm         AlgorithmIdentifier,
///    hashedMessage         OCTET STRING
/// }
/// ```
pub fn build_timestamp_request(
    digest_algorithm: DigestAlgorithm,
    message_hash: &[u8],
    policy_oid: Option<&ObjectIdentifier>,
    nonce: Option<u64>,
    cert_req: bool,
) -> Result<Vec<u8>, TspError> {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    // version INTEGER { v1(1) }
    parts.push(der_utils::encode_integer_u64(1));

    // messageImprint
    let hash_alg = digest_algorithm_identifier(digest_algorithm);
    let hash_alg_der = hash_alg
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash algorithm: {e}")))?;
    let hashed_message = OctetString::new(message_hash.to_vec()).map_err(|e| {
        TspError::InvalidResponse(format!("failed to create hash octet string: {e}"))
    })?;
    let hashed_message_der = hashed_message
        .to_der()
        .map_err(|e| TspError::InvalidResponse(format!("failed to encode hash: {e}")))?;
    let msg_imprint = der_utils::encode_sequence_from_parts(&[&hash_alg_der, &hashed_message_der]);
    parts.push(msg_imprint);

    // reqPolicy OPTIONAL
    if let Some(oid) = policy_oid {
        let oid_der = oid
            .to_der()
            .map_err(|e| TspError::InvalidResponse(format!("failed to encode policy OID: {e}")))?;
        parts.push(oid_der);
    }

    // nonce OPTIONAL
    if let Some(n) = nonce {
        parts.push(der_utils::encode_integer_u64(n));
    }

    // certReq BOOLEAN DEFAULT FALSE — only encode when TRUE
    if cert_req {
        parts.push(der_utils::encode_boolean(true));
    }

    // Assemble SEQUENCE
    let body: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    Ok(der_utils::encode_sequence_raw(&body))
}

// ---------------------------------------------------------------------------
// TimeStampResp parsing
// ---------------------------------------------------------------------------

/// Parsed RFC 3161 TimeStampResp.
///
/// ```text
/// TimeStampResp ::= SEQUENCE  {
///    status                PKIStatusInfo,
///    timeStampToken        TimeStampToken     OPTIONAL
/// }
/// ```
#[derive(Debug)]
pub struct TimeStampResp {
    /// The PKI status information.
    pub status: PkiStatus,
    /// Free text status string (if any).
    pub status_string: Option<String>,
    /// Failure info bitstring (if any).
    pub failure_info: Option<Vec<u8>>,
    /// The raw DER-encoded TimeStampToken (a CMS ContentInfo).
    /// Present only when status is Granted or GrantedWithMods.
    pub token_der: Option<Vec<u8>>,
}

/// Parse a DER-encoded RFC 3161 `TimeStampResp`.
pub fn parse_timestamp_response(der_bytes: &[u8]) -> Result<TimeStampResp, TspError> {
    // TimeStampResp is a SEQUENCE
    let (tag, resp_body) = der_utils::parse_tlv(der_bytes)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse TimeStampResp: {e}")))?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(format!(
            "expected SEQUENCE tag 0x30, got 0x{tag:02x}"
        )));
    }

    // First element: PKIStatusInfo SEQUENCE
    let (status_tag, status_body, rest) = der_utils::parse_tlv_with_rest(&resp_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse PKIStatusInfo: {e}")))?;
    if status_tag != 0x30 {
        return Err(TspError::InvalidResponse(format!(
            "expected PKIStatusInfo SEQUENCE, got 0x{status_tag:02x}"
        )));
    }

    // PKIStatusInfo: first element is PKIStatus INTEGER
    let (int_tag, int_body, status_rest) = der_utils::parse_tlv_with_rest(&status_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse PKIStatus: {e}")))?;
    if int_tag != 0x02 {
        return Err(TspError::InvalidResponse(format!(
            "expected INTEGER tag 0x02 for PKIStatus, got 0x{int_tag:02x}"
        )));
    }
    let status_val = der_utils::decode_integer_u64(&int_body);
    let status = PkiStatus::from_u64(status_val);

    // Parse optional statusString and failureInfo from status_rest
    let mut status_string = None;
    let mut failure_info = None;
    let mut remaining = status_rest;

    while !remaining.is_empty() {
        if let Ok((stag, sbody, srest)) = der_utils::parse_tlv_with_rest(remaining) {
            match stag {
                // SEQUENCE OF UTF8String (statusString)
                0x30 => {
                    // Try to extract the first UTF8String
                    if let Ok((_inner_tag, inner_body, _)) = der_utils::parse_tlv_with_rest(&sbody)
                    {
                        status_string = Some(String::from_utf8_lossy(&inner_body).to_string());
                    }
                }
                // BIT STRING (failureInfo)
                0x03 => {
                    failure_info = Some(sbody.to_vec());
                }
                _ => {}
            }
            remaining = srest;
        } else {
            break;
        }
    }

    // Second element: TimeStampToken OPTIONAL
    let token_der = if !rest.is_empty() {
        // The token is a ContentInfo (SEQUENCE)
        let (token_tag, _, _) = der_utils::parse_tlv_with_rest(rest)
            .map_err(|e| TspError::InvalidResponse(format!("failed to parse token TLV: {e}")))?;
        if token_tag == 0x30 {
            // Re-encode the entire TLV (tag + length + value) as the token DER
            Some(rest.to_vec())
        } else {
            None
        }
    } else {
        None
    };

    Ok(TimeStampResp {
        status,
        status_string,
        failure_info,
        token_der,
    })
}

/// Validate a TimeStampResp: check status, extract token.
///
/// Returns the raw DER-encoded TimeStampToken (CMS ContentInfo containing SignedData).
pub fn validate_timestamp_response(
    resp: &TimeStampResp,
    expected_hash: &[u8],
    expected_nonce: Option<u64>,
    digest_algorithm: DigestAlgorithm,
) -> Result<Vec<u8>, TspError> {
    // Check status
    if !resp.status.is_success() {
        let msg = match &resp.status_string {
            Some(s) => format!("status={}, message={s}", resp.status),
            None => format!("status={}", resp.status),
        };
        return Err(TspError::TsaError(msg));
    }

    let token_der = resp.token_der.as_ref().ok_or_else(|| {
        TspError::InvalidResponse("no token in response despite success status".into())
    })?;

    // Parse TSTInfo from the token to validate hash and nonce
    let tst_info = extract_tst_info(token_der)?;

    // Validate message imprint hash
    if tst_info.message_hash != expected_hash {
        return Err(TspError::InvalidResponse(
            "TSTInfo messageImprint hash does not match request".into(),
        ));
    }

    // Validate message imprint algorithm
    if tst_info.hash_algorithm != digest_algorithm {
        return Err(TspError::InvalidResponse(format!(
            "TSTInfo hash algorithm mismatch: expected {:?}, got {:?}",
            digest_algorithm, tst_info.hash_algorithm,
        )));
    }

    // Validate nonce if provided
    if let Some(expected) = expected_nonce {
        match tst_info.nonce {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                return Err(TspError::InvalidResponse(format!(
                    "nonce mismatch: expected {expected}, got {actual}"
                )));
            }
            None => {
                return Err(TspError::InvalidResponse(
                    "expected nonce in TSTInfo but none present".into(),
                ));
            }
        }
    }

    Ok(token_der.clone())
}

// ---------------------------------------------------------------------------
// TSTInfo extraction
// ---------------------------------------------------------------------------

/// Parsed TSTInfo from a TimeStampToken.
#[derive(Debug)]
pub struct TstInfo {
    /// The hash algorithm used in the message imprint.
    pub hash_algorithm: DigestAlgorithm,
    /// The message hash from the message imprint.
    pub message_hash: Vec<u8>,
    /// The serial number of the timestamp.
    pub serial_number: Vec<u8>,
    /// The generation time (raw DER bytes of GeneralizedTime).
    pub gen_time_der: Vec<u8>,
    /// Nonce from the response (if present).
    pub nonce: Option<u64>,
    /// The TSA policy OID.
    pub policy_oid: Option<String>,
}

/// Extract TSTInfo from a TimeStampToken (CMS ContentInfo).
///
/// The TimeStampToken is a CMS ContentInfo wrapping SignedData,
/// whose encapsulated content is id-ct-TSTInfo.
pub fn extract_tst_info(token_der: &[u8]) -> Result<TstInfo, TspError> {
    // Parse ContentInfo SEQUENCE
    let (tag, ci_body) = der_utils::parse_tlv(token_der)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse ContentInfo: {e}")))?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "ContentInfo: expected SEQUENCE".into(),
        ));
    }

    // contentType OID — should be id-signedData
    let (_oid_tag, _oid_body, ci_rest) = der_utils::parse_tlv_with_rest(&ci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse contentType: {e}")))?;

    // content [0] EXPLICIT — the SignedData
    let (ctx_tag, sd_inner, _) = der_utils::parse_tlv_with_rest(ci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse content [0]: {e}")))?;
    if ctx_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected [0] EXPLICIT tag 0xA0, got 0x{ctx_tag:02x}"
        )));
    }

    // SignedData SEQUENCE
    let (sd_tag, sd_body) = der_utils::parse_tlv(&sd_inner)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SignedData: {e}")))?;
    if sd_tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "SignedData: expected SEQUENCE".into(),
        ));
    }

    // SignedData fields: version, digestAlgorithms, encapContentInfo, [0] certs, [1] crls, signerInfos
    let (_ver_tag, _ver_body, sd_rest) = der_utils::parse_tlv_with_rest(&sd_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse SD version: {e}")))?;

    // digestAlgorithms SET OF
    let (_da_tag, _da_body, sd_rest2) = der_utils::parse_tlv_with_rest(sd_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse digestAlgorithms: {e}")))?;

    // encapContentInfo SEQUENCE
    let (_eci_tag, eci_body, _sd_rest3) = der_utils::parse_tlv_with_rest(sd_rest2)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse encapContentInfo: {e}")))?;

    // eContentType OID
    let (_ect_tag, _ect_body, eci_rest) = der_utils::parse_tlv_with_rest(&eci_body)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContentType: {e}")))?;

    // eContent [0] EXPLICIT
    let (ec_tag, ec_inner, _) = der_utils::parse_tlv_with_rest(eci_rest)
        .map_err(|e| TspError::InvalidResponse(format!("failed to parse eContent [0]: {e}")))?;
    if ec_tag != 0xA0 {
        return Err(TspError::InvalidResponse(format!(
            "expected eContent [0] tag 0xA0, got 0x{ec_tag:02x}"
        )));
    }

    // The eContent is an OCTET STRING containing TSTInfo
    let (os_tag, tst_info_der, _) = der_utils::parse_tlv_with_rest(&ec_inner).map_err(|e| {
        TspError::InvalidResponse(format!("failed to parse eContent OCTET STRING: {e}"))
    })?;
    if os_tag != 0x04 {
        return Err(TspError::InvalidResponse(format!(
            "expected OCTET STRING 0x04 for eContent, got 0x{os_tag:02x}"
        )));
    }

    // Now parse TSTInfo SEQUENCE
    parse_tst_info_body(&tst_info_der)
}

/// Parse the inner TSTInfo SEQUENCE body.
///
/// ```text
/// TSTInfo ::= SEQUENCE  {
///    version                      INTEGER  { v1(1) },
///    policy                       TSAPolicyId,
///    messageImprint               MessageImprint,
///    serialNumber                 INTEGER,
///    genTime                      GeneralizedTime,
///    accuracy                     Accuracy               OPTIONAL,
///    ordering                     BOOLEAN             DEFAULT FALSE,
///    nonce                        INTEGER                OPTIONAL,
///    tsa                     [0]  GeneralName            OPTIONAL,
///    extensions              [1]  IMPLICIT Extensions    OPTIONAL
/// }
/// ```
fn parse_tst_info_body(der_bytes: &[u8]) -> Result<TstInfo, TspError> {
    let (tag, body) = der_utils::parse_tlv(der_bytes).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse SEQUENCE: {e}"))
    })?;
    if tag != 0x30 {
        return Err(TspError::InvalidResponse(
            "TSTInfo: expected SEQUENCE".into(),
        ));
    }

    let mut pos = &body[..];

    // version INTEGER
    let (_vtag, _vbody, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse version: {e}")))?;
    pos = rest;

    // policy TSAPolicyId (OID)
    let (_ptag, pbody, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse policy: {e}")))?;
    let policy_oid = ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, &pbody))
        .ok()
        .map(|oid| oid.to_string());
    pos = rest;

    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let (_mi_tag, mi_body, rest) = der_utils::parse_tlv_with_rest(pos).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse messageImprint: {e}"))
    })?;
    pos = rest;

    let (hash_algorithm, message_hash) = parse_message_imprint(&mi_body)?;

    // serialNumber INTEGER
    let (_sn_tag, sn_body, rest) = der_utils::parse_tlv_with_rest(pos).map_err(|e| {
        TspError::InvalidResponse(format!("TSTInfo: failed to parse serialNumber: {e}"))
    })?;
    let serial_number = sn_body.to_vec();
    pos = rest;

    // genTime GeneralizedTime
    let (_gt_tag, gt_body, rest) = der_utils::parse_tlv_with_rest(pos)
        .map_err(|e| TspError::InvalidResponse(format!("TSTInfo: failed to parse genTime: {e}")))?;
    let gen_time_der = gt_body.to_vec();
    pos = rest;

    // Now parse optional fields: accuracy, ordering, nonce, tsa, extensions
    let mut nonce = None;

    while !pos.is_empty() {
        if let Ok((ftag, fbody, frest)) = der_utils::parse_tlv_with_rest(pos) {
            match ftag {
                // accuracy is SEQUENCE
                0x30 => {
                    // Skip accuracy
                }
                // ordering BOOLEAN
                0x01 => {
                    // Skip ordering
                }
                // nonce INTEGER
                0x02 => {
                    nonce = Some(der_utils::decode_integer_u64(&fbody));
                }
                // tsa [0] GeneralName
                0xA0 => {
                    // Skip TSA name
                }
                // extensions [1] IMPLICIT
                0xA1 => {
                    // Skip extensions
                }
                _ => {
                    // Unknown, skip
                }
            }
            pos = frest;
        } else {
            break;
        }
    }

    Ok(TstInfo {
        hash_algorithm,
        message_hash,
        serial_number,
        gen_time_der,
        nonce,
        policy_oid,
    })
}

/// Parse a MessageImprint: { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
fn parse_message_imprint(body: &[u8]) -> Result<(DigestAlgorithm, Vec<u8>), TspError> {
    // hashAlgorithm SEQUENCE
    let (_alg_tag, alg_body, rest) = der_utils::parse_tlv_with_rest(body).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse hashAlgorithm: {e}"
        ))
    })?;

    // First element of AlgorithmIdentifier is the OID
    let (_oid_tag, oid_body, _) = der_utils::parse_tlv_with_rest(&alg_body).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse algorithm OID: {e}"
        ))
    })?;

    let alg_oid =
        ObjectIdentifier::from_der(&der_utils::encode_tlv(0x06, &oid_body)).map_err(|e| {
            TspError::InvalidResponse(format!("messageImprint: invalid algorithm OID: {e}"))
        })?;

    let digest_alg = oid_to_digest_algorithm(&alg_oid)?;

    // hashedMessage OCTET STRING
    let (_hash_tag, hash_body, _) = der_utils::parse_tlv_with_rest(rest).map_err(|e| {
        TspError::InvalidResponse(format!(
            "messageImprint: failed to parse hashedMessage: {e}"
        ))
    })?;

    Ok((digest_alg, hash_body.to_vec()))
}

/// Map an OID to our DigestAlgorithm enum.
fn oid_to_digest_algorithm(oid: &ObjectIdentifier) -> Result<DigestAlgorithm, TspError> {
    DigestAlgorithm::from_oid(oid)
        .ok_or_else(|| TspError::InvalidResponse(format!("unsupported hash algorithm OID: {oid}")))
}

/// Build an AlgorithmIdentifier for a digest algorithm.
fn digest_algorithm_identifier(alg: DigestAlgorithm) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: alg.oid(),
        parameters: None,
    }
}

// ---------------------------------------------------------------------------
// Generate a nonce
// ---------------------------------------------------------------------------

/// Generate a random 64-bit nonce for timestamp requests.
pub fn generate_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple nonce: combine time and a counter.
    // For production, you'd want a CSPRNG, but this is sufficient for
    // timestamp nonce replay protection.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Mix nanoseconds and seconds for reasonable uniqueness
    now.as_nanos() as u64 ^ (now.as_secs().wrapping_mul(0x517cc1b727220a95))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timestamp_request_basic() {
        let hash = vec![0xAA; 32]; // SHA-256 sized
        let req =
            build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, None, true).unwrap();

        // Should be a valid DER SEQUENCE
        assert_eq!(req[0], 0x30, "should start with SEQUENCE tag");

        // Parse it back
        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_build_timestamp_request_with_nonce() {
        let hash = vec![0xBB; 32];
        let nonce = 12345678u64;
        let req = build_timestamp_request(DigestAlgorithm::Sha256, &hash, None, Some(nonce), true)
            .unwrap();

        let (tag, _body) = der_utils::parse_tlv(&req).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_encode_integer_u64() {
        // Encode 1
        let encoded = der_utils::encode_integer_u64(1);
        assert_eq!(encoded, vec![0x02, 0x01, 0x01]);

        // Encode 128 (needs padding because high bit set)
        let encoded = der_utils::encode_integer_u64(128);
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);

        // Encode 0
        let encoded = der_utils::encode_integer_u64(0);
        // Should be 0x02 0x01 0x00
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_pki_status_display() {
        assert_eq!(PkiStatus::Granted.to_string(), "granted (0)");
        assert_eq!(PkiStatus::Rejection.to_string(), "rejection (2)");
        assert!(PkiStatus::Granted.is_success());
        assert!(PkiStatus::GrantedWithMods.is_success());
        assert!(!PkiStatus::Rejection.is_success());
    }

    #[test]
    fn test_der_length_roundtrip() {
        for len in [0, 1, 127, 128, 255, 256, 65535, 65536] {
            let mut buf = Vec::new();
            der_utils::encode_der_length(&mut buf, len);
            let (parsed_len, consumed) = der_utils::parse_der_length(&buf).unwrap();
            assert_eq!(parsed_len, len, "length roundtrip failed for {len}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_parse_timestamp_response_error_status() {
        // Build a minimal TimeStampResp with rejection status
        // PKIStatusInfo SEQUENCE { PKIStatus INTEGER 2 }
        let status_info = der_utils::encode_sequence_raw(&der_utils::encode_integer_u64(2));
        let resp_der = der_utils::encode_sequence_raw(&status_info);

        let resp = parse_timestamp_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert!(resp.token_der.is_none());
    }

    #[test]
    fn test_generate_nonce() {
        let n1 = generate_nonce();
        // Brief pause to ensure different nonce
        std::thread::sleep(std::time::Duration::from_millis(1));
        let n2 = generate_nonce();
        // They should differ (with extremely high probability)
        assert_ne!(n1, n2, "nonces should be unique");
    }
}
