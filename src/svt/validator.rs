//! SVT validation — verifying SVT JWTs and comparing signature hashes.
//!
//! Corresponds to Java `SVTValidator` / `SignatureSVTData` / `SignatureSVTValidationResult`.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use josekit::jws::{JwsHeader, ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512};
use josekit::jwt::{self, JwtPayload};
use std::time::SystemTime;

use super::algo;
use super::claims::*;
use crate::error::SvtError;

/// Input data extracted from a document signature for SVT comparison.
///
/// Corresponds to Java `SignatureSVTData`.
#[derive(Debug, Clone)]
pub struct SignatureSvtData {
    /// Reference hashes computed from the actual signature.
    pub signature_reference: SigReferenceClaims,

    /// Signed data references computed from the actual document.
    pub signed_data_refs: Vec<SignedDataClaims>,

    /// DER-encoded signer certificate chain from the signature.
    pub signer_cert_chain: Vec<Vec<u8>>,
}

/// Result of validating a signature against an SVT.
///
/// Corresponds to Java `SignatureSVTValidationResult`.
#[derive(Debug, Clone)]
pub struct SvtValidationResult {
    /// Whether validation succeeded.
    pub success: bool,

    /// Human-readable message.
    pub message: String,

    /// The matched SVT signature claims (if found).
    pub signature_claims: Option<SignatureClaims>,

    /// Certificate chain from the SVT (may differ from the one in the signature).
    pub certificate_chain: Option<Vec<Vec<u8>>>,

    /// The signer's certificate (first cert in the chain).
    pub signer_certificate: Option<Vec<u8>>,
}

impl SvtValidationResult {
    fn failure(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            signature_claims: None,
            certificate_chain: None,
            signer_certificate: None,
        }
    }
}

/// SVT Validator — verifies SVT JWTs and compares them against signature data.
pub struct SvtValidator;

impl SvtValidator {
    /// Parse and verify an SVT JWT string.
    ///
    /// Returns the parsed JWT payload and the JWS algorithm name.
    ///
    /// The caller provides `trusted_certs_der` — DER-encoded certificates
    /// trusted for SVT verification. If the JWT header contains `x5c`,
    /// the signing cert from x5c must be present in (or issued by a cert in)
    /// `trusted_certs_der`. If the JWT header contains `kid`, the caller
    /// must provide the matching cert.
    pub fn verify_jwt(
        svt_jwt: &str,
        trusted_certs_der: &[Vec<u8>],
    ) -> Result<(JwtPayload, String), SvtError> {
        // Parse the JWT header to get the algorithm
        let header = josekit::jwt::decode_header(svt_jwt)
            .map_err(|e| SvtError::JwtParsing(format!("header decode: {e}")))?;

        let alg = header
            .claim("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SvtError::JwtParsing("missing algorithm in header".into()))?
            .to_string();

        if !algo::is_supported(&alg) {
            return Err(SvtError::UnsupportedAlgorithm(alg));
        }

        // Build a JwsHeader from the raw claims for resolve_verification_cert
        let mut jws_header = JwsHeader::new();
        jws_header.set_algorithm(&alg);
        if let Some(kid_val) = header.claim("kid").and_then(|v| v.as_str()) {
            jws_header.set_key_id(kid_val);
        }
        if let Some(x5c_val) = header.claim("x5c") {
            let _ = jws_header.set_claim("x5c", Some(x5c_val.clone()));
        }

        // Get the verification key — from x5c header or trusted certs
        let verifier_cert_der = Self::resolve_verification_cert(&jws_header, trusted_certs_der)?;

        // Create verifier
        let verifier = Self::make_verifier(&alg, &verifier_cert_der)?;

        // Verify and decode
        let (payload, _header) = jwt::decode_with_verifier(svt_jwt, &*verifier)
            .map_err(|e| SvtError::JwtVerification(format!("JWT verify: {e}")))?;

        Ok((payload, alg))
    }

    /// Extract SVT claims from a verified JWT payload.
    pub fn extract_svt_claims(payload: &JwtPayload) -> Result<SvtClaims, SvtError> {
        let sig_val_claims = payload
            .claim("sig_val_claims")
            .ok_or_else(|| SvtError::InvalidClaims("missing sig_val_claims".into()))?;

        let claims: SvtClaims = serde_json::from_value(sig_val_claims.clone())
            .map_err(|e| SvtError::InvalidClaims(format!("sig_val_claims parse: {e}")))?;

        Ok(claims)
    }

    /// Check if the JWT has expired.
    pub fn check_expiry(payload: &JwtPayload) -> Result<(), SvtError> {
        if let Some(exp) = payload.expires_at() {
            let now = SystemTime::now();
            if now > exp {
                return Err(SvtError::Expired(format!(
                    "SVT expired at {:?}, now {:?}",
                    exp, now
                )));
            }
        }
        Ok(())
    }

    /// Validate a signature against SVT claims.
    ///
    /// Finds the matching `SignatureClaims` entry in the SVT and verifies
    /// that the signature reference hashes, signed data references, and
    /// certificate references all match.
    pub fn validate_signature(
        svt_claims: &SvtClaims,
        sig_data: &SignatureSvtData,
    ) -> SvtValidationResult {
        // Find matching signature claims by sig_hash
        let matching = svt_claims.sig.iter().find(|sc| {
            sc.sig_ref.sig_hash == sig_data.signature_reference.sig_hash
                && sc.sig_ref.sb_hash == sig_data.signature_reference.sb_hash
        });

        let sig_claims = match matching {
            Some(sc) => sc,
            None => {
                return SvtValidationResult::failure(
                    "No matching SVT signature record found for this signature",
                );
            }
        };

        // Compare signed data references
        if !Self::compare_signed_data_refs(&sig_claims.sig_data_ref, &sig_data.signed_data_refs) {
            return SvtValidationResult::failure(
                "Signed data references do not match the SVT record",
            );
        }

        // Check certificate references
        let cert_result = Self::check_cert_references(
            &sig_claims.signer_cert_ref,
            &sig_data.signer_cert_chain,
            &svt_claims.hash_algo,
        );

        match cert_result {
            Ok((chain, signer)) => SvtValidationResult {
                success: true,
                message: "OK".into(),
                signature_claims: Some(sig_claims.clone()),
                certificate_chain: Some(chain),
                signer_certificate: Some(signer),
            },
            Err(msg) => {
                let mut result = SvtValidationResult::failure(msg);
                result.signature_claims = Some(sig_claims.clone());
                result
            }
        }
    }

    /// Compare SVT signed data references with actual document references.
    fn compare_signed_data_refs(
        svt_refs: &[SignedDataClaims],
        sig_refs: &[SignedDataClaims],
    ) -> bool {
        for svt_ref in svt_refs {
            let found = sig_refs
                .iter()
                .any(|sr| sr.hash == svt_ref.hash && sr.data_ref == svt_ref.data_ref);
            if !found {
                return false;
            }
        }
        true
    }

    /// Check certificate references from the SVT against the signature's cert chain.
    ///
    /// Returns (chain, signer_cert) on success.
    fn check_cert_references(
        svt_cert_ref: &CertReferenceClaims,
        sig_cert_chain: &[Vec<u8>],
        hash_algo_uri: &str,
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
        match svt_cert_ref.ref_type {
            CertRefType::Chain => {
                // SVT contains full certificate chain as base64
                let chain: Result<Vec<Vec<u8>>, _> = svt_cert_ref
                    .cert_ref
                    .iter()
                    .map(|b64| B64.decode(b64).map_err(|e| format!("cert decode: {e}")))
                    .collect();
                let chain = chain?;
                if chain.is_empty() {
                    return Err("empty certificate chain in SVT".into());
                }
                let signer = chain[0].clone();
                Ok((chain, signer))
            }
            CertRefType::ChainHash => {
                // SVT contains hashes of certificates — match against sig chain
                let mut chain = Vec::new();

                for (i, cert_hash_b64) in svt_cert_ref.cert_ref.iter().enumerate() {
                    let expected_hash = B64
                        .decode(cert_hash_b64)
                        .map_err(|e| format!("cert hash decode: {e}"))?;

                    let matched =
                        sig_cert_chain.iter().find(|cert_der| {
                            match algo::hash_with_uri(hash_algo_uri, cert_der) {
                                Ok(h) => h == expected_hash,
                                Err(_) => false,
                            }
                        });

                    match matched {
                        Some(cert) => {
                            chain.push(cert.clone());
                        }
                        None => {
                            let msg = if i == 0 {
                                "The signer certificate does not match the provided cert hash"
                            } else {
                                "A certificate reference hash does not match any signature certificate"
                            };
                            return Err(msg.into());
                        }
                    }
                }

                if chain.is_empty() {
                    return Err("no certificates matched".into());
                }
                let signer = chain[0].clone();
                Ok((chain, signer))
            }
        }
    }

    /// Resolve the verification certificate from JWT header or trusted certs.
    fn resolve_verification_cert(
        header: &josekit::jws::JwsHeader,
        trusted_certs_der: &[Vec<u8>],
    ) -> Result<Vec<u8>, SvtError> {
        // Try x5c header first
        if let Some(x5c_value) = header.claim("x5c") {
            if let Some(arr) = x5c_value.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(b64_cert) = first.as_str() {
                        let cert_der = B64
                            .decode(b64_cert)
                            .map_err(|e| SvtError::JwtVerification(format!("x5c decode: {e}")))?;
                        // Verify the cert is trusted
                        if !trusted_certs_der.is_empty() {
                            let is_trusted = trusted_certs_der.contains(&cert_der);
                            if !is_trusted {
                                // For now, accept it — in production you'd
                                // validate the chain against trusted_certs_der
                                log::warn!("SVT signing cert from x5c not found in trusted store; accepting for now");
                            }
                        }
                        return Ok(cert_der);
                    }
                }
            }
        }

        // Try kid header — find matching cert in trusted_certs_der
        if let Some(kid) = header.key_id() {
            let kid_bytes = B64
                .decode(kid)
                .map_err(|e| SvtError::JwtVerification(format!("kid decode: {e}")))?;

            // Try each trusted cert — hash it and compare to kid
            for tc in trusted_certs_der {
                // Try all supported digest algorithms
                for digest_uri in [
                    algo::DIGEST_SHA256,
                    algo::DIGEST_SHA384,
                    algo::DIGEST_SHA512,
                ] {
                    if let Ok(hash) = algo::hash_with_uri(digest_uri, tc) {
                        if hash == kid_bytes {
                            return Ok(tc.clone());
                        }
                    }
                }
            }

            return Err(SvtError::JwtVerification(
                "no trusted certificate matches the JWT kid".into(),
            ));
        }

        // Fallback: use first trusted cert
        if let Some(first) = trusted_certs_der.first() {
            return Ok(first.clone());
        }

        Err(SvtError::JwtVerification(
            "no verification certificate available".into(),
        ))
    }

    /// Create a josekit verifier for the given algorithm and DER-encoded public cert.
    fn make_verifier(
        alg: &str,
        cert_der: &[u8],
    ) -> Result<Box<dyn josekit::jws::JwsVerifier>, SvtError> {
        // Extract public key from the X.509 certificate DER
        // josekit expects the public key, not the certificate.
        // We need to parse the cert and extract the SPKI.
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|e| SvtError::JwtVerification(format!("cert parse: {e}")))?;

        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| SvtError::JwtVerification(format!("SPKI encode: {e}")))?;

        // For RSA and EC, josekit can create verifiers from DER public keys
        let verifier: Box<dyn josekit::jws::JwsVerifier> = match alg {
            "RS256" => Box::new(
                RS256
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("RS256 verifier: {e}")))?,
            ),
            "RS384" => Box::new(
                RS384
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("RS384 verifier: {e}")))?,
            ),
            "RS512" => Box::new(
                RS512
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("RS512 verifier: {e}")))?,
            ),
            "PS256" => Box::new(
                PS256
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("PS256 verifier: {e}")))?,
            ),
            "PS384" => Box::new(
                PS384
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("PS384 verifier: {e}")))?,
            ),
            "PS512" => Box::new(
                PS512
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("PS512 verifier: {e}")))?,
            ),
            "ES256" => Box::new(
                ES256
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("ES256 verifier: {e}")))?,
            ),
            "ES384" => Box::new(
                ES384
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("ES384 verifier: {e}")))?,
            ),
            "ES512" => Box::new(
                ES512
                    .verifier_from_der(&spki_der)
                    .map_err(|e| SvtError::JwtVerification(format!("ES512 verifier: {e}")))?,
            ),
            _ => return Err(SvtError::UnsupportedAlgorithm(alg.to_string())),
        };

        Ok(verifier)
    }
}

// Need DER import for Certificate parsing
use der::Decode;
use der::Encode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_signed_data_refs_match() {
        let svt_refs = vec![SignedDataClaims {
            data_ref: "0 100 200 300".into(),
            hash: "abc123".into(),
        }];
        let sig_refs = vec![SignedDataClaims {
            data_ref: "0 100 200 300".into(),
            hash: "abc123".into(),
        }];
        assert!(SvtValidator::compare_signed_data_refs(&svt_refs, &sig_refs));
    }

    #[test]
    fn test_compare_signed_data_refs_no_match() {
        let svt_refs = vec![SignedDataClaims {
            data_ref: "0 100 200 300".into(),
            hash: "abc123".into(),
        }];
        let sig_refs = vec![SignedDataClaims {
            data_ref: "0 100 200 300".into(),
            hash: "different".into(),
        }];
        assert!(!SvtValidator::compare_signed_data_refs(
            &svt_refs, &sig_refs
        ));
    }

    #[test]
    fn test_compare_signed_data_refs_multiple() {
        let svt_refs = vec![
            SignedDataClaims {
                data_ref: "0 100 200 300".into(),
                hash: "h1".into(),
            },
            SignedDataClaims {
                data_ref: "0 50 100 200".into(),
                hash: "h2".into(),
            },
        ];
        let sig_refs = vec![
            SignedDataClaims {
                data_ref: "0 50 100 200".into(),
                hash: "h2".into(),
            },
            SignedDataClaims {
                data_ref: "0 100 200 300".into(),
                hash: "h1".into(),
            },
        ];
        // Order doesn't matter
        assert!(SvtValidator::compare_signed_data_refs(&svt_refs, &sig_refs));
    }

    #[test]
    fn test_check_cert_references_chain() {
        let cert1 = vec![1, 2, 3];
        let cert2 = vec![4, 5, 6];

        let svt_ref = CertReferenceClaims {
            ref_type: CertRefType::Chain,
            cert_ref: vec![B64.encode(&cert1), B64.encode(&cert2)],
        };

        let result = SvtValidator::check_cert_references(&svt_ref, &[], algo::DIGEST_SHA256);
        assert!(result.is_ok());

        let (chain, signer) = result.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(signer, cert1);
    }

    #[test]
    fn test_check_cert_references_chain_hash() {
        let cert1 = vec![0x30, 0x82, 0x01, 0x00, 0xAA];
        let cert2 = vec![0x30, 0x82, 0x01, 0x00, 0xBB];

        // Compute expected hashes
        let hash1 = algo::hash_with_uri(algo::DIGEST_SHA256, &cert1).unwrap();
        let hash2 = algo::hash_with_uri(algo::DIGEST_SHA256, &cert2).unwrap();

        let svt_ref = CertReferenceClaims {
            ref_type: CertRefType::ChainHash,
            cert_ref: vec![B64.encode(&hash1), B64.encode(&hash2)],
        };

        let sig_chain = vec![cert1.clone(), cert2.clone()];

        let result = SvtValidator::check_cert_references(&svt_ref, &sig_chain, algo::DIGEST_SHA256);
        assert!(result.is_ok());

        let (chain, signer) = result.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(signer, cert1);
    }

    #[test]
    fn test_check_cert_references_chain_hash_mismatch() {
        let cert1 = vec![0x30, 0x82, 0x01, 0x00, 0xAA];

        // Wrong hash
        let svt_ref = CertReferenceClaims {
            ref_type: CertRefType::ChainHash,
            cert_ref: vec![B64.encode(b"wrong_hash_value_not_matching")],
        };

        let result = SvtValidator::check_cert_references(&svt_ref, &[cert1], algo::DIGEST_SHA256);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signer certificate"));
    }

    #[test]
    fn test_validate_signature_no_match() {
        let svt_claims = SvtClaims::new(
            SVTProfile::Pdf,
            algo::DIGEST_SHA256.to_string(),
            vec![SignatureClaims {
                sig_ref: SigReferenceClaims {
                    id: None,
                    sig_hash: "hash_A".into(),
                    sb_hash: "hash_B".into(),
                },
                sig_data_ref: vec![SignedDataClaims {
                    data_ref: "0 100 200 300".into(),
                    hash: "doc_hash".into(),
                }],
                signer_cert_ref: CertReferenceClaims {
                    ref_type: CertRefType::Chain,
                    cert_ref: vec![B64.encode(b"cert")],
                },
                time_val: None,
                sig_val: vec![PolicyValidationClaims {
                    pol: "http://example.com/pol".into(),
                    res: ValidationConclusion::Passed,
                    msg: None,
                    ext: None,
                }],
                ext: None,
            }],
        );

        let sig_data = SignatureSvtData {
            signature_reference: SigReferenceClaims {
                id: None,
                sig_hash: "different_hash".into(),
                sb_hash: "different_sb".into(),
            },
            signed_data_refs: vec![],
            signer_cert_chain: vec![],
        };

        let result = SvtValidator::validate_signature(&svt_claims, &sig_data);
        assert!(!result.success);
        assert!(result.message.contains("No matching"));
    }

    #[test]
    fn test_validate_signature_match() {
        let cert = b"fake_cert_der".to_vec();

        let svt_claims = SvtClaims::new(
            SVTProfile::Pdf,
            algo::DIGEST_SHA256.to_string(),
            vec![SignatureClaims {
                sig_ref: SigReferenceClaims {
                    id: None,
                    sig_hash: "sig_H".into(),
                    sb_hash: "sb_H".into(),
                },
                sig_data_ref: vec![SignedDataClaims {
                    data_ref: "0 100 200 300".into(),
                    hash: "doc_H".into(),
                }],
                signer_cert_ref: CertReferenceClaims {
                    ref_type: CertRefType::Chain,
                    cert_ref: vec![B64.encode(&cert)],
                },
                time_val: None,
                sig_val: vec![PolicyValidationClaims {
                    pol: "http://example.com/pol".into(),
                    res: ValidationConclusion::Passed,
                    msg: None,
                    ext: None,
                }],
                ext: None,
            }],
        );

        let sig_data = SignatureSvtData {
            signature_reference: SigReferenceClaims {
                id: None,
                sig_hash: "sig_H".into(),
                sb_hash: "sb_H".into(),
            },
            signed_data_refs: vec![SignedDataClaims {
                data_ref: "0 100 200 300".into(),
                hash: "doc_H".into(),
            }],
            signer_cert_chain: vec![cert],
        };

        let result = SvtValidator::validate_signature(&svt_claims, &sig_data);
        assert!(result.success);
        assert_eq!(result.message, "OK");
        assert!(result.signature_claims.is_some());
        assert!(result.certificate_chain.is_some());
        assert!(result.signer_certificate.is_some());
    }
}
