//! Shared signature verification functions.
//!
//! Extracted from `trust/store.rs` so that CRL, OCSP, and chain
//! verification can all reuse the same cryptographic primitives.
//!
//! Supports:
//! - RSA PKCS#1 v1.5 with SHA-256, SHA-384, SHA-512
//! - RSA-PSS (RSASSA-PSS) with SHA-256, SHA-384, SHA-512
//! - ECDSA P-256 with SHA-256
//! - ECDSA P-384 with SHA-384
//! - Ed25519

use crate::crypto::algorithm::{OID_ED25519, OID_RSASSA_PSS};
use crate::error::TrustError;

/// Verify a raw signature over `tbs_bytes` using the signer's SPKI (DER)
/// and the given signature algorithm OID.
///
/// This is the primary entry point — it dispatches to the correct
/// algorithm based on the OID.
///
/// # Supported algorithms
///
/// | OID | Algorithm |
/// |-----|-----------|
/// | `1.2.840.113549.1.1.11` | SHA-256 with RSA |
/// | `1.2.840.113549.1.1.12` | SHA-384 with RSA |
/// | `1.2.840.113549.1.1.13` | SHA-512 with RSA |
/// | `1.2.840.113549.1.1.10` | RSASSA-PSS (tries SHA-256/384/512) |
/// | `1.2.840.10045.4.3.2`   | ECDSA with SHA-256 |
/// | `1.2.840.10045.4.3.3`   | ECDSA with SHA-384 |
/// | `1.3.101.112`           | Ed25519 |
pub fn verify_signature_by_oid(
    tbs_bytes: &[u8],
    signature_bytes: &[u8],
    spki_der: &[u8],
    sig_alg_oid: &const_oid::ObjectIdentifier,
) -> Result<(), TrustError> {
    use const_oid::db;

    if *sig_alg_oid == db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha256>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha384>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_signature::<sha2::Sha512>(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == OID_RSASSA_PSS {
        // RSA-PSS: AlgorithmIdentifier parameters should specify the hash,
        // but here we only have the OID. Try SHA-256 first, then SHA-384, SHA-512.
        verify_rsa_pss_signature::<sha2::Sha256>(tbs_bytes, signature_bytes, spki_der)
            .or_else(|_| {
                verify_rsa_pss_signature::<sha2::Sha384>(tbs_bytes, signature_bytes, spki_der)
            })
            .or_else(|_| {
                verify_rsa_pss_signature::<sha2::Sha512>(tbs_bytes, signature_bytes, spki_der)
            })
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_256 {
        verify_ecdsa_p256_signature(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == db::rfc5912::ECDSA_WITH_SHA_384 {
        verify_ecdsa_p384_signature(tbs_bytes, signature_bytes, spki_der)
    } else if *sig_alg_oid == OID_ED25519 {
        verify_ed25519_signature(tbs_bytes, signature_bytes, spki_der)
    } else {
        Err(TrustError::UnsupportedAlgorithm(format!(
            "signature algorithm OID: {sig_alg_oid}"
        )))
    }
}

/// Verify a certificate's signature against its issuer's public key.
///
/// Encodes the TBS portion and checks the outer signature using
/// [`verify_signature_by_oid`].
pub fn verify_certificate_signature(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<(), TrustError> {
    use der::Encode;

    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("TBS encoding failed: {e}")))?;
    let signature_bytes = cert.signature.raw_bytes();
    let sig_alg_oid = &cert.signature_algorithm.oid;

    let spki_der = issuer_spki
        .to_der()
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI encoding failed: {e}")))?;

    verify_signature_by_oid(&tbs_bytes, signature_bytes, &spki_der, sig_alg_oid)
}

/// Verify an RSA PKCS#1 v1.5 signature over `tbs` using the given SPKI.
pub fn verify_rsa_signature<D: digest::Digest + const_oid::AssociatedOid>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(tbs);
    let scheme = Pkcs1v15Sign::new::<D>();
    pub_key
        .verify(scheme, &hash, sig)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA signature invalid: {e}")))
}

/// Verify an RSA-PSS (RSASSA-PSS) signature over `tbs` using the given SPKI.
pub fn verify_rsa_pss_signature<
    D: digest::Digest + digest::FixedOutputReset + Default + Clone + Send + Sync + 'static,
>(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use rsa::pss::Pss;
    use rsa::RsaPublicKey;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let pub_key = RsaPublicKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA key decode failed: {e}")))?;

    let hash = D::digest(tbs);
    let scheme = Pss::new::<D>();
    pub_key
        .verify(scheme, &hash, sig)
        .map_err(|e| TrustError::SignatureVerification(format!("RSA-PSS signature invalid: {e}")))
}

/// Verify an ECDSA P-256 (SHA-256) signature.
pub fn verify_ecdsa_p256_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-256 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-256 invalid: {e}")))
}

/// Verify an ECDSA P-384 (SHA-384) signature.
pub fn verify_ecdsa_p384_signature(
    tbs: &[u8],
    sig: &[u8],
    spki_der: &[u8],
) -> Result<(), TrustError> {
    use der::Decode;
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let vk = VerifyingKey::try_from(spki)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 key decode failed: {e}")))?;
    let signature = Signature::from_der(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("P-384 sig decode failed: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("ECDSA P-384 invalid: {e}")))
}

/// Verify an Ed25519 signature.
pub fn verify_ed25519_signature(tbs: &[u8], sig: &[u8], spki_der: &[u8]) -> Result<(), TrustError> {
    use der::Decode;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TrustError::SignatureVerification(format!("SPKI decode failed: {e}")))?;
    let key_bytes = spki.subject_public_key.raw_bytes();
    let vk = VerifyingKey::try_from(key_bytes)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 key decode: {e}")))?;
    let signature = Signature::from_slice(sig)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 sig decode: {e}")))?;

    vk.verify(tbs, &signature)
        .map_err(|e| TrustError::SignatureVerification(format!("Ed25519 invalid: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use x509_cert::Certificate;

    fn load_test_cert(pem_str: &str) -> Certificate {
        let (_, der) = pem_rfc7468::decode_vec(pem_str.as_bytes()).unwrap();
        Certificate::from_der(&der).unwrap()
    }

    #[test]
    fn test_verify_certificate_signature_ca_self_signed() {
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);
        // Self-signed: issuer == subject
        let result = verify_certificate_signature(&ca, &ca);
        assert!(
            result.is_ok(),
            "CA self-signature should verify: {result:?}"
        );
    }

    #[test]
    fn test_verify_certificate_signature_chain() {
        let ca_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca_cert.pem"
        ));
        let intermediate_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/intermediate_ca_cert.pem"
        ));
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let ca = load_test_cert(ca_pem);
        let intermediate = load_test_cert(intermediate_pem);
        let signer = load_test_cert(signer_pem);

        // Signer is issued by intermediate
        let result = verify_certificate_signature(&signer, &intermediate);
        assert!(
            result.is_ok(),
            "signer cert should verify against intermediate: {result:?}"
        );

        // Intermediate is issued by CA
        let result = verify_certificate_signature(&intermediate, &ca);
        assert!(
            result.is_ok(),
            "intermediate cert should verify against CA: {result:?}"
        );
    }

    #[test]
    fn test_verify_certificate_signature_wrong_issuer() {
        let signer_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signer_cert.pem"
        ));
        let signer = load_test_cert(signer_pem);

        // Self-verify should fail (signer is not self-signed)
        let result = verify_certificate_signature(&signer, &signer);
        assert!(result.is_err(), "wrong issuer should fail verification");
    }

    #[test]
    fn test_unsupported_algorithm_oid() {
        let fake_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        let result = verify_signature_by_oid(b"tbs", b"sig", b"spki", &fake_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unsupported"),
            "error should mention unsupported: {err_msg}"
        );
    }

    #[test]
    fn test_rsassa_pss_oid_dispatches() {
        // Even with bad data, the RSA-PSS branch should be reached (not "unsupported")
        let pss_oid = OID_RSASSA_PSS;
        let result = verify_signature_by_oid(b"tbs", b"sig", b"bad_spki", &pss_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        // Should fail at SPKI decode, not "unsupported algorithm"
        assert!(
            !err_msg.contains("unsupported"),
            "RSA-PSS should be dispatched, not unsupported: {err_msg}"
        );
    }

    #[test]
    fn test_ed25519_oid_dispatches() {
        let ed_oid = OID_ED25519;
        let result = verify_signature_by_oid(b"tbs", b"sig", b"bad_spki", &ed_oid);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            !err_msg.contains("unsupported"),
            "Ed25519 should be dispatched, not unsupported: {err_msg}"
        );
    }
}
