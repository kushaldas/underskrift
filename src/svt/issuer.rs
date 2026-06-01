//! SVT issuance — building and signing SVT JWTs.
//!
//! Corresponds to Java `SVTIssuer` / `SVTModel` in svt-core.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use josekit::jws::{JwsHeader, ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512};
use josekit::jwt::{self, JwtPayload};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use super::algo;
use super::claims::*;
use crate::error::SvtError;

/// Configuration model for SVT issuance.
///
/// Corresponds to Java `SVTModel`.
pub struct SvtModel {
    /// Unique identifier of the SVT issuer (becomes JWT `iss` claim).
    pub issuer_id: String,

    /// Validity period in seconds. If `None`, no `exp` claim is set.
    pub validity_period: Option<u64>,

    /// Audience identifiers. If empty, no `aud` claim is set.
    pub audience: Vec<String>,

    /// If `true`, reference certificates by hash instead of embedding
    /// the full chain in the JWT header `x5c`.
    pub cert_ref_by_hash: bool,
}

impl SvtModel {
    /// Create a builder for `SvtModel`.
    pub fn builder() -> SvtModelBuilder {
        SvtModelBuilder::default()
    }
}

/// Builder for [`SvtModel`].
#[derive(Default)]
pub struct SvtModelBuilder {
    issuer_id: Option<String>,
    validity_period: Option<u64>,
    audience: Vec<String>,
    cert_ref_by_hash: bool,
}

impl SvtModelBuilder {
    pub fn issuer_id(mut self, id: impl Into<String>) -> Self {
        self.issuer_id = Some(id.into());
        self
    }

    pub fn validity_period(mut self, seconds: u64) -> Self {
        self.validity_period = Some(seconds);
        self
    }

    pub fn audience(mut self, aud: Vec<String>) -> Self {
        self.audience = aud;
        self
    }

    pub fn cert_ref_by_hash(mut self, by_hash: bool) -> Self {
        self.cert_ref_by_hash = by_hash;
        self
    }

    pub fn build(self) -> SvtModel {
        SvtModel {
            issuer_id: self.issuer_id.unwrap_or_default(),
            validity_period: self.validity_period,
            audience: self.audience,
            cert_ref_by_hash: self.cert_ref_by_hash,
        }
    }
}

/// SVT Issuer — creates signed SVT JWTs.
///
/// The issuer holds the signing key, certificate chain, and JWS algorithm.
/// It does NOT perform signature verification itself — the caller must
/// provide pre-built [`SignatureClaims`] from their verification pipeline.
pub struct SvtIssuer {
    /// JWS algorithm name (e.g., "RS256", "ES256").
    jws_algorithm: String,

    /// PEM or DER-encoded private key for JWT signing.
    /// Stored as raw bytes; interpreted by josekit based on algorithm.
    private_key_der: Vec<u8>,

    /// DER-encoded certificate chain (signing cert first).
    certificate_chain_der: Vec<Vec<u8>>,
}

impl SvtIssuer {
    /// Create a new SVT issuer.
    ///
    /// # Arguments
    /// - `jws_algorithm`: JWS algorithm name (RS256, ES256, PS256, etc.)
    /// - `private_key_der`: PKCS#8 DER-encoded private key
    /// - `certificate_chain_der`: DER-encoded X.509 certificates (signing cert first)
    pub fn new(
        jws_algorithm: &str,
        private_key_der: Vec<u8>,
        certificate_chain_der: Vec<Vec<u8>>,
    ) -> Result<Self, SvtError> {
        if !algo::is_supported(jws_algorithm) {
            return Err(SvtError::UnsupportedAlgorithm(jws_algorithm.to_string()));
        }
        Ok(Self {
            jws_algorithm: jws_algorithm.to_string(),
            private_key_der,
            certificate_chain_der,
        })
    }

    /// Get the digest algorithm URI associated with this issuer's JWS algorithm.
    pub fn digest_algo_uri(&self) -> &'static str {
        // Safe: we validated in new()
        algo::digest_uri_for_jws(&self.jws_algorithm).unwrap()
    }

    /// Build a certificate reference claims object.
    ///
    /// If `by_hash` is true, produces `chain_hash` with hashes of the certs.
    /// Otherwise, produces `chain` with base64-encoded full certs.
    pub fn build_cert_ref(
        &self,
        cert_chain_der: &[Vec<u8>],
        by_hash: bool,
    ) -> Result<CertReferenceClaims, SvtError> {
        if by_hash {
            let digest_uri = self.digest_algo_uri();
            let refs: Result<Vec<String>, _> = cert_chain_der
                .iter()
                .map(|cert_der| {
                    let hash = algo::hash_with_uri(digest_uri, cert_der)?;
                    Ok(B64.encode(&hash))
                })
                .collect();
            Ok(CertReferenceClaims {
                ref_type: CertRefType::ChainHash,
                cert_ref: refs?,
            })
        } else {
            let refs: Vec<String> = cert_chain_der.iter().map(|c| B64.encode(c)).collect();
            Ok(CertReferenceClaims {
                ref_type: CertRefType::Chain,
                cert_ref: refs,
            })
        }
    }

    /// Create a signed SVT JWT from pre-built signature claims.
    ///
    /// This is the main entry point. The caller must build `SignatureClaims`
    /// from their verification pipeline. This function wraps them into the
    /// full JWT structure with standard claims (`iss`, `iat`, `jti`, etc.)
    /// and signs the JWT.
    pub fn issue(
        &self,
        signature_claims: Vec<SignatureClaims>,
        model: &SvtModel,
    ) -> Result<String, SvtError> {
        if signature_claims.is_empty() {
            return Err(SvtError::InvalidClaims(
                "at least one SignatureClaims required".into(),
            ));
        }

        // Validate each signature claim
        for sc in &signature_claims {
            self.validate_signature_claims(sc)?;
        }

        // Build SVT claims
        let svt_claims = SvtClaims::new(
            SVTProfile::Pdf,
            self.digest_algo_uri().to_string(),
            signature_claims,
        );

        // Serialize SVT claims to JSON Value
        let svt_claims_value: Value = serde_json::to_value(&svt_claims)
            .map_err(|e| SvtError::Serialization(e.to_string()))?;

        // Build JWT payload
        let mut payload = JwtPayload::new();
        payload.set_issuer(&model.issuer_id);
        payload.set_jwt_id(generate_jti());

        let now = SystemTime::now();
        payload.set_issued_at(&now);

        if let Some(validity) = model.validity_period {
            let exp = now + std::time::Duration::from_secs(validity);
            payload.set_expires_at(&exp);
        }

        if !model.audience.is_empty() {
            let aud_values: Vec<Value> = model
                .audience
                .iter()
                .map(|a| Value::String(a.clone()))
                .collect();
            payload
                .set_claim("aud", Some(Value::Array(aud_values)))
                .map_err(|e| SvtError::Serialization(e.to_string()))?;
        }

        // Set the sig_val_claims custom claim
        payload
            .set_claim("sig_val_claims", Some(svt_claims_value))
            .map_err(|e| SvtError::Serialization(e.to_string()))?;

        // Build JWT header
        let mut header = JwsHeader::new();
        header.set_algorithm(&self.jws_algorithm);
        header.set_token_type("JWT");

        // Set x5c or kid in header
        if !self.certificate_chain_der.is_empty() {
            if model.cert_ref_by_hash {
                // kid = hash of signing cert
                let digest_uri = self.digest_algo_uri();
                let hash = algo::hash_with_uri(digest_uri, &self.certificate_chain_der[0])?;
                header.set_key_id(B64.encode(&hash));
            } else {
                // x5c = base64 cert chain
                let x5c: Vec<Value> = self
                    .certificate_chain_der
                    .iter()
                    .map(|c| Value::String(B64.encode(c)))
                    .collect();
                header
                    .set_claim("x5c", Some(Value::Array(x5c)))
                    .map_err(|e| SvtError::Serialization(e.to_string()))?;
            }
        }

        // Sign the JWT
        let signer = self.make_signer()?;
        let token = jwt::encode_with_signer(&payload, &header, &*signer)
            .map_err(|e| SvtError::JwtSigning(e.to_string()))?;

        Ok(token)
    }

    /// Validate that a SignatureClaims object has all required fields.
    fn validate_signature_claims(&self, sc: &SignatureClaims) -> Result<(), SvtError> {
        if sc.sig_ref.sig_hash.is_empty() {
            return Err(SvtError::InvalidClaims("sig_ref.sig_hash is empty".into()));
        }
        if sc.sig_ref.sb_hash.is_empty() {
            return Err(SvtError::InvalidClaims("sig_ref.sb_hash is empty".into()));
        }
        if sc.sig_data_ref.is_empty() {
            return Err(SvtError::InvalidClaims(
                "at least one sig_data_ref required".into(),
            ));
        }
        for sdr in &sc.sig_data_ref {
            if sdr.hash.is_empty() {
                return Err(SvtError::InvalidClaims("sig_data_ref hash is empty".into()));
            }
        }
        if sc.signer_cert_ref.cert_ref.is_empty() {
            return Err(SvtError::InvalidClaims(
                "signer_cert_ref must have at least one entry".into(),
            ));
        }
        if sc.sig_val.is_empty() {
            return Err(SvtError::InvalidClaims(
                "at least one sig_val (policy validation) required".into(),
            ));
        }
        for sv in &sc.sig_val {
            if sv.pol.is_empty() {
                return Err(SvtError::InvalidClaims(
                    "sig_val policy URI is empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// Create a josekit signer for the configured algorithm.
    fn make_signer(&self) -> Result<Box<dyn josekit::jws::JwsSigner>, SvtError> {
        let alg = self.jws_algorithm.as_str();
        let key = &self.private_key_der;

        let signer: Box<dyn josekit::jws::JwsSigner> = match alg {
            "RS256" => Box::new(
                RS256
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("RS256 signer: {e}")))?,
            ),
            "RS384" => Box::new(
                RS384
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("RS384 signer: {e}")))?,
            ),
            "RS512" => Box::new(
                RS512
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("RS512 signer: {e}")))?,
            ),
            "PS256" => Box::new(
                PS256
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("PS256 signer: {e}")))?,
            ),
            "PS384" => Box::new(
                PS384
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("PS384 signer: {e}")))?,
            ),
            "PS512" => Box::new(
                PS512
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("PS512 signer: {e}")))?,
            ),
            "ES256" => Box::new(
                ES256
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("ES256 signer: {e}")))?,
            ),
            "ES384" => Box::new(
                ES384
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("ES384 signer: {e}")))?,
            ),
            "ES512" => Box::new(
                ES512
                    .signer_from_der(key)
                    .map_err(|e| SvtError::JwtSigning(format!("ES512 signer: {e}")))?,
            ),
            _ => return Err(SvtError::UnsupportedAlgorithm(alg.to_string())),
        };

        Ok(signer)
    }
}

/// Generate a random JWT ID (jti).
fn generate_jti() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let mut hasher = DefaultHasher::new();
    now.as_nanos().hash(&mut hasher);
    std::process::id().hash(&mut hasher);

    format!("{:032x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_svt_model_builder() {
        let model = SvtModel::builder()
            .issuer_id("https://svt.example.com")
            .validity_period(3600)
            .audience(vec!["aud1".into()])
            .cert_ref_by_hash(true)
            .build();

        assert_eq!(model.issuer_id, "https://svt.example.com");
        assert_eq!(model.validity_period, Some(3600));
        assert_eq!(model.audience, vec!["aud1"]);
        assert!(model.cert_ref_by_hash);
    }

    #[test]
    fn test_svt_model_builder_defaults() {
        let model = SvtModel::builder().build();
        assert_eq!(model.issuer_id, "");
        assert_eq!(model.validity_period, None);
        assert!(model.audience.is_empty());
        assert!(!model.cert_ref_by_hash);
    }

    #[test]
    fn test_generate_jti_not_empty() {
        let jti = generate_jti();
        assert!(!jti.is_empty());
    }

    #[test]
    fn test_build_cert_ref_chain() {
        // Use a dummy issuer to test cert ref building
        // We need a valid DER key. For unit testing cert ref logic,
        // we can construct a minimal issuer with a dummy key and not call sign.
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00]; // minimal DER prefix
        let issuer = SvtIssuer {
            jws_algorithm: "RS256".to_string(),
            private_key_der: vec![],
            certificate_chain_der: vec![fake_cert.clone()],
        };

        let cert_ref = issuer
            .build_cert_ref(std::slice::from_ref(&fake_cert), false)
            .unwrap();
        assert_eq!(cert_ref.ref_type, CertRefType::Chain);
        assert_eq!(cert_ref.cert_ref.len(), 1);
        assert_eq!(cert_ref.cert_ref[0], B64.encode(&fake_cert));
    }

    #[test]
    fn test_build_cert_ref_chain_hash() {
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
        let issuer = SvtIssuer {
            jws_algorithm: "RS256".to_string(),
            private_key_der: vec![],
            certificate_chain_der: vec![fake_cert.clone()],
        };

        let cert_ref = issuer
            .build_cert_ref(std::slice::from_ref(&fake_cert), true)
            .unwrap();
        assert_eq!(cert_ref.ref_type, CertRefType::ChainHash);
        assert_eq!(cert_ref.cert_ref.len(), 1);
        // Verify it's a base64-encoded SHA-256 hash (32 bytes → 44 chars base64)
        let decoded = B64.decode(&cert_ref.cert_ref[0]).unwrap();
        assert_eq!(decoded.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_validate_signature_claims_empty_sig_hash() {
        let issuer = SvtIssuer {
            jws_algorithm: "RS256".to_string(),
            private_key_der: vec![],
            certificate_chain_der: vec![],
        };

        let sc = SignatureClaims {
            sig_ref: SigReferenceClaims {
                id: None,
                sig_hash: "".to_string(),
                sb_hash: "def".to_string(),
            },
            sig_data_ref: vec![SignedDataClaims {
                data_ref: "0 100".to_string(),
                hash: "abc".to_string(),
            }],
            signer_cert_ref: CertReferenceClaims {
                ref_type: CertRefType::Chain,
                cert_ref: vec!["cert".to_string()],
            },
            time_val: None,
            sig_val: vec![PolicyValidationClaims {
                pol: "http://example.com/pol".to_string(),
                res: ValidationConclusion::Passed,
                msg: None,
                ext: None,
            }],
            ext: None,
        };

        let result = issuer.validate_signature_claims(&sc);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sig_hash"));
    }

    #[test]
    fn test_validate_signature_claims_no_sig_data_ref() {
        let issuer = SvtIssuer {
            jws_algorithm: "RS256".to_string(),
            private_key_der: vec![],
            certificate_chain_der: vec![],
        };

        let sc = SignatureClaims {
            sig_ref: SigReferenceClaims {
                id: None,
                sig_hash: "abc".to_string(),
                sb_hash: "def".to_string(),
            },
            sig_data_ref: vec![],
            signer_cert_ref: CertReferenceClaims {
                ref_type: CertRefType::Chain,
                cert_ref: vec!["cert".to_string()],
            },
            time_val: None,
            sig_val: vec![PolicyValidationClaims {
                pol: "http://example.com/pol".to_string(),
                res: ValidationConclusion::Passed,
                msg: None,
                ext: None,
            }],
            ext: None,
        };

        let result = issuer.validate_signature_claims(&sc);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_signature_claims_valid() {
        let issuer = SvtIssuer {
            jws_algorithm: "RS256".to_string(),
            private_key_der: vec![],
            certificate_chain_der: vec![],
        };

        let sc = SignatureClaims {
            sig_ref: SigReferenceClaims {
                id: None,
                sig_hash: "abc".to_string(),
                sb_hash: "def".to_string(),
            },
            sig_data_ref: vec![SignedDataClaims {
                data_ref: "0 100 200 300".to_string(),
                hash: "ghi".to_string(),
            }],
            signer_cert_ref: CertReferenceClaims {
                ref_type: CertRefType::Chain,
                cert_ref: vec!["cert".to_string()],
            },
            time_val: None,
            sig_val: vec![PolicyValidationClaims {
                pol: "http://example.com/pol".to_string(),
                res: ValidationConclusion::Passed,
                msg: None,
                ext: None,
            }],
            ext: None,
        };

        let result = issuer.validate_signature_claims(&sc);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_unsupported_algorithm() {
        let result = SvtIssuer::new("NONE", vec![], vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_eddsa_algorithm_supported() {
        let result = SvtIssuer::new("EdDSA", vec![], vec![]);
        assert!(result.is_ok());
    }
}
