//! Software-based signer — loads keys from PKCS#12, PEM, or DER files.

use crate::crypto::algorithm::{DigestAlgorithm, SignatureAlgorithm};
use crate::crypto::traits::CryptoSigner;
use crate::error::CryptoError;

/// A software-based signer that holds private key material in memory.
///
/// Supports loading from:
/// - PKCS#12 (.p12 / .pfx) files
/// - PEM-encoded private keys + certificate files
/// - DER-encoded private keys + certificate files
pub struct SoftwareSigner {
    /// The signing private key (algorithm-specific)
    key: SigningKey,
    /// The signer's certificate in DER
    certificate: Vec<u8>,
    /// Full certificate chain in DER (signer cert first, root last)
    chain: Vec<Vec<u8>>,
    /// Digest algorithm to use
    digest_algorithm: DigestAlgorithm,
    /// Detected signature algorithm
    signature_algorithm: SignatureAlgorithm,
}

/// Internal representation of the private key.
enum SigningKey {
    Rsa(rsa::RsaPrivateKey),
    EcdsaP256(p256::ecdsa::SigningKey),
    EcdsaP384(p384::ecdsa::SigningKey),
}

impl SoftwareSigner {
    /// Load a signer from a PKCS#12 file.
    pub fn from_pkcs12_file(
        path: impl AsRef<std::path::Path>,
        password: &str,
    ) -> Result<Self, CryptoError> {
        let data = std::fs::read(path).map_err(CryptoError::Io)?;
        Self::from_pkcs12_data(&data, password)
    }

    /// Load a signer from PKCS#12 bytes.
    pub fn from_pkcs12_data(data: &[u8], password: &str) -> Result<Self, CryptoError> {
        use pkcs8::DecodePrivateKey;

        let pfx = p12::PFX::parse(data)
            .map_err(|e| CryptoError::Pkcs12(format!("failed to parse PKCS#12: {e:?}")))?;

        // Extract private key (DER-encoded PKCS#8)
        let key_bags = pfx
            .key_bags(password)
            .map_err(|e| CryptoError::Pkcs12(format!("failed to extract key bags: {e:?}")))?;
        let key_der = key_bags
            .into_iter()
            .next()
            .ok_or_else(|| CryptoError::Pkcs12("no private key found in PKCS#12".into()))?;

        // Extract certificates (DER-encoded X.509)
        let cert_bags = pfx
            .cert_x509_bags(password)
            .map_err(|e| CryptoError::Pkcs12(format!("failed to extract cert bags: {e:?}")))?;
        if cert_bags.is_empty() {
            return Err(CryptoError::Pkcs12(
                "no certificates found in PKCS#12".into(),
            ));
        }

        // First cert is the signer cert, rest are the chain
        let certificate = cert_bags[0].clone();
        let chain = cert_bags;

        // Try to parse the key as RSA first, then ECDSA P-256, then P-384
        // The key_der from p12 is typically PKCS#8 format
        if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_der(&key_der) {
            return Ok(Self {
                key: SigningKey::Rsa(rsa_key),
                certificate,
                chain,
                digest_algorithm: DigestAlgorithm::Sha256,
                signature_algorithm: SignatureAlgorithm::RsaPkcs1v15,
            });
        }

        if let Ok(p256_key) = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der) {
            return Ok(Self {
                key: SigningKey::EcdsaP256(p256_key),
                certificate,
                chain,
                digest_algorithm: DigestAlgorithm::Sha256,
                signature_algorithm: SignatureAlgorithm::EcdsaP256,
            });
        }

        if let Ok(p384_key) = p384::ecdsa::SigningKey::from_pkcs8_der(&key_der) {
            return Ok(Self {
                key: SigningKey::EcdsaP384(p384_key),
                certificate,
                chain,
                digest_algorithm: DigestAlgorithm::Sha384,
                signature_algorithm: SignatureAlgorithm::EcdsaP384,
            });
        }

        Err(CryptoError::UnsupportedKeyType(
            "could not parse private key as RSA, ECDSA P-256, or ECDSA P-384".into(),
        ))
    }

    /// Create a signer from a DER-encoded RSA private key and DER-encoded certificate chain.
    pub fn from_rsa_der(key_der: &[u8], cert_chain: Vec<Vec<u8>>) -> Result<Self, CryptoError> {
        use pkcs8::DecodePrivateKey;

        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(key_der)
            .map_err(|e| CryptoError::Pkcs8(format!("failed to parse RSA key: {e}")))?;
        let certificate = cert_chain
            .first()
            .ok_or_else(|| CryptoError::Certificate("no certificate provided".into()))?
            .clone();

        Ok(Self {
            key: SigningKey::Rsa(rsa_key),
            certificate,
            chain: cert_chain,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1v15,
        })
    }

    /// Set the digest algorithm (default: SHA-256).
    pub fn with_digest_algorithm(mut self, alg: DigestAlgorithm) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Set the signature algorithm.
    ///
    /// For RSA keys, this allows switching between PKCS#1 v1.5 (default)
    /// and RSA-PSS padding. For ECDSA keys, this is ignored (the algorithm
    /// is determined by the key type).
    pub fn with_signature_algorithm(mut self, alg: SignatureAlgorithm) -> Self {
        self.signature_algorithm = alg;
        self
    }
}

impl CryptoSigner for SoftwareSigner {
    fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match &self.key {
            SigningKey::Rsa(key) => match self.signature_algorithm {
                SignatureAlgorithm::RsaPss => {
                    use rsa::pss::Pss;
                    let padding = match self.digest_algorithm {
                        DigestAlgorithm::Sha256 => Pss::new::<sha2::Sha256>(),
                        DigestAlgorithm::Sha384 => Pss::new::<sha2::Sha384>(),
                        DigestAlgorithm::Sha512 => Pss::new::<sha2::Sha512>(),
                        DigestAlgorithm::Sha3_256 => Pss::new::<sha3::Sha3_256>(),
                        DigestAlgorithm::Sha3_384 => Pss::new::<sha3::Sha3_384>(),
                        DigestAlgorithm::Sha3_512 => Pss::new::<sha3::Sha3_512>(),
                    };
                    key.sign(padding, hash)
                        .map(|sig| sig.to_vec())
                        .map_err(|e| CryptoError::SigningFailed(e.to_string()))
                }
                _ => {
                    // Default: PKCS#1 v1.5
                    // Note: SHA-3 digests don't have AssociatedOid in the sha3 crate,
                    // so PKCS#1 v1.5 + SHA-3 is not directly supported. For SHA-3 digests,
                    // we automatically fall back to RSA-PSS (there are no combined OIDs
                    // for RSA PKCS#1v1.5 + SHA-3 anyway).
                    if self.digest_algorithm.is_sha3() {
                        use rsa::pss::Pss;
                        let padding = match self.digest_algorithm {
                            DigestAlgorithm::Sha3_256 => Pss::new::<sha3::Sha3_256>(),
                            DigestAlgorithm::Sha3_384 => Pss::new::<sha3::Sha3_384>(),
                            DigestAlgorithm::Sha3_512 => Pss::new::<sha3::Sha3_512>(),
                            _ => unreachable!(),
                        };
                        key.sign(padding, hash)
                            .map(|sig| sig.to_vec())
                            .map_err(|e| CryptoError::SigningFailed(e.to_string()))
                    } else {
                        use rsa::Pkcs1v15Sign;
                        let padding = match self.digest_algorithm {
                            DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
                            DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
                            DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
                            _ => unreachable!("SHA-3 handled above"),
                        };
                        key.sign(padding, hash)
                            .map(|sig| sig.to_vec())
                            .map_err(|e| CryptoError::SigningFailed(e.to_string()))
                    }
                }
            },
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = key.sign(hash);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningKey::EcdsaP384(key) => {
                use p384::ecdsa::signature::Signer;
                let sig: p384::ecdsa::Signature = key.sign(hash);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }

    fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    fn certificate_chain_der(&self) -> Vec<&[u8]> {
        self.chain.iter().map(|c| c.as_slice()).collect()
    }

    fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
}
