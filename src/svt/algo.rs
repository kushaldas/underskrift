//! Algorithm registry mapping JWS algorithm names to digest algorithm URIs.
//!
//! Follows the mapping from the Java `SVTAlgoRegistry` in svt-core.

use crate::error::SvtError;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Digest algorithm URI constants (XML identifiers).
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// SHA-3 digest algorithm URI constants (W3C XML Digital Signatures).
pub const DIGEST_SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
pub const DIGEST_SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
pub const DIGEST_SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

/// JWS algorithm name constants.
pub const ALG_RS256: &str = "RS256";
pub const ALG_RS384: &str = "RS384";
pub const ALG_RS512: &str = "RS512";
pub const ALG_PS256: &str = "PS256";
pub const ALG_PS384: &str = "PS384";
pub const ALG_PS512: &str = "PS512";
pub const ALG_ES256: &str = "ES256";
pub const ALG_ES384: &str = "ES384";
pub const ALG_ES512: &str = "ES512";
/// EdDSA (Ed25519/Ed448) JWS algorithm name.
pub const ALG_EDDSA: &str = "EdDSA";

/// Properties for a supported SVT algorithm.
#[derive(Debug, Clone)]
pub struct AlgoProperties {
    /// JWS algorithm name (e.g., "RS256").
    pub jws_algo: &'static str,
    /// XML URI for the digest algorithm.
    pub digest_algo_uri: &'static str,
}

/// Supported algorithm registry entries.
static ALGO_REGISTRY: &[AlgoProperties] = &[
    AlgoProperties {
        jws_algo: ALG_RS256,
        digest_algo_uri: DIGEST_SHA256,
    },
    AlgoProperties {
        jws_algo: ALG_RS384,
        digest_algo_uri: DIGEST_SHA384,
    },
    AlgoProperties {
        jws_algo: ALG_RS512,
        digest_algo_uri: DIGEST_SHA512,
    },
    AlgoProperties {
        jws_algo: ALG_PS256,
        digest_algo_uri: DIGEST_SHA256,
    },
    AlgoProperties {
        jws_algo: ALG_PS384,
        digest_algo_uri: DIGEST_SHA384,
    },
    AlgoProperties {
        jws_algo: ALG_PS512,
        digest_algo_uri: DIGEST_SHA512,
    },
    AlgoProperties {
        jws_algo: ALG_ES256,
        digest_algo_uri: DIGEST_SHA256,
    },
    AlgoProperties {
        jws_algo: ALG_ES384,
        digest_algo_uri: DIGEST_SHA384,
    },
    AlgoProperties {
        jws_algo: ALG_ES512,
        digest_algo_uri: DIGEST_SHA512,
    },
    // EdDSA uses SHA-512 internally for Ed25519 (per RFC 8032)
    AlgoProperties {
        jws_algo: ALG_EDDSA,
        digest_algo_uri: DIGEST_SHA512,
    },
];

/// Look up the algorithm properties for a JWS algorithm name.
pub fn get_algo_properties(jws_algo: &str) -> Option<&'static AlgoProperties> {
    ALGO_REGISTRY.iter().find(|a| a.jws_algo == jws_algo)
}

/// Check if a JWS algorithm is supported.
pub fn is_supported(jws_algo: &str) -> bool {
    get_algo_properties(jws_algo).is_some()
}

/// Get the digest algorithm URI for a JWS algorithm.
pub fn digest_uri_for_jws(jws_algo: &str) -> Result<&'static str, SvtError> {
    get_algo_properties(jws_algo)
        .map(|p| p.digest_algo_uri)
        .ok_or_else(|| SvtError::UnsupportedAlgorithm(jws_algo.to_string()))
}

/// Compute a hash using the digest algorithm identified by its URI.
pub fn hash_with_uri(digest_uri: &str, data: &[u8]) -> Result<Vec<u8>, SvtError> {
    match digest_uri {
        DIGEST_SHA256 => Ok(Sha256::digest(data).to_vec()),
        DIGEST_SHA384 => Ok(Sha384::digest(data).to_vec()),
        DIGEST_SHA512 => Ok(Sha512::digest(data).to_vec()),
        DIGEST_SHA3_256 => {
            use sha3::Sha3_256;
            Ok(Sha3_256::digest(data).to_vec())
        }
        DIGEST_SHA3_384 => {
            use sha3::Sha3_384;
            Ok(Sha3_384::digest(data).to_vec())
        }
        DIGEST_SHA3_512 => {
            use sha3::Sha3_512;
            Ok(Sha3_512::digest(data).to_vec())
        }
        _ => Err(SvtError::UnsupportedAlgorithm(format!(
            "unsupported digest URI: {digest_uri}"
        ))),
    }
}

/// Compute a hash using the digest algorithm associated with a JWS algorithm.
pub fn hash_for_jws(jws_algo: &str, data: &[u8]) -> Result<Vec<u8>, SvtError> {
    let uri = digest_uri_for_jws(jws_algo)?;
    hash_with_uri(uri, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_algos_supported() {
        for name in [
            ALG_RS256, ALG_RS384, ALG_RS512, ALG_PS256, ALG_PS384, ALG_PS512, ALG_ES256, ALG_ES384,
            ALG_ES512, ALG_EDDSA,
        ] {
            assert!(is_supported(name), "expected {name} to be supported");
        }
    }

    #[test]
    fn test_unsupported_algo() {
        assert!(!is_supported("NONE"));
        assert!(digest_uri_for_jws("NONE").is_err());
    }

    #[test]
    fn test_digest_uri_mapping() {
        assert_eq!(digest_uri_for_jws(ALG_RS256).unwrap(), DIGEST_SHA256);
        assert_eq!(digest_uri_for_jws(ALG_RS384).unwrap(), DIGEST_SHA384);
        assert_eq!(digest_uri_for_jws(ALG_ES512).unwrap(), DIGEST_SHA512);
        assert_eq!(digest_uri_for_jws(ALG_PS256).unwrap(), DIGEST_SHA256);
    }

    #[test]
    fn test_hash_with_uri_sha256() {
        let hash = hash_with_uri(DIGEST_SHA256, b"hello").unwrap();
        assert_eq!(hash.len(), 32);

        // Known SHA-256 of "hello"
        let expected = Sha256::digest(b"hello");
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_hash_with_uri_sha384() {
        let hash = hash_with_uri(DIGEST_SHA384, b"hello").unwrap();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_hash_with_uri_sha512() {
        let hash = hash_with_uri(DIGEST_SHA512, b"hello").unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_with_unsupported_uri() {
        let r = hash_with_uri("http://example.com/unsupported", b"hello");
        assert!(r.is_err());
    }

    #[test]
    fn test_hash_with_uri_sha3_256() {
        let hash = hash_with_uri(DIGEST_SHA3_256, b"hello").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_with_uri_sha3_384() {
        let hash = hash_with_uri(DIGEST_SHA3_384, b"hello").unwrap();
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_hash_with_uri_sha3_512() {
        let hash = hash_with_uri(DIGEST_SHA3_512, b"hello").unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_eddsa_digest_uri() {
        assert_eq!(digest_uri_for_jws(ALG_EDDSA).unwrap(), DIGEST_SHA512);
    }

    #[test]
    fn test_hash_for_jws() {
        let h1 = hash_for_jws(ALG_ES256, b"test").unwrap();
        let h2 = hash_with_uri(DIGEST_SHA256, b"test").unwrap();
        assert_eq!(h1, h2);
    }
}
