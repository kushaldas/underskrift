//! CMS/PKCS#7 SignedData builder for PDF signatures.
//!
//! Constructs the CMS `SignedData` structure that goes into the PDF's
//! `/Contents` field. Handles signed attributes, unsigned attributes,
//! certificate embedding, and size estimation.
//!
//! Supports both PAdES (ETSI.CAdES.detached) and traditional (adbe.pkcs7.detached)
//! SubFilter modes. PAdES requires `signingCertificateV2` and omits `signingTime`;
//! traditional allows `signingTime` and doesn't require `signingCertificateV2`.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::rfc5911;
use const_oid::db::rfc5912;
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::Certificate;

use const_oid::ObjectIdentifier;

use crate::crypto::algorithm::{DigestAlgorithm, SignatureAlgorithm};
use crate::crypto::traits::CryptoSigner;
use crate::error::CmsError;

/// OID for the CMS Algorithm Protection attribute (RFC 6211).
/// `id-aa-CMSAlgorithmProtection OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///   us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 52 }`
pub(crate) const ID_AA_CMS_ALGORITHM_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.52");

/// Build the RSASSA-PSS-params ASN.1 structure for a given digest algorithm.
///
/// Encodes the AlgorithmIdentifier parameters for RSASSA-PSS (RFC 4055):
/// ```text
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1,
///     maskGenAlgorithm    [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
///     saltLength          [2] INTEGER DEFAULT 20,
///     trailerField        [3] TrailerField DEFAULT trailerFieldBC
/// }
/// ```
/// Build the RSASSA-PSS-params ASN.1 Any value for a given digest algorithm.
///
/// This is `pub(crate)` so that `svt::embed` can reuse it for SVT CMS construction.
pub(crate) fn rsassa_pss_params_any(digest: DigestAlgorithm) -> Result<Any, String> {
    let digest_oid = digest.oid();
    let salt_len: u32 = match digest {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha3_256 => 32,
        DigestAlgorithm::Sha384 | DigestAlgorithm::Sha3_384 => 48,
        DigestAlgorithm::Sha512 | DigestAlgorithm::Sha3_512 => 64,
    };

    // Encode the hash AlgorithmIdentifier: SEQUENCE { OID, NULL }
    let digest_oid_bytes =
        der::Encode::to_der(&digest_oid).map_err(|e| format!("digest OID encode: {e}"))?;
    let hash_alg_id = encode_sequence(&[&digest_oid_bytes]);

    // MGF AlgorithmIdentifier: SEQUENCE { id-mgf1 OID, hash AlgorithmIdentifier }
    let mgf1_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8"); // id-mgf1
    let mgf1_oid_bytes =
        der::Encode::to_der(&mgf1_oid).map_err(|e| format!("MGF1 OID encode: {e}"))?;
    let mgf_alg_id = encode_sequence(&[&mgf1_oid_bytes, &hash_alg_id]);

    // Salt length: INTEGER
    let salt_bytes = encode_integer(salt_len);

    // Now build the params SEQUENCE with explicit context tags
    // [0] EXPLICIT hashAlgorithm
    let tagged_hash = encode_context_explicit(0, &hash_alg_id);
    // [1] EXPLICIT maskGenAlgorithm
    let tagged_mgf = encode_context_explicit(1, &mgf_alg_id);
    // [2] EXPLICIT saltLength
    let tagged_salt = encode_context_explicit(2, &salt_bytes);

    let params_inner: &[&[u8]] = &[
        tagged_hash.as_slice(),
        tagged_mgf.as_slice(),
        tagged_salt.as_slice(),
    ];
    let params_seq = encode_sequence(params_inner);

    Any::new(Tag::Sequence, params_seq[2..].to_vec())
        .map_err(|e| format!("RSASSA-PSS params Any: {e}"))
}

/// The mode of CMS construction — affects which signed attributes are included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CmsProfile {
    /// PAdES (ETSI.CAdES.detached): requires signingCertificateV2, omits signingTime
    #[default]
    Pades,
    /// Traditional (adbe.pkcs7.detached): allows signingTime, no signingCertificateV2 required
    Traditional,
}

/// Controls where the `signingTime` attribute is placed in the CMS structure.
///
/// By default, `signingTime` is placed in the signed attributes (when using
/// Traditional profile). Some workflows may need it as an unsigned attribute
/// instead, or in both locations.
///
/// **Note**: In PAdES mode, `signingTime` is always omitted from signed attributes
/// per ETSI EN 319 122-1. This setting only affects PAdES when set to `Unsigned`
/// or `Both`, in which case the unsigned copy is still added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningTimePlacement {
    /// Place `signingTime` only in signed attributes (default for Traditional).
    /// In PAdES mode, this means the time is omitted entirely.
    #[default]
    Signed,
    /// Place `signingTime` only in unsigned attributes.
    Unsigned,
    /// Place `signingTime` in both signed and unsigned attributes.
    /// In PAdES mode, only the unsigned copy is included.
    Both,
}

/// Intermediate state from [`PdfCmsBuilder::pre_sign`] for deferred/remote signing.
///
/// Contains the hash that must be signed by the remote party (`attrs_hash`)
/// and all the CMS structural components needed to assemble the final
/// `SignedData` once the signature bytes are available.
///
/// This struct is opaque to callers — the only field they need is `attrs_hash`.
/// Pass the whole struct back to [`PdfCmsBuilder::complete_cms`] along with
/// the raw signature bytes to produce the final CMS DER.
pub struct CmsPreSignData {
    /// The hash of the DER-encoded signed attributes.
    /// This is what must be signed by the remote/external signing key.
    pub attrs_hash: Vec<u8>,

    // -- internal CMS components (not part of public contract) --
    pub(crate) sid: SignerIdentifier,
    pub(crate) digest_alg: AlgorithmIdentifierOwned,
    pub(crate) sig_alg: AlgorithmIdentifierOwned,
    pub(crate) digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    pub(crate) encap_content_info: EncapsulatedContentInfo,
    pub(crate) signed_attrs: SetOfVec<Attribute>,
    pub(crate) unsigned_attrs: Option<SetOfVec<Attribute>>,
    pub(crate) certificates: CertificateSet,
}

/// Builder for CMS SignedData structures suitable for PDF signatures.
pub struct PdfCmsBuilder<'a> {
    /// The signer providing key material and certificates
    signer: &'a dyn CryptoSigner,
    /// Whether to embed the full certificate chain
    embed_chain: bool,
    /// Signing time (None = omit, Some = include based on placement)
    signing_time: Option<chrono::NaiveDateTime>,
    /// CMS profile (PAdES vs Traditional)
    profile: CmsProfile,
    /// Where to place the signingTime attribute
    signing_time_placement: SigningTimePlacement,
}

impl<'a> PdfCmsBuilder<'a> {
    /// Create a new CMS builder.
    pub fn new(signer: &'a dyn CryptoSigner) -> Self {
        Self {
            signer,
            embed_chain: true,
            signing_time: None,
            profile: CmsProfile::default(),
            signing_time_placement: SigningTimePlacement::default(),
        }
    }

    /// Set whether to embed the full certificate chain.
    pub fn embed_chain(mut self, embed: bool) -> Self {
        self.embed_chain = embed;
        self
    }

    /// Set the signing time.
    ///
    /// By default, this is placed in the signed attributes for Traditional mode
    /// and omitted for PAdES mode. Use [`signing_time_placement`](Self::signing_time_placement)
    /// to control where the attribute is placed.
    pub fn signing_time(mut self, time: chrono::NaiveDateTime) -> Self {
        self.signing_time = Some(time);
        self
    }

    /// Set the CMS profile.
    pub fn profile(mut self, profile: CmsProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the placement of the `signingTime` attribute.
    ///
    /// Controls whether `signingTime` goes into signed attributes, unsigned
    /// attributes, or both. See [`SigningTimePlacement`] for details.
    ///
    /// Only takes effect when a signing time has been set via
    /// [`signing_time`](Self::signing_time).
    pub fn signing_time_placement(mut self, placement: SigningTimePlacement) -> Self {
        self.signing_time_placement = placement;
        self
    }

    /// Estimate the size of the final DER-encoded CMS signature.
    ///
    /// This is used to determine how large the `/Contents` placeholder
    /// needs to be. Returns a conservative upper bound.
    pub fn estimate_size(&self) -> usize {
        let chain = self.signer.certificate_chain_der();
        let cert_size: usize = if self.embed_chain {
            chain.iter().map(|c| c.len()).sum::<usize>() + chain.len() * 32 // ASN.1 overhead per cert
        } else {
            self.signer.certificate_der().len() + 32
        };

        // Signature value: RSA up to 512 bytes (4096-bit), ECDSA up to 144 bytes
        let sig_size = match self.signer.signature_algorithm() {
            SignatureAlgorithm::RsaPkcs1v15 | SignatureAlgorithm::RsaPss => 512,
            _ => 144,
        };

        // Signed attributes: ~256 bytes, ASN.1 overhead: ~512 bytes
        // Add 2KB buffer for safety
        cert_size + sig_size + 256 + 512 + 2048
    }

    /// Build and sign the CMS SignedData for the given data hash.
    ///
    /// `data_hash` is the hash of the ByteRange-selected portions of the PDF.
    /// The hash must have been computed using the signer's configured digest algorithm.
    ///
    /// Returns the DER-encoded `ContentInfo` wrapping the `SignedData`.
    pub fn build(&self, data_hash: &[u8]) -> Result<Vec<u8>, CmsError> {
        // 1. Parse the signer's certificate to extract issuer + serial
        let cert_der = self.signer.certificate_der();
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| CmsError::Der(format!("failed to parse signer certificate: {e}")))?;

        // 2. Build SignerIdentifier (IssuerAndSerialNumber)
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });

        // 3. Determine algorithm identifiers
        let digest_alg = self.digest_algorithm_identifier();
        let sig_alg = self.signature_algorithm_identifier()?;

        // 4. Build the set of digest algorithms (just one)
        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(digest_alg.clone())
            .map_err(|e| CmsError::Builder(format!("failed to build digest algorithm set: {e}")))?;

        // 5. Build EncapsulatedContentInfo — detached (no econtent for PDF signing)
        let encap_content_info = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        };

        // 6. Build signed attributes
        let signed_attrs = self.build_signed_attributes(data_hash, &cert)?;

        // 7. Compute the signature over the DER-encoded signed attributes
        //    Per RFC 5652 §5.4: encode the signed attributes as a SET OF,
        //    then hash and sign that encoding.
        let attrs_to_sign = self.encode_attrs_for_signing(&signed_attrs)?;
        let attrs_hash = self.signer.digest_algorithm().digest(&attrs_to_sign);
        let signature_bytes = self
            .signer
            .sign_hash(&attrs_hash)
            .map_err(|e| CmsError::Builder(format!("signing failed: {e}")))?;

        // 8. Build unsigned attributes (if any)
        let unsigned_attrs = self.build_unsigned_attributes()?;

        // 9. Build SignerInfo
        let signer_info = SignerInfo {
            version: CmsVersion::V1, // V1 when using IssuerAndSerialNumber
            sid,
            digest_alg,
            signed_attrs: Some(signed_attrs),
            signature_algorithm: sig_alg,
            signature: OctetString::new(signature_bytes).map_err(|e| {
                CmsError::Der(format!("failed to create signature octet string: {e}"))
            })?,
            unsigned_attrs,
        };

        let mut signer_infos_set = SetOfVec::new();
        signer_infos_set
            .insert(signer_info)
            .map_err(|e| CmsError::Builder(format!("failed to build signer infos set: {e}")))?;

        // 9. Build the certificate set
        let certificates = self.build_certificate_set()?;

        // 10. Assemble SignedData
        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms,
            encap_content_info,
            certificates: Some(certificates),
            crls: None,
            signer_infos: SignerInfos(signer_infos_set),
        };

        // 11. Wrap in ContentInfo and DER-encode
        let signed_data_der = signed_data
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode SignedData: {e}")))?;

        let content = Any::from_der(&signed_data_der)
            .map_err(|e| CmsError::Der(format!("failed to re-parse SignedData as Any: {e}")))?;

        let content_info = ContentInfo {
            content_type: rfc5911::ID_SIGNED_DATA,
            content,
        };

        content_info
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode ContentInfo: {e}")))
    }

    /// Prepare a CMS SignedData for remote/deferred signing (phase 1 of 2).
    ///
    /// Builds everything except the actual cryptographic signature: parses the
    /// signer certificate, constructs signed attributes (including `messageDigest`
    /// with the `data_hash`), DER-encodes them, and computes the hash that must
    /// be signed by the remote party.
    ///
    /// Returns a [`CmsPreSignData`] containing:
    /// - `attrs_hash`: the hash to send to the remote signer
    /// - Internal state needed by [`complete_cms`] to finish the CMS
    ///
    /// The caller should sign `attrs_hash` using the private key corresponding
    /// to the signer certificate, then call [`complete_cms`] with the result.
    ///
    /// # Example (three-phase flow)
    ///
    /// ```ignore
    /// let builder = PdfCmsBuilder::new(&signer_info).profile(CmsProfile::Pades);
    /// let pre = builder.pre_sign(data_hash)?;
    ///
    /// // Send pre.attrs_hash to remote signing service...
    /// let signature_bytes = remote_sign(&pre.attrs_hash);
    ///
    /// let cms_der = builder.complete_cms(&pre, &signature_bytes)?;
    /// ```
    pub fn pre_sign(&self, data_hash: &[u8]) -> Result<CmsPreSignData, CmsError> {
        // 1. Parse the signer's certificate
        let cert_der = self.signer.certificate_der();
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| CmsError::Der(format!("failed to parse signer certificate: {e}")))?;

        // 2. Build SignerIdentifier
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });

        // 3. Determine algorithm identifiers
        let digest_alg = self.digest_algorithm_identifier();
        let sig_alg = self.signature_algorithm_identifier()?;

        // 4. Build digest algorithm set
        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(digest_alg.clone())
            .map_err(|e| CmsError::Builder(format!("failed to build digest algorithm set: {e}")))?;

        // 5. Build EncapsulatedContentInfo (detached)
        let encap_content_info = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        };

        // 6. Build signed attributes
        let signed_attrs = self.build_signed_attributes(data_hash, &cert)?;

        // 7. DER-encode signed attributes and compute the hash-to-sign
        let attrs_to_sign = self.encode_attrs_for_signing(&signed_attrs)?;
        let attrs_hash = self.signer.digest_algorithm().digest(&attrs_to_sign);

        // 8. Build unsigned attributes (if any)
        let unsigned_attrs = self.build_unsigned_attributes()?;

        // 9. Build the certificate set (needed for complete_cms)
        let certificates = self.build_certificate_set()?;

        Ok(CmsPreSignData {
            attrs_hash,
            sid,
            digest_alg,
            sig_alg,
            digest_algorithms,
            encap_content_info,
            signed_attrs,
            unsigned_attrs,
            certificates,
        })
    }

    /// Complete a CMS SignedData using a pre-computed signature (phase 2 of 2).
    ///
    /// Takes the [`CmsPreSignData`] from [`pre_sign`] and the raw signature
    /// bytes produced by signing `pre_sign_data.attrs_hash` with the private key.
    ///
    /// Returns the DER-encoded `ContentInfo` wrapping the `SignedData`, ready
    /// to inject into a PDF `/Contents` field.
    pub fn complete_cms(
        &self,
        pre: &CmsPreSignData,
        signature_bytes: &[u8],
    ) -> Result<Vec<u8>, CmsError> {
        // 1. Build SignerInfo with the externally-produced signature
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: pre.sid.clone(),
            digest_alg: pre.digest_alg.clone(),
            signed_attrs: Some(pre.signed_attrs.clone()),
            signature_algorithm: pre.sig_alg.clone(),
            signature: OctetString::new(signature_bytes.to_vec()).map_err(|e| {
                CmsError::Der(format!("failed to create signature octet string: {e}"))
            })?,
            unsigned_attrs: pre.unsigned_attrs.clone(),
        };

        let mut signer_infos_set = SetOfVec::new();
        signer_infos_set
            .insert(signer_info)
            .map_err(|e| CmsError::Builder(format!("failed to build signer infos set: {e}")))?;

        // 2. Assemble SignedData
        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: pre.digest_algorithms.clone(),
            encap_content_info: pre.encap_content_info.clone(),
            certificates: Some(pre.certificates.clone()),
            crls: None,
            signer_infos: SignerInfos(signer_infos_set),
        };

        // 3. Wrap in ContentInfo and DER-encode
        let signed_data_der = signed_data
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode SignedData: {e}")))?;

        let content = Any::from_der(&signed_data_der)
            .map_err(|e| CmsError::Der(format!("failed to re-parse SignedData as Any: {e}")))?;

        let content_info = ContentInfo {
            content_type: rfc5911::ID_SIGNED_DATA,
            content,
        };

        content_info
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode ContentInfo: {e}")))
    }

    /// Build the signed attributes set.
    ///
    /// Always includes:
    /// - `contentType` (id-data)
    /// - `messageDigest` (the hash of the PDF byte ranges)
    /// - `CMSAlgorithmProtection` (RFC 6211 — digest + signature algo binding)
    ///
    /// PAdES additionally includes:
    /// - `signingCertificateV2` (ESS)
    ///
    /// Traditional optionally includes:
    /// - `signingTime` (when placement is `Signed` or `Both`)
    fn build_signed_attributes(
        &self,
        data_hash: &[u8],
        cert: &Certificate,
    ) -> Result<SetOfVec<Attribute>, CmsError> {
        let mut attrs: Vec<Attribute> = Vec::new();

        // 1. Content-type attribute (always required)
        attrs.push(build_content_type_attr()?);

        // 2. Message-digest attribute (always required)
        attrs.push(build_message_digest_attr(data_hash)?);

        // 3. Profile-specific attributes
        match self.profile {
            CmsProfile::Pades => {
                // PAdES requires signingCertificateV2
                attrs.push(self.build_signing_certificate_v2_attr(cert)?);
                // PAdES never includes signingTime in signed attributes
            }
            CmsProfile::Traditional => {
                // Traditional may include signingTime in signed attrs
                let include_signed = matches!(
                    self.signing_time_placement,
                    SigningTimePlacement::Signed | SigningTimePlacement::Both
                );
                if include_signed {
                    if let Some(time) = &self.signing_time {
                        attrs.push(build_signing_time_attr(time)?);
                    }
                }
            }
        }

        // 4. CMS Algorithm Protection (RFC 6211) — always included
        let digest_alg = self.digest_algorithm_identifier();
        let sig_alg = self.signature_algorithm_identifier()?;
        attrs.push(build_cms_algorithm_protection_attr(&digest_alg, &sig_alg)?);

        SetOfVec::try_from(attrs)
            .map_err(|e| CmsError::Builder(format!("failed to build signed attributes set: {e}")))
    }

    /// Build unsigned attributes for the `SignerInfo`.
    ///
    /// Currently supports placing `signingTime` as an unsigned attribute
    /// when [`SigningTimePlacement`] is `Unsigned` or `Both`.
    ///
    /// Returns `None` if there are no unsigned attributes to include.
    fn build_unsigned_attributes(&self) -> Result<Option<SetOfVec<Attribute>>, CmsError> {
        let include_unsigned = matches!(
            self.signing_time_placement,
            SigningTimePlacement::Unsigned | SigningTimePlacement::Both
        );

        if !include_unsigned {
            return Ok(None);
        }

        let time = match &self.signing_time {
            Some(t) => t,
            None => return Ok(None),
        };

        let attr = build_signing_time_attr(time)?;
        let mut attrs = SetOfVec::new();
        attrs
            .insert(attr)
            .map_err(|e| CmsError::Builder(format!("failed to build unsigned attributes: {e}")))?;

        Ok(Some(attrs))
    }

    /// Build the ESS `signingCertificateV2` attribute for PAdES.
    ///
    /// This attribute binds the signing certificate to the signature,
    /// preventing certificate substitution attacks. It contains a hash
    /// of the signer's certificate.
    ///
    /// ASN.1 structure (RFC 5035):
    /// ```text
    /// SigningCertificateV2 ::= SEQUENCE {
    ///     certs SEQUENCE OF ESSCertIDv2,
    ///     policies SEQUENCE OF PolicyInformation OPTIONAL
    /// }
    /// ESSCertIDv2 ::= SEQUENCE {
    ///     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
    ///     certHash Hash,
    ///     issuerSerial IssuerSerial OPTIONAL
    /// }
    /// ```
    fn build_signing_certificate_v2_attr(&self, cert: &Certificate) -> Result<Attribute, CmsError> {
        // Hash the entire DER-encoded signer certificate
        let cert_der = cert
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode cert for hash: {e}")))?;
        let cert_hash = self.signer.digest_algorithm().digest(&cert_der);

        // Build the ESSCertIDv2 manually as DER.
        // When the hash algorithm is SHA-256 (the default), the hashAlgorithm
        // field can be omitted per RFC 5035. We always include it for clarity.
        let hash_alg_der = self
            .digest_algorithm_identifier()
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to encode hash alg: {e}")))?;
        let cert_hash_octet = OctetString::new(cert_hash)
            .map_err(|e| CmsError::Der(format!("failed to create cert hash octet string: {e}")))?;
        let cert_hash_der = cert_hash_octet
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to encode cert hash: {e}")))?;

        // Build IssuerSerial
        let issuer_serial_der = build_issuer_serial_der(cert)?;

        // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm, certHash, issuerSerial }
        let ess_cert_id_der = encode_sequence(&[&hash_alg_der, &cert_hash_der, &issuer_serial_der]);

        // certs SEQUENCE OF ESSCertIDv2 (just one)
        let certs_seq = encode_sequence(&[&ess_cert_id_der]);

        // SigningCertificateV2 ::= SEQUENCE { certs }
        // (policies omitted)
        let signing_cert_v2 = encode_sequence(&[&certs_seq]);

        // Build the Attribute
        let value = AttributeValue::from_der(&signing_cert_v2).map_err(|e| {
            CmsError::Der(format!(
                "failed to parse signingCertificateV2 as AttributeValue: {e}"
            ))
        })?;
        let mut values = SetOfVec::new();
        values
            .insert(value)
            .map_err(|e| CmsError::Builder(format!("failed to insert attr value: {e}")))?;

        Ok(Attribute {
            oid: rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2,
            values,
        })
    }

    /// DER-encode signed attributes for signing.
    ///
    /// Per RFC 5652 §5.4, when computing the signature over signed attributes,
    /// the attributes are DER-encoded as a SET OF (implicit tag 0x31), NOT as
    /// the IMPLICIT [0] tagged version used in the SignerInfo.
    fn encode_attrs_for_signing(&self, attrs: &SetOfVec<Attribute>) -> Result<Vec<u8>, CmsError> {
        // First encode the attributes as they would appear in SignerInfo
        // (which uses IMPLICIT [0] CONSTRUCTED, tag 0xA0).
        // Then replace the tag byte with SET OF (0x31).
        let encoded = attrs
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to DER-encode signed attributes: {e}")))?;

        // The first byte is the SET OF tag (0x31) since SetOfVec encodes as SET OF.
        // This is already correct for signing purposes.
        // However, in the SignerInfo encoding, signed_attrs gets tagged as [0] IMPLICIT.
        // The to_der() on SetOfVec produces the raw SET OF encoding, which is what we want.
        Ok(encoded)
    }

    /// Get the AlgorithmIdentifier for the digest algorithm.
    fn digest_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        let oid = match self.signer.digest_algorithm() {
            DigestAlgorithm::Sha256 => rfc5912::ID_SHA_256,
            DigestAlgorithm::Sha384 => rfc5912::ID_SHA_384,
            DigestAlgorithm::Sha512 => rfc5912::ID_SHA_512,
            DigestAlgorithm::Sha3_256 => crate::crypto::algorithm::OID_SHA3_256,
            DigestAlgorithm::Sha3_384 => crate::crypto::algorithm::OID_SHA3_384,
            DigestAlgorithm::Sha3_512 => crate::crypto::algorithm::OID_SHA3_512,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    /// Get the AlgorithmIdentifier for the signature algorithm.
    fn signature_algorithm_identifier(&self) -> Result<AlgorithmIdentifierOwned, CmsError> {
        use crate::crypto::algorithm::OID_RSASSA_PSS;

        let (oid, parameters) = match (
            self.signer.signature_algorithm(),
            self.signer.digest_algorithm(),
        ) {
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha256) => {
                // RSA PKCS#1 v1.5 with SHA-256 requires NULL parameters
                let null_any = Any::new(Tag::Null, Vec::new())
                    .map_err(|e| CmsError::Der(format!("failed to create NULL Any: {e}")))?;
                (rfc5912::SHA_256_WITH_RSA_ENCRYPTION, Some(null_any))
            }
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha384) => {
                let null_any = Any::new(Tag::Null, Vec::new())
                    .map_err(|e| CmsError::Der(format!("failed to create NULL Any: {e}")))?;
                (rfc5912::SHA_384_WITH_RSA_ENCRYPTION, Some(null_any))
            }
            (SignatureAlgorithm::RsaPkcs1v15, DigestAlgorithm::Sha512) => {
                let null_any = Any::new(Tag::Null, Vec::new())
                    .map_err(|e| CmsError::Der(format!("failed to create NULL Any: {e}")))?;
                (rfc5912::SHA_512_WITH_RSA_ENCRYPTION, Some(null_any))
            }
            (SignatureAlgorithm::RsaPkcs1v15, digest) => {
                // RSA PKCS#1 v1.5 with SHA-3 — uses the same RSA OID pattern
                // but SHA-3 doesn't have dedicated rsaEncryption+sha3 combined OIDs.
                // Fall back to RSASSA-PSS with explicit parameters for SHA-3.
                let params = rsassa_pss_params_any(digest)
                    .map_err(|e| CmsError::Der(format!("RSA-PSS params: {e}")))?;
                (OID_RSASSA_PSS, Some(params))
            }
            (SignatureAlgorithm::RsaPss, digest) => {
                let params = rsassa_pss_params_any(digest)
                    .map_err(|e| CmsError::Der(format!("RSA-PSS params: {e}")))?;
                (OID_RSASSA_PSS, Some(params))
            }
            (SignatureAlgorithm::EcdsaP256, _) => (rfc5912::ECDSA_WITH_SHA_256, None),
            (SignatureAlgorithm::EcdsaP384, _) => (rfc5912::ECDSA_WITH_SHA_384, None),
            (SignatureAlgorithm::Ed25519, _) => (crate::crypto::algorithm::OID_ED25519, None),
        };

        Ok(AlgorithmIdentifierOwned { oid, parameters })
    }

    /// Build the certificate set to embed in the SignedData.
    fn build_certificate_set(&self) -> Result<CertificateSet, CmsError> {
        let mut cert_set = SetOfVec::new();

        if self.embed_chain {
            for cert_der in self.signer.certificate_chain_der() {
                let cert = Certificate::from_der(cert_der).map_err(|e| {
                    CmsError::Der(format!("failed to parse chain certificate: {e}"))
                })?;
                cert_set
                    .insert(CertificateChoices::Certificate(cert))
                    .map_err(|e| {
                        CmsError::Builder(format!("failed to insert certificate into set: {e}"))
                    })?;
            }
        } else {
            let cert = Certificate::from_der(self.signer.certificate_der())
                .map_err(|e| CmsError::Der(format!("failed to parse signer certificate: {e}")))?;
            cert_set
                .insert(CertificateChoices::Certificate(cert))
                .map_err(|e| {
                    CmsError::Builder(format!("failed to insert signer certificate into set: {e}"))
                })?;
        }

        Ok(CertificateSet(cert_set))
    }
}

// ---------------------------------------------------------------------------
// Helper functions for building standard CMS signed attributes
// ---------------------------------------------------------------------------

/// Build the `contentType` signed attribute (always `id-data` for PDF signing).
fn build_content_type_attr() -> Result<Attribute, CmsError> {
    // The value is the OID id-data, encoded as an OID
    let oid_bytes = rfc5911::ID_DATA
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode id-data OID: {e}")))?;
    let value = AttributeValue::from_der(&oid_bytes)
        .map_err(|e| CmsError::Der(format!("failed to parse content-type value: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("failed to insert content-type value: {e}")))?;

    Ok(Attribute {
        oid: rfc5911::ID_CONTENT_TYPE,
        values,
    })
}

/// Build the `messageDigest` signed attribute containing the hash of the PDF byte ranges.
fn build_message_digest_attr(digest: &[u8]) -> Result<Attribute, CmsError> {
    let octet_string = OctetString::new(digest.to_vec())
        .map_err(|e| CmsError::Der(format!("failed to create digest octet string: {e}")))?;
    let octet_der = octet_string
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode digest octet string: {e}")))?;
    let value = AttributeValue::from_der(&octet_der)
        .map_err(|e| CmsError::Der(format!("failed to parse message-digest value: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("failed to insert message-digest value: {e}")))?;

    Ok(Attribute {
        oid: rfc5911::ID_MESSAGE_DIGEST,
        values,
    })
}

/// Build the `signingTime` signed attribute.
fn build_signing_time_attr(time: &chrono::NaiveDateTime) -> Result<Attribute, CmsError> {
    // Per X.680: use UTCTime for years 1950-2049, GeneralizedTime otherwise
    let year = time
        .and_utc()
        .format("%Y")
        .to_string()
        .parse::<u16>()
        .unwrap_or(2025);

    let dt = der::DateTime::new(
        year,
        time.format("%m").to_string().parse().unwrap_or(1),
        time.format("%d").to_string().parse().unwrap_or(1),
        time.format("%H").to_string().parse().unwrap_or(0),
        time.format("%M").to_string().parse().unwrap_or(0),
        time.format("%S").to_string().parse().unwrap_or(0),
    )
    .map_err(|e| CmsError::Der(format!("failed to create der::DateTime: {e}")))?;

    let time_der = if (1950..=2049).contains(&year) {
        let utc_time = der::asn1::UtcTime::from_date_time(dt)
            .map_err(|e| CmsError::Der(format!("failed to create UtcTime: {e}")))?;
        utc_time
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to encode UtcTime: {e}")))?
    } else {
        let gen_time = der::asn1::GeneralizedTime::from_date_time(dt);
        gen_time
            .to_der()
            .map_err(|e| CmsError::Der(format!("failed to encode GeneralizedTime: {e}")))?
    };

    let value = AttributeValue::from_der(&time_der)
        .map_err(|e| CmsError::Der(format!("failed to parse signing-time value: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("failed to insert signing-time value: {e}")))?;

    Ok(Attribute {
        oid: rfc5911::ID_SIGNING_TIME,
        values,
    })
}

/// Build the CMS Algorithm Protection signed attribute (RFC 6211).
///
/// This attribute binds the digest and signature algorithms to the signed
/// data, preventing algorithm substitution attacks where an adversary modifies
/// the algorithm identifiers in the unsigned portions of `SignerInfo`.
///
/// ASN.1 structure:
/// ```text
/// CMSAlgorithmProtection ::= SEQUENCE {
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
///     macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL
/// }
/// ```
///
/// For `SignedData`, `signatureAlgorithm` with IMPLICIT tag `[1]` is always present.
fn build_cms_algorithm_protection_attr(
    digest_alg: &AlgorithmIdentifierOwned,
    sig_alg: &AlgorithmIdentifierOwned,
) -> Result<Attribute, CmsError> {
    // 1. DER-encode the digestAlgorithm
    let digest_alg_der = digest_alg
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode digest alg for CMS-AP: {e}")))?;

    // 2. DER-encode the signatureAlgorithm, then re-tag as IMPLICIT [1]
    let sig_alg_der = sig_alg
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode sig alg for CMS-AP: {e}")))?;
    let tagged_sig_alg = encode_context_implicit(1, &sig_alg_der);

    // 3. Build the CMSAlgorithmProtection SEQUENCE
    let cmsap_seq = encode_sequence(&[&digest_alg_der, &tagged_sig_alg]);

    // 4. Wrap as an Attribute
    let value = AttributeValue::from_der(&cmsap_seq).map_err(|e| {
        CmsError::Der(format!(
            "failed to parse CMSAlgorithmProtection as AttributeValue: {e}"
        ))
    })?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("failed to insert CMS-AP value: {e}")))?;

    Ok(Attribute {
        oid: ID_AA_CMS_ALGORITHM_PROTECTION,
        values,
    })
}

/// Build the DER encoding of IssuerSerial for ESS signingCertificateV2.
///
/// ```text
/// IssuerSerial ::= SEQUENCE {
///     issuer GeneralNames,
///     serialNumber CertificateSerialNumber
/// }
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// GeneralName ::= CHOICE { directoryName [4] Name, ... }
/// ```
fn build_issuer_serial_der(cert: &Certificate) -> Result<Vec<u8>, CmsError> {
    // Encode the issuer Name
    let issuer_der = cert
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode issuer: {e}")))?;

    // Wrap issuer as GeneralName directoryName [4] EXPLICIT
    let general_name = encode_context_explicit(4, &issuer_der);
    // Wrap in GeneralNames SEQUENCE
    let general_names = encode_sequence(&[&general_name]);

    // Encode serial number
    let serial_der = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| CmsError::Der(format!("failed to encode serial number: {e}")))?;

    // IssuerSerial SEQUENCE
    Ok(encode_sequence(&[&general_names, &serial_der]))
}

// ---------------------------------------------------------------------------
// Low-level DER encoding helpers
// ---------------------------------------------------------------------------

/// Encode a DER SEQUENCE wrapping the concatenated parts.
fn encode_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(1 + length_bytes(total_len) + total_len);
    out.push(0x30); // SEQUENCE tag
    encode_length(&mut out, total_len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// Encode a context-specific EXPLICIT tag wrapping content.
fn encode_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | tag_num; // context-specific, constructed, explicit
    let mut out = Vec::with_capacity(1 + length_bytes(content.len()) + content.len());
    out.push(tag);
    encode_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encode a context-specific IMPLICIT tag by replacing the outer tag of a
/// constructed value (e.g., a SEQUENCE) with the context-specific tag.
///
/// For IMPLICIT tagging, we replace the original tag byte (e.g., 0x30 for SEQUENCE)
/// with the context-specific constructed tag (0xA0 | tag_num). The length and
/// content remain unchanged. This is correct for constructed types like
/// `AlgorithmIdentifier` which are SEQUENCEs.
fn encode_context_implicit(tag_num: u8, der: &[u8]) -> Vec<u8> {
    assert!(!der.is_empty(), "cannot IMPLICIT-tag empty DER");
    let mut out = der.to_vec();
    // Replace the outer tag (0x30 for SEQUENCE) with context-specific constructed
    out[0] = 0xA0 | tag_num;
    out
}

/// Encode DER definite-form length.
fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// How many bytes the DER length encoding takes.
fn length_bytes(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else if len <= 0xFFFF {
        3
    } else if len <= 0xFF_FFFF {
        4
    } else {
        5
    }
}

/// Encode a small unsigned integer as DER INTEGER.
fn encode_integer(val: u32) -> Vec<u8> {
    if val == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let bytes = val.to_be_bytes();
    // Skip leading zeros
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];
    // If high bit set, prepend a zero byte
    let needs_pad = significant[0] & 0x80 != 0;
    let len = significant.len() + if needs_pad { 1 } else { 0 };
    let mut out = vec![0x02]; // INTEGER tag
    encode_length(&mut out, len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(significant);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Expose CMS-AP builder for cross-module testing.
    pub(crate) fn build_cmsap_for_test(
        digest_alg: &AlgorithmIdentifierOwned,
        sig_alg: &AlgorithmIdentifierOwned,
    ) -> Attribute {
        build_cms_algorithm_protection_attr(digest_alg, sig_alg)
            .expect("failed to build CMS-AP for test")
    }

    #[test]
    fn test_content_type_attr() {
        let attr = build_content_type_attr().unwrap();
        assert_eq!(attr.oid, rfc5911::ID_CONTENT_TYPE);
        assert_eq!(attr.values.len(), 1);
    }

    #[test]
    fn test_message_digest_attr() {
        let digest = vec![0xAA; 32]; // Fake SHA-256 digest
        let attr = build_message_digest_attr(&digest).unwrap();
        assert_eq!(attr.oid, rfc5911::ID_MESSAGE_DIGEST);
        assert_eq!(attr.values.len(), 1);
    }

    #[test]
    fn test_signing_time_attr() {
        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let attr = build_signing_time_attr(&time).unwrap();
        assert_eq!(attr.oid, rfc5911::ID_SIGNING_TIME);
        assert_eq!(attr.values.len(), 1);
    }

    #[test]
    fn test_encode_sequence() {
        let inner = &[0x02, 0x01, 0x05]; // INTEGER 5
        let seq = encode_sequence(&[inner]);
        assert_eq!(seq, vec![0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn test_encode_length() {
        // Short form
        let mut buf = Vec::new();
        encode_length(&mut buf, 0x7F);
        assert_eq!(buf, vec![0x7F]);

        // Long form, 1 byte
        buf.clear();
        encode_length(&mut buf, 0x80);
        assert_eq!(buf, vec![0x81, 0x80]);

        // Long form, 2 bytes
        buf.clear();
        encode_length(&mut buf, 0x0100);
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_cms_builder_with_signer() {
        // Load our test PKCS#12 and verify the builder can construct CMS
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let builder = PdfCmsBuilder::new(&signer).profile(CmsProfile::Pades);

        // Estimate size should be reasonable
        let est = builder.estimate_size();
        assert!(est > 1000, "estimate too small: {est}");
        assert!(est < 100_000, "estimate too large: {est}");

        // Build with a fake hash
        let fake_hash = vec![0xBB; 32]; // SHA-256 sized
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        // Verify we got a valid DER-encoded ContentInfo
        assert!(!cms_der.is_empty());
        let content_info =
            ContentInfo::from_der(&cms_der).expect("failed to parse CMS ContentInfo");
        assert_eq!(content_info.content_type, rfc5911::ID_SIGNED_DATA);

        // Parse back the SignedData — use to_der() not value()
        let sd_bytes = content_info
            .content
            .to_der()
            .expect("failed to re-encode content");
        let signed_data = SignedData::from_der(&sd_bytes).expect("failed to parse SignedData");
        assert_eq!(signed_data.digest_algorithms.len(), 1);
        assert!(signed_data.certificates.is_some());
        assert_eq!(signed_data.signer_infos.0.len(), 1);

        // Check the signer info
        let si = &signed_data.signer_infos.0.as_slice()[0];
        assert!(si.signed_attrs.is_some());
        let attrs = si.signed_attrs.as_ref().unwrap();
        // Should have: contentType, messageDigest, signingCertificateV2, CMSAlgorithmProtection (PAdES mode)
        assert!(
            attrs.len() >= 4,
            "expected at least 4 signed attributes, got {}",
            attrs.len()
        );

        // Verify CMS-AP attribute is present
        let has_cmsap = attrs
            .iter()
            .any(|a| a.oid == ID_AA_CMS_ALGORITHM_PROTECTION);
        assert!(has_cmsap, "CMS Algorithm Protection attribute not found");
    }

    #[test]
    fn test_cms_builder_traditional_mode() {
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("failed to load test PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let builder = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time(time);

        let fake_hash = vec![0xCC; 32];
        let cms_der = builder.build(&fake_hash).expect("CMS build failed");

        let content_info =
            ContentInfo::from_der(&cms_der).expect("failed to parse CMS ContentInfo");
        let sd_bytes = content_info
            .content
            .to_der()
            .expect("failed to re-encode content");
        let signed_data = SignedData::from_der(&sd_bytes).expect("failed to parse SignedData");

        let si = &signed_data.signer_infos.0.as_slice()[0];
        let attrs = si.signed_attrs.as_ref().unwrap();
        // Traditional with signing_time: contentType, messageDigest, signingTime, CMSAlgorithmProtection
        assert!(
            attrs.len() >= 4,
            "expected at least 4 signed attributes, got {}",
            attrs.len()
        );

        // Verify CMS-AP attribute is present in Traditional mode too
        let has_cmsap = attrs
            .iter()
            .any(|a| a.oid == ID_AA_CMS_ALGORITHM_PROTECTION);
        assert!(
            has_cmsap,
            "CMS Algorithm Protection attribute not found in Traditional mode"
        );
    }

    #[test]
    fn test_cms_algorithm_protection_attr_structure() {
        // Build a CMS-AP attribute and verify its DER structure
        let digest_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_256,
            parameters: None,
        };
        let null_any = Any::new(Tag::Null, Vec::new()).unwrap();
        let sig_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(null_any),
        };

        let attr = build_cms_algorithm_protection_attr(&digest_alg, &sig_alg).unwrap();
        assert_eq!(attr.oid, ID_AA_CMS_ALGORITHM_PROTECTION);
        assert_eq!(attr.values.len(), 1);

        // Parse the attribute value back as DER and verify structure
        let value = attr.values.iter().next().unwrap();
        let value_der = value.to_der().unwrap();
        // Should be a SEQUENCE containing digestAlgorithm + [1] signatureAlgorithm
        assert_eq!(value_der[0], 0x30, "expected SEQUENCE tag");
    }

    #[test]
    fn test_encode_context_implicit() {
        // A simple SEQUENCE: 0x30 0x03 0x02 0x01 0x05
        let seq = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let tagged = encode_context_implicit(1, &seq);
        // Should replace 0x30 with 0xA1
        assert_eq!(tagged[0], 0xA1);
        assert_eq!(&tagged[1..], &seq[1..]);
    }

    /// Helper to parse CMS DER back to (SignedData, SignerInfo)
    fn parse_cms_signer_info(cms_der: &[u8]) -> (SignedData, SignerInfo) {
        let content_info = ContentInfo::from_der(cms_der).expect("parse ContentInfo");
        let sd_bytes = content_info.content.to_der().expect("re-encode content");
        let signed_data = SignedData::from_der(&sd_bytes).expect("parse SignedData");
        let si = signed_data.signer_infos.0.as_slice()[0].clone();
        (signed_data, si)
    }

    /// Check whether signingTime OID is present in a set of attributes.
    fn has_signing_time(attrs: &SetOfVec<Attribute>) -> bool {
        attrs.iter().any(|a| a.oid == rfc5911::ID_SIGNING_TIME)
    }

    #[test]
    fn test_signing_time_placement_signed_default() {
        // Default (Signed): signingTime in signed attrs, NOT in unsigned attrs
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time(time)
            // Default placement = Signed
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // Signed attrs SHOULD contain signingTime
        assert!(
            has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "signingTime missing from signed attrs with Signed placement"
        );

        // Unsigned attrs should be None (no unsigned attrs at all)
        assert!(
            si.unsigned_attrs.is_none(),
            "unsigned attrs should be None with Signed placement"
        );
    }

    #[test]
    fn test_signing_time_placement_unsigned() {
        // Unsigned: signingTime NOT in signed attrs, IS in unsigned attrs
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(SigningTimePlacement::Unsigned)
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // Signed attrs should NOT contain signingTime
        assert!(
            !has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "signingTime should not be in signed attrs with Unsigned placement"
        );

        // Unsigned attrs SHOULD exist and contain signingTime
        let unsigned = si
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs should be present");
        assert!(
            has_signing_time(unsigned),
            "signingTime missing from unsigned attrs with Unsigned placement"
        );
    }

    #[test]
    fn test_signing_time_placement_both() {
        // Both: signingTime in BOTH signed and unsigned attrs
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(SigningTimePlacement::Both)
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // Signed attrs SHOULD contain signingTime
        assert!(
            has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "signingTime missing from signed attrs with Both placement"
        );

        // Unsigned attrs SHOULD also contain signingTime
        let unsigned = si
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs should be present with Both placement");
        assert!(
            has_signing_time(unsigned),
            "signingTime missing from unsigned attrs with Both placement"
        );
    }

    #[test]
    fn test_signing_time_pades_unsigned() {
        // PAdES + Unsigned: signed attrs never have signingTime (PAdES rule),
        // but unsigned copy IS present.
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Pades)
            .signing_time(time)
            .signing_time_placement(SigningTimePlacement::Unsigned)
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // PAdES signed attrs should never have signingTime
        assert!(
            !has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "PAdES should never have signingTime in signed attrs"
        );

        // Unsigned attrs SHOULD contain signingTime
        let unsigned = si
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs should be present for PAdES + Unsigned");
        assert!(
            has_signing_time(unsigned),
            "signingTime missing from unsigned attrs for PAdES + Unsigned"
        );
    }

    #[test]
    fn test_signing_time_pades_both() {
        // PAdES + Both: signed attrs never have signingTime (PAdES rule),
        // unsigned copy IS present.
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Pades)
            .signing_time(time)
            .signing_time_placement(SigningTimePlacement::Both)
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // PAdES signed attrs should never have signingTime
        assert!(
            !has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "PAdES + Both: should never have signingTime in signed attrs"
        );

        // Unsigned attrs SHOULD contain signingTime
        let unsigned = si
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs should be present for PAdES + Both");
        assert!(
            has_signing_time(unsigned),
            "signingTime missing from unsigned attrs for PAdES + Both"
        );
    }

    #[test]
    fn test_signing_time_no_time_set() {
        // If signing_time is not set, no signingTime attr should appear anywhere
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let cms_der = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time_placement(SigningTimePlacement::Both)
            // Note: no signing_time() call
            .build(&[0xAA; 32])
            .expect("build");

        let (_sd, si) = parse_cms_signer_info(&cms_der);

        // No signingTime anywhere because the time itself was never set
        assert!(
            !has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "signingTime should not appear without a time value"
        );
        assert!(
            si.unsigned_attrs.is_none(),
            "unsigned attrs should be None when no time is set"
        );
    }

    #[test]
    fn test_signing_time_placement_presign_unsigned() {
        // Remote signing path: pre_sign + complete_cms with Unsigned placement
        let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(p12_path, "test123")
            .expect("load PKCS#12");

        let time =
            chrono::NaiveDateTime::parse_from_str("2025-06-15 12:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        let builder = PdfCmsBuilder::new(&signer)
            .profile(CmsProfile::Traditional)
            .signing_time(time)
            .signing_time_placement(SigningTimePlacement::Unsigned);

        let fake_hash = vec![0xDD; 32];
        let pre = builder.pre_sign(&fake_hash).expect("pre_sign");

        // pre.unsigned_attrs should have signingTime
        assert!(
            pre.unsigned_attrs.is_some(),
            "pre_sign should produce unsigned attrs with Unsigned placement"
        );
        assert!(
            has_signing_time(pre.unsigned_attrs.as_ref().unwrap()),
            "pre_sign unsigned attrs should contain signingTime"
        );

        // Signed attrs should NOT have signingTime
        assert!(
            !has_signing_time(&pre.signed_attrs),
            "pre_sign signed attrs should not contain signingTime with Unsigned placement"
        );

        // Complete the CMS with a real signature and verify the result
        let sig_bytes = signer.sign_hash(&pre.attrs_hash).expect("sign hash");
        let cms_der = builder
            .complete_cms(&pre, &sig_bytes)
            .expect("complete_cms");

        let (_sd, si) = parse_cms_signer_info(&cms_der);
        assert!(
            !has_signing_time(si.signed_attrs.as_ref().unwrap()),
            "complete_cms: signingTime should not be in signed attrs"
        );
        let unsigned = si
            .unsigned_attrs
            .as_ref()
            .expect("complete_cms: unsigned attrs should be present");
        assert!(
            has_signing_time(unsigned),
            "complete_cms: signingTime should be in unsigned attrs"
        );
    }
}
