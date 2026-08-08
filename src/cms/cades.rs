//! Standalone CAdES (ETSI EN 319 122-1) construction and qualifying properties.
//!
//! This builds CAdES signatures independent of PDF — in both shapes the
//! standard allows — plus the unsigned-attribute layer that upgrades a baseline
//! signature to higher conformance levels:
//!
//! - **CAdES-B-B**: [`sign_detached`] — a detached `SignedData` over external
//!   content, with content-type, message-digest, signing-certificate-v2 and
//!   signing-time signed attributes.
//! - **CAdES-B-B, enveloping**: [`sign_attached`] — the same signature with the
//!   content carried inside the CMS, so the result is one self-contained file
//!   (what Italian practice names `.p7m`). [`extract_content`] unwraps it.
//! - **Multiple signatures**: [`add_signer`] for parallel signatures over the
//!   same content, [`countersign`] for a signature over another signature.
//! - **CAdES-B-T**: attach a [`signature_timestamp_attr`] (RFC 3161 token over
//!   the signature value) via [`add_unsigned_attributes`].
//! - **CAdES-B-LT**: attach [`certificate_values_attr`] and
//!   [`revocation_values_attr`] (the certs/OCSP/CRLs needed to validate the
//!   signature long-term) via [`add_unsigned_attributes`].
//!
//! CAdES-B-LTA (archive-timestamp-v3 with `ats-hash-index-v3`) is intentionally
//! not implemented here yet; it is the most intricate part of the format and is
//! tracked as follow-on work.
//!
//! The [`signature_value`] helper returns the bytes a caller must timestamp to
//! produce the B-T signature timestamp.

#[cfg(test)]
use cms::content_info::ContentInfo;
#[cfg(test)]
use cms::signed_data::SignedData;
use const_oid::db::rfc5911;
use const_oid::ObjectIdentifier;
use der::asn1::SetOfVec;
use der::{Decode, Encode};
use x509_cert::attr::{Attribute, AttributeValue};

use crate::crypto::traits::CryptoSigner;
use crate::error::CmsError;

use super::builder::{CmsProfile, PdfCmsBuilder};

/// `id-aa-signatureTimeStampToken`: `1.2.840.113549.1.9.16.2.14`.
const OID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-aa-ets-certValues`: `1.2.840.113549.1.9.16.2.23`.
const OID_AA_ETS_CERT_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.23");
/// `id-aa-ets-revocationValues`: `1.2.840.113549.1.9.16.2.24`.
const OID_AA_ETS_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");

// --- minimal DER helpers (constructed types only) --------------------------

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = len.to_be_bytes().to_vec();
        while bytes.first() == Some(&0) {
            bytes.remove(0);
        }
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Tag-length-value with an explicit tag byte over already-encoded `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// SEQUENCE (tag 0x30) over the concatenation of `items`.
fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

/// IMPLICIT `[n]` constructed context tag (0xA0 | n) over `content`.
fn implicit_context(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, content)
}

// --- CAdES-B-B -------------------------------------------------------------

/// Produce a detached CAdES-B-B signature over `content`.
///
/// The content is hashed with the signer's configured digest algorithm and
/// placed in the `messageDigest` signed attribute; the `SignedData` is detached
/// (no encapsulated content). `signing_time`, when provided, is included as the
/// `signingTime` signed attribute (recommended for CAdES baseline).
///
/// Returns the DER-encoded `ContentInfo` wrapping the `SignedData`.
pub fn sign_detached(
    content: &[u8],
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
) -> Result<Vec<u8>, CmsError> {
    sign_cades(content, signer, signing_time, false)
}

/// Produce an **enveloping** (attached) CAdES-B-B signature over `content`.
///
/// Identical to [`sign_detached`] except that `content` is carried inside the
/// `SignedData` as encapsulated content, so the DER is self-contained: the
/// verifier needs nothing but this one blob to check the signature and recover
/// the original bytes (see [`extract_content`]).
///
/// This is the shape of a CAdES envelope as distributed on its own — for
/// instance the `.p7m` files used for Italian digital signatures. The file
/// naming is up to the caller; this function only produces the DER.
///
/// Returns the DER-encoded `ContentInfo` wrapping the `SignedData`.
pub fn sign_attached(
    content: &[u8],
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
) -> Result<Vec<u8>, CmsError> {
    sign_cades(content, signer, signing_time, true)
}

fn sign_cades(
    content: &[u8],
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
    attach: bool,
) -> Result<Vec<u8>, CmsError> {
    let data_hash = signer.digest_algorithm().digest(content);
    let mut builder = PdfCmsBuilder::new(signer).profile(CmsProfile::Cades);
    if attach {
        builder = builder.encapsulate(content);
    }
    if let Some(t) = signing_time {
        builder = builder.signing_time(t);
    }
    builder.build(&data_hash)
}

/// Recover the encapsulated content from an enveloping CMS `SignedData`.
///
/// Returns the original bytes that were signed by [`sign_attached`]. This does
/// **not** verify the signature — it only unwraps the envelope; validate the
/// signature separately before trusting the content.
///
/// Errors if `cms_der` is not a `SignedData`, or if it is detached (no
/// encapsulated content to extract).
pub fn extract_content(cms_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    RawSignedData::parse(cms_der)?
        .econtent()?
        .ok_or_else(|| CmsError::Builder("CMS is detached: no encapsulated content".into()))
}

// --- unsigned-attribute builders -------------------------------------------

fn single_value_attr(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute, CmsError> {
    let value = AttributeValue::from_der(value_der)
        .map_err(|e| CmsError::Der(format!("attribute value parse: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| CmsError::Builder(format!("insert attribute value: {e}")))?;
    Ok(Attribute { oid, values })
}

/// Build the `signature-time-stamp-token` unsigned attribute (CAdES-B-T).
///
/// `tst_der` is the DER of the RFC 3161 timestamp token (a CMS `ContentInfo`),
/// computed by a TSA over the signature value (see [`signature_value`]).
pub fn signature_timestamp_attr(tst_der: &[u8]) -> Result<Attribute, CmsError> {
    // The attribute value is the timestamp token (a ContentInfo) verbatim.
    single_value_attr(OID_AA_SIGNATURE_TIME_STAMP_TOKEN, tst_der)
}

/// Build the `certificate-values` unsigned attribute (CAdES-B-LT).
///
/// `certs_der` are the DER-encoded X.509 certificates needed to validate the
/// signature (the chain beyond what is already embedded in `SignedData.certificates`).
///
/// ```text
/// CertificateValues ::= SEQUENCE OF Certificate
/// ```
pub fn certificate_values_attr(certs_der: &[&[u8]]) -> Result<Attribute, CmsError> {
    // Validate each entry is a parseable certificate before embedding.
    for der in certs_der {
        x509_cert::Certificate::from_der(der)
            .map_err(|e| CmsError::Der(format!("certificate-values entry parse: {e}")))?;
    }
    let items: Vec<Vec<u8>> = certs_der.iter().map(|c| c.to_vec()).collect();
    let seq = sequence(&items);
    single_value_attr(OID_AA_ETS_CERT_VALUES, &seq)
}

/// Build the `revocation-values` unsigned attribute (CAdES-B-LT).
///
/// `crls_der` are DER-encoded `CertificateList`s; `ocsp_basic_der` are
/// DER-encoded `BasicOCSPResponse`s (the inner response, not the OCSP response
/// wrapper). Either list may be empty.
///
/// ```text
/// RevocationValues ::= SEQUENCE {
///   crlVals  [0] SEQUENCE OF CertificateList    OPTIONAL,
///   ocspVals [1] SEQUENCE OF BasicOCSPResponse  OPTIONAL,
///   otherRevVals [2] OtherRevVals               OPTIONAL }
/// ```
pub fn revocation_values_attr(
    crls_der: &[&[u8]],
    ocsp_basic_der: &[&[u8]],
) -> Result<Attribute, CmsError> {
    let mut fields: Vec<Vec<u8>> = Vec::new();
    if !crls_der.is_empty() {
        let items: Vec<Vec<u8>> = crls_der.iter().map(|c| c.to_vec()).collect();
        // [0] IMPLICIT SEQUENCE OF CertificateList
        fields.push(implicit_context(0, &items.concat()));
    }
    if !ocsp_basic_der.is_empty() {
        let items: Vec<Vec<u8>> = ocsp_basic_der.iter().map(|c| c.to_vec()).collect();
        // [1] IMPLICIT SEQUENCE OF BasicOCSPResponse
        fields.push(implicit_context(1, &items.concat()));
    }
    let seq = sequence(&fields);
    single_value_attr(OID_AA_ETS_REVOCATION_VALUES, &seq)
}

// --- DER surgery ------------------------------------------------------------
//
// Everything below rewrites an existing CMS *without* round-tripping it through
// the parsed model. The reason is narrow but decisive: a signature covers the
// exact bytes of its `signedAttrs`, and re-encoding a parsed `SET OF` re-sorts
// its elements — so a CMS written by a tool that ordered them differently comes
// back with a digest its own signature no longer matches.
//
// The read side of this crate already learned that lesson: `verify` reads the
// original attribute bytes out of the DER rather than re-encoding them. These
// helpers apply the same rule on the write side. The invariant is simple —
// **every byte covered by a signature is copied verbatim**. Unsigned attributes
// are covered by nothing, which is exactly why they are the one part we rebuild.

/// Read the TLV at `offset`, returning `(tag, value, offset just past it)`.
fn read_tlv(data: &[u8], offset: usize) -> Result<(u8, &[u8], usize), CmsError> {
    let truncated = || CmsError::Der("truncated DER".into());
    let tag = *data.get(offset).ok_or_else(truncated)?;
    let first = *data.get(offset + 1).ok_or_else(truncated)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        // Indefinite length (n == 0) is BER, which has no place in a signature.
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return Err(CmsError::Der(format!(
                "unsupported DER length form {first:#04x}"
            )));
        }
        let bytes = data.get(offset + 2..offset + 2 + n).ok_or_else(truncated)?;
        let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, 2 + n)
    };
    let start = offset + header;
    let end = start.checked_add(len).ok_or_else(truncated)?;
    Ok((tag, data.get(start..end).ok_or_else(truncated)?, end))
}

/// The value of a single TLV.
fn value_of(tlv_bytes: &[u8]) -> Result<&[u8], CmsError> {
    read_tlv(tlv_bytes, 0).map(|(_, value, _)| value)
}

/// The child TLVs of a constructed value, each as a verbatim slice.
fn children(value: &[u8]) -> Result<Vec<&[u8]>, CmsError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let (_, _, end) = read_tlv(value, pos)?;
        out.push(&value[pos..end]);
        pos = end;
    }
    Ok(out)
}

/// Emit a constructed TLV over `items`, ordered as X.690 §11.6 requires of a
/// `SET OF`. Sorting moves whole elements and never rewrites one, so it cannot
/// disturb a signature; encoding an unsorted set, on the other hand, produces
/// something strict DER decoders reject.
fn set_of(tag: u8, mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort();
    tlv(tag, &items.concat())
}

/// A `SignedData` taken apart into its still-encoded pieces.
///
/// Fields that no operation here touches (`version`, `encapContentInfo`, the
/// CRLs) are kept as whole TLVs; the `SET OF` fields are kept as their element
/// TLVs so elements can be added without re-encoding the ones already there.
struct RawSignedData {
    content_type: Vec<u8>,
    version: Vec<u8>,
    digest_algorithms: Vec<Vec<u8>>,
    encap_content_info: Vec<u8>,
    certificates: Option<Vec<Vec<u8>>>,
    crls: Option<Vec<u8>>,
    signer_infos: Vec<Vec<u8>>,
}

impl RawSignedData {
    fn parse(cms_der: &[u8]) -> Result<Self, CmsError> {
        let (tag, ci_body, _) = read_tlv(cms_der, 0)?;
        if tag != 0x30 {
            return Err(CmsError::Der("ContentInfo is not a SEQUENCE".into()));
        }
        let ci = children(ci_body)?;
        if ci.len() != 2 {
            return Err(CmsError::Der(format!(
                "ContentInfo has {} fields, expected contentType and content",
                ci.len()
            )));
        }
        let expected = rfc5911::ID_SIGNED_DATA
            .to_der()
            .map_err(|e| CmsError::Der(format!("encode signedData OID: {e}")))?;
        if ci[0] != expected {
            return Err(CmsError::Builder("not a SignedData ContentInfo".into()));
        }

        // content is [0] EXPLICIT, so its value is the SignedData SEQUENCE.
        let (tag, sd_body, _) = read_tlv(value_of(ci[1])?, 0)?;
        if tag != 0x30 {
            return Err(CmsError::Der("SignedData is not a SEQUENCE".into()));
        }
        let fields = children(sd_body)?;
        if fields.len() < 4 {
            return Err(CmsError::Der(format!(
                "SignedData has {} fields, expected at least 4",
                fields.len()
            )));
        }

        let owned = |tlvs: Vec<&[u8]>| tlvs.into_iter().map(<[u8]>::to_vec).collect::<Vec<_>>();
        let mut raw = RawSignedData {
            content_type: ci[0].to_vec(),
            version: fields[0].to_vec(),
            digest_algorithms: owned(children(value_of(fields[1])?)?),
            encap_content_info: fields[2].to_vec(),
            certificates: None,
            crls: None,
            signer_infos: Vec::new(),
        };
        for field in &fields[3..] {
            match field[0] {
                0xA0 => raw.certificates = Some(owned(children(value_of(field)?)?)),
                0xA1 => raw.crls = Some(field.to_vec()),
                0x31 => raw.signer_infos = owned(children(value_of(field)?)?),
                tag => {
                    return Err(CmsError::Der(format!(
                        "unexpected SignedData field with tag {tag:#04x}"
                    )))
                }
            }
        }
        if raw.signer_infos.is_empty() {
            return Err(CmsError::Builder("SignedData has no SignerInfo".into()));
        }
        Ok(raw)
    }

    fn encode(self) -> Vec<u8> {
        let mut fields = vec![
            self.version,
            set_of(0x31, self.digest_algorithms),
            self.encap_content_info,
        ];
        if let Some(certificates) = self.certificates {
            fields.push(set_of(0xA0, certificates));
        }
        if let Some(crls) = self.crls {
            fields.push(crls);
        }
        fields.push(set_of(0x31, self.signer_infos));

        let signed_data = sequence(&fields);
        sequence(&[self.content_type, implicit_context(0, &signed_data)])
    }

    /// The encapsulated content, or `None` when the CMS is detached.
    fn econtent(&self) -> Result<Option<Vec<u8>>, CmsError> {
        let fields = children(value_of(&self.encap_content_info)?)?;
        let Some(explicit) = fields.get(1) else {
            return Ok(None);
        };
        let (tag, octets, _) = read_tlv(value_of(explicit)?, 0)?;
        if tag != 0x04 {
            return Err(CmsError::Der(format!(
                "encapsulated content has tag {tag:#04x}, expected a primitive OCTET STRING"
            )));
        }
        Ok(Some(octets.to_vec()))
    }

    fn signer_info(&self, index: usize) -> Result<&[u8], CmsError> {
        self.signer_infos
            .get(index)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                CmsError::Builder(format!(
                    "no SignerInfo at index {index}: the CMS has {}",
                    self.signer_infos.len()
                ))
            })
    }

    /// Add `certs` (DER `CertificateChoices`) that are not already present.
    fn merge_certificates(&mut self, certs: Option<Vec<Vec<u8>>>) {
        let Some(certs) = certs else { return };
        let existing = self.certificates.get_or_insert_with(Vec::new);
        for cert in certs {
            if !existing.contains(&cert) {
                existing.push(cert);
            }
        }
    }
}

/// The `signature` value of a raw `SignerInfo`.
///
/// It is the only primitive OCTET STRING among the immediate children: the
/// `subjectKeyIdentifier` form of `sid` is `[0]` and both attribute sets are
/// constructed context tags, so there is nothing to confuse it with.
fn signer_info_signature(signer_info: &[u8]) -> Result<Vec<u8>, CmsError> {
    children(value_of(signer_info)?)?
        .into_iter()
        .find(|child| child[0] == 0x04)
        .ok_or_else(|| CmsError::Der("SignerInfo has no signature value".into()))
        .and_then(|child| Ok(value_of(child)?.to_vec()))
}

/// Return `signer_info` with `new_attrs` merged into its unsigned attributes.
///
/// Everything else — `signedAttrs` above all — is copied byte for byte, so the
/// signature this `SignerInfo` carries keeps verifying. Attributes are keyed by
/// OID, so adding one that is already present adds its value to the existing
/// attribute rather than producing a second one.
fn signer_info_with_unsigned(
    signer_info: &[u8],
    new_attrs: Vec<Attribute>,
) -> Result<Vec<u8>, CmsError> {
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut attrs: Vec<Attribute> = Vec::new();

    for child in children(value_of(signer_info)?)? {
        if child[0] == 0xA1 {
            // [1] IMPLICIT differs from the SET OF it stands for by one tag
            // byte, so re-tagging in place is enough to parse it.
            let mut as_set = child.to_vec();
            as_set[0] = 0x31;
            let existing = SetOfVec::<Attribute>::from_der(&as_set)
                .map_err(|e| CmsError::Der(format!("parse unsigned attributes: {e}")))?;
            attrs.extend(existing.iter().cloned());
        } else {
            fields.push(child.to_vec());
        }
    }

    for new_attr in new_attrs {
        match attrs.iter_mut().find(|a| a.oid == new_attr.oid) {
            Some(existing) => {
                for value in new_attr.values.iter() {
                    existing.values.insert(value.clone()).map_err(|e| {
                        CmsError::Builder(format!("add value to attribute {}: {e}", new_attr.oid))
                    })?;
                }
            }
            None => attrs.push(new_attr),
        }
    }

    if !attrs.is_empty() {
        let set = SetOfVec::try_from(attrs)
            .map_err(|e| CmsError::Builder(format!("rebuild unsigned attributes: {e}")))?;
        let mut der = set
            .to_der()
            .map_err(|e| CmsError::Der(format!("encode unsigned attributes: {e}")))?;
        der[0] = 0xA1;
        // unsignedAttrs is the last field of SignerInfo.
        fields.push(der);
    }

    Ok(sequence(&fields))
}

// --- composition over an existing CMS --------------------------------------

/// Return the signature value (the `SignerInfo.signature` octets) from a
/// detached CMS. This is the data a TSA must timestamp to produce the B-T
/// signature timestamp (the caller hashes these bytes and sends the digest).
pub fn signature_value(cms_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let raw = RawSignedData::parse(cms_der)?;
    if raw.signer_infos.len() != 1 {
        return Err(CmsError::Builder(format!(
            "expected exactly one SignerInfo, found {}",
            raw.signer_infos.len()
        )));
    }
    signer_info_signature(raw.signer_info(0)?)
}

/// Like [`signature_value`], but for a CMS carrying several parallel
/// signatures: returns the signature value of the signer at `index`, so each
/// one can be timestamped separately.
pub fn signature_value_at(cms_der: &[u8], index: usize) -> Result<Vec<u8>, CmsError> {
    let raw = RawSignedData::parse(cms_der)?;
    signer_info_signature(raw.signer_info(index)?)
}

/// Add unsigned attributes to the single `SignerInfo` of a CMS, preserving any
/// already present.
///
/// This is the composition primitive used to upgrade B-B → B-T (add a
/// signature timestamp) and B-T → B-LT (add certificate/revocation values).
/// Signed material is copied verbatim, so this is safe to apply to a CMS
/// produced by another implementation.
pub fn add_unsigned_attributes(
    cms_der: &[u8],
    new_attrs: Vec<Attribute>,
) -> Result<Vec<u8>, CmsError> {
    let raw = RawSignedData::parse(cms_der)?;
    if raw.signer_infos.len() != 1 {
        return Err(CmsError::Builder(format!(
            "expected exactly one SignerInfo, found {}",
            raw.signer_infos.len()
        )));
    }
    add_unsigned_attributes_at(cms_der, 0, new_attrs)
}

/// Like [`add_unsigned_attributes`], but targets the signer at `index` in a CMS
/// carrying several parallel signatures — each signer gets its own timestamp
/// and its own validation material.
///
/// `index` counts in encoded (`SET OF`) order, the order verification reports
/// signers in. Adding to a signer changes its encoding and so may move it
/// within that order: re-read the indices after each call rather than assuming
/// they are stable.
pub fn add_unsigned_attributes_at(
    cms_der: &[u8],
    index: usize,
    new_attrs: Vec<Attribute>,
) -> Result<Vec<u8>, CmsError> {
    let mut raw = RawSignedData::parse(cms_der)?;
    let updated = signer_info_with_unsigned(raw.signer_info(index)?, new_attrs)?;
    raw.signer_infos[index] = updated;
    Ok(raw.encode())
}

/// Parse a CMS into the typed model.
///
/// Test-only on purpose: the composition functions above deliberately never go
/// through it, because re-encoding what it returns is what corrupts signatures.
/// Assertions are free to use it — they only read.
#[cfg(test)]
fn parse_signed_data(cms_der: &[u8]) -> Result<SignedData, CmsError> {
    let ci = ContentInfo::from_der(cms_der)
        .map_err(|e| CmsError::Der(format!("parse ContentInfo: {e}")))?;
    if ci.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(CmsError::Builder("not a SignedData ContentInfo".into()));
    }
    let sd_der = ci
        .content
        .to_der()
        .map_err(|e| CmsError::Der(format!("extract SignedData: {e}")))?;
    SignedData::from_der(&sd_der).map_err(|e| CmsError::Der(format!("parse SignedData: {e}")))
}

// --- multiple signatures ----------------------------------------------------

/// Add a **parallel** signature: a second (third, …) `SignerInfo` over the very
/// same content, inside the same `SignedData`.
///
/// All signers are peers — none signs the others' signatures, and removing one
/// leaves the rest valid. For a signature *over* an existing signature, see
/// [`countersign`].
///
/// `content` may be `None` when `cms_der` is enveloping (the content is taken
/// from the envelope); for a detached CMS the caller must supply the same bytes
/// the existing signers signed.
///
/// The signers already present are transplanted byte for byte, so their
/// signatures survive intact even when the CMS came from another implementation.
pub fn add_signer(
    cms_der: &[u8],
    content: Option<&[u8]>,
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
) -> Result<Vec<u8>, CmsError> {
    let mut raw = RawSignedData::parse(cms_der)?;

    let content = match content {
        Some(content) => content.to_vec(),
        None => raw.econtent()?.ok_or_else(|| {
            CmsError::Builder("CMS is detached: the signed content must be supplied".into())
        })?,
    };

    // Sign the content standalone, then transplant the resulting SignerInfo.
    let fresh = RawSignedData::parse(&sign_detached(&content, signer, signing_time)?)?;

    raw.signer_infos.extend(fresh.signer_infos);
    for alg in fresh.digest_algorithms {
        if !raw.digest_algorithms.contains(&alg) {
            raw.digest_algorithms.push(alg);
        }
    }
    raw.merge_certificates(fresh.certificates);

    Ok(raw.encode())
}

/// `id-countersignature`: `1.2.840.113549.1.9.6` (RFC 5652 §11.4).
const OID_COUNTERSIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");

/// Countersign the signature at index `target`: a signature *over another
/// signature* rather than over the content.
///
/// Per RFC 5652 §11.4 the countersigner signs the target's `signature` value,
/// and the resulting `SignerInfo` is attached to the target as a
/// `countersignature` unsigned attribute. Because it is an unsigned attribute,
/// adding it does not disturb the signature it countersigns.
///
/// `target` indexes the `SignerInfo`s in the order they appear in the encoded
/// `SET OF` — the same order [`add_signer`] and verification report them in.
/// Use `0` for the common single-signature case.
///
/// The countersigner's certificate chain is merged into the `SignedData`, and
/// repeated calls stack countersignatures on the same target.
pub fn countersign(
    cms_der: &[u8],
    target: usize,
    signer: &dyn CryptoSigner,
    signing_time: Option<chrono::NaiveDateTime>,
) -> Result<Vec<u8>, CmsError> {
    let mut raw = RawSignedData::parse(cms_der)?;

    // The countersigner signs the target's signature value, not the content.
    let digest = signer
        .digest_algorithm()
        .digest(&signer_info_signature(raw.signer_info(target)?)?);

    let mut builder = PdfCmsBuilder::new(signer).profile(CmsProfile::Countersignature);
    if let Some(time) = signing_time {
        builder = builder.signing_time(time);
    }
    let counter = RawSignedData::parse(&builder.build(&digest)?)?;
    let attr = single_value_attr(OID_COUNTERSIGNATURE, counter.signer_info(0)?)?;

    let updated = signer_info_with_unsigned(raw.signer_info(target)?, vec![attr])?;
    raw.signer_infos[target] = updated;
    raw.merge_certificates(counter.certificates);

    Ok(raw.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::algorithm::DigestAlgorithm;
    use crate::crypto::software::SoftwareSigner;
    use cms::signed_data::SignerInfo;

    fn signer() -> SoftwareSigner {
        let p12 = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
        SoftwareSigner::from_pkcs12_file(p12, "test123").expect("load signer")
    }

    #[test]
    fn detached_cades_bb_is_wellformed_and_has_unsigned_attr_slot() {
        let content = b"hello cades world";
        let cms = sign_detached(content, &signer(), None).expect("sign detached");

        // It parses as a SignedData ContentInfo with exactly one SignerInfo.
        let sd = parse_signed_data(&cms).expect("parse");
        assert_eq!(sd.signer_infos.0.len(), 1);
        // Detached: no encapsulated content.
        assert!(sd.encap_content_info.econtent.is_none());
        // The signature value is retrievable for timestamping.
        let sigval = signature_value(&cms).expect("sig value");
        assert!(!sigval.is_empty());
    }

    #[test]
    fn attached_cades_carries_the_content_and_gives_it_back() {
        let content = b"documento da imbustare";
        let cms = sign_attached(content, &signer(), None).expect("sign attached");

        let sd = parse_signed_data(&cms).expect("parse");
        assert!(sd.encap_content_info.econtent.is_some());
        assert_eq!(sd.encap_content_info.econtent_type, rfc5911::ID_DATA);
        assert_eq!(extract_content(&cms).expect("extract"), content);

        // A detached envelope has nothing to extract.
        let detached = sign_detached(content, &signer(), None).expect("sign detached");
        assert!(extract_content(&detached).is_err());
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Re-sign `cms` with its signed attributes in reverse order.
    ///
    /// The result is a perfectly valid signature over a `SET OF` that is not in
    /// DER order — which is what an implementation that does not canonicalise
    /// produces, and what our own builder can never produce. Composing onto a
    /// file like this is the case that decides whether the composition
    /// functions are safe to point at someone else's CMS.
    fn with_unsorted_signed_attrs(cms: &[u8], signer: &dyn CryptoSigner) -> Vec<u8> {
        let mut raw = RawSignedData::parse(cms).expect("parse");
        let fields = children(value_of(&raw.signer_infos[0]).unwrap()).unwrap();

        let attrs_tlv = fields.iter().find(|c| c[0] == 0xA0).expect("signed attrs");
        let mut attrs = children(value_of(attrs_tlv).unwrap()).unwrap();
        attrs.reverse();
        let unsorted: Vec<u8> = attrs.concat();
        assert_ne!(
            unsorted,
            value_of(attrs_tlv).unwrap(),
            "the attributes were already symmetric; the fixture proves nothing"
        );

        // RFC 5652 §5.4: what gets signed is the attributes as a SET OF.
        let hash = signer.digest_algorithm().digest(&tlv(0x31, &unsorted));
        let signature = signer.sign_hash(&hash).expect("re-sign");

        let mut rebuilt: Vec<Vec<u8>> = Vec::new();
        for field in fields {
            match field[0] {
                0xA0 => rebuilt.push(tlv(0xA0, &unsorted)),
                0x04 => rebuilt.push(tlv(0x04, &signature)),
                _ => rebuilt.push(field.to_vec()),
            }
        }
        raw.signer_infos[0] = sequence(&rebuilt);
        raw.encode()
    }

    /// The reason every composition function does DER surgery instead of
    /// re-encoding the parsed model.
    ///
    /// A signature covers the exact bytes of its `signedAttrs`. Round-tripping
    /// them through `SetOfVec` re-sorts the attributes, so a CMS whose author
    /// ordered them differently comes back with its own signature no longer
    /// matching. This builds exactly such a CMS and composes onto it.
    #[test]
    fn composing_onto_a_non_canonical_cms_leaves_its_signature_valid() {
        let content = b"gia firmato da un altro strumento";
        let signer = signer();
        let canonical = sign_attached(content, &signer, None).expect("sign");
        let cms = with_unsorted_signed_attrs(&canonical, &signer);

        let signed_attrs =
            children(value_of(&RawSignedData::parse(&cms).unwrap().signer_infos[0]).unwrap())
                .unwrap()
                .into_iter()
                .find(|child| child[0] == 0xA0)
                .expect("signed attrs")
                .to_vec();

        // The hand-built fixture must itself be valid, or the rest proves nothing.
        #[cfg(feature = "verify")]
        {
            let (_, results) = crate::verify::cms_verify::verify_enveloped(&cms).expect("verify");
            assert!(
                results[0].signature_valid && results[0].digest_matches,
                "the non-canonical fixture is not a valid signature: {:?}",
                results[0].issues
            );
        }

        let other = signer.with_digest_algorithm(DigestAlgorithm::Sha512);
        let composed = [
            (
                "add_signer",
                add_signer(&cms, None, &other, None).expect("add signer"),
            ),
            (
                "countersign",
                countersign(&cms, 0, &other, None).expect("countersign"),
            ),
            (
                "add_unsigned_attributes",
                add_unsigned_attributes(&cms, vec![signature_timestamp_attr(&cms).unwrap()])
                    .expect("add unsigned"),
            ),
        ];

        for (name, output) in composed {
            assert!(
                contains(&output, &signed_attrs),
                "{name} re-encoded the signed attributes"
            );
            #[cfg(feature = "verify")]
            {
                let (recovered, results) =
                    crate::verify::cms_verify::verify_enveloped(&output).expect("verify");
                assert_eq!(recovered, content, "{name} altered the content");
                assert!(
                    results[0].signature_valid && results[0].digest_matches,
                    "{name} invalidated the signature that was already there: {:?}",
                    results[0].issues
                );
            }
        }
    }

    #[test]
    fn parallel_signatures_stack_and_each_one_verifies() {
        let content = b"firmato da due parti";
        let first = signer();
        // A different digest algorithm makes a distinguishable second signer and
        // exercises the digestAlgorithms merge.
        let second = signer().with_digest_algorithm(DigestAlgorithm::Sha512);

        let single = sign_attached(content, &first, None).expect("first signature");
        let certs_before = parse_signed_data(&single)
            .expect("parse")
            .certificates
            .map(|set| set.0.len())
            .unwrap_or(0);
        let cms = add_signer(&single, None, &second, None).expect("second signature");

        let sd = parse_signed_data(&cms).expect("parse");
        assert_eq!(sd.signer_infos.0.len(), 2);
        assert_eq!(sd.digest_algorithms.len(), 2);
        // The two signers share a chain, which must not be duplicated.
        assert_eq!(sd.certificates.as_ref().unwrap().0.len(), certs_before);
        // The content survives untouched.
        assert_eq!(extract_content(&cms).expect("extract"), content);

        #[cfg(feature = "verify")]
        {
            let (recovered, results) =
                crate::verify::cms_verify::verify_enveloped(&cms).expect("verify");
            assert_eq!(recovered, content);
            assert_eq!(results.len(), 2);
            for (i, result) in results.iter().enumerate() {
                assert!(
                    result.signature_valid,
                    "signer {i} signature: {:?}",
                    result.issues
                );
                assert!(
                    result.digest_matches,
                    "signer {i} digest: {:?}",
                    result.issues
                );
            }
        }
    }

    #[test]
    fn countersignature_attaches_without_breaking_the_signature_it_covers() {
        let content = b"da controfirmare";
        let cms = sign_attached(content, &signer(), None).expect("sign");
        let original_sigval = signature_value(&cms).expect("sig value");

        let countersigner = signer().with_digest_algorithm(DigestAlgorithm::Sha512);
        let cms = countersign(&cms, 0, &countersigner, None).expect("countersign");

        let sd = parse_signed_data(&cms).expect("parse");
        // Still one signer: the countersignature rides in its unsigned attrs.
        assert_eq!(sd.signer_infos.0.len(), 1);
        let si = sd.signer_infos.0.iter().next().unwrap();
        assert_eq!(si.signature.as_bytes(), original_sigval);

        let attr = si
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attrs")
            .iter()
            .find(|a| a.oid == OID_COUNTERSIGNATURE)
            .expect("countersignature attribute");
        assert_eq!(attr.values.len(), 1);

        // The countersigner signed the signature value, per RFC 5652 §11.4,
        // and must not carry a contentType attribute.
        let counter_si = SignerInfo::from_der(&attr.values.get(0).unwrap().to_der().unwrap())
            .expect("parse countersignature SignerInfo");
        let signed_attrs = counter_si.signed_attrs.as_ref().expect("signed attrs");
        assert!(!signed_attrs
            .iter()
            .any(|a| a.oid == const_oid::db::rfc5911::ID_CONTENT_TYPE));
        let expected = DigestAlgorithm::Sha512.digest(&original_sigval);
        let message_digest = signed_attrs
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .expect("messageDigest");
        assert!(message_digest.values.get(0).unwrap().value() == expected);

        // A second countersignature joins the same attribute rather than adding
        // a duplicate one.
        let cms = countersign(&cms, 0, &signer(), None).expect("second countersignature");
        let sd = parse_signed_data(&cms).expect("parse");
        let si = sd.signer_infos.0.iter().next().unwrap();
        let counters: Vec<_> = si
            .unsigned_attrs
            .as_ref()
            .unwrap()
            .iter()
            .filter(|a| a.oid == OID_COUNTERSIGNATURE)
            .collect();
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].values.len(), 2);

        // The original signature is still intact underneath both of them.
        #[cfg(feature = "verify")]
        {
            let (_, results) = crate::verify::cms_verify::verify_enveloped(&cms).expect("verify");
            assert!(results[0].signature_valid, "{:?}", results[0].issues);
        }
    }

    #[test]
    fn add_certificate_and_revocation_values_roundtrips() {
        let cms = sign_detached(b"data", &signer(), None).expect("sign");

        let signer_cert = signer().certificate_der().to_vec();
        let cert_attr = certificate_values_attr(&[&signer_cert]).expect("cert values");
        let rev_attr = revocation_values_attr(&[], &[b"fake-basic-ocsp"]).expect("rev values");

        let upgraded =
            add_unsigned_attributes(&cms, vec![cert_attr, rev_attr]).expect("add unsigned");

        // Re-parse and confirm the unsigned attributes are present with the
        // right OIDs, and the signature value is unchanged (B-LT does not
        // re-sign).
        let sd = parse_signed_data(&upgraded).expect("parse upgraded");
        let si = sd.signer_infos.0.iter().next().unwrap();
        let unsigned = si.unsigned_attrs.as_ref().expect("unsigned attrs present");
        let oids: Vec<_> = unsigned.iter().map(|a| a.oid).collect();
        assert!(oids.contains(&OID_AA_ETS_CERT_VALUES));
        assert!(oids.contains(&OID_AA_ETS_REVOCATION_VALUES));

        assert_eq!(
            signature_value(&cms).unwrap(),
            signature_value(&upgraded).unwrap(),
            "adding validation data must not change the signature"
        );
    }

    #[cfg(feature = "verify")]
    #[test]
    fn detached_cades_bb_verifies_cryptographically() {
        let content = b"the quick brown fox";
        let s = signer();
        let cms = sign_detached(content, &s, None).expect("sign");

        let data_hash = s.digest_algorithm().digest(content);
        let result = crate::verify::cms_verify::verify_cms(&cms, &data_hash).expect("verify");
        assert!(result.signature_valid, "issues: {:?}", result.issues);
        assert!(
            result.digest_matches,
            "messageDigest must match content hash"
        );
        // CAdES baseline carries signingCertificateV2.
        assert_eq!(result.ess_cert_id_match, Some(true));
    }

    #[cfg(feature = "verify")]
    #[test]
    fn b_t_signature_timestamp_is_surfaced_by_verifier() {
        let s = signer();
        let cms = sign_detached(b"content", &s, None).expect("sign");
        // Embed a placeholder signature-timestamp token (verifier exposes it raw).
        let fake_tst = der::asn1::OctetString::new(vec![9, 9, 9])
            .unwrap()
            .to_der()
            .unwrap();
        let bt = add_unsigned_attributes(&cms, vec![signature_timestamp_attr(&fake_tst).unwrap()])
            .expect("add ts");

        let data_hash = s.digest_algorithm().digest(b"content");
        let result = crate::verify::cms_verify::verify_cms(&bt, &data_hash).expect("verify");
        assert!(result.signature_valid, "issues: {:?}", result.issues);
        assert_eq!(
            result.signature_timestamp_token.as_deref(),
            Some(fake_tst.as_slice()),
            "verifier must surface the embedded signature timestamp token"
        );
    }

    #[test]
    fn signature_timestamp_attr_wraps_token() {
        // A syntactically-valid placeholder token (any DER) is embedded verbatim.
        let fake_tst = der::asn1::OctetString::new(vec![1, 2, 3, 4])
            .unwrap()
            .to_der()
            .unwrap();
        let attr = signature_timestamp_attr(&fake_tst).expect("ts attr");
        assert_eq!(attr.oid, OID_AA_SIGNATURE_TIME_STAMP_TOKEN);

        let cms = sign_detached(b"x", &signer(), None).expect("sign");
        let bt = add_unsigned_attributes(&cms, vec![attr]).expect("add ts");
        let sd = parse_signed_data(&bt).expect("parse");
        let si = sd.signer_infos.0.iter().next().unwrap();
        assert!(si
            .unsigned_attrs
            .as_ref()
            .unwrap()
            .iter()
            .any(|a| a.oid == OID_AA_SIGNATURE_TIME_STAMP_TOKEN));
    }
}
