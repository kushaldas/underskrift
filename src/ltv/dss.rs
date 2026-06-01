//! Document Security Store (DSS) builder.
//!
//! Builds the PDF DSS dictionary containing certificates, OCSP responses,
//! and CRLs needed for long-term validation (PAdES B-LT and B-LTA).
//!
//! The DSS is added as an incremental update to the PDF, which preserves
//! existing signatures.

use std::collections::HashMap;

use der::Encode;
use lopdf::{Document, Object, Stream};
use x509_cert::Certificate;

use super::crl::CrlClient;
use super::ocsp::OcspClient;
use crate::error::LtvError;

/// A VRI (Validation Related Information) entry for a specific signature.
#[derive(Debug, Clone, Default)]
pub struct VriEntry {
    /// DER-encoded certificates related to this signature.
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses related to this signature.
    pub ocsps: Vec<Vec<u8>>,
    /// DER-encoded CRLs related to this signature.
    pub crls: Vec<Vec<u8>>,
}

/// Builder for the PDF Document Security Store (DSS) dictionary.
///
/// Collects certificates, OCSP responses, and CRLs for embedding
/// into the PDF for long-term validation.
///
/// # DSS Dictionary Structure
///
/// ```text
/// /DSS <<
///     /Certs [stream stream ...]
///     /OCSPs [stream stream ...]
///     /CRLs  [stream stream ...]
///     /VRI <<
///         /BASE16_SHA1_OF_SIG_CONTENTS <<
///             /Cert [stream ...]
///             /OCSP [stream ...]
///             /CRL  [stream ...]
///         >>
///     >>
/// >>
/// ```
#[derive(Debug, Clone, Default)]
pub struct DssBuilder {
    /// All DER-encoded certificates (deduped).
    pub certificates: Vec<Vec<u8>>,
    /// All DER-encoded OCSP responses.
    pub ocsp_responses: Vec<Vec<u8>>,
    /// All DER-encoded CRLs.
    pub crls: Vec<Vec<u8>>,
    /// Per-signature VRI entries, keyed by hex-encoded SHA-1 of the /Contents value.
    pub vri_entries: HashMap<String, VriEntry>,
}

impl DssBuilder {
    /// Create a new empty DSS builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER-encoded certificate (deduped).
    pub fn add_certificate(&mut self, cert_der: Vec<u8>) {
        if !self.certificates.contains(&cert_der) {
            self.certificates.push(cert_der);
        }
    }

    /// Add a DER-encoded OCSP response.
    pub fn add_ocsp_response(&mut self, ocsp_der: Vec<u8>) {
        self.ocsp_responses.push(ocsp_der);
    }

    /// Add a DER-encoded CRL.
    pub fn add_crl(&mut self, crl_der: Vec<u8>) {
        if !self.crls.contains(&crl_der) {
            self.crls.push(crl_der);
        }
    }

    /// Add a VRI entry for a specific signature.
    ///
    /// `sig_contents_sha1_hex` is the uppercase hex-encoded SHA-1 hash
    /// of the signature's /Contents value (raw bytes, not the hex string).
    pub fn add_vri_entry(&mut self, sig_contents_sha1_hex: String, entry: VriEntry) {
        self.vri_entries.insert(sig_contents_sha1_hex, entry);
    }

    /// Collect validation data for a certificate chain.
    ///
    /// Fetches OCSP responses and CRLs for each certificate in the chain,
    /// and adds them to the builder.
    pub async fn collect_validation_data(
        &mut self,
        chain: &[Certificate],
        ocsp_client: &OcspClient,
        crl_client: &CrlClient,
    ) -> Result<(), LtvError> {
        // Add all chain certificates
        for cert in chain {
            let cert_der = cert
                .to_der()
                .map_err(|e| LtvError::Dss(format!("failed to encode certificate: {e}")))?;
            self.add_certificate(cert_der);
        }

        // For each cert (except the last, which is the root/anchor),
        // try to get OCSP response and/or CRL
        for i in 0..chain.len().saturating_sub(1) {
            let cert = &chain[i];
            let issuer = &chain[i + 1];

            // Try OCSP first (preferred, smaller)
            match ocsp_client.fetch_ocsp_response(cert, issuer).await {
                Ok(ocsp_resp) => {
                    log::debug!("Got OCSP response for cert at index {i}");
                    self.add_ocsp_response(ocsp_resp);
                }
                Err(e) => {
                    log::warn!("OCSP failed for cert at index {i}: {e}");

                    // Fall back to CRL
                    match crl_client.fetch_crls_for_cert(cert).await {
                        Ok(fetched_crls) => {
                            for crl in fetched_crls {
                                log::debug!("Got CRL for cert at index {i}");
                                self.add_crl(crl);
                            }
                        }
                        Err(e) => {
                            log::warn!("CRL also failed for cert at index {i}: {e}");
                            // Continue — we'll add what we can
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Build the DSS dictionary as a lopdf Dictionary.
    ///
    /// Returns a tuple of (dss_dictionary, Vec<(ObjectId, stream_object)>)
    /// where the stream objects need to be added to the PDF document separately.
    pub fn build_dss_dict(&self, doc: &mut Document) -> Result<Object, LtvError> {
        let mut dss_dict = lopdf::Dictionary::new();

        // /Certs array — each cert is a stream object
        if !self.certificates.is_empty() {
            let mut cert_refs = Vec::new();
            for cert_der in &self.certificates {
                let stream = Stream::new(lopdf::Dictionary::new(), cert_der.clone());
                let id = doc.add_object(Object::Stream(stream));
                cert_refs.push(Object::Reference(id));
            }
            dss_dict.set("Certs", Object::Array(cert_refs));
        }

        // /OCSPs array
        if !self.ocsp_responses.is_empty() {
            let mut ocsp_refs = Vec::new();
            for ocsp_der in &self.ocsp_responses {
                let stream = Stream::new(lopdf::Dictionary::new(), ocsp_der.clone());
                let id = doc.add_object(Object::Stream(stream));
                ocsp_refs.push(Object::Reference(id));
            }
            dss_dict.set("OCSPs", Object::Array(ocsp_refs));
        }

        // /CRLs array
        if !self.crls.is_empty() {
            let mut crl_refs = Vec::new();
            for crl_der in &self.crls {
                let stream = Stream::new(lopdf::Dictionary::new(), crl_der.clone());
                let id = doc.add_object(Object::Stream(stream));
                crl_refs.push(Object::Reference(id));
            }
            dss_dict.set("CRLs", Object::Array(crl_refs));
        }

        // /VRI dictionary
        if !self.vri_entries.is_empty() {
            let mut vri_dict = lopdf::Dictionary::new();
            for (hash_key, entry) in &self.vri_entries {
                let mut entry_dict = lopdf::Dictionary::new();

                if !entry.certs.is_empty() {
                    let mut refs = Vec::new();
                    for cert_der in &entry.certs {
                        let stream = Stream::new(lopdf::Dictionary::new(), cert_der.clone());
                        let id = doc.add_object(Object::Stream(stream));
                        refs.push(Object::Reference(id));
                    }
                    entry_dict.set("Cert", Object::Array(refs));
                }

                if !entry.ocsps.is_empty() {
                    let mut refs = Vec::new();
                    for ocsp_der in &entry.ocsps {
                        let stream = Stream::new(lopdf::Dictionary::new(), ocsp_der.clone());
                        let id = doc.add_object(Object::Stream(stream));
                        refs.push(Object::Reference(id));
                    }
                    entry_dict.set("OCSP", Object::Array(refs));
                }

                if !entry.crls.is_empty() {
                    let mut refs = Vec::new();
                    for crl_der in &entry.crls {
                        let stream = Stream::new(lopdf::Dictionary::new(), crl_der.clone());
                        let id = doc.add_object(Object::Stream(stream));
                        refs.push(Object::Reference(id));
                    }
                    entry_dict.set("CRL", Object::Array(refs));
                }

                vri_dict.set(hash_key.as_str(), Object::Dictionary(entry_dict));
            }
            dss_dict.set("VRI", Object::Dictionary(vri_dict));
        }

        // /Type /DSS
        dss_dict.set("Type", Object::Name(b"DSS".to_vec()));

        Ok(Object::Dictionary(dss_dict))
    }

    /// Check if the DSS has any data.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
            && self.ocsp_responses.is_empty()
            && self.crls.is_empty()
            && self.vri_entries.is_empty()
    }

    /// Get the total number of items.
    pub fn total_items(&self) -> usize {
        self.certificates.len() + self.ocsp_responses.len() + self.crls.len()
    }
}

/// Compute the VRI key for a signature's /Contents value.
///
/// The key is the uppercase hex-encoded SHA-1 hash of the raw
/// signature bytes (the DER-encoded CMS SignedData, not the hex string).
pub fn compute_vri_key(signature_contents_bytes: &[u8]) -> String {
    use sha1::Digest;
    let hash = sha1::Sha1::digest(signature_contents_bytes);
    hex::encode_upper(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dss_builder_new_is_empty() {
        let builder = DssBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.total_items(), 0);
    }

    #[test]
    fn test_dss_builder_add_certificate() {
        let mut builder = DssBuilder::new();
        builder.add_certificate(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        assert_eq!(builder.certificates.len(), 1);
        assert!(!builder.is_empty());
    }

    #[test]
    fn test_dss_builder_dedup_certificates() {
        let mut builder = DssBuilder::new();
        let cert = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        builder.add_certificate(cert.clone());
        builder.add_certificate(cert.clone());
        assert_eq!(
            builder.certificates.len(),
            1,
            "duplicates should be ignored"
        );
    }

    #[test]
    fn test_compute_vri_key() {
        let key = compute_vri_key(b"test signature contents");
        assert_eq!(key.len(), 40, "SHA-1 hex should be 40 chars");
        // Should be uppercase hex
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(key.chars().all(|c| !c.is_ascii_lowercase()));
    }

    #[test]
    fn test_dss_builder_add_vri() {
        let mut builder = DssBuilder::new();
        let entry = VriEntry {
            certs: vec![vec![0x30, 0x01, 0x01]],
            ocsps: vec![],
            crls: vec![],
        };
        builder.add_vri_entry("ABC123".to_string(), entry);
        assert!(!builder.is_empty());
        assert!(builder.vri_entries.contains_key("ABC123"));
    }

    #[test]
    fn test_build_dss_dict() {
        let mut builder = DssBuilder::new();
        builder.add_certificate(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        builder.add_crl(vec![0x30, 0x03, 0x04, 0x05, 0x06]);

        let mut doc = Document::new();
        let dss_obj = builder.build_dss_dict(&mut doc).unwrap();

        if let Object::Dictionary(dict) = &dss_obj {
            assert!(dict.has(b"Type"));
            assert!(dict.has(b"Certs"));
            assert!(dict.has(b"CRLs"));
            assert!(!dict.has(b"OCSPs"), "no OCSPs were added");
        } else {
            panic!("expected Dictionary");
        }
    }
}
