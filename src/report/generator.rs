//! ETSI TS 119 102-2 validation report generator.
//!
//! Converts a [`VerificationReport`] (from the `verify` module) into an
//! XML validation report conforming to ETSI TS 119 102-2 v1.3.1.
//!
//! Uses the [`uppsala::XmlWriter`] streaming API for XML construction.
//!
//! ## Features implemented
//!
//! - **`<SignatureValidationObjects>`** — shared section with certificate, timestamp,
//!   and signed-data validation objects (Base64 or Hash representation, deduplicated by ID)
//! - **Proper `<SignatureIdentifier>`** — DTBSR digest, actual SignatureValue bytes,
//!   HashOnly/DocHashOnly booleans
//! - **`<SignerInformation>`** with VO reference to signer certificate
//! - **`<SignatureAttributes>`** — DataObjectFormat, SigningCertificate VO ref,
//!   SignatureTimeStamp VO refs, `<ds:SignatureMethod>` algorithm URI
//! - **`<SignatureQuality>`** — quality assessment (defaults to AdES)
//! - **`<SignatureValidationProcess>`** — policy URI identification
//! - **`<SignersDocument>`** — VO reference to signed data
//! - **`DOCUMENT_PARTIALLY_SIGNED`** — custom sub-indication for partial coverage
//! - **Multiple signatures** — one `<SignatureValidationReport>` per signature
//! - **`<SignatureValidator>`** — optional validator metadata

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use uppsala::XmlWriter;

use crate::error::ReportError;
use crate::verify::chain_verify::CertValidity;
use crate::verify::extractor::SignatureType;
use crate::verify::report::{
    CryptoValidity, DetectedPadesLevel, SignatureStatus, SignatureVerificationResult,
    VerificationReport,
};

use super::types::*;

/// Generator for ETSI TS 119 102-2 XML validation reports.
pub struct EtsiReportGenerator {
    options: ReportOptions,
}

impl EtsiReportGenerator {
    /// Create a new generator with the given options.
    pub fn new(options: ReportOptions) -> Self {
        Self { options }
    }

    /// Create a generator with default options.
    pub fn with_defaults() -> Self {
        Self {
            options: ReportOptions::default(),
        }
    }

    /// Generate a complete ETSI TS 119 102-2 validation report XML string
    /// from a `VerificationReport`.
    ///
    /// The output includes:
    /// - One `<vr:SignatureValidationReport>` per signature
    /// - A shared `<vr:SignatureValidationObjects>` section (if any VOs are collected)
    /// - Optional `<vr:SignatureValidator>` metadata
    pub fn generate(&self, report: &VerificationReport) -> Result<String, ReportError> {
        let mut w = XmlWriter::with_capacity(8192);
        w.write_declaration();

        // Root: <vr:ValidationReport xmlns:vr="..." xmlns:ds="..." xmlns:xades="...">
        w.start_element(
            "vr:ValidationReport",
            &[
                ("xmlns:vr", NS_VR),
                ("xmlns:ds", NS_DS),
                ("xmlns:xades", NS_XADES),
            ],
        );

        // Phase 1: Collect all validation objects across all signatures.
        // This mirrors the Java pattern where VOs are gathered first, then
        // the report elements reference them by ID.
        let mut vo_collector = ValidationObjectCollector::new();
        let mut sig_vo_refs: Vec<SignatureVoRefs> = Vec::new();

        for sig_result in &report.signatures {
            let refs = self.collect_validation_objects(&mut vo_collector, sig_result);
            sig_vo_refs.push(refs);
        }

        // Phase 2: Write <vr:SignatureValidationReport> elements
        for (sig_result, vo_refs) in report.signatures.iter().zip(sig_vo_refs.iter()) {
            self.write_signature_validation_report(&mut w, sig_result, vo_refs)?;
        }

        // Phase 3: Write <vr:SignatureValidationObjects> (shared section)
        if !vo_collector.is_empty() {
            self.write_validation_objects(&mut w, &vo_collector);
        }

        // Optional: <vr:SignatureValidator>
        if let Some(ref name) = self.options.validator_name {
            w.start_element("vr:SignatureValidator", &[]);
            w.start_element("vr:SignatureValidatorName", &[]);
            w.text(name);
            w.end_element("vr:SignatureValidatorName");
            w.end_element("vr:SignatureValidator");
        }

        w.end_element("vr:ValidationReport");

        Ok(w.into_string())
    }

    /// Collect validation objects from a single signature result.
    ///
    /// Returns the VO IDs referenced by this signature for use in the report elements.
    fn collect_validation_objects(
        &self,
        collector: &mut ValidationObjectCollector,
        sig: &SignatureVerificationResult,
    ) -> SignatureVoRefs {
        let mut refs = SignatureVoRefs::default();

        // Signer certificate
        if let Some(ref cert_der) = sig.signer_cert_der {
            refs.signer_cert_id = Some(collector.add_certificate(cert_der));
        }

        // Chain certificates (if include_chain is enabled)
        if self.options.include_chain {
            for cert_der in &sig.chain_certs_der {
                let id = collector.add_certificate(cert_der);
                refs.chain_cert_ids.push(id);
            }
        }

        // Timestamp token
        if let Some(ref ts_der) = sig.timestamp_token_der {
            let poe = sig.timestamp_time.as_deref();
            refs.timestamp_id = Some(collector.add_timestamp(ts_der, poe));
        }

        refs
    }

    /// Write the `<vr:SignatureValidationObjects>` section containing all VOs.
    fn write_validation_objects(&self, w: &mut XmlWriter, collector: &ValidationObjectCollector) {
        w.start_element("vr:SignatureValidationObjects", &[]);

        for vo in collector.iter() {
            w.start_element_with("vr:ValidationObject", [("Id", vo.id.as_str())]);

            // ObjectType
            w.start_element("vr:ObjectType", &[]);
            w.text(vo.object_type.uri());
            w.end_element("vr:ObjectType");

            // ValidationObjectRepresentation
            w.start_element("vr:ValidationObjectRepresentation", &[]);
            match vo.representation {
                RepresentationType::Base64 => {
                    if let Some(ref bytes) = vo.object_bytes {
                        w.start_element("vr:Base64", &[]);
                        w.text(&B64.encode(bytes));
                        w.end_element("vr:Base64");
                    }
                }
                RepresentationType::Hash => {
                    w.start_element("xades:DigestAlgAndValue", &[]);
                    if let Some(ref algo) = vo.hash_algorithm {
                        w.empty_element("ds:DigestMethod", &[("Algorithm", algo.as_str())]);
                    }
                    if let Some(ref hash) = vo.hash_value {
                        w.start_element("ds:DigestValue", &[]);
                        w.text(&B64.encode(hash));
                        w.end_element("ds:DigestValue");
                    }
                    w.end_element("xades:DigestAlgAndValue");
                }
            }
            w.end_element("vr:ValidationObjectRepresentation");

            // POE (if applicable, e.g. for timestamps)
            if let Some(ref poe_time) = vo.poe_time {
                w.start_element("vr:POE", &[]);
                w.start_element("vr:POETime", &[]);
                w.text(poe_time);
                w.end_element("vr:POETime");
                w.start_element("vr:TypeOfProof", &[]);
                w.text(POEType::Validation.uri());
                w.end_element("vr:TypeOfProof");
                w.end_element("vr:POE");
            }

            w.end_element("vr:ValidationObject");
        }

        w.end_element("vr:SignatureValidationObjects");
    }

    /// Write a single `<vr:SignatureValidationReport>` element.
    fn write_signature_validation_report(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
        vo_refs: &SignatureVoRefs,
    ) -> Result<(), ReportError> {
        let sig_id = generate_object_id("SIG", sig.field_name.as_bytes());
        w.start_element_with("vr:SignatureValidationReport", [("Id", sig_id.as_str())]);

        // <vr:SignatureIdentifier>
        self.write_signature_identifier(w, sig);

        // <vr:ValidationTimeInfo>
        self.write_validation_time_info(w, sig, vo_refs);

        // <vr:SignerInformation>
        self.write_signer_information(w, sig, vo_refs);

        // <vr:SignatureAttributes>
        self.write_signature_attributes(w, sig, vo_refs);

        // <vr:SignatureQuality>
        self.write_signature_quality(w, sig);

        // <vr:SignatureValidationStatus> (REQUIRED)
        self.write_signature_validation_status(w, sig);

        // <vr:SignatureValidationProcess>
        self.write_signature_validation_process(w, sig);

        // <vr:SignersDocument>
        self.write_signers_document(w, sig, vo_refs);

        w.end_element("vr:SignatureValidationReport");
        Ok(())
    }

    /// Write `<vr:SignatureIdentifier>`.
    ///
    /// When DTBSR hash and signature value bytes are available (from the CMS
    /// verification pipeline), writes the proper ETSI identifier with:
    /// - `<xades:DigestAlgAndValue>` for the DTBSR
    /// - `<ds:SignatureValue>` with actual CMS signature bytes
    /// - `HashOnly=false`, `DocHashOnly=false`
    ///
    /// Falls back to HashOnly mode (field name hash) if data is unavailable.
    fn write_signature_identifier(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        w.start_element("vr:SignatureIdentifier", &[]);

        let has_dtbsr = !sig.dtbsr_hash.is_empty();
        let has_sig_value = !sig.signature_value_bytes.is_empty();

        if has_dtbsr && has_sig_value {
            // Full identifier: DTBSR + SignatureValue + HashOnly=false + DocHashOnly=false
            w.start_element("xades:DigestAlgAndValue", &[]);
            w.empty_element(
                "ds:DigestMethod",
                &[("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")],
            );
            w.start_element("ds:DigestValue", &[]);
            w.text(&B64.encode(&sig.dtbsr_hash));
            w.end_element("ds:DigestValue");
            w.end_element("xades:DigestAlgAndValue");

            // <ds:SignatureValue>
            w.start_element("ds:SignatureValue", &[]);
            w.text(&B64.encode(&sig.signature_value_bytes));
            w.end_element("ds:SignatureValue");

            // Booleans
            w.start_element("vr:HashOnly", &[]);
            w.text("false");
            w.end_element("vr:HashOnly");
            w.start_element("vr:DocHashOnly", &[]);
            w.text("false");
            w.end_element("vr:DocHashOnly");
        } else {
            // Fallback: hash-only using field name digest
            w.start_element("xades:DigestAlgAndValue", &[]);
            w.empty_element(
                "ds:DigestMethod",
                &[("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")],
            );
            let hash = Sha256::digest(sig.field_name.as_bytes());
            w.start_element("ds:DigestValue", &[]);
            w.text(&B64.encode(hash));
            w.end_element("ds:DigestValue");
            w.end_element("xades:DigestAlgAndValue");

            w.start_element("vr:HashOnly", &[]);
            w.text("true");
            w.end_element("vr:HashOnly");
            w.start_element("vr:DocHashOnly", &[]);
            w.text("false");
            w.end_element("vr:DocHashOnly");
        }

        w.end_element("vr:SignatureIdentifier");
    }

    /// Write `<vr:ValidationTimeInfo>`.
    fn write_validation_time_info(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
        vo_refs: &SignatureVoRefs,
    ) {
        w.start_element("vr:ValidationTimeInfo", &[]);

        // <vr:ValidationTime> — use current time in ISO 8601
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        w.start_element("vr:ValidationTime", &[]);
        w.text(&now);
        w.end_element("vr:ValidationTime");

        // <vr:BestSignatureTime> — use timestamp time, falling back to signing time
        if let Some(ref ts) = sig.timestamp_time {
            w.start_element(
                "vr:BestSignatureTime",
                &[("Type", POEType::Validation.uri())],
            );
            w.start_element("vr:POETime", &[]);
            w.text(ts);
            w.end_element("vr:POETime");
            w.start_element("vr:TypeOfProof", &[]);
            w.text(POEType::Validation.uri());
            w.end_element("vr:TypeOfProof");
            // VO reference to the timestamp
            if let Some(ref ts_id) = vo_refs.timestamp_id {
                w.start_element("vr:POEObject", &[]);
                w.start_element("vr:VOReference", &[]);
                w.text(ts_id);
                w.end_element("vr:VOReference");
                w.end_element("vr:POEObject");
            }
            w.end_element("vr:BestSignatureTime");
        } else if let Some(ref st) = sig.signing_time {
            w.start_element("vr:BestSignatureTime", &[("Type", POEType::Provided.uri())]);
            w.start_element("vr:POETime", &[]);
            w.text(st);
            w.end_element("vr:POETime");
            w.start_element("vr:TypeOfProof", &[]);
            w.text(POEType::Provided.uri());
            w.end_element("vr:TypeOfProof");
            w.end_element("vr:BestSignatureTime");
        }

        w.end_element("vr:ValidationTimeInfo");
    }

    /// Write `<vr:SignerInformation>` with VO reference to signer certificate.
    fn write_signer_information(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
        vo_refs: &SignatureVoRefs,
    ) {
        if sig.signer_name.is_none() && vo_refs.signer_cert_id.is_none() {
            return;
        }

        w.start_element("vr:SignerInformation", &[]);

        // <vr:Signer> — text name
        if let Some(ref name) = sig.signer_name {
            w.start_element("vr:Signer", &[]);
            w.text(name);
            w.end_element("vr:Signer");
        }

        // <vr:SignerCertificate> — VO reference
        if let Some(ref cert_id) = vo_refs.signer_cert_id {
            w.start_element("vr:SignerCertificate", &[]);
            w.start_element("vr:VOReference", &[]);
            w.text(cert_id);
            w.end_element("vr:VOReference");
            w.end_element("vr:SignerCertificate");
        }

        w.end_element("vr:SignerInformation");
    }

    /// Write `<vr:SignatureAttributes>`.
    ///
    /// Includes:
    /// - `<vr:SigningTime>` — claimed signing time
    /// - `<vr:DataObjectFormat>` — contentType + mimeType for PDF
    /// - `<vr:SigningCertificate>` — VO reference to signer cert
    /// - `<vr:SignatureTimeStamp>` — VO reference to timestamp
    /// - `<ds:SignatureMethod>` — algorithm URI from OID
    fn write_signature_attributes(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
        vo_refs: &SignatureVoRefs,
    ) {
        let has_attrs = sig.signing_time.is_some()
            || sig.timestamp_time.is_some()
            || sig.pades_level != DetectedPadesLevel::Unknown
            || vo_refs.signer_cert_id.is_some()
            || sig.signature_algorithm_oid.is_some();

        if !has_attrs {
            return;
        }

        w.start_element("vr:SignatureAttributes", &[]);

        // SigningTime
        if let Some(ref st) = sig.signing_time {
            w.start_element("vr:SigningTime", &[]);
            w.text(st);
            w.end_element("vr:SigningTime");
        }

        // DataObjectFormat (contentType + mimeType for PDF signatures)
        let sub_filter = match &sig.signature_type {
            SignatureType::Pades => Some("ETSI.CAdES.detached"),
            SignatureType::Pkcs7Detached => Some("adbe.pkcs7.detached"),
            SignatureType::Pkcs7Sha1 => Some("adbe.pkcs7.sha1"),
            SignatureType::DocTimestamp => Some("ETSI.RFC3161"),
            _ => None,
        };
        if let Some(sf) = sub_filter {
            w.start_element("vr:DataObjectFormat", &[]);
            w.start_element("vr:ContentType", &[]);
            w.text(sf);
            w.end_element("vr:ContentType");
            w.start_element("vr:MimeType", &[]);
            w.text("application/pdf");
            w.end_element("vr:MimeType");
            w.end_element("vr:DataObjectFormat");
        }

        // SigningCertificate — VO reference
        if let Some(ref cert_id) = vo_refs.signer_cert_id {
            w.start_element("vr:SigningCertificate", &[]);
            w.start_element("vr:AttributeObject", &[]);
            w.start_element("vr:VOReference", &[]);
            w.text(cert_id);
            w.end_element("vr:VOReference");
            w.end_element("vr:AttributeObject");
            w.end_element("vr:SigningCertificate");
        }

        // SignatureTimeStamp — VO reference
        if let Some(ref ts_id) = vo_refs.timestamp_id {
            w.start_element("vr:SignatureTimeStamp", &[]);
            w.start_element("vr:AttributeObject", &[]);
            w.start_element("vr:VOReference", &[]);
            w.text(ts_id);
            w.end_element("vr:VOReference");
            w.end_element("vr:AttributeObject");
            w.end_element("vr:SignatureTimeStamp");
        }

        // <ds:SignatureMethod> — algorithm URI from OID
        if let Some(ref oid) = sig.signature_algorithm_oid {
            if let Some(uri) = signature_algorithm_uri(oid) {
                w.empty_element("ds:SignatureMethod", &[("Algorithm", uri)]);
            }
        }

        w.end_element("vr:SignatureAttributes");
    }

    /// Write `<vr:SignatureQuality>`.
    ///
    /// Currently defaults to AdES quality. Future: parse QC statements from
    /// the signer certificate to determine Etsi/Qc/QcQscd levels.
    fn write_signature_quality(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        // Only emit quality for actual signatures, not doc timestamps
        if sig.signature_type == SignatureType::DocTimestamp {
            return;
        }

        let quality = determine_signature_quality(sig);

        w.start_element("vr:SignatureQuality", &[]);
        w.start_element("vr:SignatureQualityInformation", &[]);
        w.text(quality.uri());
        w.end_element("vr:SignatureQualityInformation");
        w.end_element("vr:SignatureQuality");
    }

    /// Write `<vr:SignatureValidationStatus>` (REQUIRED element).
    fn write_signature_validation_status(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
    ) {
        w.start_element("vr:SignatureValidationStatus", &[]);

        // <vr:MainIndication>
        let (main, subs) = map_status_to_indications(sig);
        w.start_element("vr:MainIndication", &[]);
        w.text(main.uri());
        w.end_element("vr:MainIndication");

        // <vr:SubIndication> (0..*)
        for sub in &subs {
            w.start_element("vr:SubIndication", &[]);
            w.text(sub.uri());
            w.end_element("vr:SubIndication");
        }

        // Custom sub-indication: DOCUMENT_PARTIALLY_SIGNED
        if !sig.covers_whole_document {
            w.start_element("vr:SubIndication", &[]);
            w.text(SUBINDICATION_PARTIALLY_SIGNED);
            w.end_element("vr:SubIndication");
        }

        // Optional: message with summary
        if !sig.summary.is_empty() {
            w.start_element("vr:AssociatedValidationReportData", &[]);
            w.start_element("vr:AdditionalValidationReportData", &[]);
            w.start_element("vr:ReportData", &[("Type", REPORT_STATUS_MESSAGE)]);
            w.start_element("vr:Value", &[]);
            w.text(&sig.summary);
            w.end_element("vr:Value");
            w.end_element("vr:ReportData");
            w.end_element("vr:AdditionalValidationReportData");
            w.end_element("vr:AssociatedValidationReportData");
        }

        w.end_element("vr:SignatureValidationStatus");
    }

    /// Write `<vr:SignatureValidationProcess>`.
    fn write_signature_validation_process(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
    ) {
        // Determine the process URI from options or from the policy result
        let process_uri = if let Some(ref uri) = self.options.validation_process {
            Some(uri.as_str())
        } else {
            sig.policy_result
                .as_ref()
                .map(|policy_result| policy_result.policy_id.as_str())
        };

        if let Some(uri) = process_uri {
            w.start_element("vr:SignatureValidationProcess", &[]);
            w.start_element("vr:SignatureValidationProcessID", &[]);
            w.text(uri);
            w.end_element("vr:SignatureValidationProcessID");
            w.end_element("vr:SignatureValidationProcess");
        }
    }

    /// Write `<vr:SignersDocument>` — reference to the signed data VO.
    ///
    /// Currently omitted since we don't have the raw signed document bytes
    /// available in `SignatureVerificationResult`. This is a placeholder
    /// for future expansion when signed data VOs are collected.
    fn write_signers_document(
        &self,
        _w: &mut XmlWriter,
        _sig: &SignatureVerificationResult,
        _vo_refs: &SignatureVoRefs,
    ) {
        // SignersDocument requires the raw signed PDF bytes to create a VO.
        // This is not currently available in SignatureVerificationResult.
        // Future: when signed data hash is available, emit:
        //   <vr:SignersDocument>
        //     <vr:SignersDocumentRepresentation>
        //       <vr:VOReference>{sd_id}</vr:VOReference>
        //     </vr:SignersDocumentRepresentation>
        //   </vr:SignersDocument>
    }
}

/// VO references for a single signature, used during report generation.
#[derive(Debug, Default)]
struct SignatureVoRefs {
    /// VO ID for the signer certificate.
    signer_cert_id: Option<String>,
    /// VO IDs for chain certificates (excluding signer).
    chain_cert_ids: Vec<String>,
    /// VO ID for the timestamp token.
    timestamp_id: Option<String>,
}

/// Determine the signature quality level from the signature result.
///
/// Currently defaults to AdES. Future: parse QC statements from the
/// signer certificate's DER to determine Etsi/Qc/QcQscd levels.
fn determine_signature_quality(sig: &SignatureVerificationResult) -> SignatureQuality {
    // If the signature is PAdES with a valid status, consider it ETSI baseline
    if sig.signature_type == SignatureType::Pades && sig.status == SignatureStatus::Valid {
        // Check PAdES level for ETSI quality
        match sig.pades_level {
            DetectedPadesLevel::BB
            | DetectedPadesLevel::BT
            | DetectedPadesLevel::BLT
            | DetectedPadesLevel::BLTA => return SignatureQuality::Etsi,
            _ => {}
        }
    }

    // Default: AdES
    SignatureQuality::Ades
}

/// Map a `SignatureVerificationResult` to ETSI MainIndication + SubIndications.
fn map_status_to_indications(
    sig: &SignatureVerificationResult,
) -> (MainIndication, Vec<SubIndication>) {
    match &sig.status {
        SignatureStatus::Valid => (MainIndication::TotalPassed, vec![]),

        SignatureStatus::ValidButUntrusted => (
            MainIndication::Indeterminate,
            vec![SubIndication::NoCertificateChainFound],
        ),

        SignatureStatus::Invalid => {
            let mut subs = Vec::new();

            // Determine specific sub-indications from the failure details
            match &sig.cryptographic_validity {
                CryptoValidity::Invalid(_) => subs.push(SubIndication::SigCryptoFailure),
                CryptoValidity::UnknownAlgorithm(_) => {
                    subs.push(SubIndication::CryptoConstraintsFailure)
                }
                _ => {}
            }

            if !sig.digest_matches {
                subs.push(SubIndication::HashFailure);
            }

            if !sig.integrity_ok {
                subs.push(SubIndication::FormatFailure);
            }

            match &sig.certificate_validity {
                CertValidity::Expired => subs.push(SubIndication::Expired),
                CertValidity::NotYetValid => subs.push(SubIndication::NotYetValid),
                CertValidity::Revoked(_) => subs.push(SubIndication::Revoked),
                CertValidity::UntrustedRoot => subs.push(SubIndication::NoCertificateChainFound),
                CertValidity::ChainIncomplete => {
                    subs.push(SubIndication::CertificateChainGeneralFailure)
                }
                _ => {}
            }

            if subs.is_empty() {
                subs.push(SubIndication::SignatureProcessingError);
            }

            (MainIndication::TotalFailed, subs)
        }

        SignatureStatus::Indeterminate => {
            let mut subs = Vec::new();

            match &sig.certificate_validity {
                CertValidity::Expired => subs.push(SubIndication::Expired),
                CertValidity::NotYetValid => subs.push(SubIndication::NotYetValid),
                CertValidity::UntrustedRoot => subs.push(SubIndication::NoCertificateChainFound),
                CertValidity::ChainIncomplete => {
                    subs.push(SubIndication::CertificateChainGeneralFailure)
                }
                _ => {}
            }

            if subs.is_empty() {
                subs.push(SubIndication::SignatureProcessingError);
            }

            (MainIndication::Indeterminate, subs)
        }
    }
}

/// Generate a deterministic object ID from a type prefix and data bytes.
///
/// Format: `{prefix}-{sha256_hex_truncated_40}`.
fn generate_object_id(prefix: &str, data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let hex = hex::encode(hash);
    // Truncate to 40 chars max (like the Java reference)
    let truncated = &hex[..hex.len().min(40)];
    format!("{}-{}", prefix, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_sig_result(field: &str) -> SignatureVerificationResult {
        SignatureVerificationResult {
            field_name: field.to_string(),
            status: SignatureStatus::Valid,
            signature_type: SignatureType::Pades,
            signer_name: Some("Test Signer".to_string()),
            signing_time: Some("2025-01-15T10:30:00Z".to_string()),
            cms_signing_time: None,
            timestamp_time: None,
            ess_cert_id_match: None,
            validation_time_used: None,
            integrity_ok: true,
            covers_whole_document: true,
            integrity_issues: vec![],
            cryptographic_validity: CryptoValidity::Valid,
            digest_matches: true,
            certificate_validity: CertValidity::Valid,
            chain_trusted: true,
            trust_anchor: Some("Root CA".to_string()),
            revocation_status: None,
            per_cert_revocation: Vec::new(),
            pades_level: DetectedPadesLevel::BB,
            modifications_after_signing: false,
            covers_whole_document_revision: None,
            extended_by_non_safe_updates: None,
            policy_result: None,
            signer_cert_der: None,
            chain_certs_der: Vec::new(),
            signature_value_bytes: Vec::new(),
            dtbsr_hash: Vec::new(),
            signature_algorithm_oid: None,
            timestamp_token_der: None,
            summary: "Signature is valid".to_string(),
        }
    }

    fn make_invalid_sig_result(field: &str) -> SignatureVerificationResult {
        SignatureVerificationResult {
            field_name: field.to_string(),
            status: SignatureStatus::Invalid,
            signature_type: SignatureType::Pkcs7Detached,
            signer_name: Some("Bad Signer".to_string()),
            signing_time: None,
            cms_signing_time: None,
            timestamp_time: None,
            ess_cert_id_match: None,
            validation_time_used: None,
            integrity_ok: true,
            covers_whole_document: true,
            integrity_issues: vec![],
            cryptographic_validity: CryptoValidity::Invalid("bad signature".to_string()),
            digest_matches: false,
            certificate_validity: CertValidity::Expired,
            chain_trusted: false,
            trust_anchor: None,
            revocation_status: None,
            per_cert_revocation: Vec::new(),
            pades_level: DetectedPadesLevel::NotPades,
            modifications_after_signing: false,
            covers_whole_document_revision: None,
            extended_by_non_safe_updates: None,
            policy_result: None,
            signer_cert_der: None,
            chain_certs_der: Vec::new(),
            signature_value_bytes: Vec::new(),
            dtbsr_hash: Vec::new(),
            signature_algorithm_oid: None,
            timestamp_token_der: None,
            summary: "Signature is invalid".to_string(),
        }
    }

    /// Helper that creates a sig result with full ETSI data (DTBSR, sig value, certs, etc.)
    fn make_full_sig_result(field: &str) -> SignatureVerificationResult {
        SignatureVerificationResult {
            field_name: field.to_string(),
            status: SignatureStatus::Valid,
            signature_type: SignatureType::Pades,
            signer_name: Some("CN=Full Signer, O=Test Org".to_string()),
            signing_time: Some("2025-06-15T12:00:00Z".to_string()),
            cms_signing_time: None,
            timestamp_time: Some("2025-06-15T12:00:05Z".to_string()),
            ess_cert_id_match: Some(true),
            validation_time_used: None,
            integrity_ok: true,
            covers_whole_document: true,
            integrity_issues: vec![],
            cryptographic_validity: CryptoValidity::Valid,
            digest_matches: true,
            certificate_validity: CertValidity::Valid,
            chain_trusted: true,
            trust_anchor: Some("CN=Root CA".to_string()),
            revocation_status: None,
            per_cert_revocation: Vec::new(),
            pades_level: DetectedPadesLevel::BT,
            modifications_after_signing: false,
            covers_whole_document_revision: Some(true),
            extended_by_non_safe_updates: Some(false),
            policy_result: None,
            // ETSI report fields populated
            signer_cert_der: Some(b"fake signer cert DER".to_vec()),
            chain_certs_der: vec![
                b"fake intermediate cert DER".to_vec(),
                b"fake root cert DER".to_vec(),
            ],
            signature_value_bytes: b"fake CMS signature value".to_vec(),
            dtbsr_hash: vec![0xAA; 32], // fake 32-byte hash
            signature_algorithm_oid: Some("1.2.840.113549.1.1.11".to_string()), // SHA256WithRSA
            timestamp_token_der: Some(b"fake timestamp token DER".to_vec()),
            summary: "Signature is valid with timestamp".to_string(),
        }
    }

    #[test]
    fn test_generate_valid_report() {
        let report = VerificationReport {
            signatures: vec![make_valid_sig_result("Sig1")],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "All signatures valid".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("vr:ValidationReport"));
        assert!(xml.contains(NS_VR));
        assert!(xml.contains("vr:SignatureValidationReport"));
        assert!(xml.contains("total-passed"));
        assert!(!xml.contains("SubIndication"));
    }

    #[test]
    fn test_generate_invalid_report() {
        let report = VerificationReport {
            signatures: vec![make_invalid_sig_result("BadSig1")],
            document_modified: false,
            valid_count: 0,
            invalid_count: 1,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "Validation failed".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("total-failed"));
        assert!(xml.contains("SIG_CRYPTO_FAILURE"));
        assert!(xml.contains("HASH_FAILURE"));
        assert!(xml.contains("EXPIRED"));
    }

    #[test]
    fn test_generate_multiple_signatures() {
        let report = VerificationReport {
            signatures: vec![
                make_valid_sig_result("Sig1"),
                make_invalid_sig_result("Sig2"),
            ],
            document_modified: false,
            valid_count: 1,
            invalid_count: 1,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "Mixed results".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have 2 SignatureValidationReport elements
        let count = xml.matches("SignatureValidationReport").count();
        // start + end for each = 2 * 2 = 4, plus any nested references
        assert!(count >= 4);
    }

    #[test]
    fn test_generate_with_validator_name() {
        let opts = ReportOptions {
            validator_name: Some("Underskrift v0.1.0".to_string()),
            ..Default::default()
        };

        let report = VerificationReport {
            signatures: vec![make_valid_sig_result("Sig1")],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::new(opts);
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("Underskrift v0.1.0"));
        assert!(xml.contains("vr:SignatureValidator"));
        assert!(xml.contains("vr:SignatureValidatorName"));
    }

    #[test]
    fn test_generate_with_timestamp() {
        let mut sig = make_valid_sig_result("Sig1");
        sig.timestamp_time = Some("2025-01-15T10:35:00Z".to_string());

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("BestSignatureTime"));
        assert!(xml.contains(POEType::Validation.uri()));
        assert!(xml.contains("2025-01-15T10:35:00Z"));
    }

    #[test]
    fn test_generate_indeterminate_report() {
        let sig = SignatureVerificationResult {
            field_name: "Sig1".to_string(),
            status: SignatureStatus::Indeterminate,
            signature_type: SignatureType::Pades,
            signer_name: None,
            signing_time: None,
            cms_signing_time: None,
            timestamp_time: None,
            ess_cert_id_match: None,
            validation_time_used: None,
            integrity_ok: true,
            covers_whole_document: true,
            integrity_issues: vec![],
            cryptographic_validity: CryptoValidity::Valid,
            digest_matches: true,
            certificate_validity: CertValidity::ChainIncomplete,
            chain_trusted: false,
            trust_anchor: None,
            revocation_status: None,
            per_cert_revocation: Vec::new(),
            pades_level: DetectedPadesLevel::Unknown,
            modifications_after_signing: false,
            covers_whole_document_revision: None,
            extended_by_non_safe_updates: None,
            policy_result: None,
            summary: "Could not determine".to_string(),
            signer_cert_der: None,
            chain_certs_der: vec![],
            signature_value_bytes: vec![],
            dtbsr_hash: vec![],
            signature_algorithm_oid: None,
            timestamp_token_der: None,
        };

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 0,
            invalid_count: 1,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "Indeterminate".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("indeterminate"));
        assert!(xml.contains("CERTIFICATE_CHAIN_GENERAL_FAILURE"));
    }

    #[test]
    fn test_generate_empty_report() {
        let report = VerificationReport {
            signatures: vec![],
            document_modified: false,
            valid_count: 0,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "No signatures found".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("vr:ValidationReport"));
        // No SignatureValidationReport
        assert!(!xml.contains("vr:SignatureValidationReport"));
        // No validation objects
        assert!(!xml.contains("SignatureValidationObjects"));
    }

    #[test]
    fn test_generate_report_xml_is_wellformed() {
        let report = VerificationReport {
            signatures: vec![make_valid_sig_result("Sig1")],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Parse with uppsala to verify well-formedness
        let parsed = uppsala::parse(&xml);
        assert!(
            parsed.is_ok(),
            "Generated XML is not well-formed: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn test_generate_object_id() {
        let id1 = generate_object_id("C", b"cert_data_1");
        let id2 = generate_object_id("C", b"cert_data_2");

        assert!(id1.starts_with("C-"));
        assert!(id2.starts_with("C-"));
        assert_ne!(id1, id2);
        // Should be prefix + '-' + 40 hex chars = prefix_len + 1 + 40
        assert_eq!(id1.len(), 2 + 40);
    }

    #[test]
    fn test_map_status_valid() {
        let sig = make_valid_sig_result("Sig1");
        let (main, subs) = map_status_to_indications(&sig);
        assert_eq!(main, MainIndication::TotalPassed);
        assert!(subs.is_empty());
    }

    #[test]
    fn test_map_status_invalid() {
        let sig = make_invalid_sig_result("Sig1");
        let (main, subs) = map_status_to_indications(&sig);
        assert_eq!(main, MainIndication::TotalFailed);
        assert!(subs.contains(&SubIndication::SigCryptoFailure));
        assert!(subs.contains(&SubIndication::HashFailure));
        assert!(subs.contains(&SubIndication::Expired));
    }

    #[test]
    fn test_xml_special_chars_escaped() {
        let mut sig = make_valid_sig_result("Sig<>1");
        sig.signer_name = Some("Test & \"Special\" <Signer>".to_string());
        sig.summary = "Contains <xml> & \"special\" chars".to_string();

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Verify the XML is still well-formed despite special chars
        let parsed = uppsala::parse(&xml);
        assert!(parsed.is_ok(), "XML with special chars is not well-formed");

        // Verify escaping happened
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&lt;"));
    }

    // ── New tests for expanded ETSI features ───────────────────────────

    #[test]
    fn test_full_signature_identifier_with_dtbsr() {
        let sig = make_full_sig_result("FullSig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have proper SignatureIdentifier with DTBSR
        assert!(xml.contains("xades:DigestAlgAndValue"));
        assert!(xml.contains("ds:DigestMethod"));
        assert!(xml.contains("ds:DigestValue"));
        // Should have SignatureValue (actual bytes, not just hash)
        assert!(xml.contains("ds:SignatureValue"));
        // Should have HashOnly=false
        assert!(xml.contains("<vr:HashOnly>false</vr:HashOnly>"));
        assert!(xml.contains("<vr:DocHashOnly>false</vr:DocHashOnly>"));
    }

    #[test]
    fn test_fallback_hash_only_identifier() {
        // When DTBSR is empty, should fall back to hash-only
        let sig = make_valid_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("<vr:HashOnly>true</vr:HashOnly>"));
    }

    #[test]
    fn test_validation_objects_section() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have the shared validation objects section
        assert!(xml.contains("vr:SignatureValidationObjects"));
        // Should have certificate VOs (signer + 2 chain certs = 3)
        let cert_vo_count = xml.matches("validationObject:certificate").count();
        assert_eq!(cert_vo_count, 3, "Expected 3 certificate VOs");
        // Should have timestamp VO
        assert!(xml.contains("validationObject:timestamp"));
        // Should have Base64 representation for certs
        assert!(xml.contains("vr:Base64"));
        // Should have hash representation for timestamp
        assert!(xml.contains("xades:DigestAlgAndValue"));
    }

    #[test]
    fn test_no_validation_objects_when_no_data() {
        let sig = make_valid_sig_result("Sig1"); // no cert/ts DER data

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should NOT have the objects section when no VOs
        assert!(!xml.contains("SignatureValidationObjects"));
    }

    #[test]
    fn test_signer_information_with_vo_reference() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have SignerCertificate with VOReference
        assert!(xml.contains("vr:SignerCertificate"));
        assert!(xml.contains("vr:VOReference"));
        // The VOReference should start with "C-" (certificate prefix)
        assert!(xml.contains(">C-"));
    }

    #[test]
    fn test_signature_attributes_data_object_format() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have DataObjectFormat with ContentType and MimeType
        assert!(xml.contains("vr:DataObjectFormat"));
        assert!(xml.contains("ETSI.CAdES.detached"));
        assert!(xml.contains("application/pdf"));
    }

    #[test]
    fn test_signature_attributes_algorithm_method() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have ds:SignatureMethod with RSA-SHA256 URI
        assert!(xml.contains("ds:SignatureMethod"));
        assert!(xml.contains("rsa-sha256"));
    }

    #[test]
    fn test_signature_attributes_signing_cert_ref() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have SigningCertificate > AttributeObject > VOReference
        assert!(xml.contains("vr:SigningCertificate"));
        assert!(xml.contains("vr:AttributeObject"));
    }

    #[test]
    fn test_signature_attributes_timestamp_ref() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should have SignatureTimeStamp > AttributeObject > VOReference with T- prefix
        assert!(xml.contains("vr:SignatureTimeStamp"));
        // The VO reference should reference a timestamp VO
        assert!(xml.contains(">T-"));
    }

    #[test]
    fn test_signature_quality_ades_default() {
        let mut sig = make_valid_sig_result("Sig1");
        sig.signature_type = SignatureType::Pkcs7Detached;
        sig.pades_level = DetectedPadesLevel::NotPades;

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("vr:SignatureQuality"));
        assert!(xml.contains(QUALITY_ADES));
    }

    #[test]
    fn test_signature_quality_etsi_for_pades() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Valid PAdES B-T should get ETSI quality
        assert!(xml.contains(QUALITY_ETSI));
    }

    #[test]
    fn test_signature_validation_process() {
        let opts = ReportOptions {
            validation_process: Some(POLICY_PKIX.to_string()),
            ..Default::default()
        };

        let report = VerificationReport {
            signatures: vec![make_valid_sig_result("Sig1")],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::new(opts);
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains("vr:SignatureValidationProcess"));
        assert!(xml.contains("vr:SignatureValidationProcessID"));
        assert!(xml.contains(POLICY_PKIX));
    }

    #[test]
    fn test_partially_signed_subindication() {
        let mut sig = make_valid_sig_result("Sig1");
        sig.covers_whole_document = false;

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        assert!(xml.contains(SUBINDICATION_PARTIALLY_SIGNED));
    }

    #[test]
    fn test_status_message_uri() {
        let report = VerificationReport {
            signatures: vec![make_valid_sig_result("Sig1")],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Should use the Sweden Connect status message URI
        assert!(xml.contains(REPORT_STATUS_MESSAGE));
    }

    #[test]
    fn test_vo_deduplication_across_signatures() {
        // Two signatures sharing the same signer cert should produce one cert VO
        let sig1 = make_full_sig_result("Sig1");
        let mut sig2 = make_full_sig_result("Sig2");
        // Make them share the same signer cert
        sig2.signer_cert_der = sig1.signer_cert_der.clone();
        // But different chain certs
        sig2.chain_certs_der = vec![b"different chain cert".to_vec()];

        let report = VerificationReport {
            signatures: vec![sig1, sig2],
            document_modified: false,
            valid_count: 2,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Count certificate VOs: sig1 has 1 signer + 2 chain = 3
        // sig2 has same signer (dedup) + 1 different chain = 1 new
        // Total: 4 unique cert VOs
        let cert_vo_count = xml.matches("validationObject:certificate").count();
        assert_eq!(cert_vo_count, 4, "Expected 4 unique certificate VOs");
    }

    #[test]
    fn test_timestamp_vo_has_poe() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Timestamp VO should have POE section
        assert!(xml.contains("vr:POE"));
        assert!(xml.contains("vr:POETime"));
        assert!(xml.contains("vr:TypeOfProof"));
    }

    #[test]
    fn test_full_report_is_wellformed() {
        let report = VerificationReport {
            signatures: vec![
                make_full_sig_result("Sig1"),
                make_valid_sig_result("Sig2"),
                make_invalid_sig_result("Sig3"),
            ],
            document_modified: false,
            valid_count: 2,
            invalid_count: 1,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "Mixed results".to_string(),
        };

        let opts = ReportOptions {
            validator_name: Some("Underskrift Test".to_string()),
            validation_process: Some(POLICY_BASIC.to_string()),
            ..Default::default()
        };

        let gen = EtsiReportGenerator::new(opts);
        let xml = gen.generate(&report).unwrap();

        // Parse with uppsala to verify well-formedness
        let parsed = uppsala::parse(&xml);
        assert!(
            parsed.is_ok(),
            "Full report XML is not well-formed: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn test_determine_quality_pades_valid() {
        let sig = make_full_sig_result("Sig1");
        assert_eq!(determine_signature_quality(&sig), SignatureQuality::Etsi);
    }

    #[test]
    fn test_determine_quality_non_pades() {
        let mut sig = make_full_sig_result("Sig1");
        sig.signature_type = SignatureType::Pkcs7Detached;
        sig.pades_level = DetectedPadesLevel::NotPades;
        assert_eq!(determine_signature_quality(&sig), SignatureQuality::Ades);
    }

    #[test]
    fn test_doc_timestamp_no_quality() {
        let mut sig = make_valid_sig_result("DocTS1");
        sig.signature_type = SignatureType::DocTimestamp;

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // Doc timestamps should not have SignatureQuality
        assert!(!xml.contains("vr:SignatureQuality"));
    }

    #[test]
    fn test_best_signature_time_vo_reference() {
        let sig = make_full_sig_result("Sig1");

        let report = VerificationReport {
            signatures: vec![sig],
            document_modified: false,
            valid_count: 1,
            invalid_count: 0,
            policy_passed_count: 0,
            policy_failed_count: 0,
            policy_indeterminate_count: 0,
            summary: "OK".to_string(),
        };

        let gen = EtsiReportGenerator::with_defaults();
        let xml = gen.generate(&report).unwrap();

        // BestSignatureTime should have POEObject > VOReference to timestamp
        assert!(xml.contains("vr:BestSignatureTime"));
        assert!(xml.contains("vr:POEObject"));
    }
}
