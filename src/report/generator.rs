//! ETSI TS 119 102-2 validation report generator.
//!
//! Converts a [`VerificationReport`] (from the `verify` module) into an
//! XML validation report conforming to ETSI TS 119 102-2 v1.3.1.
//!
//! Uses the [`uppsala::XmlWriter`] streaming API for XML construction.

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
    pub fn generate(&self, report: &VerificationReport) -> Result<String, ReportError> {
        let mut w = XmlWriter::with_capacity(4096);
        w.write_declaration();

        // Root: <vr:ValidationReport xmlns:vr="..." xmlns:ds="...">
        w.start_element(
            "vr:ValidationReport",
            &[
                ("xmlns:vr", NS_VR),
                ("xmlns:ds", NS_DS),
                ("xmlns:xades", NS_XADES),
            ],
        );

        // One <vr:SignatureValidationReport> per signature
        for sig_result in &report.signatures {
            self.write_signature_validation_report(&mut w, sig_result)?;
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

    /// Write a single `<vr:SignatureValidationReport>` element.
    fn write_signature_validation_report(
        &self,
        w: &mut XmlWriter,
        sig: &SignatureVerificationResult,
    ) -> Result<(), ReportError> {
        let sig_id = generate_object_id("SIG", sig.field_name.as_bytes());
        w.start_element_with("vr:SignatureValidationReport", [("Id", sig_id.as_str())]);

        // <vr:SignatureIdentifier>
        self.write_signature_identifier(w, sig);

        // <vr:ValidationTimeInfo>
        self.write_validation_time_info(w, sig);

        // <vr:SignatureAttributes>
        self.write_signature_attributes(w, sig);

        // <vr:SignerInformation>
        self.write_signer_information(w, sig);

        // <vr:SignatureValidationStatus> (REQUIRED)
        self.write_signature_validation_status(w, sig);

        w.end_element("vr:SignatureValidationReport");
        Ok(())
    }

    /// Write `<vr:SignatureIdentifier>`.
    fn write_signature_identifier(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        w.start_element("vr:SignatureIdentifier", &[]);

        // <vr:SignatureValue> — we use the field name hash as a stand-in
        // since we don't have the raw CMS signature value readily available.
        w.start_element("vr:HashOnly", &[]);

        w.start_element(
            "ds:DigestMethod",
            &[("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")],
        );
        w.end_element("ds:DigestMethod");

        let hash = Sha256::digest(sig.field_name.as_bytes());
        w.start_element("ds:DigestValue", &[]);
        w.text(&B64.encode(hash));
        w.end_element("ds:DigestValue");

        w.end_element("vr:HashOnly");

        w.end_element("vr:SignatureIdentifier");
    }

    /// Write `<vr:ValidationTimeInfo>`.
    fn write_validation_time_info(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        w.start_element("vr:ValidationTimeInfo", &[]);

        // <vr:ValidationTime> — use current time in ISO 8601
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        w.start_element("vr:ValidationTime", &[]);
        w.text(&now);
        w.end_element("vr:ValidationTime");

        // <vr:BestSignatureTime> — use signing time or timestamp time if available
        if let Some(ref ts) = sig.timestamp_time {
            w.start_element(
                "vr:BestSignatureTime",
                &[("Type", POEType::Validation.uri())],
            );
            w.text(ts);
            w.end_element("vr:BestSignatureTime");
        } else if let Some(ref st) = sig.signing_time {
            w.start_element("vr:BestSignatureTime", &[("Type", POEType::Provided.uri())]);
            w.text(st);
            w.end_element("vr:BestSignatureTime");
        }

        w.end_element("vr:ValidationTimeInfo");
    }

    /// Write `<vr:SignatureAttributes>`.
    fn write_signature_attributes(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        let has_attrs = sig.signing_time.is_some()
            || sig.timestamp_time.is_some()
            || sig.pades_level != DetectedPadesLevel::Unknown;

        if !has_attrs {
            return;
        }

        w.start_element("vr:SignatureAttributes", &[]);

        // SubFilter attribute
        let sub_filter = match &sig.signature_type {
            SignatureType::Pades => Some("ETSI.CAdES.detached"),
            SignatureType::Pkcs7Detached => Some("adbe.pkcs7.detached"),
            SignatureType::Pkcs7Sha1 => Some("adbe.pkcs7.sha1"),
            SignatureType::DocTimestamp => Some("ETSI.RFC3161"),
            _ => None,
        };
        if let Some(sf) = sub_filter {
            w.start_element("vr:SubFilter", &[]);
            w.text(sf);
            w.end_element("vr:SubFilter");
        }

        // SigningTime
        if let Some(ref st) = sig.signing_time {
            w.start_element("vr:SigningTime", &[]);
            w.text(st);
            w.end_element("vr:SigningTime");
        }

        // SignatureTimeStamp — if timestamp time present
        if sig.timestamp_time.is_some() {
            w.start_element("vr:SignatureTimeStamp", &[]);
            w.end_element("vr:SignatureTimeStamp");
        }

        w.end_element("vr:SignatureAttributes");
    }

    /// Write `<vr:SignerInformation>`.
    fn write_signer_information(&self, w: &mut XmlWriter, sig: &SignatureVerificationResult) {
        if sig.signer_name.is_none() {
            return;
        }

        w.start_element("vr:SignerInformation", &[]);

        if let Some(ref name) = sig.signer_name {
            w.start_element("vr:Signer", &[]);
            w.text(name);
            w.end_element("vr:Signer");
        }

        w.end_element("vr:SignerInformation");
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

        // Optional: message with summary
        if !sig.summary.is_empty() {
            w.start_element("vr:AssociatedValidationReportData", &[]);
            w.start_element("vr:AdditionalValidationReportData", &[]);
            w.start_element("vr:ReportData", &[("Type", "urn:underskrift:message")]);
            w.start_element("vr:Value", &[]);
            w.text(&sig.summary);
            w.end_element("vr:Value");
            w.end_element("vr:ReportData");
            w.end_element("vr:AdditionalValidationReportData");
            w.end_element("vr:AssociatedValidationReportData");
        }

        w.end_element("vr:SignatureValidationStatus");
    }
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
            summary: "Signature is invalid".to_string(),
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
}
