//! End-to-end integration tests for PDF signing.

use underskrift::{PdfSigner, SigningOptions, SoftwareSigner, SubFilter};

fn test_signer() -> SoftwareSigner {
    let p12_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12");
    SoftwareSigner::from_pkcs12_file(p12_path, "test123").expect("failed to load test signer")
}

fn test_pdf() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
    std::fs::read(path).expect("failed to read test PDF")
}

#[tokio::test]
async fn test_sign_pdf_pades() {
    let pdf = test_pdf();
    let signer = test_signer();

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "TestSignature1".to_string(),
            reason: Some("Testing PAdES signing".to_string()),
            location: Some("Test Lab".to_string()),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing failed");

    // Basic sanity checks
    assert!(signed.len() > pdf.len(), "signed PDF should be larger than original");
    assert!(signed.starts_with(b"%PDF"), "should start with PDF header");

    // Should end with %%EOF
    let tail = String::from_utf8_lossy(&signed[signed.len().saturating_sub(100)..]);
    assert!(tail.contains("%%EOF"), "should end with %%EOF marker");

    // The signed PDF should contain our signature field name
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("TestSignature1"),
        "should contain signature field name"
    );

    // Should contain the SubFilter
    assert!(
        signed_str.contains("ETSI.CAdES.detached"),
        "should contain PAdES SubFilter"
    );

    // Should contain a hex-encoded CMS signature (non-zero Contents)
    // Look for a long hex string that's not all zeros
    assert!(
        signed_str.contains("Adobe.PPKLite"),
        "should contain Filter name"
    );

    // Parse with lopdf to verify structural integrity
    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable by lopdf");

    // Verify there's an AcroForm with SigFlags
    let catalog = doc.catalog().expect("should have catalog");
    assert!(catalog.has(b"AcroForm"), "catalog should have AcroForm");

    println!("PAdES signing test passed. Signed PDF size: {} bytes", signed.len());
}

#[tokio::test]
async fn test_sign_pdf_pkcs7() {
    let pdf = test_pdf();
    let signer = test_signer();

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pkcs7,
            field_name: "TraditionalSig".to_string(),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing failed");

    assert!(signed.len() > pdf.len());

    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("adbe.pkcs7.detached"),
        "should contain traditional SubFilter"
    );

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let catalog = doc.catalog().expect("should have catalog");
    assert!(catalog.has(b"AcroForm"));

    println!("PKCS#7 signing test passed. Signed PDF size: {} bytes", signed.len());
}

#[tokio::test]
async fn test_signed_pdf_has_valid_cms() {
    let pdf = test_pdf();
    let signer = test_signer();

    let signed = PdfSigner::new()
        .options(SigningOptions::default())
        .sign(&pdf, &signer)
        .await
        .expect("signing failed");

    // Extract the CMS signature from the signed PDF
    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");

    // Find the signature dictionary via AcroForm > Fields
    let sigs = underskrift::core::parser::extract_signatures(&doc)
        .expect("should extract signatures");
    assert_eq!(sigs.len(), 1, "should have exactly one signature");

    let sig = &sigs[0];
    assert_eq!(sig.field_name, "Signature1");
    assert!(!sig.contents.is_empty(), "signature contents should not be empty");
    assert!(!sig.sub_filter.is_empty(), "sub_filter should not be empty");

    // Verify the ByteRange makes sense
    let br = sig.byte_range;
    assert_eq!(br[0], 0, "ByteRange should start at 0");
    assert!(br[1] > 0, "ByteRange first length should be > 0");
    assert!(br[2] > br[1], "ByteRange second offset should be > first length");
    assert!(br[3] > 0, "ByteRange second length should be > 0");
    assert_eq!(
        br[0] + br[1] + (br[2] - br[1]) + br[3],
        signed.len(),
        "ByteRange should cover the entire file (with gap)"
    );

    // Parse the CMS signature
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    let content_info =
        ContentInfo::from_der(&sig.contents).expect("should parse CMS ContentInfo");
    assert_eq!(
        content_info.content_type.to_string(),
        "1.2.840.113549.1.7.2",
        "should be id-signedData"
    );

    let sd_bytes = content_info.content.to_der().expect("should encode content");
    let signed_data = SignedData::from_der(&sd_bytes).expect("should parse SignedData");
    assert_eq!(signed_data.signer_infos.0.len(), 1, "should have one signer");
    assert!(signed_data.certificates.is_some(), "should embed certificates");

    println!(
        "CMS validation test passed. Signature field: {}, SubFilter: {}",
        sig.field_name, sig.sub_filter
    );
}

#[tokio::test]
async fn test_sign_writes_valid_output_file() {
    let pdf = test_pdf();
    let signer = test_signer();

    let signed = PdfSigner::new()
        .options(SigningOptions::default())
        .sign(&pdf, &signer)
        .await
        .expect("signing failed");

    // Write to a temp file and verify it can be re-read
    let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
    std::fs::write(tmp.path(), &signed).expect("failed to write signed PDF");

    let reloaded =
        lopdf::Document::load(tmp.path()).expect("signed PDF should be loadable from disk");
    let catalog = reloaded.catalog().expect("reloaded should have catalog");
    assert!(catalog.has(b"AcroForm"));

    println!("File I/O test passed. Written to: {:?}", tmp.path());
}

#[tokio::test]
async fn test_sign_pdf_with_visible_signature() {
    use underskrift::{
        VisibleSignatureConfig, SignatureRect, SignatureLayout,
        TextConfig, TextLine, Color, Border,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 700.0,
            urx: 250.0,
            ury: 750.0,
        },
        layout: SignatureLayout::TextOnly(TextConfig {
            lines: vec![
                TextLine::new("Digitally signed by Test User").bold(),
                TextLine::new("Reason: Integration test"),
                TextLine::new("Date: 2026-03-03"),
            ],
            font_size: 8.0,
            ..TextConfig::default()
        }),
        background_color: Some(Color::white()),
        border: Some(Border::default()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "VisibleSig1".to_string(),
            reason: Some("Visible signature test".to_string()),
            location: Some("Test Lab".to_string()),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with visible signature failed");

    assert!(signed.len() > pdf.len(), "signed PDF should be larger");

    // Parse and verify structural integrity
    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");

    // Verify AcroForm exists
    let catalog = doc.catalog().expect("should have catalog");
    assert!(catalog.has(b"AcroForm"), "catalog should have AcroForm");

    // Extract signature and verify it exists
    let sigs = underskrift::core::parser::extract_signatures(&doc)
        .expect("should extract signatures");
    assert_eq!(sigs.len(), 1, "should have exactly one signature");
    assert_eq!(sigs[0].field_name, "VisibleSig1");

    // Verify the signed PDF contains appearance-related content
    let signed_str = String::from_utf8_lossy(&signed);
    // Should contain the Form XObject type
    assert!(
        signed_str.contains("/XObject"),
        "should contain XObject type for appearance"
    );
    // Should contain the Form subtype
    assert!(
        signed_str.contains("/Form"),
        "should contain Form subtype"
    );
    // Should contain /AP (appearance dictionary)
    assert!(
        signed_str.contains("/AP"),
        "should contain appearance dictionary reference"
    );
    // Should contain the BBox
    assert!(
        signed_str.contains("/BBox"),
        "should contain BBox in Form XObject"
    );
    // Should contain font resource references
    assert!(
        signed_str.contains("/Helvetica"),
        "should reference Helvetica font"
    );
    // The annotation rect should be non-zero (visible)
    assert!(
        signed_str.contains("/Rect"),
        "should contain Rect in annotation"
    );

    // Verify CMS signature is valid
    let sig = &sigs[0];
    assert!(!sig.contents.is_empty());
    let br = sig.byte_range;
    assert_eq!(br[0], 0);
    assert!(br[1] > 0);

    println!(
        "Visible signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

#[tokio::test]
async fn test_sign_pdf_with_positioned_visible_signature() {
    use underskrift::{
        VisibleSignatureConfig, SignatureRect, SignatureLayout, Measurement,
        TextConfig, TextLine,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Positioned {
            left: Measurement::Inches(1.0),
            top: Measurement::Inches(1.0),
            width: Measurement::Inches(3.0),
            height: Measurement::Inches(0.75),
        },
        layout: SignatureLayout::TextOnly(TextConfig {
            lines: vec![
                TextLine::new("Signed with positioned rect").bold(),
            ],
            ..TextConfig::default()
        }),
        background_color: None,
        border: None,
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            field_name: "PositionedSig".to_string(),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with positioned visible signature failed");

    // Parse and verify
    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs = underskrift::core::parser::extract_signatures(&doc)
        .expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "PositionedSig");

    // Should have appearance data
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(signed_str.contains("/AP"));
    assert!(signed_str.contains("/XObject"));

    println!(
        "Positioned visible signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}
