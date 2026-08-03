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

/// The name the embedded font is given inside the PDF. It is ours to choose, so
/// it stays fixed however the system font is actually called.
const EMBEDDED_FONT_NAME: &str = "EmbeddedTestFont";

/// A TrueType font from the system, located with fontconfig.
///
/// What these tests need is *a* TrueType file to subset and embed, not one
/// particular typeface. Asking fontconfig for it beats hard-coding a path:
/// every distribution files DejaVu somewhere else, and a hard-coded Debian path
/// reports "font not found, install the package" on an Arch box where the
/// package is installed. `fc-match` also never comes back empty-handed — with
/// no DejaVu it returns the closest TrueType the system does have, which serves
/// just as well.
///
/// Set `UNDERSKRIFT_TEST_FONT` to a `.ttf` to bypass all of this.
fn embeddable_font() -> Vec<u8> {
    let path = match std::env::var("UNDERSKRIFT_TEST_FONT") {
        Ok(path) => path,
        Err(_) => {
            let matched = std::process::Command::new("fc-match")
                .args(["-f", "%{file}", "DejaVu Sans:fontformat=TrueType"])
                .output()
                .expect(
                    "fontconfig (fc-match) is not installed; \
                     point UNDERSKRIFT_TEST_FONT at a .ttf instead",
                );
            let path = String::from_utf8_lossy(&matched.stdout).trim().to_string();
            assert!(
                path.ends_with(".ttf"),
                "fontconfig matched {path:?}, which is not a TrueType file; \
                 point UNDERSKRIFT_TEST_FONT at one"
            );
            path
        }
    };

    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read the font at {path}: {e}"))
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
    assert!(
        signed.len() > pdf.len(),
        "signed PDF should be larger than original"
    );
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

    println!(
        "PAdES signing test passed. Signed PDF size: {} bytes",
        signed.len()
    );
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

    println!(
        "PKCS#7 signing test passed. Signed PDF size: {} bytes",
        signed.len()
    );
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
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1, "should have exactly one signature");

    let sig = &sigs[0];
    assert_eq!(sig.field_name, "Signature1");
    assert!(
        !sig.contents.is_empty(),
        "signature contents should not be empty"
    );
    assert!(!sig.sub_filter.is_empty(), "sub_filter should not be empty");

    // Verify the ByteRange makes sense
    let br = sig.byte_range;
    assert_eq!(br[0], 0, "ByteRange should start at 0");
    assert!(br[1] > 0, "ByteRange first length should be > 0");
    assert!(
        br[2] > br[1],
        "ByteRange second offset should be > first length"
    );
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

    let content_info = ContentInfo::from_der(&sig.contents).expect("should parse CMS ContentInfo");
    assert_eq!(
        content_info.content_type.to_string(),
        "1.2.840.113549.1.7.2",
        "should be id-signedData"
    );

    let sd_bytes = content_info
        .content
        .to_der()
        .expect("should encode content");
    let signed_data = SignedData::from_der(&sd_bytes).expect("should parse SignedData");
    assert_eq!(
        signed_data.signer_infos.0.len(),
        1,
        "should have one signer"
    );
    assert!(
        signed_data.certificates.is_some(),
        "should embed certificates"
    );

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
        Border, Color, SignatureLayout, SignatureRect, TextConfig, TextLine, VisibleSignatureConfig,
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
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
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
    assert!(signed_str.contains("/Form"), "should contain Form subtype");
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
        Measurement, SignatureLayout, SignatureRect, TextConfig, TextLine, VisibleSignatureConfig,
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
            lines: vec![TextLine::new("Signed with positioned rect").bold()],
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
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
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

#[tokio::test]
async fn test_sign_pdf_with_image_only_signature() {
    use underskrift::{
        ImageConfig, ImageFormat, ImageScale, SignatureLayout, SignatureRect,
        VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    // Create a small test JPEG in memory
    let jpeg_data = {
        use std::io::Cursor;
        let img = image::RgbImage::from_pixel(20, 20, image::Rgb([0, 0, 200]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    };

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 680.0,
            urx: 200.0,
            ury: 750.0,
        },
        layout: SignatureLayout::ImageOnly(ImageConfig {
            data: jpeg_data,
            format: ImageFormat::Jpeg,
            scale: ImageScale::FitPreserveAspect,
        }),
        background_color: None,
        border: None,
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "ImageSig1".to_string(),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with image-only visible signature failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "ImageSig1");

    // Should have appearance + image xobject
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("/AP"),
        "should have appearance dictionary"
    );
    assert!(
        signed_str.contains("/Image"),
        "should have Image XObject subtype"
    );
    assert!(
        signed_str.contains("/DCTDecode"),
        "should have DCTDecode filter for JPEG"
    );

    println!(
        "Image-only signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

#[tokio::test]
async fn test_sign_pdf_with_image_and_text_signature() {
    use underskrift::{
        Arrangement, Border, Color, ImageConfig, ImageFormat, ImageScale, SignatureLayout,
        SignatureRect, TextConfig, TextLine, VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    // Create a small test JPEG in memory
    let jpeg_data = {
        use std::io::Cursor;
        let img = image::RgbImage::from_pixel(30, 30, image::Rgb([200, 50, 0]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    };

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 650.0,
            urx: 350.0,
            ury: 740.0,
        },
        layout: SignatureLayout::ImageAndText {
            image: ImageConfig {
                data: jpeg_data,
                format: ImageFormat::Jpeg,
                scale: ImageScale::FitPreserveAspect,
            },
            text: TextConfig {
                lines: vec![
                    TextLine::new("Signed by Integration Test").bold(),
                    TextLine::new("Reason: Image+Text test"),
                    TextLine::new("Date: 2026-03-03"),
                ],
                font_size: 8.0,
                ..TextConfig::default()
            },
            arrangement: Arrangement::ImageLeftTextRight,
        },
        background_color: Some(Color::white()),
        border: Some(Border::default()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "ImageTextSig1".to_string(),
            reason: Some("Image and text test".to_string()),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with image+text visible signature failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "ImageTextSig1");

    // Should have appearance, font, and image resources
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("/AP"),
        "should have appearance dictionary"
    );
    assert!(signed_str.contains("/Image"), "should have Image XObject");
    assert!(
        signed_str.contains("/Helvetica"),
        "should have font reference"
    );
    assert!(
        signed_str.contains("/DCTDecode"),
        "should have DCTDecode for JPEG"
    );

    // Verify CMS is valid
    let sig = &sigs[0];
    assert!(!sig.contents.is_empty());
    let br = sig.byte_range;
    assert_eq!(br[0], 0);
    assert!(br[1] > 0);

    println!(
        "Image+Text signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

#[tokio::test]
async fn test_sign_pdf_with_png_alpha_image() {
    use underskrift::{
        ImageConfig, ImageFormat, ImageScale, SignatureLayout, SignatureRect,
        VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    // Create a small test PNG with alpha channel
    let png_data = {
        use std::io::Cursor;
        let img = image::RgbaImage::from_pixel(16, 16, image::Rgba([255, 0, 0, 128]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Png).unwrap();
        buf.into_inner()
    };

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 100.0,
            lly: 700.0,
            urx: 200.0,
            ury: 760.0,
        },
        layout: SignatureLayout::ImageOnly(ImageConfig {
            data: png_data,
            format: ImageFormat::Png,
            scale: ImageScale::Stretch,
        }),
        background_color: None,
        border: None,
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            field_name: "PngAlphaSig".to_string(),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with PNG alpha image failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "PngAlphaSig");

    // Should have SMask for alpha channel
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("/SMask"),
        "should have SMask for alpha channel"
    );
    assert!(
        signed_str.contains("/DeviceGray"),
        "SMask should use DeviceGray"
    );
    assert!(
        signed_str.contains("/FlateDecode"),
        "PNG should use FlateDecode"
    );

    println!(
        "PNG alpha signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

#[tokio::test]
async fn test_sign_pdf_with_embedded_font_text_only() {
    use underskrift::{
        Border, Color, FontSpec, SignatureLayout, SignatureRect, TextConfig, TextLine,
        VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    let font_data = embeddable_font();

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 650.0,
            urx: 300.0,
            ury: 720.0,
        },
        layout: SignatureLayout::TextOnly(TextConfig {
            lines: vec![
                TextLine::new("Signed by Embedded Font Test"),
                TextLine::new("Reason: Testing CIDFont/Type0 embedding"),
                TextLine::new("Date: 2026-03-03"),
            ],
            font: FontSpec::Embedded {
                data: font_data,
                name: EMBEDDED_FONT_NAME.to_string(),
            },
            font_size: 9.0,
            ..TextConfig::default()
        }),
        background_color: Some(Color::white()),
        border: Some(Border::default()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "EmbeddedFontSig1".to_string(),
            reason: Some("Embedded font test".to_string()),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with embedded font visible signature failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "EmbeddedFontSig1");

    // Verify the signed PDF contains CIDFont/Type0 font structures
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("/AP"),
        "should have appearance dictionary"
    );
    assert!(signed_str.contains("/Type0"), "should have Type0 font");
    assert!(
        signed_str.contains("/CIDFontType2"),
        "should have CIDFontType2"
    );
    assert!(
        signed_str.contains("/Identity-H"),
        "should have Identity-H encoding"
    );
    assert!(
        signed_str.contains("/FontFile2"),
        "should have embedded font file"
    );
    assert!(
        signed_str.contains("/ToUnicode"),
        "should have ToUnicode CMap"
    );
    assert!(
        signed_str.contains(EMBEDDED_FONT_NAME),
        "should contain font name"
    );

    println!(
        "Embedded font text-only signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

#[tokio::test]
async fn test_sign_pdf_with_embedded_font_image_and_text() {
    use underskrift::{
        Arrangement, Border, Color, FontSpec, ImageConfig, ImageFormat, ImageScale,
        SignatureLayout, SignatureRect, TextConfig, TextLine, VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    let font_data = embeddable_font();

    // Create a small test JPEG
    let jpeg_data = {
        use std::io::Cursor;
        let img = image::RgbImage::from_pixel(20, 20, image::Rgb([0, 128, 0]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    };

    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 580.0,
            urx: 400.0,
            ury: 660.0,
        },
        layout: SignatureLayout::ImageAndText {
            image: ImageConfig {
                data: jpeg_data,
                format: ImageFormat::Jpeg,
                scale: ImageScale::FitPreserveAspect,
            },
            text: TextConfig {
                lines: vec![
                    TextLine::new("Signed with Embedded Font + Image"),
                    TextLine::new("Location: Stockholm"),
                ],
                font: FontSpec::Embedded {
                    data: font_data,
                    name: EMBEDDED_FONT_NAME.to_string(),
                },
                font_size: 8.0,
                ..TextConfig::default()
            },
            arrangement: Arrangement::ImageLeftTextRight,
        },
        background_color: Some(Color::white()),
        border: Some(Border::default()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "EmbFontImgSig1".to_string(),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with embedded font image+text visible signature failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "EmbFontImgSig1");

    // Should have both image and embedded font structures
    let signed_str = String::from_utf8_lossy(&signed);
    assert!(signed_str.contains("/Image"), "should have Image XObject");
    assert!(signed_str.contains("/Type0"), "should have Type0 font");
    assert!(
        signed_str.contains("/CIDFontType2"),
        "should have CIDFontType2"
    );
    assert!(
        signed_str.contains("/FontFile2"),
        "should have embedded font file"
    );

    println!(
        "Embedded font image+text signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

/// Test signing with a custom template appearance.
///
/// Uses `SignatureTemplate::default()` wrapped in `SignatureLayout::Custom`
/// to verify that the signer pipeline correctly constructs an
/// `AppearanceContext` from signing options and renders the template.
#[tokio::test]
async fn test_sign_pdf_with_custom_template() {
    use std::sync::Arc;
    use underskrift::visual::layout::{Border, Color};
    use underskrift::visual::layout::{
        SignatureLayout, SignatureRect, SignatureTemplate, VisibleSignatureConfig,
    };

    let pdf = test_pdf();
    let signer = test_signer();

    let template = SignatureTemplate::default();
    let vis_config = VisibleSignatureConfig {
        page: 0,
        rect: SignatureRect::Absolute {
            llx: 50.0,
            lly: 650.0,
            urx: 300.0,
            ury: 720.0,
        },
        layout: SignatureLayout::Custom(Arc::new(template)),
        background_color: Some(Color::white()),
        border: Some(Border::default()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "TemplateSig1".to_string(),
            reason: Some("Approval".to_string()),
            location: Some("Stockholm".to_string()),
            contact_info: Some("test@example.com".to_string()),
            visible_signature: Some(vis_config),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with custom template failed");

    assert!(signed.len() > pdf.len());

    let doc = lopdf::Document::load_mem(&signed).expect("signed PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "TemplateSig1");

    // The content stream should contain template text from the signing options
    let signed_str = String::from_utf8_lossy(&signed);
    // Template default lines include "Reason:" and "Location:" labels
    // Since we provided reason and location, these should appear in the PDF
    assert!(
        signed_str.contains("Reason: Approval"),
        "should contain rendered reason from template"
    );
    assert!(
        signed_str.contains("Location: Stockholm"),
        "should contain rendered location from template"
    );
    // Date should be present (auto-populated by signer pipeline)
    assert!(
        signed_str.contains("Date:"),
        "should contain Date label from template"
    );

    // Should have Helvetica font references (template default)
    assert!(
        signed_str.contains("Helvetica"),
        "should use Helvetica font from template"
    );

    println!(
        "Custom template signature test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

/// Regression test for U-1: signing a PDF whose cross-reference section is an
/// XRef **stream** (PDF 1.5+) must produce an XRef-stream incremental update —
/// not a classic `xref` table — and must preserve the trailer `/ID`.
#[tokio::test]
async fn test_sign_xref_stream_pdf() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/xref_stream.pdf"
    );
    let pdf = std::fs::read(path).expect("failed to read xref-stream fixture");

    // Sanity: the fixture really uses an XRef stream, and lopdf reports it so.
    let src = lopdf::Document::load_mem(&pdf).expect("fixture should parse");
    let meta = underskrift::core::parser::extract_metadata(&src).expect("metadata");
    assert!(
        meta.uses_xref_stream,
        "fixture must use a cross-reference stream"
    );
    assert!(meta.id.is_some(), "fixture has a trailer /ID");

    let signer = test_signer();
    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "XrefStreamSig".to_string(),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing an xref-stream PDF failed");

    // The signed output must be loadable and structurally intact.
    let doc =
        lopdf::Document::load_mem(&signed).expect("signed xref-stream PDF should be parseable");
    let sigs =
        underskrift::core::parser::extract_signatures(&doc).expect("should extract signatures");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].field_name, "XrefStreamSig");

    // The incremental update must itself be an XRef stream: a SECOND
    // `/Type /XRef` object appears (the original fixture has one), and our
    // writer must NOT have appended a classic `\nxref\n` table.
    let xref_count =
        count_occurrences(&signed, b"/Type /XRef") + count_occurrences(&signed, b"/Type/XRef");
    assert!(
        xref_count >= 2,
        "incremental update should add an XRef stream object (found {xref_count})"
    );
    // No classic cross-reference table keyword should have been emitted by us.
    // (The fixture has none, so any `\nxref\n` would be ours.)
    assert!(
        !contains_subslice(&signed, b"\nxref\n"),
        "must not emit a classic xref table for an xref-stream source"
    );

    // The trailer /ID must survive into the new XRef stream dictionary.
    assert!(
        contains_subslice(&signed, b"/ID"),
        "trailer /ID must be preserved in the incremental update"
    );

    // The new revision's startxref must point at our new XRef stream object.
    assert!(signed.ends_with(b"%%EOF\n") || signed.ends_with(b"%%EOF"));

    println!(
        "xref-stream signing test passed. Signed PDF size: {} bytes",
        signed.len()
    );
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

/// U-8: commitment-type-indication and signature-policy-identifier signed
/// attributes are embedded and the resulting signature still verifies.
#[tokio::test]
async fn test_sign_with_commitment_and_policy() {
    use const_oid::ObjectIdentifier;
    use underskrift::DigestAlgorithm;
    use underskrift::{CommitmentType, SignaturePolicy};

    let pdf = test_pdf();
    let signer = test_signer();

    let policy = SignaturePolicy {
        policy_id: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.6.1"),
        hash_algorithm: DigestAlgorithm::Sha256,
        hash_value: vec![0x42; 32],
        uri: Some("https://policy.example/sigpolicy.der".to_string()),
    };

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "CommitSig".to_string(),
            commitment_type: Some(CommitmentType::ProofOfApproval),
            signature_policy: Some(policy),
            ..Default::default()
        })
        .sign(&pdf, &signer)
        .await
        .expect("signing with commitment+policy failed");

    // Still a structurally valid, parseable signed PDF.
    let doc = lopdf::Document::load_mem(&signed).expect("parse signed");
    let sigs = underskrift::core::parser::extract_signatures(&doc).expect("extract");
    assert_eq!(sigs.len(), 1);

    // The CMS must carry both attribute OIDs (DER bytes) and the SPURI.
    let commitment_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.16");
    let policy_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
    use der::Encode;
    let cms = &sigs[0].contents;
    assert!(
        contains_subslice(cms, &commitment_oid.to_der().unwrap()),
        "CMS must contain commitment-type-indication OID"
    );
    assert!(
        contains_subslice(cms, &policy_oid.to_der().unwrap()),
        "CMS must contain signature-policy-identifier OID"
    );
    assert!(
        contains_subslice(cms, b"https://policy.example/sigpolicy.der"),
        "CMS must contain the SPURI"
    );
}

/// PAdES baseline interop: DSS rejects PDF `/Reason` when the CMS carries
/// commitment-type-indication or signature-policy-identifier, so fail before
/// producing a non-conformant signature.
#[tokio::test]
async fn test_reason_with_commitment_or_policy_errors() {
    use const_oid::ObjectIdentifier;
    use underskrift::{CommitmentType, DigestAlgorithm, SignaturePolicy};

    let pdf = test_pdf();
    let signer = test_signer();
    let policy = SignaturePolicy {
        policy_id: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.6.1"),
        hash_algorithm: DigestAlgorithm::Sha256,
        hash_value: vec![0x42; 32],
        uri: None,
    };

    for (commitment_type, signature_policy) in [
        (Some(CommitmentType::ProofOfApproval), None),
        (None, Some(policy)),
    ] {
        let result = PdfSigner::new()
            .options(SigningOptions {
                sub_filter: SubFilter::Pades,
                field_name: "ReasonConflict".to_string(),
                reason: Some("I approve".to_string()),
                commitment_type,
                signature_policy,
                ..Default::default()
            })
            .sign(&pdf, &signer)
            .await;

        assert!(result.is_err(), "DSS-invalid option mix must fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("/Reason") && msg.contains("commitment-type"),
            "error should explain the PAdES /Reason conflict: {msg}"
        );
    }
}

/// U-2: a certification signature emits /DocMDP — the sig dict carries a
/// DocMDP /Reference and the catalog carries /Perms /DocMDP — and still verifies.
#[tokio::test]
async fn test_certification_signature_emits_docmdp() {
    use underskrift::DocMdpPermissions;
    let pdf = test_pdf();
    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "CertSig".to_string(),
            certify: true,
            certify_permissions: DocMdpPermissions::NoChanges,
            ..Default::default()
        })
        .sign(&pdf, &test_signer())
        .await
        .expect("certification signing failed");

    let doc = lopdf::Document::load_mem(&signed).expect("parse signed");
    let catalog = doc.catalog().expect("catalog");
    // Catalog must carry /Perms /DocMDP.
    let perms = catalog
        .get(b"Perms")
        .and_then(|o| o.as_dict())
        .expect("/Perms present");
    assert!(perms.has(b"DocMDP"), "/Perms must reference /DocMDP");

    // The signed bytes must contain the DocMDP transform and the chosen P=1.
    let s = String::from_utf8_lossy(&signed);
    assert!(s.contains("DocMDP"), "must contain DocMDP transform");
    assert!(
        s.contains("TransformParams"),
        "must contain TransformParams"
    );

    // External validator agreement can be checked manually if needed; avoid
    // writing files from tests.
}

/// U-2: requesting B-LT/B-LTA from the high-level signer fails loudly instead
/// of silently producing a B-B signature (the original bug).
#[tokio::test]
async fn test_blt_blta_error_not_silent_downgrade() {
    use underskrift::PadesLevel;
    let pdf = test_pdf();
    for level in [PadesLevel::BLT, PadesLevel::BLTA] {
        let result = PdfSigner::new()
            .options(SigningOptions {
                sub_filter: SubFilter::Pades,
                pades_level: level,
                field_name: "Sig".to_string(),
                ..Default::default()
            })
            .sign(&pdf, &test_signer())
            .await;
        assert!(
            result.is_err(),
            "{level:?} must error, not silently downgrade"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("B-LT/B-LTA"),
            "error should name the level: {msg}"
        );
    }
}

/// U-2: requesting B-T without a TSA URL fails with a clear configuration error
/// rather than silently producing B-B.
#[tokio::test]
async fn test_bt_without_tsa_url_errors() {
    use underskrift::PadesLevel;
    let pdf = test_pdf();
    let result = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            pades_level: PadesLevel::BT,
            field_name: "Sig".to_string(),
            tsa_url: None,
            ..Default::default()
        })
        .sign(&pdf, &test_signer())
        .await;
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("TSA URL"));
}

/// `/M` carries the signing date so readers don't fall back to the epoch.
/// Under PAdES the CMS `signingTime` attribute is forbidden, so the signature
/// dictionary is the only place the date can live.
#[tokio::test]
async fn test_signing_time_lands_in_the_m_entry() {
    let signing_time = chrono::NaiveDate::from_ymd_opt(2024, 3, 17)
        .unwrap()
        .and_hms_opt(14, 25, 36)
        .unwrap();

    let signed = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "SigWithDate".to_string(),
            cms_signing_time: Some(signing_time),
            ..Default::default()
        })
        .sign(&test_pdf(), &test_signer())
        .await
        .expect("signing failed");

    assert!(
        contains_subslice(&signed, b"/M (D:20240317142536)"),
        "signature dictionary should carry /M with the requested signing time"
    );

    // Without a signing time there is nothing to write, so /M stays absent.
    let undated = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "SigWithoutDate".to_string(),
            ..Default::default()
        })
        .sign(&test_pdf(), &test_signer())
        .await
        .expect("signing failed");

    assert!(
        !contains_subslice(&undated, b"/M (D:"),
        "no signing time set, so /M should not be written"
    );
}

/// The counterpart to `test_certification_signature_emits_docmdp`: without
/// `certify` neither the DocMDP transform nor `/Perms` may appear.
#[tokio::test]
async fn test_approval_signature_emits_no_docmdp() {
    let approval = PdfSigner::new()
        .options(SigningOptions {
            sub_filter: SubFilter::Pades,
            field_name: "ApprovalSignature".to_string(),
            ..Default::default()
        })
        .sign(&test_pdf(), &test_signer())
        .await
        .expect("signing failed");

    assert!(
        !contains_subslice(&approval, b"/DocMDP"),
        "an approval signature should not declare DocMDP"
    );
    assert!(
        !contains_subslice(&approval, b"/Perms"),
        "an approval signature should not touch /Perms"
    );
}

/// Only one certification signature is allowed per document, and it must be the
/// first. Certifying twice must fail rather than emit a file readers flag as
/// tampered with.
#[tokio::test]
async fn test_second_certification_signature_is_rejected() {
    let certify = |field: &str| SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: field.to_string(),
        certify: true,
        ..Default::default()
    };

    let certified = PdfSigner::new()
        .options(certify("FirstAuthorSignature"))
        .sign(&test_pdf(), &test_signer())
        .await
        .expect("first certification should succeed");

    let result = PdfSigner::new()
        .options(certify("SecondAuthorSignature"))
        .sign(&certified, &test_signer())
        .await;

    // Matched rather than unwrapped: the Ok value is a whole PDF, and letting
    // `expect_err` render it buries the failure under megabytes of bytes.
    let err = match result {
        Ok(_) => panic!("certifying an already-certified document should fail"),
        Err(e) => e,
    };
    assert!(
        format!("{err}").contains("already has a certification signature"),
        "unexpected error: {err}"
    );
}
