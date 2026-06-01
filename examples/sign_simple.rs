//! Simple PDF signing example.
//!
//! Usage:
//!   cargo run --example sign_simple -- <input.pdf> <key.p12> <password> [output.pdf]
//!
//! If no output path is given, writes to `<input>_signed.pdf`.
//!
//! Example:
//!   cargo run --example sign_simple -- document.pdf signer.p12 mypassword

use underskrift::{CryptoSigner, PdfSigner, SigningOptions, SoftwareSigner, SubFilter};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <input.pdf> <key.p12> <password> [output.pdf]",
            args[0]
        );
        eprintln!();
        eprintln!("Options are hard-coded for simplicity. Edit the source to change:");
        eprintln!("  - SubFilter (PAdES or PKCS#7)");
        eprintln!("  - Field name, reason, location");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let p12_path = &args[2];
    let password = &args[3];
    let output_path = if args.len() > 4 {
        args[4].clone()
    } else {
        let stem = input_path.trim_end_matches(".pdf");
        format!("{}_signed.pdf", stem)
    };

    // Load the PDF
    eprintln!("Reading PDF: {}", input_path);
    let pdf_data = std::fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to read input PDF: {e}");
        std::process::exit(1);
    });
    eprintln!("  PDF size: {} bytes", pdf_data.len());

    // Load the PKCS#12 signer
    eprintln!("Loading PKCS#12 key: {}", p12_path);
    let signer = SoftwareSigner::from_pkcs12_file(p12_path, password).unwrap_or_else(|e| {
        eprintln!("Failed to load PKCS#12 file: {e}");
        eprintln!(
            "  Note: The .p12 file must use legacy encryption (openssl pkcs12 -export -legacy ...)"
        );
        std::process::exit(1);
    });
    eprintln!("  Key algorithm: {:?}", signer.signature_algorithm());

    // Configure signing options
    let options = SigningOptions {
        sub_filter: SubFilter::Pades,
        field_name: "Signature1".to_string(),
        reason: Some("Document signed with underskrift".to_string()),
        location: Some("CLI".to_string()),
        ..Default::default()
    };
    eprintln!("  SubFilter: {:?}", options.sub_filter);

    // Sign the PDF (using a simple blocking runtime)
    eprintln!("Signing...");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let signed = rt
        .block_on(async {
            PdfSigner::new()
                .options(options)
                .sign(&pdf_data, &signer)
                .await
        })
        .unwrap_or_else(|e| {
            eprintln!("Signing failed: {e}");
            std::process::exit(1);
        });

    // Write output
    std::fs::write(&output_path, &signed).unwrap_or_else(|e| {
        eprintln!("Failed to write output: {e}");
        std::process::exit(1);
    });

    eprintln!("Signed PDF written to: {}", output_path);
    eprintln!(
        "  Output size: {} bytes (original: {} bytes, delta: +{} bytes)",
        signed.len(),
        pdf_data.len(),
        signed.len() - pdf_data.len()
    );

    // Quick verification: parse with lopdf to confirm structural validity
    match lopdf::Document::load_mem(&signed) {
        Ok(doc) => {
            let pages = doc.get_pages();
            eprintln!(
                "  Verification: lopdf can parse the output ({} pages)",
                pages.len()
            );
        }
        Err(e) => {
            eprintln!("  WARNING: lopdf failed to parse the output: {e}");
        }
    }
}
