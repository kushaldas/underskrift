//! Enveloping (attached) CAdES signing — the CMS carries the signed file.
//!
//! Unlike PDF signing, the input is not touched and can be any file: the output
//! is a self-contained DER blob holding both the content and the signature.
//! This is what Italian practice calls a `.p7m`; the extension is a convention
//! of the caller, so pick whatever name your workflow expects.
//!
//! Usage:
//!   cargo run --example sign_envelope -- <input file> <key.p12> <password> [output] [mode]
//!
//! If no output path is given, writes to `<input>.p7m`. `mode` is one of:
//!
//! - `single` (default) — one signature
//! - `parallel` — a second signature alongside the first, both over the content
//! - `countersigned` — a signature over the first signature
//!
//! The extra signer reuses the same key with a different digest algorithm, which
//! is enough to make a distinct `SignerInfo` without a second fixture.

use underskrift::{cades, CryptoSigner, DigestAlgorithm, SoftwareSigner};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <input file> <key.p12> <password> [output] [single|parallel|countersigned]",
            args[0]
        );
        std::process::exit(1);
    }

    let input_path = &args[1];
    let p12_path = &args[2];
    let password = &args[3];
    let output_path = if args.len() > 4 {
        args[4].clone()
    } else {
        format!("{input_path}.p7m")
    };

    let content = std::fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("Failed to read input: {e}");
        std::process::exit(1);
    });

    let signer = SoftwareSigner::from_pkcs12_file(p12_path, password).unwrap_or_else(|e| {
        eprintln!("Failed to load PKCS#12 file: {e}");
        std::process::exit(1);
    });
    eprintln!("  Key algorithm: {:?}", signer.signature_algorithm());

    // CAdES keeps the signing time inside the CMS, where PAdES forbids it.
    let now = Some(chrono::Utc::now().naive_utc());
    let envelope = cades::sign_attached(&content, &signer, now).unwrap_or_else(|e| {
        eprintln!("Signing failed: {e}");
        std::process::exit(1);
    });

    let mode = args.get(5).map(String::as_str).unwrap_or("single");
    let second = SoftwareSigner::from_pkcs12_file(p12_path, password)
        .expect("reload signer")
        .with_digest_algorithm(DigestAlgorithm::Sha512);
    let envelope = match mode {
        "single" => envelope,
        "parallel" => cades::add_signer(&envelope, None, &second, now).expect("second signature"),
        "countersigned" => {
            cades::countersign(&envelope, 0, &second, now).expect("countersignature")
        }
        other => {
            eprintln!("Unknown mode: {other}");
            std::process::exit(1);
        }
    };
    eprintln!("  Mode: {mode}");

    std::fs::write(&output_path, &envelope).unwrap_or_else(|e| {
        eprintln!("Failed to write output: {e}");
        std::process::exit(1);
    });

    eprintln!("Envelope written to: {output_path}");
    eprintln!(
        "  {} bytes of content wrapped in {} bytes of CMS",
        content.len(),
        envelope.len()
    );

    // The envelope must give back exactly what went in, or the signature covers
    // something the recipient will never see.
    let recovered = cades::extract_content(&envelope).expect("re-read the envelope");
    assert_eq!(recovered, content, "envelope does not round-trip");
    eprintln!("  Content round-trips out of the envelope");
}
