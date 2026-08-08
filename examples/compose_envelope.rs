//! Add your signature to a CAdES envelope somebody else produced.
//!
//! This is the receiving end of the workflow: a `.p7m` arrives already signed,
//! and you have to add a signature without invalidating the one in it. Both
//! operations here copy the existing signed bytes verbatim, so the original
//! signature keeps verifying under the tool that produced it.
//!
//! Usage:
//!   cargo run --example compose_envelope -- <in.p7m> <key.p12> <password> <out.p7m> <mode>
//!
//! `mode` is `parallel` (a second signature over the same content) or
//! `countersign` (a signature over the first signature).

use underskrift::{cades, SoftwareSigner};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "Usage: {} <in.p7m> <key.p12> <password> <out.p7m> <parallel|countersign>",
            args[0]
        );
        std::process::exit(1);
    }
    let (input, p12, password, output, mode) =
        (&args[1], &args[2], &args[3], &args[4], args[5].as_str());

    let envelope = std::fs::read(input).unwrap_or_else(|e| {
        eprintln!("Failed to read the envelope: {e}");
        std::process::exit(1);
    });
    let signer = SoftwareSigner::from_pkcs12_file(p12, password).unwrap_or_else(|e| {
        eprintln!("Failed to load PKCS#12 file: {e}");
        std::process::exit(1);
    });

    let now = Some(chrono::Utc::now().naive_utc());
    let composed = match mode {
        // `None`: the content is already in the envelope, so it is taken from there.
        "parallel" => cades::add_signer(&envelope, None, &signer, now),
        "countersign" => cades::countersign(&envelope, 0, &signer, now),
        other => {
            eprintln!("Unknown mode: {other}");
            std::process::exit(1);
        }
    }
    .unwrap_or_else(|e| {
        eprintln!("Composition failed: {e}");
        std::process::exit(1);
    });

    std::fs::write(output, &composed).unwrap_or_else(|e| {
        eprintln!("Failed to write output: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "{mode}: {} → {} bytes, written to {output}",
        envelope.len(),
        composed.len()
    );
}
