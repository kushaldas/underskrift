# underskrift

A Rust library for digitally signing and verifying PDF documents. Supports
PAdES B-B through B-LTA, PKCS#7 (traditional PDF signatures), visible and
invisible signatures, LTV (long-term validation), RFC 3161 timestamps,
RFC 9321 SVT tokens, and ETSI TS 119 102-2 validation reports.

*Underskrift* is Swedish for *signature*.

## Features

- **PAdES B-B / B-T / B-LT / B-LTA** conformance levels
- **PKCS#7** (traditional `adbe.pkcs7.detached`) signatures
- **Visible signatures** with configurable layouts, images (JPEG/PNG), and
  embedded font subsetting
- **RFC 3161 timestamping** with TSA client and pool (failover)
- **Long-term validation (LTV)** -- OCSP, CRL fetching, DSS embedding
- **Signature verification** -- integrity checks, CMS validation, certificate
  chain verification against configurable trust stores
- **Validation policy framework** -- basic and PKIX-based policies with
  revocation checking and grace periods
- **SACI AuthnContext** parsing (RFC 7773, Swedish e-signing infrastructure)
- **SVT** (Signature Validation Tokens, RFC 9321) -- issue and validate JWTs,
  embed as document timestamps
- **ETSI TS 119 102-2** XML validation reports
- **Three-phase remote signing** -- prepare hash, sign externally (HSM / cloud
  KMS / smart card), finalize PDF
- **Pluggable crypto** -- bring your own signer via the `CryptoSigner` trait;
  built-in `SoftwareSigner` supports PKCS#12, PEM, and DER key files
- **Algorithm coverage** -- RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-256, P-384,
  P-521), Ed25519, SHA-256/384/512, SHA3-256/384/512

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
underskrift = "0.1"
```

All features are enabled by default. To use only a subset:

```toml
[dependencies]
underskrift = { version = "0.1", default-features = false, features = ["verify"] }
```

### Sign a PDF

```rust
use underskrift::{PdfSigner, SigningOptions, SoftwareSigner, SubFilter};

let pdf_data = std::fs::read("document.pdf")?;
let signer = SoftwareSigner::from_pkcs12_file("key.p12", "password")?;

let options = SigningOptions {
    sub_filter: SubFilter::Pades,
    field_name: "Signature1".to_string(),
    reason: Some("Approved".to_string()),
    ..Default::default()
};

let signed = PdfSigner::new()
    .options(options)
    .sign(&pdf_data, &signer)
    .await?;

std::fs::write("signed.pdf", &signed)?;
```

### Verify a PDF

```rust
use underskrift::{SignatureVerifier, BasicPdfSignaturePolicy};
use underskrift::trust::{TrustStore, TrustStoreSet};

let pdf_data = std::fs::read("signed.pdf")?;

let store = TrustStore::from_pem_directory("./certs/")?;
let trust = TrustStoreSet::new().with_sig_store(store);

let report = SignatureVerifier::new(&trust)
    .policy(BasicPdfSignaturePolicy::new())
    .verify_pdf(&pdf_data)?;

println!("{} signature(s), {} valid", report.signatures.len(), report.valid_count);
for sig in &report.signatures {
    println!("  {}: {:?}", sig.field_name, sig.status);
}
```

### Three-phase remote signing

For HSMs, cloud KMS, or other external signing services where the private key
is not directly accessible:

```rust
use underskrift::{
    prepare_signature, finalize_signature,
    RemoteSignerInfo, RemoteSigningOptions, DigestAlgorithm,
};

// Phase 1: prepare -- returns the hash to be signed externally
let cert_chain = load_certificate_chain(); // Vec<Vec<u8>> (DER)
let signer_info = RemoteSignerInfo::new(cert_chain, SignatureAlgorithm::RsaPkcs1v15);
let options = RemoteSigningOptions::default();
let prepared = prepare_signature(&pdf_data, &signer_info, &options)?;

// Phase 2: sign the hash externally (your HSM / KMS / smart card)
let signature_bytes = your_external_signer.sign(&prepared.attrs_hash)?;

// Phase 3: finalize -- inject signature into the PDF
let signed_pdf = finalize_signature(prepared, &signature_bytes)?;
```

## Feature flags

| Flag       | Default | Description                                              |
|------------|---------|----------------------------------------------------------|
| `verify`   | yes     | Signature verification and validation                    |
| `tsp`      | yes     | RFC 3161 timestamp client (requires network)             |
| `ltv`      | yes     | Long-term validation: OCSP, CRL, DSS (implies `tsp`)    |
| `blocking` | yes     | Synchronous wrappers via `tokio::runtime::block_on()`    |
| `visual`   | yes     | Visible signature appearances, image embedding, fonts    |
| `saci`     | yes     | SACI AuthnContext X.509 extension parsing (RFC 7773)     |
| `svt`      | yes     | RFC 9321 Signature Validation Tokens (JWT-based)         |
| `report`   | yes     | ETSI TS 119 102-2 XML validation reports (implies `verify`) |

## Modules

| Module   | Description                                              |
|----------|----------------------------------------------------------|
| `core`   | PDF signature structures, byte ranges, incremental saves, revision parsing |
| `cms`    | CMS/PKCS#7 SignedData construction (PAdES and traditional profiles)        |
| `crypto` | Signing key abstraction, software signer, algorithm registry              |
| `signer` | High-level `PdfSigner` orchestrator with builder pattern                  |
| `remote` | Three-phase remote/deferred signing protocol                              |
| `trust`  | `TrustStore` and `TrustStoreSet` for certificate management              |
| `policy` | Validation policy framework (`BasicPdfSignaturePolicy`, `PkixPdfSignaturePolicy`) |
| `verify` | Signature verification: integrity, CMS, chain, revocation                 |
| `tsp`    | RFC 3161 TSA client and response parsing                                  |
| `ltv`    | OCSP/CRL clients, certificate chain building, DSS embedding              |
| `visual` | Visible signature layout, image handling, font subsetting                 |
| `saci`   | SACI AuthnContext parsing for Swedish e-signing                           |
| `svt`    | SVT issuance, validation, and PDF embedding                              |
| `report` | ETSI XML validation report generation                                     |

## Supported algorithms

**Signing**: RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256, ECDSA P-384, ECDSA P-521,
Ed25519

**Digest**: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512

**Key formats**: PKCS#12 (`.p12`/`.pfx`), PEM, DER

## Running tests

Test fixtures (keys, certificates) are generated by a script:

```sh
./gen-test-fixtures.sh    # generates test keys with password "test123"
cargo test --all-features
```

There is also an example:

```sh
cargo run --example sign_simple -- input.pdf key.p12 password [output.pdf]
```

## License

BSD-2-Clause
