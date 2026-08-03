//! Generates the test certificate chain before the crate is compiled.
//!
//! `src/verify/chain_verify.rs` pulls fixture certificates in with
//! `include_str!`, so they have to exist before rustc runs — a helper that
//! generated them at test time would already be too late. Running
//! `gen-test-fixtures.sh` by hand was the previous answer, and forgetting it
//! produced a missing-file error with no hint of what to do about it.
//!
//! This is inert for anyone consuming the crate as a dependency:
//! `tests/fixtures` is excluded from the published package, so the directory
//! is not there and this returns immediately.

use std::path::Path;
use std::process::Command;

/// What `gen-test-fixtures.sh` leaves behind. The private keys and the
/// serial files are deliberately not listed: the certificates are what the
/// build and the test suite actually read.
const GENERATED: [&str; 5] = [
    "ca_cert.pem",
    "intermediate_ca_cert.pem",
    "signer_cert.pem",
    "chain.pem",
    "signer.p12",
];

fn main() {
    println!("cargo:rerun-if-changed=gen-test-fixtures.sh");

    // Each generated file has to be declared too, not just the script. Cargo
    // replays a cached build script rather than re-running it, so without
    // these a deleted fixture leaves the script dormant and the build fails on
    // a missing include_str! while cheerfully reprinting this script's old
    // output. A path that does not exist counts as changed, which is exactly
    // the trigger wanted here.
    for name in GENERATED {
        println!("cargo:rerun-if-changed=tests/fixtures/{name}");
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set");
    let fixtures = Path::new(&manifest_dir).join("tests").join("fixtures");
    let script = Path::new(&manifest_dir).join("gen-test-fixtures.sh");

    // Building as a dependency, or from a published tarball: nothing to do.
    if !fixtures.is_dir() || !script.is_file() {
        return;
    }

    // The script mints a fresh CA every time it runs. Doing that on every
    // build would hand each compile a different chain and invalidate the
    // cache, so only step in when something is actually missing.
    if GENERATED.iter().all(|name| fixtures.join(name).exists()) {
        return;
    }

    if Command::new("openssl").arg("version").output().is_err() {
        panic!(
            "test fixtures are missing and openssl was not found on PATH.\n\
             Install openssl, or generate them by hand:\n\
             \n    cd tests/fixtures && bash ../../gen-test-fixtures.sh\n"
        );
    }

    println!("cargo:warning=test fixtures missing — running gen-test-fixtures.sh");

    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&fixtures)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "could not run gen-test-fixtures.sh: {e}\n\
                 Generate the fixtures by hand:\n\
                 \n    cd tests/fixtures && bash ../../gen-test-fixtures.sh\n"
            )
        });

    if !status.success() {
        panic!(
            "gen-test-fixtures.sh failed with {status}.\n\
             Run it by hand to see why:\n\
             \n    cd tests/fixtures && bash ../../gen-test-fixtures.sh\n"
        );
    }

    // A script that exits 0 without producing the files would otherwise
    // surface as a confusing include_str! error further along the build.
    for name in GENERATED {
        if !fixtures.join(name).exists() {
            panic!("gen-test-fixtures.sh reported success but did not produce {name}");
        }
    }
}
