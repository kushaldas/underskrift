//! Standalone CAdES envelopes: reading foreign ones, composing onto them, and
//! reporting honestly when part of the result is broken.
//!
//! The fixture at the centre of this file, `foreign_envelope.p7m`, is signed by
//! **openssl** rather than by us (see `gen-test-fixtures.sh`). Tests that only
//! read our own output prove the encoder and the decoder agree with each other,
//! which they would even if both were wrong. This one costs a shell command and
//! removes that whole class of blind spot — it already caught us rejecting the
//! `rsaEncryption` signatureAlgorithm shape that RFC 3370 §3.2 recommends.
//!
//! The multi-signature cases matter for one reason in particular: a verifier
//! that quietly reports the *first* signer's fate for every signer will look
//! perfectly healthy until the day a document arrives with one good signature
//! and one bad one.

use underskrift::{cades, verify_enveloped, DigestAlgorithm, SoftwareSigner};

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn signer() -> SoftwareSigner {
    SoftwareSigner::from_pkcs12_file(fixture("signer.p12"), "test123").expect("load signer")
}

/// A distinguishable second signer. Same key, different digest: enough to make
/// a distinct `SignerInfo` without a second fixture identity.
fn other_signer() -> SoftwareSigner {
    signer().with_digest_algorithm(DigestAlgorithm::Sha512)
}

fn foreign_envelope() -> Vec<u8> {
    std::fs::read(fixture("foreign_envelope.p7m")).expect("openssl-signed fixture")
}

fn sample_pdf() -> Vec<u8> {
    std::fs::read(fixture("sample.pdf")).expect("sample pdf")
}

// --- minimal DER walking, for corrupting one signer and nobody else ---------

fn read_tlv(data: &[u8], offset: usize) -> (u8, usize, usize) {
    let tag = data[offset];
    let first = data[offset + 1] as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        let len = data[offset + 2..offset + 2 + n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, 2 + n)
    };
    let start = offset + header;
    (tag, start, start + len)
}

fn children(data: &[u8], start: usize, end: usize) -> Vec<(u8, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let (tag, vstart, vend) = read_tlv(data, pos);
        out.push((tag, pos, vstart, vend));
        pos = vend;
    }
    out
}

/// Offsets of the signature value of the `SignerInfo` at `index`.
fn signature_span(cms: &[u8], index: usize) -> (usize, usize) {
    let (_, ci_start, ci_end) = read_tlv(cms, 0);
    let content = children(cms, ci_start, ci_end)[1];
    let (_, sd_start, sd_end) = read_tlv(cms, content.2);
    let sd_fields = children(cms, sd_start, sd_end);
    // digestAlgorithms is a SET too; signerInfos is the last one.
    let signer_infos = *sd_fields.iter().rfind(|f| f.0 == 0x31).unwrap();
    let infos = children(cms, signer_infos.2, signer_infos.3);
    let (_, si_start, si_end) = read_tlv(cms, infos[index].1);
    let signature = children(cms, si_start, si_end)
        .into_iter()
        .find(|c| c.0 == 0x04)
        .expect("signature value");
    (signature.2, signature.3)
}

/// Offsets of the signature value of the countersignature riding on signer 0.
fn countersignature_signature_span(cms: &[u8]) -> (usize, usize) {
    const OID_COUNTERSIGNATURE: [u8; 11] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06,
    ];

    let (_, ci_start, ci_end) = read_tlv(cms, 0);
    let content = children(cms, ci_start, ci_end)[1];
    let (_, sd_start, sd_end) = read_tlv(cms, content.2);
    let sd_fields = children(cms, sd_start, sd_end);
    let signer_infos = *sd_fields.iter().rfind(|f| f.0 == 0x31).unwrap();
    let infos = children(cms, signer_infos.2, signer_infos.3);
    let (_, si_start, si_end) = read_tlv(cms, infos[0].1);

    let unsigned = children(cms, si_start, si_end)
        .into_iter()
        .find(|c| c.0 == 0xA1)
        .expect("unsigned attributes");
    let attr = children(cms, unsigned.2, unsigned.3)
        .into_iter()
        .find(|a| {
            let oid = children(cms, a.2, a.3)[0];
            cms[oid.1..oid.3] == OID_COUNTERSIGNATURE
        })
        .expect("countersignature attribute");

    let values = children(cms, attr.2, attr.3)[1];
    let counter = children(cms, values.2, values.3)[0];
    let (_, cs_start, cs_end) = read_tlv(cms, counter.1);
    let signature = children(cms, cs_start, cs_end)
        .into_iter()
        .find(|c| c.0 == 0x04)
        .expect("countersignature signature value");
    (signature.2, signature.3)
}

/// Flip a byte inside the signature of one signer, leaving the others alone.
fn break_signature(cms: &[u8], index: usize) -> Vec<u8> {
    let (start, _) = signature_span(cms, index);
    let mut broken = cms.to_vec();
    broken[start] ^= 0xFF;
    broken
}

// --- reading what somebody else produced ------------------------------------

#[test]
fn foreign_envelope_is_readable_and_verifies() {
    let cms = foreign_envelope();

    assert_eq!(
        cades::extract_content(&cms).expect("extract"),
        sample_pdf(),
        "the content openssl enveloped did not come back out intact"
    );

    let (content, results) = verify_enveloped(&cms).expect("verify");
    assert_eq!(content, sample_pdf());
    assert_eq!(results.len(), 1);
    assert!(
        results[0].signature_valid,
        "openssl's own signature was rejected: {:?}",
        results[0].issues
    );
    assert!(results[0].digest_matches);
}

#[test]
fn foreign_envelope_with_tampered_content_is_rejected() {
    let cms = foreign_envelope();
    // Flip a byte of the encapsulated content, well past the header.
    let mut tampered = cms.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0xFF;

    match verify_enveloped(&tampered) {
        // Either the structure no longer parses, or it parses and the digest
        // must not match. Silently reporting a valid signature is the one
        // outcome that would be a bug.
        Err(_) => {}
        Ok((_, results)) => assert!(
            !results[0].digest_matches || !results[0].signature_valid,
            "a tampered envelope verified clean"
        ),
    }
}

// --- composing onto what somebody else produced -----------------------------

#[test]
fn adding_a_signer_to_a_foreign_envelope_keeps_the_foreign_signature_valid() {
    let cms = foreign_envelope();
    let composed = cades::add_signer(&cms, None, &other_signer(), None).expect("add signer");

    let (content, results) = verify_enveloped(&composed).expect("verify");
    assert_eq!(content, sample_pdf(), "composition altered the content");
    assert_eq!(results.len(), 2, "expected the original signer plus ours");
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.signature_valid && result.digest_matches,
            "signer {i} broke when a parallel signature was added: {:?}",
            result.issues
        );
    }
}

#[test]
fn countersigning_a_foreign_envelope_keeps_the_foreign_signature_valid() {
    let cms = foreign_envelope();
    let composed = cades::countersign(&cms, 0, &other_signer(), None).expect("countersign");

    let (content, results) = verify_enveloped(&composed).expect("verify");
    assert_eq!(content, sample_pdf());
    assert_eq!(
        results.len(),
        1,
        "a countersignature is not a second signer"
    );
    assert!(
        results[0].signature_valid && results[0].digest_matches,
        "countersigning invalidated the signature it covers: {:?}",
        results[0].issues
    );
}

#[test]
fn timestamping_a_foreign_envelope_keeps_the_foreign_signature_valid() {
    let cms = foreign_envelope();
    // Any well-formed DER stands in for a TSA token here; what is under test is
    // that attaching an unsigned attribute leaves the signed part alone.
    let attr = cades::signature_timestamp_attr(&cms).expect("attribute");
    let stamped = cades::add_unsigned_attributes(&cms, vec![attr]).expect("add unsigned");

    let (_, results) = verify_enveloped(&stamped).expect("verify");
    assert!(
        results[0].signature_valid,
        "attaching an unsigned attribute invalidated the signature: {:?}",
        results[0].issues
    );
}

// --- one good signature, one bad --------------------------------------------

#[test]
fn a_broken_signer_does_not_condemn_the_others() {
    let cms = cades::add_signer(&foreign_envelope(), None, &other_signer(), None).expect("compose");

    for broken in 0..2 {
        let tampered = break_signature(&cms, broken);
        let (content, results) = verify_enveloped(&tampered).expect("verify");

        assert_eq!(content, sample_pdf(), "the content is not in question here");
        assert_eq!(results.len(), 2);
        assert!(
            !results[broken].signature_valid,
            "signer {broken} had its signature corrupted and still verified"
        );

        let intact = 1 - broken;
        assert!(
            results[intact].signature_valid,
            "signer {intact} was reported broken because signer {broken} is: {:?}",
            results[intact].issues
        );
        // Both digests still cover the untouched content: only a signature was
        // corrupted, so a digest mismatch here would mean we mixed the signers up.
        assert!(results[broken].digest_matches && results[intact].digest_matches);
    }
}

#[test]
fn a_signer_committing_to_different_content_is_reported_as_a_digest_mismatch() {
    // A signature that is cryptographically sound but attests to something else
    // entirely — the shape a naive verifier is most likely to wave through.
    let cms = cades::add_signer(
        &foreign_envelope(),
        Some(b"un contenuto completamente diverso"),
        &other_signer(),
        None,
    )
    .expect("compose");

    let (_, results) = verify_enveloped(&cms).expect("verify");
    assert_eq!(results.len(), 2);
    assert!(
        results[0].signature_valid && results[0].digest_matches,
        "the original signer should be untouched: {:?}",
        results[0].issues
    );
    assert!(
        results[1].signature_valid,
        "the added signature is cryptographically fine"
    );
    assert!(
        !results[1].digest_matches,
        "a signer attesting to other content was accepted as covering this one"
    );
}

#[test]
fn a_countersignature_is_verified_not_just_carried() {
    let cms =
        cades::countersign(&foreign_envelope(), 0, &other_signer(), None).expect("countersign");
    let (_, results) = verify_enveloped(&cms).expect("verify");

    assert_eq!(results[0].countersignatures.len(), 1);
    let counter = &results[0].countersignatures[0];
    assert!(
        counter.signature_valid,
        "the countersignature did not verify: {:?}",
        counter.issues
    );
    assert!(
        counter.digest_matches,
        "the countersignature is not bound to the signature it covers: {:?}",
        counter.issues
    );
    assert!(
        counter.signer_certificate.is_some(),
        "countersigner unknown"
    );
    assert_eq!(counter.digest_algorithm, Some(DigestAlgorithm::Sha512));
    assert!(counter.issues.is_empty(), "{:?}", counter.issues);
}

/// A countersignature lives in unsigned attributes, so nothing protects it:
/// anyone can rewrite it in transit. Both ways of getting it wrong have to be
/// caught, and neither may drag the signature underneath down with it.
#[test]
fn a_tampered_countersignature_is_caught_and_blamed_on_itself() {
    let cms =
        cades::countersign(&foreign_envelope(), 0, &other_signer(), None).expect("countersign");

    // 1. Corrupted countersignature bytes: it no longer verifies.
    let (start, _) = countersignature_signature_span(&cms);
    let mut corrupted = cms.clone();
    corrupted[start] ^= 0xFF;
    let (_, results) = verify_enveloped(&corrupted).expect("verify");
    assert!(
        results[0].signature_valid,
        "corrupting a countersignature invalidated the signature beneath it"
    );
    let counter = &results[0].countersignatures[0];
    assert!(
        !counter.signature_valid,
        "a corrupted countersignature verified"
    );

    // 2. The countersignature is intact, but the signature it covers is not the
    //    one it was made over. Its own signature still verifies perfectly — only
    //    the messageDigest binding stands between this and a countersignature
    //    reused from another document.
    let mut swapped = cms.clone();
    let (target_start, target_end) = signature_span(&cms, 0);
    let replacement: Vec<u8> = swapped[target_start..target_end]
        .iter()
        .map(|b| b ^ 0x01)
        .collect();
    swapped[target_start..target_end].copy_from_slice(&replacement);

    let (_, results) = verify_enveloped(&swapped).expect("verify");
    let counter = &results[0].countersignatures[0];
    assert!(
        !counter.digest_matches,
        "a countersignature covering a different signature value was accepted"
    );
}

#[test]
fn countersignatures_stack_on_a_signer_that_already_has_one() {
    let once = cades::countersign(&foreign_envelope(), 0, &other_signer(), None).expect("first");
    let twice = cades::countersign(&once, 0, &signer(), None).expect("second");

    let (_, results) = verify_enveloped(&twice).expect("verify");
    assert!(
        results[0].signature_valid,
        "two countersignatures broke the signature underneath: {:?}",
        results[0].issues
    );
    assert!(
        twice.len() > once.len(),
        "the second countersignature was silently dropped"
    );
}

// --- refusals ----------------------------------------------------------------

#[test]
fn detached_and_out_of_range_inputs_are_refused_not_guessed() {
    let detached = cades::sign_detached(b"contenuto", &signer(), None).expect("sign");

    assert!(
        cades::extract_content(&detached).is_err(),
        "a detached CMS has no content to hand back"
    );
    assert!(
        cades::add_signer(&detached, None, &signer(), None).is_err(),
        "a parallel signer over a detached CMS needs the content supplied"
    );
    // With the content supplied it must work.
    assert!(cades::add_signer(&detached, Some(b"contenuto"), &other_signer(), None).is_ok());

    let cms = foreign_envelope();
    assert!(cades::countersign(&cms, 7, &signer(), None).is_err());
    assert!(cades::signature_value_at(&cms, 7).is_err());
    assert!(verify_enveloped(b"not der at all").is_err());
    assert!(cades::extract_content(&sample_pdf()).is_err());
}
