//! ByteRange gap detection and incremental update analysis.
//!
//! Verifies that a signature's ByteRange correctly covers the expected portions
//! of the PDF file. Detects common attacks:
//! - ByteRange gaps (Signature Wrapping Attack)
//! - ByteRange not starting at 0
//! - ByteRange not ending at EOF (for the last signature)
//! - Overlapping ranges

use crate::crypto::algorithm::DigestAlgorithm;

/// Result of a ByteRange integrity check.
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// Whether the ByteRange is structurally valid
    pub valid: bool,
    /// Whether the ByteRange covers the entire file (no uncovered gaps beyond /Contents)
    pub covers_whole_file: bool,
    /// The computed hash of the byte-range-selected data
    pub data_hash: Vec<u8>,
    /// Human-readable issues found, if any
    pub issues: Vec<String>,
}

/// Verify the ByteRange integrity of a signature.
///
/// Checks that:
/// 1. The ByteRange starts at offset 0
/// 2. The two ranges are contiguous (the gap is exactly the /Contents hex string)
/// 3. The second range extends to the end of the file (for complete coverage)
/// 4. The ranges don't overlap or extend beyond the file
///
/// Also computes the hash of the byte-range-selected data for CMS verification.
///
/// `pdf_data` is the complete PDF file bytes.
/// `byte_range` is [offset1, length1, offset2, length2].
/// `digest_alg` is the digest algorithm to use for hashing.
/// `file_length` is the total length of the PDF (may differ from pdf_data.len()
/// for incremental signatures that don't cover the whole file).
pub fn verify_byte_range(
    pdf_data: &[u8],
    byte_range: &[usize; 4],
    digest_alg: DigestAlgorithm,
) -> IntegrityResult {
    let file_len = pdf_data.len();
    let mut issues = Vec::new();

    let [offset1, length1, offset2, length2] = *byte_range;

    // Check 1: First range must start at offset 0
    if offset1 != 0 {
        issues.push(format!(
            "ByteRange does not start at 0 (starts at {offset1})"
        ));
    }

    // Check 2: Ranges must not exceed file length
    let end1 = offset1.saturating_add(length1);
    let end2 = offset2.saturating_add(length2);

    if end1 > file_len {
        issues.push(format!(
            "first range extends beyond file: {end1} > {file_len}"
        ));
    }
    if end2 > file_len {
        issues.push(format!(
            "second range extends beyond file: {end2} > {file_len}"
        ));
    }

    // Check 3: Ranges must not overlap
    if offset2 < end1 {
        issues.push(format!(
            "ranges overlap: second range starts at {offset2} before first ends at {end1}"
        ));
    }

    // Check 4: The gap between ranges should be the /Contents hex string.
    // In a valid PDF signature, the gap is exactly the hex-encoded contents
    // between '<' and '>'. The gap size should be even (hex encoding).
    // This also defends against Signature Wrapping Attacks (SWA) where an
    // attacker moves the real /Contents to a different offset and places
    // malicious content at the ByteRange gap position.
    let gap_start = end1;
    let gap_end = offset2;
    if gap_end > gap_start {
        let gap_size = gap_end - gap_start;
        // The gap includes the '<' and '>' delimiters, so the hex content
        // size is gap_size - 2. This should be even.
        if gap_size < 2 {
            issues.push(format!("gap between ranges is too small: {gap_size} bytes"));
        } else if gap_start < file_len && gap_end <= file_len {
            // SWA defense: verify the gap actually contains a valid hex string
            // delimited by '<' and '>' — this is what a legitimate /Contents
            // value looks like in the raw PDF bytes.
            validate_contents_gap(pdf_data, gap_start, gap_end, &mut issues);
        }
    }

    // Check 5: Second range should extend to EOF for complete coverage
    let covers_whole_file = end2 == file_len;

    // Note: Not covering to EOF is expected for non-final signatures in
    // multi-signature PDFs (e.g., when a document timestamp was added after
    // the signature). This is NOT an integrity error — it's informational.
    // The `covers_whole_file` field captures this separately.

    // Compute the hash of the byte-range-selected data
    // `valid` reflects structural integrity only (checks 1-4), NOT whether
    // the signature covers to EOF.
    let valid = issues.is_empty();
    let data_hash = if end1 <= file_len && end2 <= file_len && offset2 <= file_len {
        compute_byte_range_hash(pdf_data, byte_range, digest_alg)
    } else {
        // Can't compute hash if ranges are out of bounds
        Vec::new()
    };

    IntegrityResult {
        valid,
        covers_whole_file,
        data_hash,
        issues,
    }
}

/// Validate that the ByteRange gap contains a valid /Contents hex string.
///
/// In a legitimate PDF signature, the gap between the two byte ranges is
/// the /Contents value: a hex-encoded string delimited by `<` and `>`,
/// containing only hex digits (`0-9`, `a-f`, `A-F`) and possibly trailing
/// null (`00`) padding.
///
/// This check defends against Signature Wrapping Attacks (SWA), where an
/// attacker shifts the real /Contents to a different file offset and places
/// crafted content at the ByteRange gap position.
fn validate_contents_gap(
    pdf_data: &[u8],
    gap_start: usize,
    gap_end: usize,
    issues: &mut Vec<String>,
) {
    let gap = &pdf_data[gap_start..gap_end];

    // Check 1: Must start with '<' and end with '>'
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        issues.push(
            "ByteRange gap does not contain a valid hex string (missing '<'/'>' delimiters); \
             possible signature wrapping attack"
                .to_string(),
        );
        return;
    }

    // Check 2: The content between delimiters must be hex digits only
    let hex_content = &gap[1..gap.len() - 1];
    if hex_content.is_empty() {
        issues.push("ByteRange gap hex string is empty".to_string());
        return;
    }

    // Allow hex digits (0-9, a-f, A-F) and whitespace (PDF spec allows
    // whitespace in hex strings, though it's unusual in /Contents)
    let invalid_count = hex_content
        .iter()
        .filter(|&&b| !b.is_ascii_hexdigit() && !b.is_ascii_whitespace())
        .count();

    if invalid_count > 0 {
        issues.push(format!(
            "ByteRange gap contains {invalid_count} non-hex byte(s); \
             possible signature wrapping attack"
        ));
    }

    // Check 3: Hex content length should be even (each byte = 2 hex digits)
    let hex_only_len = hex_content.iter().filter(|b| b.is_ascii_hexdigit()).count();
    if hex_only_len % 2 != 0 {
        issues.push(
            "ByteRange gap hex string has odd length (expected even for byte encoding)".to_string(),
        );
    }
}

/// Compute the hash of the byte-range-selected portions of the PDF.
///
/// Concatenates the bytes from [offset1..offset1+length1] and
/// [offset2..offset2+length2], then hashes with the specified algorithm.
pub fn compute_byte_range_hash(
    pdf_data: &[u8],
    byte_range: &[usize; 4],
    digest_alg: DigestAlgorithm,
) -> Vec<u8> {
    let [offset1, length1, offset2, length2] = *byte_range;

    let range1 = &pdf_data[offset1..offset1 + length1];
    let range2 = &pdf_data[offset2..offset2 + length2];

    let mut hasher = digest_alg.new_hasher();
    hasher.update(range1);
    hasher.update(range2);
    hasher.finalize()
}

/// Check whether a signed PDF has been modified after the last signature.
///
/// For the last signature in a document, the ByteRange should cover the
/// entire file. If it doesn't, bytes were appended after signing
/// (potentially an incremental update / another signature).
pub fn check_post_signature_modifications(pdf_data: &[u8], byte_range: &[usize; 4]) -> bool {
    let [_, _, offset2, length2] = *byte_range;
    let end = offset2 + length2;
    end < pdf_data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic PDF byte buffer with a valid /Contents hex string
    /// in the gap between byte ranges.
    fn build_pdf_with_valid_gap(size: usize, gap_start: usize, gap_end: usize) -> Vec<u8> {
        let mut pdf_data = vec![0x41; size]; // fill with 'A' (arbitrary)
                                             // Place '<' ... hex digits ... '>' in the gap
        pdf_data[gap_start] = b'<';
        pdf_data[gap_end - 1] = b'>';
        // Fill the hex content area with '0' (valid hex digit)
        for b in &mut pdf_data[gap_start + 1..gap_end - 1] {
            *b = b'0';
        }
        pdf_data
    }

    #[test]
    fn test_valid_byte_range() {
        // Simulate a valid byte range covering a 1000-byte file
        // with a 100-byte gap for /Contents containing a valid hex string
        let pdf_data = build_pdf_with_valid_gap(1000, 400, 500);
        let byte_range = [0, 400, 500, 500]; // gap: 400..500

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(result.valid, "issues: {:?}", result.issues);
        assert!(result.covers_whole_file);
        assert!(result.issues.is_empty(), "issues: {:?}", result.issues);
        assert_eq!(result.data_hash.len(), 32); // SHA-256
    }

    #[test]
    fn test_byte_range_not_starting_at_zero() {
        let pdf_data = vec![0xAA; 1000];
        let byte_range = [10, 390, 500, 500]; // doesn't start at 0

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.contains("does not start at 0")));
    }

    #[test]
    fn test_byte_range_not_covering_eof() {
        // Use valid hex gap so the only "issue" is EOF coverage (which is informational)
        let pdf_data = build_pdf_with_valid_gap(1000, 400, 500);
        let byte_range = [0, 400, 500, 400]; // ends at 900, not 1000

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.covers_whole_file);
        // Not covering EOF is informational, not an integrity error —
        // it's expected for non-final signatures in multi-signature PDFs.
        // The `covers_whole_file` field captures this; no issue string is emitted.
        assert!(
            result.valid,
            "ByteRange not covering EOF should still be structurally valid; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_byte_range_exceeds_file() {
        let pdf_data = vec![0xAA; 500];
        let byte_range = [0, 400, 500, 500]; // extends to 1000, but file is 500

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.contains("extends beyond file")));
    }

    #[test]
    fn test_post_signature_modification_detection() {
        let pdf_data = vec![0xAA; 1000];
        // Signature covers to byte 900; file is 1000 bytes → modification detected
        assert!(check_post_signature_modifications(
            &pdf_data,
            &[0, 400, 500, 400]
        ));
        // Signature covers entire file → no modification
        assert!(!check_post_signature_modifications(
            &pdf_data,
            &[0, 400, 500, 500]
        ));
    }

    #[test]
    fn test_hash_computation_sha256() {
        let mut pdf_data = vec![0u8; 100];
        // Fill range1 and range2 with known data
        pdf_data[0..40].fill(0xAA);
        pdf_data[60..100].fill(0xBB);
        let byte_range = [0, 40, 60, 40];

        let hash = compute_byte_range_hash(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert_eq!(hash.len(), 32);

        // Verify hash is deterministic
        let hash2 = compute_byte_range_hash(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert_eq!(hash, hash2);
    }

    // ── SWA defense tests ────────────────────────────────────────────

    #[test]
    fn test_swa_gap_missing_delimiters() {
        // Gap contains arbitrary bytes instead of <hex> — SWA indicator
        let pdf_data = vec![0xAA; 1000];
        let byte_range = [0, 400, 500, 500];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.contains("signature wrapping attack")),
            "should flag missing delimiters as SWA; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_swa_gap_only_opening_delimiter() {
        // Gap starts with '<' but doesn't end with '>'
        let mut pdf_data = vec![0x30; 1000]; // '0' bytes
        pdf_data[400] = b'<';
        // No closing '>'
        let byte_range = [0, 400, 500, 500];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(result
            .issues
            .iter()
            .any(|i| i.contains("signature wrapping attack")));
    }

    #[test]
    fn test_swa_gap_non_hex_content() {
        // Gap has correct delimiters but contains non-hex bytes (e.g., PDF objects)
        let mut pdf_data = vec![0x41; 1000]; // 'A' fill
        pdf_data[400] = b'<';
        pdf_data[499] = b'>';
        // Put some non-hex bytes inside: 'Z', '{', '}' etc.
        pdf_data[410] = b'Z';
        pdf_data[420] = b'{';
        pdf_data[430] = b'}';
        let byte_range = [0, 400, 500, 500];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(
            result.issues.iter().any(|i| i.contains("non-hex byte")),
            "should flag non-hex content; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_swa_gap_valid_hex_with_mixed_case() {
        // Valid /Contents: <aAbBcCdDeEfF0123456789...>
        let mut pdf_data = vec![0x41; 1000];
        pdf_data[400] = b'<';
        pdf_data[499] = b'>';
        // Fill with valid mixed-case hex digits
        let hex_chars = b"0123456789abcdefABCDEF";
        for (i, b) in pdf_data[401..499].iter_mut().enumerate() {
            *b = hex_chars[i % hex_chars.len()];
        }
        let byte_range = [0, 400, 500, 500];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(
            result.valid,
            "valid hex gap should pass; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_swa_gap_empty_hex_string() {
        // Gap is just "<>" — empty hex string
        let mut pdf_data = vec![0x41; 1000];
        // Make gap exactly 2 bytes: [400] = '<', [401] = '>'
        pdf_data[400] = b'<';
        pdf_data[401] = b'>';
        let byte_range = [0, 400, 402, 598];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.valid);
        assert!(
            result.issues.iter().any(|i| i.contains("empty")),
            "should flag empty hex string; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_swa_gap_odd_hex_length() {
        // Gap with odd number of hex digits — suspicious
        let mut pdf_data = vec![0x41; 1000];
        pdf_data[400] = b'<';
        pdf_data[404] = b'>'; // gap = <xxx> = 3 hex chars (odd)
        for b in &mut pdf_data[401..404] {
            *b = b'a';
        }
        let byte_range = [0, 400, 405, 595];

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        // Odd length is a warning but the gap IS a valid hex string structurally
        assert!(
            result.issues.iter().any(|i| i.contains("odd length")),
            "should warn about odd hex length; issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_validate_contents_gap_direct() {
        // Test the validate_contents_gap function directly
        let mut issues = Vec::new();

        // Valid gap
        let valid_gap = b"<0123456789abcdef>";
        let mut data = vec![0u8; 100];
        data[10..10 + valid_gap.len()].copy_from_slice(valid_gap);
        validate_contents_gap(&data, 10, 10 + valid_gap.len(), &mut issues);
        assert!(
            issues.is_empty(),
            "valid gap should have no issues: {:?}",
            issues
        );

        // Invalid: no delimiters
        issues.clear();
        let bad_gap = b"0123456789abcdef00";
        let mut data2 = vec![0u8; 100];
        data2[10..10 + bad_gap.len()].copy_from_slice(bad_gap);
        validate_contents_gap(&data2, 10, 10 + bad_gap.len(), &mut issues);
        assert!(
            !issues.is_empty(),
            "missing delimiters should produce issues"
        );
        assert!(issues[0].contains("signature wrapping attack"));
    }
}
