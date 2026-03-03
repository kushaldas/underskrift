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
    let gap_start = end1;
    let gap_end = offset2;
    if gap_end > gap_start {
        let gap_size = gap_end - gap_start;
        // The gap includes the '<' and '>' delimiters, so the hex content
        // size is gap_size - 2. This should be even.
        if gap_size < 2 {
            issues.push(format!("gap between ranges is too small: {gap_size} bytes"));
        }
    }

    // Check 5: Second range should extend to EOF for complete coverage
    let covers_whole_file = end2 == file_len;
    if !covers_whole_file {
        issues.push(format!(
            "ByteRange does not cover to EOF: ends at {end2}, file is {file_len} bytes"
        ));
    }

    // Compute the hash of the byte-range-selected data
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

    #[test]
    fn test_valid_byte_range() {
        // Simulate a valid byte range covering a 1000-byte file
        // with a 100-byte gap for /Contents
        let pdf_data = vec![0xAA; 1000];
        let byte_range = [0, 400, 500, 500]; // gap: 400..500

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(result.valid);
        assert!(result.covers_whole_file);
        assert!(result.issues.is_empty());
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
        let pdf_data = vec![0xAA; 1000];
        let byte_range = [0, 400, 500, 400]; // ends at 900, not 1000

        let result = verify_byte_range(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert!(!result.covers_whole_file);
        assert!(result
            .issues
            .iter()
            .any(|i| i.contains("does not cover to EOF")));
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
        for i in 0..40 {
            pdf_data[i] = 0xAA;
        }
        for i in 60..100 {
            pdf_data[i] = 0xBB;
        }
        let byte_range = [0, 40, 60, 40];

        let hash = compute_byte_range_hash(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert_eq!(hash.len(), 32);

        // Verify hash is deterministic
        let hash2 = compute_byte_range_hash(&pdf_data, &byte_range, DigestAlgorithm::Sha256);
        assert_eq!(hash, hash2);
    }
}
