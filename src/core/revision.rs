//! PDF incremental revision analysis.
//!
//! Analyzes the incremental update structure of a PDF to determine whether
//! modifications made after a signature are safe (e.g., DSS updates, timestamps)
//! or potentially malicious (content changes, shadow attacks).
//!
//! # Architecture
//!
//! The analysis works in five phases:
//! 1. **%%EOF scanning** — find all revision boundaries in the raw bytes
//! 2. **Per-revision parsing** — load each prefix with lopdf to get xref tables
//! 3. **Xref diffing** — compare consecutive revisions for changed/added objects
//! 4. **Classification** — determine safe vs unsafe modifications
//! 5. **Query** — answer questions about signature coverage
//!
//! # Example
//!
//! ```no_run
//! use underskrift::core::revision::{RevisionAnalysis, DefaultSafeObjectClassifier};
//!
//! let pdf_bytes = std::fs::read("signed.pdf").unwrap();
//! let analysis = RevisionAnalysis::analyze(&pdf_bytes, &DefaultSafeObjectClassifier).unwrap();
//!
//! println!("Found {} revisions", analysis.revisions().len());
//!
//! // Check if a signature covers the whole document
//! let byte_range = [0usize, 1000, 1200, 500];
//! if analysis.covers_whole_document(&byte_range) {
//!     println!("Signature covers entire document");
//! }
//! ```

use std::collections::BTreeMap;

use lopdf::{Document, Object, ObjectId};

use crate::error::CoreError;

// ── Data structures ──────────────────────────────────────────────────────────

/// Information about a single xref entry.
#[derive(Debug, Clone)]
pub struct XrefInfo {
    /// Byte offset of the object in the PDF.
    pub offset: i64,
    /// Generation number.
    pub generation: u16,
}

/// A single PDF incremental update revision.
#[derive(Debug, Clone)]
pub struct PdfRevision {
    /// Byte length from file start to end of this revision (including `%%EOF` + trailing newlines).
    pub length: usize,
    /// Whether this revision contains a document signature.
    pub is_signature: bool,
    /// Whether this revision contains a document timestamp (`SubFilter /ETSI.RFC3161`).
    pub is_doc_timestamp: bool,
    /// Whether this is a valid DSS-only update.
    pub valid_dss: bool,
    /// Whether this revision is a safe update (no visual/content changes).
    pub safe_update: bool,
    /// Whether the root catalog was updated in this revision.
    pub root_update: bool,
    /// Whether any non-root objects had changed xref entries.
    pub non_root_update: bool,
    /// Whether the root dictionary contains only recognized value types.
    pub legal_root_object: bool,
    /// Object ID (number) of the root catalog in this revision.
    pub root_object_id: u32,
    /// Full cumulative xref table for this revision (object number → info).
    pub xref_table: BTreeMap<u32, XrefInfo>,
    /// Objects whose xref offset changed from the prior revision: obj_num → [old_offset, new_offset].
    pub changed_xref: BTreeMap<u32, [i64; 2]>,
    /// Objects newly added in this revision: obj_num → offset.
    pub added_xref: BTreeMap<u32, i64>,
    /// Root dictionary keys that were changed from the prior revision.
    pub changed_root_items: Vec<String>,
    /// Root dictionary keys that were newly added in this revision.
    pub added_root_items: Vec<String>,
    /// Object IDs (numbers) considered safe to modify in this revision.
    pub safe_objects: Vec<u32>,
}

/// Result of a full revision analysis of a PDF document.
#[derive(Debug)]
pub struct RevisionAnalysis {
    /// Ordered list of revisions, from oldest (smallest) to newest (largest).
    revisions: Vec<PdfRevision>,
    /// The raw PDF bytes (kept for `get_signed_document`).
    pdf_bytes: Vec<u8>,
}

// ── SafeObjectClassifier trait ───────────────────────────────────────────────

/// Trait for classifying which PDF objects are safe to modify between revisions.
///
/// The default implementation recognizes DSS, Extensions, Metadata, and Info
/// objects. The strict implementation recognizes nothing beyond AcroForm.
pub trait SafeObjectClassifier: std::fmt::Debug {
    /// Add object IDs that are safe to modify to the `safe_objects` list.
    ///
    /// Called after per-revision root analysis. `doc` is the parsed document
    /// for this revision, and `root_dict` is the root catalog dictionary.
    fn add_safe_objects(
        &self,
        doc: &Document,
        root_dict: &lopdf::Dictionary,
        trailer: &lopdf::Dictionary,
        safe_objects: &mut Vec<u32>,
    );
}

/// Default safe object classifier.
///
/// Recognizes DSS, Extensions, Metadata (from root), Info (from trailer),
/// and all objects referenced within the DSS dictionary as safe.
#[derive(Debug, Clone)]
pub struct DefaultSafeObjectClassifier;

/// Strict safe object classifier.
///
/// Does not recognize any additional safe objects beyond what the core
/// analysis already handles (AcroForm fonts, signature widgets).
#[derive(Debug, Clone)]
pub struct StrictSafeObjectClassifier;

impl SafeObjectClassifier for DefaultSafeObjectClassifier {
    fn add_safe_objects(
        &self,
        doc: &Document,
        root_dict: &lopdf::Dictionary,
        trailer: &lopdf::Dictionary,
        safe_objects: &mut Vec<u32>,
    ) {
        // DSS, Extensions, Metadata from root
        for key in &[b"DSS".as_slice(), b"Extensions", b"Metadata"] {
            if let Ok(obj) = root_dict.get(*key) {
                if let Ok(id) = obj.as_reference() {
                    safe_objects.push(id.0);
                }
            }
        }

        // If DSS exists, add all objects referenced within it
        if let Ok(dss_ref) = root_dict.get(b"DSS") {
            if let Ok(dss_id) = dss_ref.as_reference() {
                if let Ok(dss_obj) = doc.get_object(dss_id) {
                    if let Ok(dss_dict) = dss_obj.as_dict() {
                        collect_references_from_dict(doc, dss_dict, safe_objects);
                    }
                }
            }
        }

        // Info from trailer
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(id) = info_ref.as_reference() {
                safe_objects.push(id.0);
            }
        }
    }
}

impl SafeObjectClassifier for StrictSafeObjectClassifier {
    fn add_safe_objects(
        &self,
        _doc: &Document,
        _root_dict: &lopdf::Dictionary,
        _trailer: &lopdf::Dictionary,
        _safe_objects: &mut Vec<u32>,
    ) {
        // Strict mode: no additional safe objects
    }
}

/// Recursively collect all object references from a dictionary and its sub-arrays.
fn collect_references_from_dict(
    doc: &Document,
    dict: &lopdf::Dictionary,
    safe_objects: &mut Vec<u32>,
) {
    for (_key, value) in dict.iter() {
        match value {
            Object::Reference(id) => {
                safe_objects.push(id.0);
                // Also recurse into the referenced object if it's a dict or array
                if let Ok(obj) = doc.get_object(*id) {
                    if let Ok(sub_dict) = obj.as_dict() {
                        collect_references_from_dict(doc, sub_dict, safe_objects);
                    } else if let Ok(arr) = obj.as_array() {
                        collect_references_from_array(arr, safe_objects);
                    }
                }
            }
            Object::Array(arr) => {
                collect_references_from_array(arr, safe_objects);
            }
            _ => {}
        }
    }
}

/// Collect all object references from an array.
fn collect_references_from_array(arr: &[Object], safe_objects: &mut Vec<u32>) {
    for item in arr {
        if let Object::Reference(id) = item {
            safe_objects.push(id.0);
        }
    }
}

// ── %%EOF scanning ───────────────────────────────────────────────────────────

/// Boundary of a single revision found by scanning for `%%EOF`.
#[derive(Debug, Clone)]
struct RevisionBoundary {
    /// Byte length from start of file to end of this revision (including trailing newlines).
    length: usize,
}

/// Scan the raw PDF bytes for all `%%EOF` markers and return revision boundaries
/// sorted from oldest (smallest length) to newest (largest length).
fn scan_eof_markers(pdf_bytes: &[u8]) -> Vec<RevisionBoundary> {
    let eof_marker = b"%%EOF";
    let mut boundaries = Vec::new();

    // Scan forward through the file looking for %%EOF markers
    let mut pos = 0;
    while pos + eof_marker.len() <= pdf_bytes.len() {
        if let Some(idx) = find_bytes(&pdf_bytes[pos..], eof_marker) {
            let abs_pos = pos + idx;
            let mut rev_len = abs_pos + eof_marker.len();

            // Include trailing newline(s)
            if rev_len < pdf_bytes.len() {
                if pdf_bytes[rev_len] == b'\n' {
                    rev_len += 1;
                } else if pdf_bytes[rev_len] == b'\r' {
                    rev_len += 1;
                    if rev_len < pdf_bytes.len() && pdf_bytes[rev_len] == b'\n' {
                        rev_len += 1;
                    }
                }
            }

            boundaries.push(RevisionBoundary { length: rev_len });
            pos = rev_len;
        } else {
            break;
        }
    }

    boundaries
}

/// Find the first occurrence of `needle` in `haystack`, returning the byte offset.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ── Object comparison ────────────────────────────────────────────────────────

/// Compare two lopdf Objects for semantic equality.
///
/// This follows the Java `ObjectValue.matches()` logic:
/// - References: compare object IDs
/// - Dictionaries: recursive key-by-key comparison
/// - Arrays: element-by-element comparison
/// - Names/Strings: case-insensitive comparison
/// - Numbers: exact comparison (integers) or epsilon comparison (reals)
/// - Booleans: value comparison
/// - Null: never matches
fn objects_match(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::Reference(id_a), Object::Reference(id_b)) => id_a == id_b,
        (Object::Dictionary(da), Object::Dictionary(db)) => dicts_match(da, db),
        (Object::Array(aa), Object::Array(ab)) => arrays_match(aa, ab),
        (Object::Name(na), Object::Name(nb)) => na.eq_ignore_ascii_case(nb),
        (Object::String(sa, _), Object::String(sb, _)) => sa == sb,
        (Object::Integer(ia), Object::Integer(ib)) => ia == ib,
        (Object::Real(ra), Object::Real(rb)) => (*ra - *rb).abs() < 1e-4,
        (Object::Integer(i), Object::Real(r)) | (Object::Real(r), Object::Integer(i)) => {
            (*r - *i as f32).abs() < 1e-4
        }
        (Object::Boolean(ba), Object::Boolean(bb)) => ba == bb,
        (Object::Null, Object::Null) => false, // Java behavior: Null never matches
        _ => false,
    }
}

/// Compare two dictionaries for semantic equality.
fn dicts_match(a: &lopdf::Dictionary, b: &lopdf::Dictionary) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (key, val_a) in a.iter() {
        match b.get(key) {
            Ok(val_b) => {
                if !objects_match(val_a, val_b) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// Compare two arrays for semantic equality.
fn arrays_match(a: &[Object], b: &[Object]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| objects_match(x, y))
}

// ── Invisible annotation detection ──────────────────────────────────────────

/// Check if a PDF annotation object is invisible.
///
/// An annotation is considered invisible if any of these conditions hold:
/// 1. Flag bits indicate Invisible, Hidden, or NoView
/// 2. Subtype is "Popup"
/// 3. Subtype is "Link" with no appearance, zero border, and zero-area rect
/// 4. Subtype is "Widget" and this is a signature revision
/// 5. Not printable, no appearance, and zero-area rect
fn is_invisible_annotation(
    doc: &Document,
    annot_obj: &Object,
    is_signature_revision: bool,
) -> bool {
    let dict = match resolve_to_dict(doc, annot_obj) {
        Some(d) => d,
        None => return false,
    };

    // Step 1: Check /F (flags)
    let flags = dict
        .get(b"F")
        .ok()
        .and_then(|f| f.as_i64().ok())
        .unwrap_or(0) as u32;

    const INVISIBLE: u32 = 1 << 0; // bit 1
    const HIDDEN: u32 = 1 << 1; // bit 2
    const PRINT: u32 = 1 << 2; // bit 3
    const NO_VIEW: u32 = 1 << 5; // bit 6

    if flags & INVISIBLE != 0 || flags & HIDDEN != 0 || flags & NO_VIEW != 0 {
        return true;
    }

    // Step 2: Check subtype
    let subtype_bytes = dict
        .get(b"Subtype")
        .ok()
        .and_then(|s| s.as_name().ok());
    let subtype = subtype_bytes
        .map(|b| std::str::from_utf8(b).unwrap_or(""))
        .unwrap_or("");

    if subtype == "Popup" {
        return true;
    }

    // Step 3: Check /Rect for zero area
    let zero_area = is_zero_area_rect(dict);

    // Step 4: Check for appearance stream (/AP -> /N)
    let has_appearance = dict
        .get(b"AP")
        .ok()
        .and_then(|ap| ap.as_dict().ok())
        .and_then(|ap_dict| ap_dict.get(b"N").ok())
        .is_some();

    // Step 5: Border width
    let border_width = get_border_width(dict);

    // Step 6: Specific safe cases
    // 6a: Link with no appearance, zero border, zero area
    if subtype == "Link" && !has_appearance && border_width <= f32::EPSILON && zero_area {
        return true;
    }

    // 6b: Widget in a signature revision
    if subtype == "Widget" && is_signature_revision {
        return true;
    }

    // 6c: Not printable, no appearance, zero area
    if flags & PRINT == 0 && !has_appearance && zero_area {
        return true;
    }

    false
}

/// Check if a /Rect array represents a zero-area rectangle.
fn is_zero_area_rect(dict: &lopdf::Dictionary) -> bool {
    let rect = match dict.get(b"Rect").ok().and_then(|r| r.as_array().ok()) {
        Some(r) if r.len() == 4 => r,
        _ => return false,
    };

    let coords: Vec<f32> = rect
        .iter()
        .filter_map(|v| match v {
            Object::Real(r) => Some(*r),
            Object::Integer(i) => Some(*i as f32),
            _ => None,
        })
        .collect();

    if coords.len() != 4 {
        return false;
    }

    let width = (coords[2] - coords[0]).abs();
    let height = (coords[3] - coords[1]).abs();

    width <= 0.001 && height <= 0.001
}

/// Get the border width from /Border or /BS/W.
fn get_border_width(dict: &lopdf::Dictionary) -> f32 {
    // Try /Border array — width is at index 2
    if let Ok(border) = dict.get(b"Border") {
        if let Ok(arr) = border.as_array() {
            if arr.len() >= 3 {
                return match &arr[2] {
                    Object::Real(r) => *r,
                    Object::Integer(i) => *i as f32,
                    _ => 1.0,
                };
            }
        }
    }

    // Try /BS dictionary -> /W
    if let Ok(bs) = dict.get(b"BS") {
        if let Ok(bs_dict) = bs.as_dict() {
            if let Ok(w) = bs_dict.get(b"W") {
                return match w {
                    Object::Real(r) => *r,
                    Object::Integer(i) => *i as f32,
                    _ => 1.0,
                };
            }
        }
    }

    1.0 // default border width
}

/// Resolve an Object to a dictionary, dereferencing indirect references.
fn resolve_to_dict<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a lopdf::Dictionary> {
    match obj {
        Object::Dictionary(d) => Some(d),
        Object::Reference(id) => doc
            .get_object(*id)
            .ok()
            .and_then(|o| o.as_dict().ok()),
        _ => None,
    }
}

// ── Annotation change detection ──────────────────────────────────────────────

/// Check if the difference between old_obj and new_obj is limited to adding
/// invisible annotations (i.e. the /Annots array grew but only with invisible ones).
fn is_only_new_annotations(
    doc_old: &Document,
    doc_new: &Document,
    old_obj: &Object,
    new_obj: &Object,
    is_signature_revision: bool,
) -> bool {
    // If both are annotation objects themselves, check if the new one is invisible
    if is_annotation_object(old_obj) && is_annotation_object(new_obj) {
        return is_invisible_annotation(doc_new, new_obj, is_signature_revision);
    }

    // Both must be dictionaries (typically page objects)
    let old_dict = match old_obj.as_dict() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let new_dict = match new_obj.as_dict() {
        Ok(d) => d,
        Err(_) => return false,
    };

    // All keys except /Annots must match between old and new
    for (key, old_val) in old_dict.iter() {
        if key == b"Annots" {
            continue;
        }
        match new_dict.get(key) {
            Ok(new_val) => {
                if !objects_match(old_val, new_val) {
                    // Special case: /Fields can differ if this is a signature revision
                    if key == b"Fields" && is_signature_revision {
                        continue;
                    }
                    return false;
                }
            }
            Err(_) => return false,
        }
    }

    // New dict must not have added keys other than /Annots
    for (key, _) in new_dict.iter() {
        if key == b"Annots" {
            continue;
        }
        if old_dict.get(key).is_err() {
            return false;
        }
    }

    // Check /Annots: new must contain all of old, and any new entries must be invisible
    let old_annots = get_annots_array(doc_old, old_dict);
    let new_annots = get_annots_array(doc_new, new_dict);

    let old_refs: Vec<ObjectId> = old_annots
        .iter()
        .filter_map(|o| {
            if let Object::Reference(id) = o {
                Some(*id)
            } else {
                None
            }
        })
        .collect();

    let new_refs: Vec<ObjectId> = new_annots
        .iter()
        .filter_map(|o| {
            if let Object::Reference(id) = o {
                Some(*id)
            } else {
                None
            }
        })
        .collect();

    // All old annotations must still be present
    for old_ref in &old_refs {
        if !new_refs.contains(old_ref) {
            return false;
        }
    }

    // Any new annotations must be invisible
    for new_ref in &new_refs {
        if !old_refs.contains(new_ref) {
            if let Ok(annot_obj) = doc_new.get_object(*new_ref) {
                if !is_invisible_annotation(doc_new, annot_obj, is_signature_revision) {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    true
}

/// Check if an object looks like an annotation (has /Type /Annot or /Subtype).
fn is_annotation_object(obj: &Object) -> bool {
    if let Ok(dict) = obj.as_dict() {
        if let Ok(ty) = dict.get(b"Type") {
            if let Ok(name) = ty.as_name() {
                return std::str::from_utf8(name).unwrap_or("") == "Annot";
            }
        }
        // Some annotations don't have /Type but do have /Subtype
        return dict.has(b"Subtype") && dict.has(b"Rect");
    }
    false
}

/// Get the /Annots array from a dictionary, resolving indirect references.
fn get_annots_array<'a>(doc: &'a Document, dict: &'a lopdf::Dictionary) -> Vec<&'a Object> {
    let annots = match dict.get(b"Annots") {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };

    match annots {
        Object::Array(arr) => arr.iter().collect(),
        Object::Reference(id) => {
            if let Ok(obj) = doc.get_object(*id) {
                if let Ok(arr) = obj.as_array() {
                    return arr.iter().collect();
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

// ── Root dictionary analysis helpers ─────────────────────────────────────────

/// Add safe object IDs based on a root dictionary key.
fn add_root_safe_objects(
    doc: &Document,
    root_dict: &lopdf::Dictionary,
    key: &[u8],
    safe_objects: &mut Vec<u32>,
) {
    if key == b"AcroForm" {
        // AcroForm itself is safe, plus DR/Font inside it
        if let Ok(af_ref) = root_dict.get(b"AcroForm") {
            if let Ok(af_id) = af_ref.as_reference() {
                safe_objects.push(af_id.0);
                if let Ok(af_obj) = doc.get_object(af_id) {
                    if let Ok(af_dict) = af_obj.as_dict() {
                        // DR -> Font
                        if let Ok(dr) = af_dict.get(b"DR") {
                            if let Ok(dr_id) = dr.as_reference() {
                                safe_objects.push(dr_id.0);
                                if let Ok(dr_obj) = doc.get_object(dr_id) {
                                    if let Ok(dr_dict) = dr_obj.as_dict() {
                                        if let Ok(font) = dr_dict.get(b"Font") {
                                            if let Ok(font_id) = font.as_reference() {
                                                safe_objects.push(font_id.0);
                                            }
                                        }
                                    }
                                }
                            } else if let Ok(dr_dict) = dr.as_dict() {
                                if let Ok(font) = dr_dict.get(b"Font") {
                                    if let Ok(font_id) = font.as_reference() {
                                        safe_objects.push(font_id.0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if key == b"OpenAction" {
        // If OpenAction is an array with exactly one COSObject, mark it safe
        if let Ok(oa) = root_dict.get(b"OpenAction") {
            if let Ok(arr) = oa.as_array() {
                if arr.len() == 1 {
                    if let Object::Reference(id) = &arr[0] {
                        safe_objects.push(id.0);
                    }
                }
            }
        }
    }
}

// ── Main analysis ────────────────────────────────────────────────────────────

impl RevisionAnalysis {
    /// Analyze a PDF's incremental revision structure.
    ///
    /// Returns a `RevisionAnalysis` with all revisions classified as safe/unsafe,
    /// or an error if the PDF cannot be parsed at all.
    pub fn analyze(
        pdf_bytes: &[u8],
        classifier: &dyn SafeObjectClassifier,
    ) -> Result<Self, CoreError> {
        // Phase 1: Find all %%EOF markers
        let boundaries = scan_eof_markers(pdf_bytes);
        if boundaries.is_empty() {
            return Err(CoreError::InvalidStructure(
                "no %%EOF markers found in PDF".into(),
            ));
        }

        // Load the full document to extract signature info
        let full_doc = Document::load_mem(pdf_bytes)?;
        let signatures = extract_signature_byte_ranges(&full_doc);

        // Phase 2: Build initial revisions with parsed xref tables
        let mut revisions: Vec<PdfRevision> = Vec::new();

        for boundary in &boundaries {
            let rev_bytes = &pdf_bytes[..boundary.length];

            // Correlate with signatures
            let is_signature = signatures
                .iter()
                .any(|s| s.covered_length == boundary.length && !s.is_doc_timestamp);
            let is_doc_timestamp = signatures
                .iter()
                .any(|s| s.covered_length == boundary.length && s.is_doc_timestamp);

            // Try to load the truncated prefix as a PDF
            let parsed = match Document::load_mem(rev_bytes) {
                Ok(doc) => Some(doc),
                Err(e) => {
                    log::warn!(
                        "Failed to parse revision at length {}: {}",
                        boundary.length,
                        e
                    );
                    None
                }
            };

            let (xref_table, root_object_id) = if let Some(ref doc) = parsed {
                let xref = extract_xref_table(doc);
                let root_id = get_root_object_id(doc).unwrap_or(0);
                (xref, root_id)
            } else {
                (BTreeMap::new(), 0)
            };

            revisions.push(PdfRevision {
                length: boundary.length,
                is_signature,
                is_doc_timestamp,
                valid_dss: false,
                safe_update: false,
                root_update: false,
                non_root_update: false,
                legal_root_object: true,
                root_object_id,
                xref_table,
                changed_xref: BTreeMap::new(),
                added_xref: BTreeMap::new(),
                changed_root_items: Vec::new(),
                added_root_items: Vec::new(),
                safe_objects: Vec::new(),
            });
        }

        // Phase 3 & 4: Compute xref diffs and classify each revision
        for i in 0..revisions.len() {
            if i == 0 {
                // First revision: everything is "added", nothing changed
                let added: BTreeMap<u32, i64> = revisions[i]
                    .xref_table
                    .iter()
                    .map(|(k, v)| (*k, v.offset))
                    .collect();
                revisions[i].added_xref = added;
                revisions[i].safe_update = true; // First revision is inherently safe
                continue;
            }

            // Compute changed and added xrefs
            let prev_xref = revisions[i - 1].xref_table.clone();
            let curr_xref = &revisions[i].xref_table;
            let root_id = revisions[i].root_object_id;

            let mut changed: BTreeMap<u32, [i64; 2]> = BTreeMap::new();
            let mut added: BTreeMap<u32, i64> = BTreeMap::new();
            let mut root_update = false;
            let mut non_root_update = false;

            for (obj_num, curr_info) in curr_xref {
                if let Some(prev_info) = prev_xref.get(obj_num) {
                    if prev_info.offset != curr_info.offset {
                        changed.insert(*obj_num, [prev_info.offset, curr_info.offset]);
                        if *obj_num == root_id {
                            root_update = true;
                        } else {
                            non_root_update = true;
                        }
                    }
                } else {
                    added.insert(*obj_num, curr_info.offset);
                }
            }

            revisions[i].changed_xref = changed;
            revisions[i].added_xref = added;
            revisions[i].root_update = root_update;
            revisions[i].non_root_update = non_root_update;

            // Phase 4: Classify this revision
            // Load both this and previous revision's documents for object comparison
            let prev_bytes = &pdf_bytes[..revisions[i - 1].length];
            let curr_bytes = &pdf_bytes[..revisions[i].length];

            let prev_doc = Document::load_mem(prev_bytes).ok();
            let curr_doc = Document::load_mem(curr_bytes).ok();

            if let (Some(ref prev_doc), Some(ref curr_doc)) = (&prev_doc, &curr_doc) {
                classify_revision(
                    &mut revisions[i],
                    prev_doc,
                    curr_doc,
                    classifier,
                );
            } else {
                // If we can't parse either doc, mark as unsafe
                revisions[i].safe_update = false;
            }
        }

        Ok(RevisionAnalysis {
            revisions,
            pdf_bytes: pdf_bytes.to_vec(),
        })
    }

    /// Get the ordered list of revisions (oldest first).
    pub fn revisions(&self) -> &[PdfRevision] {
        &self.revisions
    }

    /// Get the number of revisions.
    pub fn revision_count(&self) -> usize {
        self.revisions.len()
    }

    /// Find the revision index that matches a signature's ByteRange.
    ///
    /// The ByteRange `[offset1, length1, offset2, length2]` covers bytes
    /// `0..length1` and `offset2..offset2+length2`. The total coverage is
    /// `offset2 + length2`, which should equal a revision boundary.
    pub fn find_signature_revision(&self, byte_range: &[usize; 4]) -> Option<usize> {
        let covered_length = byte_range[2] + byte_range[3];
        self.revisions
            .iter()
            .position(|r| r.length == covered_length)
    }

    /// Check if a signature covers the whole document.
    ///
    /// Returns `true` if the signature is the last revision, or if all
    /// subsequent revisions are safe updates.
    pub fn covers_whole_document(&self, byte_range: &[usize; 4]) -> bool {
        let rev_idx = match self.find_signature_revision(byte_range) {
            Some(idx) => idx,
            None => return false,
        };

        // If this is the last revision, it covers everything
        if rev_idx == self.revisions.len() - 1 {
            return true;
        }

        // Check all subsequent revisions are safe
        for i in (rev_idx + 1)..self.revisions.len() {
            if !self.revisions[i].safe_update {
                return false;
            }
        }

        true
    }

    /// Check if a signature has been extended by non-safe updates.
    ///
    /// Scans forward from the signature's revision looking for the first
    /// revision that is not a signature, not a document timestamp, and not
    /// a valid DSS. If found, returns whether that revision is unsafe.
    pub fn is_extended_by_non_safe_updates(&self, byte_range: &[usize; 4]) -> bool {
        let rev_idx = match self.find_signature_revision(byte_range) {
            Some(idx) => idx,
            None => return false,
        };

        for i in (rev_idx + 1)..self.revisions.len() {
            let rev = &self.revisions[i];
            if !rev.is_signature && !rev.is_doc_timestamp && !rev.valid_dss {
                return !rev.safe_update;
            }
        }

        false
    }

    /// Get the bytes of the document as it was when a particular signature was applied.
    ///
    /// Returns the PDF bytes truncated to the revision boundary matching
    /// the signature's ByteRange.
    pub fn get_signed_document(&self, byte_range: &[usize; 4]) -> Option<&[u8]> {
        let rev_idx = self.find_signature_revision(byte_range)?;
        let length = self.revisions[rev_idx].length;
        Some(&self.pdf_bytes[..length])
    }
}

/// Classify a single revision: determine safe objects, root changes, safe_update, valid_dss.
fn classify_revision(
    rev: &mut PdfRevision,
    prev_doc: &Document,
    curr_doc: &Document,
    classifier: &dyn SafeObjectClassifier,
) {
    let root_id = (rev.root_object_id, 0u16);

    // Get root dictionaries
    let curr_root = curr_doc
        .get_object(root_id)
        .ok()
        .and_then(|o| o.as_dict().ok());
    let prev_root = prev_doc
        .get_object(root_id)
        .ok()
        .and_then(|o| o.as_dict().ok());

    // Check non-root changed objects for safety
    let mut safe_objects: Vec<u32> = Vec::new();

    for (obj_num, _offsets) in &rev.changed_xref {
        if *obj_num == rev.root_object_id {
            continue;
        }

        let old_obj = prev_doc.get_object((*obj_num, 0));
        let new_obj = curr_doc.get_object((*obj_num, 0));

        match (old_obj, new_obj) {
            (Ok(old), Ok(new)) => {
                if is_only_new_annotations(
                    prev_doc,
                    curr_doc,
                    old,
                    new,
                    rev.is_signature || rev.is_doc_timestamp,
                ) {
                    safe_objects.push(*obj_num);
                }
            }
            (Err(_), Err(_)) => {
                // Both missing — consider safe
                safe_objects.push(*obj_num);
            }
            _ => {
                // One exists and the other doesn't — not safe
            }
        }
    }

    // Analyze root dictionary changes if root was updated
    let mut legal_root_object = true;
    let mut changed_root_items: Vec<String> = Vec::new();
    let mut added_root_items: Vec<String> = Vec::new();

    if rev.root_update {
        if let (Some(prev_root), Some(curr_root)) = (prev_root, curr_root) {
            for (key, new_val) in curr_root.iter() {
                let key_str = String::from_utf8_lossy(key).to_string();

                if let Ok(old_val) = prev_root.get(key) {
                    // Key existed before — check if value changed
                    if !objects_match(old_val, new_val) {
                        changed_root_items.push(key_str);
                    }
                } else {
                    // New key
                    added_root_items.push(key_str);
                }

                // Add safe objects for known root keys
                add_root_safe_objects(curr_doc, curr_root, key, &mut safe_objects);
            }
        } else if curr_root.is_none() {
            legal_root_object = false;
        }
    }

    // Apply the classifier's safe objects
    if let Some(curr_root) = curr_root {
        let trailer = curr_doc.trailer.clone();
        classifier.add_safe_objects(curr_doc, curr_root, &trailer, &mut safe_objects);
    }

    // Determine safe_update
    let unsupported_root_change = changed_root_items
        .iter()
        .any(|k| k != "AcroForm");

    let unsafe_ref_update = rev
        .changed_xref
        .keys()
        .any(|obj_num| {
            *obj_num != rev.root_object_id && !safe_objects.contains(obj_num)
        });

    let safe_update = !unsupported_root_change && !unsafe_ref_update && legal_root_object;

    // Determine valid_dss
    let valid_dss = rev.root_update
        && safe_update
        && legal_root_object
        && changed_root_items.is_empty()
        && (
            // Exactly one added item: "DSS"
            (added_root_items.len() == 1 && added_root_items.contains(&"DSS".to_string()))
            ||
            // Exactly two added items: "DSS" and "Extensions"
            (added_root_items.len() == 2
                && added_root_items.contains(&"DSS".to_string())
                && added_root_items.contains(&"Extensions".to_string()))
        );

    rev.safe_objects = safe_objects;
    rev.legal_root_object = legal_root_object;
    rev.changed_root_items = changed_root_items;
    rev.added_root_items = added_root_items;
    rev.safe_update = safe_update;
    rev.valid_dss = valid_dss;
}

// ── Helpers for parsing ──────────────────────────────────────────────────────

/// Information about a signature's byte range from the full document.
struct SignatureByteRangeInfo {
    covered_length: usize,
    is_doc_timestamp: bool,
}

/// Extract byte range info for all signatures in a document.
fn extract_signature_byte_ranges(doc: &Document) -> Vec<SignatureByteRangeInfo> {
    let mut result = Vec::new();

    let fields = match get_acroform_fields(doc) {
        Some(f) => f,
        None => return result,
    };

    for field_ref in &fields {
        if let Object::Reference(id) = field_ref {
            if let Ok(field_obj) = doc.get_object(*id) {
                if let Ok(field_dict) = field_obj.as_dict() {
                    // Check if this is a signature field
                    let is_sig = field_dict
                        .get(b"FT")
                        .ok()
                        .and_then(|ft| ft.as_name().ok())
                        .map(|ft| ft == b"Sig")
                        .unwrap_or(false);

                    if !is_sig {
                        continue;
                    }

                    // Get the signature dictionary (may be inline or via /V reference)
                    let sig_dict = get_sig_dict(doc, field_dict);

                    if let Some(sig_dict) = sig_dict {
                        // Extract byte range
                        if let Some(br) = extract_byte_range(sig_dict) {
                            let covered_length = br[2] + br[3];

                            // Check SubFilter for document timestamp
                            let is_doc_timestamp = sig_dict
                                .get(b"SubFilter")
                                .ok()
                                .and_then(|sf| sf.as_name().ok())
                                .map(|sf| sf == b"ETSI.RFC3161")
                                .unwrap_or(false);

                            result.push(SignatureByteRangeInfo {
                                covered_length,
                                is_doc_timestamp,
                            });
                        }
                    }
                }
            }
        }
    }

    result
}

/// Get AcroForm /Fields array from the document catalog.
fn get_acroform_fields(doc: &Document) -> Option<Vec<Object>> {
    let catalog = doc.catalog().ok()?;
    let acroform = catalog.get(b"AcroForm").ok()?;

    let acroform_dict = match acroform {
        Object::Reference(id) => doc.get_object(*id).ok()?.as_dict().ok()?,
        Object::Dictionary(d) => d,
        _ => return None,
    };

    let fields = acroform_dict.get(b"Fields").ok()?;
    match fields {
        Object::Array(arr) => Some(arr.clone()),
        Object::Reference(id) => {
            let obj = doc.get_object(*id).ok()?;
            obj.as_array().ok().cloned()
        }
        _ => None,
    }
}

/// Get the signature dictionary from a field, handling both inline /V and reference.
fn get_sig_dict<'a>(doc: &'a Document, field_dict: &'a lopdf::Dictionary) -> Option<&'a lopdf::Dictionary> {
    // Try /V first (standard location for signature value)
    if let Ok(v) = field_dict.get(b"V") {
        match v {
            Object::Reference(id) => {
                if let Ok(obj) = doc.get_object(*id) {
                    return obj.as_dict().ok();
                }
            }
            Object::Dictionary(d) => return Some(d),
            _ => {}
        }
    }

    // The field itself might be the sig dict (combined field/widget)
    if field_dict.has(b"ByteRange") && field_dict.has(b"Contents") {
        return Some(field_dict);
    }

    None
}

/// Extract a ByteRange from a signature dictionary.
fn extract_byte_range(sig_dict: &lopdf::Dictionary) -> Option<[usize; 4]> {
    let br = sig_dict.get(b"ByteRange").ok()?;
    let arr = br.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }

    let values: Vec<usize> = arr
        .iter()
        .filter_map(|v| v.as_i64().ok().map(|i| i as usize))
        .collect();

    if values.len() == 4 {
        Some([values[0], values[1], values[2], values[3]])
    } else {
        None
    }
}

/// Extract the xref table from a lopdf Document as our BTreeMap format.
fn extract_xref_table(doc: &Document) -> BTreeMap<u32, XrefInfo> {
    let mut table = BTreeMap::new();

    for (id, entry) in &doc.reference_table.entries {
        match entry {
            lopdf::xref::XrefEntry::Normal { offset, generation } => {
                table.insert(
                    *id,
                    XrefInfo {
                        offset: *offset as i64,
                        generation: *generation,
                    },
                );
            }
            lopdf::xref::XrefEntry::Compressed { container, index } => {
                // For compressed objects, store the container's object number as a
                // pseudo-offset (negative to distinguish from normal entries)
                table.insert(
                    *id,
                    XrefInfo {
                        offset: -((*container as i64) * 1000 + *index as i64),
                        generation: 0,
                    },
                );
            }
            _ => {
                // Free entries are not tracked
            }
        }
    }

    table
}

/// Get the root object ID from a document's trailer.
fn get_root_object_id(doc: &Document) -> Option<u32> {
    let root_ref = doc.trailer.get(b"Root").ok()?;
    let id = root_ref.as_reference().ok()?;
    Some(id.0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── %%EOF scanner tests ──────────────────────────────────────────────

    #[test]
    fn test_scan_single_eof() {
        let data = b"%PDF-1.4\nsome content\n%%EOF\n";
        let boundaries = scan_eof_markers(data);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].length, data.len());
    }

    #[test]
    fn test_scan_multiple_eofs() {
        let data = b"%PDF-1.4\ncontent\n%%EOF\nmore content\n%%EOF\n";
        let boundaries = scan_eof_markers(data);
        assert_eq!(boundaries.len(), 2);
        assert!(boundaries[0].length < boundaries[1].length);
        assert_eq!(boundaries[1].length, data.len());
    }

    #[test]
    fn test_scan_eof_with_crlf() {
        let data = b"%PDF-1.4\ncontent\n%%EOF\r\n";
        let boundaries = scan_eof_markers(data);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].length, data.len());
    }

    #[test]
    fn test_scan_eof_no_trailing_newline() {
        let data = b"%PDF-1.4\ncontent\n%%EOF";
        let boundaries = scan_eof_markers(data);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].length, data.len());
    }

    #[test]
    fn test_scan_no_eof() {
        let data = b"%PDF-1.4\ncontent without eof marker";
        let boundaries = scan_eof_markers(data);
        assert!(boundaries.is_empty());
    }

    // ── Object comparison tests ──────────────────────────────────────────

    #[test]
    fn test_objects_match_integers() {
        assert!(objects_match(&Object::Integer(42), &Object::Integer(42)));
        assert!(!objects_match(&Object::Integer(42), &Object::Integer(43)));
    }

    #[test]
    fn test_objects_match_reals() {
        assert!(objects_match(&Object::Real(3.14), &Object::Real(3.14)));
        assert!(objects_match(
            &Object::Real(3.14),
            &Object::Real(3.14005)
        )); // within epsilon
        assert!(!objects_match(&Object::Real(3.14), &Object::Real(3.15)));
    }

    #[test]
    fn test_objects_match_names() {
        assert!(objects_match(
            &Object::Name(b"Foo".to_vec()),
            &Object::Name(b"foo".to_vec())
        ));
        assert!(!objects_match(
            &Object::Name(b"Foo".to_vec()),
            &Object::Name(b"Bar".to_vec())
        ));
    }

    #[test]
    fn test_objects_match_references() {
        assert!(objects_match(
            &Object::Reference((1, 0)),
            &Object::Reference((1, 0))
        ));
        assert!(!objects_match(
            &Object::Reference((1, 0)),
            &Object::Reference((2, 0))
        ));
    }

    #[test]
    fn test_objects_match_arrays() {
        let a = Object::Array(vec![Object::Integer(1), Object::Integer(2)]);
        let b = Object::Array(vec![Object::Integer(1), Object::Integer(2)]);
        let c = Object::Array(vec![Object::Integer(1), Object::Integer(3)]);
        assert!(objects_match(&a, &b));
        assert!(!objects_match(&a, &c));
    }

    #[test]
    fn test_objects_match_dicts() {
        let mut da = lopdf::Dictionary::new();
        da.set("Key", Object::Integer(1));
        let mut db = lopdf::Dictionary::new();
        db.set("Key", Object::Integer(1));
        let mut dc = lopdf::Dictionary::new();
        dc.set("Key", Object::Integer(2));

        assert!(objects_match(
            &Object::Dictionary(da.clone()),
            &Object::Dictionary(db)
        ));
        assert!(!objects_match(
            &Object::Dictionary(da),
            &Object::Dictionary(dc)
        ));
    }

    #[test]
    fn test_objects_match_null_never_matches() {
        assert!(!objects_match(&Object::Null, &Object::Null));
    }

    #[test]
    fn test_objects_match_different_types() {
        assert!(!objects_match(&Object::Integer(1), &Object::Boolean(true)));
    }

    // ── Rect / annotation helper tests ───────────────────────────────────

    #[test]
    fn test_zero_area_rect() {
        let mut dict = lopdf::Dictionary::new();
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(0.0),
            ]),
        );
        assert!(is_zero_area_rect(&dict));
    }

    #[test]
    fn test_non_zero_area_rect() {
        let mut dict = lopdf::Dictionary::new();
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(100.0),
                Object::Real(50.0),
            ]),
        );
        assert!(!is_zero_area_rect(&dict));
    }

    #[test]
    fn test_border_width_from_border_array() {
        let mut dict = lopdf::Dictionary::new();
        dict.set(
            "Border",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Real(2.5),
            ]),
        );
        assert!((get_border_width(&dict) - 2.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_border_width_default() {
        let dict = lopdf::Dictionary::new();
        assert!((get_border_width(&dict) - 1.0).abs() < f32::EPSILON);
    }

    // ── Integration test with real PDF ───────────────────────────────────

    #[test]
    fn test_analyze_unsigned_pdf() {
        let pdf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
        let pdf_bytes = std::fs::read(pdf_path).expect("read sample.pdf");

        let analysis =
            RevisionAnalysis::analyze(&pdf_bytes, &DefaultSafeObjectClassifier)
                .expect("analyze should succeed");

        assert!(
            analysis.revision_count() >= 1,
            "should find at least one revision"
        );

        // The first (and only) revision of an unsigned PDF should be safe
        let first = &analysis.revisions()[0];
        assert!(first.safe_update, "first revision should be safe");
        assert!(!first.is_signature, "unsigned PDF should not have signature revision");
    }

    #[test]
    fn test_analyze_signed_pdf() {
        // Sign a PDF, then analyze it
        let pdf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
        let pdf_bytes = std::fs::read(pdf_path).expect("read sample.pdf");

        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12"),
            "test123",
        )
        .expect("load signer");

        let signed_pdf = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                crate::signer::PdfSigner::new()
                    .options(crate::signer::SigningOptions::default())
                    .sign(&pdf_bytes, &signer)
                    .await
            })
            .expect("sign PDF");

        let analysis =
            RevisionAnalysis::analyze(&signed_pdf, &DefaultSafeObjectClassifier)
                .expect("analyze should succeed");

        // Should have at least 2 revisions: original + signature
        assert!(
            analysis.revision_count() >= 2,
            "signed PDF should have at least 2 revisions, got {}",
            analysis.revision_count()
        );

        // There should be at least one signature revision
        let has_sig = analysis.revisions().iter().any(|r| r.is_signature);
        assert!(has_sig, "should find a signature revision");

        // The signature should cover the whole document
        // (since there are no modifications after signing)
        let sig_rev = analysis
            .revisions()
            .iter()
            .find(|r| r.is_signature)
            .expect("should find a signature revision");
        assert!(sig_rev.safe_update, "signature revision should be safe");

        // Find the matching byte range from the full doc
        let full_doc = Document::load_mem(&signed_pdf).expect("load signed");
        let sig_byte_ranges = extract_signature_byte_ranges(&full_doc);
        assert!(!sig_byte_ranges.is_empty(), "should have signature byte ranges");

        // We need the actual ByteRange to test covers_whole_document
        let sigs = crate::core::parser::extract_signatures(&full_doc)
            .expect("extract sigs");
        assert_eq!(sigs.len(), 1);
        let br = sigs[0].byte_range;
        assert!(
            analysis.covers_whole_document(&br),
            "signature should cover whole document"
        );
        assert!(
            !analysis.is_extended_by_non_safe_updates(&br),
            "no non-safe extensions expected"
        );
    }

    #[test]
    fn test_get_signed_document() {
        let pdf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
        let pdf_bytes = std::fs::read(pdf_path).expect("read sample.pdf");

        let signer = crate::crypto::software::SoftwareSigner::from_pkcs12_file(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signer.p12"),
            "test123",
        )
        .expect("load signer");

        let signed_pdf = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                crate::signer::PdfSigner::new()
                    .options(crate::signer::SigningOptions::default())
                    .sign(&pdf_bytes, &signer)
                    .await
            })
            .expect("sign PDF");

        let analysis =
            RevisionAnalysis::analyze(&signed_pdf, &DefaultSafeObjectClassifier)
                .expect("analyze");

        let full_doc = Document::load_mem(&signed_pdf).expect("load signed");
        let sigs = crate::core::parser::extract_signatures(&full_doc).expect("extract sigs");
        let br = sigs[0].byte_range;

        let signed_doc_bytes = analysis.get_signed_document(&br);
        assert!(signed_doc_bytes.is_some());
        let signed_doc_bytes = signed_doc_bytes.unwrap();
        assert!(
            signed_doc_bytes.len() <= signed_pdf.len(),
            "signed document should be <= full PDF"
        );
        assert!(
            signed_doc_bytes.starts_with(b"%PDF"),
            "should start with PDF header"
        );
    }

    #[test]
    fn test_find_signature_revision_not_found() {
        let pdf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
        let pdf_bytes = std::fs::read(pdf_path).expect("read sample.pdf");

        let analysis =
            RevisionAnalysis::analyze(&pdf_bytes, &DefaultSafeObjectClassifier)
                .expect("analyze");

        // Bogus byte range that doesn't match any revision
        let br = [0, 100, 200, 100];
        assert!(analysis.find_signature_revision(&br).is_none());
        assert!(!analysis.covers_whole_document(&br));
        assert!(!analysis.is_extended_by_non_safe_updates(&br));
        assert!(analysis.get_signed_document(&br).is_none());
    }

    #[test]
    fn test_strict_classifier_no_safe_objects() {
        let pdf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
        let pdf_bytes = std::fs::read(pdf_path).expect("read sample.pdf");

        let analysis =
            RevisionAnalysis::analyze(&pdf_bytes, &StrictSafeObjectClassifier)
                .expect("analyze");

        // Should still parse fine
        assert!(analysis.revision_count() >= 1);
    }

    #[test]
    fn test_objects_match_mixed_number_types() {
        // Integer vs Real comparison
        assert!(objects_match(
            &Object::Integer(42),
            &Object::Real(42.0)
        ));
        assert!(!objects_match(
            &Object::Integer(42),
            &Object::Real(43.0)
        ));
    }

    #[test]
    fn test_invisible_annotation_hidden_flag() {
        let doc = Document::with_version("1.4");
        let mut dict = lopdf::Dictionary::new();
        dict.set("Type", Object::Name(b"Annot".to_vec()));
        dict.set("Subtype", Object::Name(b"Text".to_vec()));
        dict.set("F", Object::Integer(2)); // Hidden flag (bit 2)
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(100.0),
                Object::Real(50.0),
            ]),
        );

        assert!(is_invisible_annotation(
            &doc,
            &Object::Dictionary(dict),
            false
        ));
    }

    #[test]
    fn test_invisible_annotation_popup() {
        let doc = Document::with_version("1.4");
        let mut dict = lopdf::Dictionary::new();
        dict.set("Subtype", Object::Name(b"Popup".to_vec()));
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(10.0),
                Object::Real(10.0),
                Object::Real(200.0),
                Object::Real(100.0),
            ]),
        );

        assert!(is_invisible_annotation(
            &doc,
            &Object::Dictionary(dict),
            false
        ));
    }

    #[test]
    fn test_invisible_annotation_widget_in_sig_revision() {
        let doc = Document::with_version("1.4");
        let mut dict = lopdf::Dictionary::new();
        dict.set("Type", Object::Name(b"Annot".to_vec()));
        dict.set("Subtype", Object::Name(b"Widget".to_vec()));
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(200.0),
                Object::Real(100.0),
            ]),
        );
        dict.set("F", Object::Integer(4)); // Print flag

        // Widget is invisible only in signature revisions
        assert!(is_invisible_annotation(
            &doc,
            &Object::Dictionary(dict.clone()),
            true
        ));
        assert!(!is_invisible_annotation(
            &doc,
            &Object::Dictionary(dict),
            false
        ));
    }

    #[test]
    fn test_visible_annotation() {
        let doc = Document::with_version("1.4");
        let mut dict = lopdf::Dictionary::new();
        dict.set("Type", Object::Name(b"Annot".to_vec()));
        dict.set("Subtype", Object::Name(b"Text".to_vec()));
        dict.set("F", Object::Integer(4)); // Print flag only
        dict.set(
            "Rect",
            Object::Array(vec![
                Object::Real(10.0),
                Object::Real(10.0),
                Object::Real(200.0),
                Object::Real(100.0),
            ]),
        );

        // Has a normal appearance
        let mut ap = lopdf::Dictionary::new();
        ap.set("N", Object::Integer(1)); // placeholder for appearance stream
        dict.set("AP", Object::Dictionary(ap));

        assert!(!is_invisible_annotation(
            &doc,
            &Object::Dictionary(dict),
            false
        ));
    }
}
