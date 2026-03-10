//! PDF object enumeration and serialization.
//!
//! Iterates all indirect objects in a PDF, classifies them by type,
//! and serializes their data to `serde_json::Value` for consumption
//! by Python or other consumers.

use lopdf::{Document, Object};
use serde_json::{json, Value};

use crate::error::InspectError;

/// The kind of a PDF object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectKind {
    Dictionary,
    Stream,
    Array,
    Name,
    String,
    Integer,
    Real,
    Boolean,
    Null,
    Reference,
}

impl ObjectKind {
    /// Return the kind as a string label.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Dictionary => "Dictionary",
            ObjectKind::Stream => "Stream",
            ObjectKind::Array => "Array",
            ObjectKind::Name => "Name",
            ObjectKind::String => "String",
            ObjectKind::Integer => "Integer",
            ObjectKind::Real => "Real",
            ObjectKind::Boolean => "Boolean",
            ObjectKind::Null => "Null",
            ObjectKind::Reference => "Reference",
        }
    }
}

/// Information about a single PDF indirect object.
#[derive(Debug, Clone)]
pub struct PdfObjectInfo {
    /// Object number.
    pub obj_num: u32,
    /// Generation number.
    pub gen_num: u16,
    /// The kind of object.
    pub kind: ObjectKind,
    /// The /Type entry value (e.g. "/Page"), if present.
    pub type_name: Option<String>,
    /// The /Subtype entry value, if present.
    pub subtype_name: Option<String>,
    /// Dictionary or stream dictionary keys (e.g. ["/Type", "/MediaBox"]).
    pub keys: Vec<String>,
    /// For streams, the /Length value (raw, pre-decompression).
    pub stream_length: Option<usize>,
    /// Recursively serialized JSON data.
    pub data: Value,
}

/// Result of inspecting a PDF's full object tree.
#[derive(Debug, Clone)]
pub struct PdfInspection {
    /// PDF version string (e.g. "1.7").
    pub pdf_version: String,
    /// Number of pages.
    pub num_pages: usize,
    /// Total number of indirect objects.
    pub num_objects: usize,
    /// All indirect objects with their metadata and serialized data.
    pub objects: Vec<PdfObjectInfo>,
    /// The document catalog serialized to JSON.
    pub catalog: Value,
}

/// Inspect all objects in a PDF.
///
/// Parses the PDF from raw bytes, enumerates every indirect object,
/// classifies it, and serializes its contents to JSON-compatible values.
pub fn inspect_pdf(pdf_data: &[u8]) -> Result<PdfInspection, InspectError> {
    let doc = Document::load_mem(pdf_data).map_err(|e| InspectError::PdfParse(format!("{e}")))?;

    let mut objects = Vec::new();

    // Iterate all indirect objects in the document
    for (&(obj_num, gen_num), object) in &doc.objects {
        let info = classify_object(&doc, obj_num, gen_num, object);
        objects.push(info);
    }

    // Sort by object number for stable ordering
    objects.sort_by_key(|o| (o.obj_num, o.gen_num));

    // PDF version
    let pdf_version = doc.version.clone();

    // Page count via the Pages tree
    let num_pages = count_pages(&doc);

    // Catalog
    let catalog = match doc.catalog() {
        Ok(cat) => serialize_dict(&doc, cat, 0, 50),
        Err(_) => Value::Null,
    };

    Ok(PdfInspection {
        pdf_version,
        num_pages,
        num_objects: objects.len(),
        objects,
        catalog,
    })
}

/// Count pages by walking the /Pages tree.
fn count_pages(doc: &Document) -> usize {
    let catalog = match doc.catalog() {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let pages_ref = match catalog.get(b"Pages") {
        Ok(Object::Reference(id)) => *id,
        _ => return 0,
    };

    let pages_dict = match doc.get_object(pages_ref).and_then(Object::as_dict) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    match pages_dict.get(b"Count") {
        Ok(Object::Integer(n)) => *n as usize,
        _ => 0,
    }
}

/// Classify and serialize one indirect object.
fn classify_object(doc: &Document, obj_num: u32, gen_num: u16, object: &Object) -> PdfObjectInfo {
    match object {
        Object::Dictionary(dict) => {
            let type_name = dict
                .get(b"Type")
                .and_then(Object::as_name)
                .ok()
                .map(|n| format!("/{}", std::str::from_utf8(n).unwrap_or("?")));
            let subtype_name = dict
                .get(b"Subtype")
                .and_then(Object::as_name)
                .ok()
                .map(|n| format!("/{}", std::str::from_utf8(n).unwrap_or("?")));
            let keys = dict
                .iter()
                .map(|(k, _)| format!("/{}", std::str::from_utf8(k).unwrap_or("?")))
                .collect();
            let data = serialize_dict(doc, dict, 0, 50);

            PdfObjectInfo {
                obj_num,
                gen_num,
                kind: ObjectKind::Dictionary,
                type_name,
                subtype_name,
                keys,
                stream_length: None,
                data,
            }
        }
        Object::Stream(stream) => {
            let dict = &stream.dict;
            let type_name = dict
                .get(b"Type")
                .and_then(Object::as_name)
                .ok()
                .map(|n| format!("/{}", std::str::from_utf8(n).unwrap_or("?")));
            let subtype_name = dict
                .get(b"Subtype")
                .and_then(Object::as_name)
                .ok()
                .map(|n| format!("/{}", std::str::from_utf8(n).unwrap_or("?")));
            let keys: Vec<String> = dict
                .iter()
                .map(|(k, _)| format!("/{}", std::str::from_utf8(k).unwrap_or("?")))
                .collect();

            // Get the stream length from /Length key (raw, not decompressed)
            let stream_length = dict
                .get(b"Length")
                .and_then(Object::as_i64)
                .ok()
                .map(|n| n as usize);

            let mut data = serialize_dict(doc, dict, 0, 50);
            // Mark as stream
            if let Value::Object(ref mut map) = data {
                map.insert("__stream__".to_string(), Value::Bool(true));
                map.insert(
                    "__stream_length__".to_string(),
                    stream_length.map_or(Value::Null, |n| Value::Number(n.into())),
                );
            }

            PdfObjectInfo {
                obj_num,
                gen_num,
                kind: ObjectKind::Stream,
                type_name,
                subtype_name,
                keys,
                stream_length,
                data,
            }
        }
        Object::Array(arr) => {
            let data = serialize_array(doc, arr, 0, 50);
            PdfObjectInfo {
                obj_num,
                gen_num,
                kind: ObjectKind::Array,
                type_name: None,
                subtype_name: None,
                keys: vec![],
                stream_length: None,
                data,
            }
        }
        _ => {
            let (kind, data) = serialize_primitive(object);
            PdfObjectInfo {
                obj_num,
                gen_num,
                kind,
                type_name: None,
                subtype_name: None,
                keys: vec![],
                stream_length: None,
                data,
            }
        }
    }
}

/// Serialize a lopdf Dictionary to a serde_json Value.
fn serialize_dict(
    doc: &Document,
    dict: &lopdf::Dictionary,
    depth: usize,
    max_items: usize,
) -> Value {
    if depth > 6 {
        return Value::String("<nested too deep>".to_string());
    }

    let mut map = serde_json::Map::new();
    for (i, (key, val)) in dict.iter().enumerate() {
        if i >= max_items {
            map.insert(
                "__truncated__".to_string(),
                Value::String(format!("{} more keys", dict.len() - max_items)),
            );
            break;
        }
        let key_str = format!("/{}", std::str::from_utf8(key).unwrap_or("?"));
        map.insert(key_str, serialize_value(doc, val, depth + 1, max_items));
    }
    Value::Object(map)
}

/// Serialize a lopdf Array to a serde_json Value.
fn serialize_array(doc: &Document, arr: &[Object], depth: usize, max_items: usize) -> Value {
    if depth > 6 {
        return Value::String("<nested too deep>".to_string());
    }

    let mut items = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        if i >= max_items {
            items.push(Value::String(format!(
                "<{} more items>",
                arr.len() - max_items
            )));
            break;
        }
        items.push(serialize_value(doc, item, depth + 1, max_items));
    }
    Value::Array(items)
}

/// Serialize any lopdf Object to a serde_json Value.
fn serialize_value(doc: &Document, val: &Object, depth: usize, max_items: usize) -> Value {
    if depth > 6 {
        return Value::String("<nested too deep>".to_string());
    }

    match val {
        Object::Reference(id) => {
            // Show as "N M R" string (matching pikepdf behavior)
            Value::String(format!("{} {} R", id.0, id.1))
        }
        Object::Dictionary(dict) => serialize_dict(doc, dict, depth, max_items),
        Object::Stream(stream) => {
            let mut data = serialize_dict(doc, &stream.dict, depth, max_items);
            if let Value::Object(ref mut map) = data {
                map.insert("__stream__".to_string(), Value::Bool(true));
                let len = stream
                    .dict
                    .get(b"Length")
                    .and_then(Object::as_i64)
                    .ok()
                    .map(|n| n as usize);
                map.insert(
                    "__stream_length__".to_string(),
                    len.map_or(Value::Null, |n| Value::Number(n.into())),
                );
            }
            data
        }
        Object::Array(arr) => serialize_array(doc, arr, depth, max_items),
        Object::Name(name) => {
            Value::String(format!("/{}", std::str::from_utf8(name).unwrap_or("?")))
        }
        Object::String(bytes, _) => {
            // Try UTF-8 first, fall back to latin-1
            match std::str::from_utf8(bytes) {
                Ok(s) => Value::String(s.to_string()),
                Err(_) => {
                    let s: String = bytes.iter().map(|&b| b as char).collect();
                    Value::String(s)
                }
            }
        }
        Object::Integer(n) => json!(*n),
        Object::Real(n) => json!(*n),
        Object::Boolean(b) => json!(*b),
        Object::Null => Value::Null,
    }
}

/// Serialize a primitive (non-container) object and return its kind.
fn serialize_primitive(object: &Object) -> (ObjectKind, Value) {
    match object {
        Object::Name(name) => (
            ObjectKind::Name,
            Value::String(format!("/{}", std::str::from_utf8(name).unwrap_or("?"))),
        ),
        Object::String(bytes, _) => {
            let s = match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => bytes.iter().map(|&b| b as char).collect(),
            };
            (ObjectKind::String, Value::String(s))
        }
        Object::Integer(n) => (ObjectKind::Integer, json!(*n)),
        Object::Real(n) => (ObjectKind::Real, json!(*n)),
        Object::Boolean(b) => (ObjectKind::Boolean, json!(*b)),
        Object::Null => (ObjectKind::Null, Value::Null),
        Object::Reference(id) => (
            ObjectKind::Reference,
            Value::String(format!("{} {} R", id.0, id.1)),
        ),
        // These should not appear as top-level indirect objects but handle them
        Object::Dictionary(_) => (ObjectKind::Dictionary, Value::Null),
        Object::Stream(_) => (ObjectKind::Stream, Value::Null),
        Object::Array(_) => (ObjectKind::Array, Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_sample_pdf() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = inspect_pdf(&pdf_data).expect("inspection failed");
        assert!(!result.pdf_version.is_empty());
        assert!(result.num_pages > 0);
        assert!(result.num_objects > 0);
        assert!(!result.objects.is_empty());

        // Check that catalog is a non-null JSON object
        assert!(result.catalog.is_object());
    }

    #[test]
    fn test_object_kinds_present() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = inspect_pdf(&pdf_data).expect("inspection failed");

        // A typical PDF should have at least dictionaries
        let has_dict = result
            .objects
            .iter()
            .any(|o| o.kind == ObjectKind::Dictionary);
        assert!(has_dict, "should have at least one Dictionary object");
    }

    #[test]
    fn test_object_info_fields() {
        let pdf_data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.pdf"
        ))
        .expect("failed to read sample PDF");

        let result = inspect_pdf(&pdf_data).expect("inspection failed");

        // Every object should have valid obj_num > 0
        for obj in &result.objects {
            assert!(obj.obj_num > 0, "obj_num should be > 0");
        }

        // Look for a /Page type object
        let has_page = result
            .objects
            .iter()
            .any(|o| o.type_name.as_deref() == Some("/Page"));
        assert!(has_page, "should have at least one /Page object");
    }

    #[test]
    fn test_depth_limit() {
        // Verify the depth limit by serializing deeply nested data
        let dict = lopdf::Dictionary::new();
        let doc = Document::new();
        // At depth 7, it should return the truncation string
        let val = serialize_dict(&doc, &dict, 7, 50);
        assert_eq!(val, Value::String("<nested too deep>".to_string()));
    }

    #[test]
    fn test_invalid_pdf() {
        let result = inspect_pdf(b"not a pdf");
        assert!(result.is_err());
    }
}
