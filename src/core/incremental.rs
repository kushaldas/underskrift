//! Custom byte-level incremental PDF writer.
//!
//! PDF signing requires appending new objects to an existing PDF via an
//! incremental update, with **exact control** over byte offsets. This writer
//! handles serializing new/modified objects, building the cross-reference table,
//! and tracking offsets for ByteRange and /Contents placement.
//!
//! We do NOT use lopdf's `IncrementalDocument` for writing because it doesn't
//! expose the byte-offset hooks needed for signing.

use std::io::Write;

use lopdf::{Dictionary, Object, ObjectId};

use crate::core::byte_range::ByteRange;
use crate::error::CoreError;

/// Tracks a new object to be written in the incremental update.
#[derive(Debug)]
struct PendingObject {
    id: ObjectId,
    object: Object,
}

/// Byte-level incremental PDF writer for signing.
///
/// Appends new objects, xref table, and trailer to an existing PDF byte stream,
/// while tracking exact byte offsets for ByteRange/Contents backpatching.
pub struct IncrementalWriter {
    /// The original PDF bytes (read-only)
    original: Vec<u8>,
    /// Objects to append
    pending_objects: Vec<PendingObject>,
    /// The object ID of the signature dictionary (for offset tracking)
    sig_dict_id: Option<ObjectId>,
    /// Size reserved for hex-encoded /Contents (number of hex chars)
    contents_hex_size: usize,
    /// Previous trailer's /Size value
    prev_size: u32,
    /// Byte offset of the previous xref table (for /Prev in trailer)
    prev_xref_offset: usize,
    /// The root object ID (catalog)
    root_id: ObjectId,
}

impl IncrementalWriter {
    /// Create a new incremental writer.
    ///
    /// - `original`: the complete original PDF bytes
    /// - `prev_size`: the `/Size` from the original trailer (next object number)
    /// - `prev_xref_offset`: byte offset of the original xref table (for `/Prev`)
    /// - `root_id`: the `/Root` catalog object ID
    /// - `contents_hex_size`: how many hex characters to reserve for `/Contents`
    pub fn new(
        original: Vec<u8>,
        prev_size: u32,
        prev_xref_offset: usize,
        root_id: ObjectId,
        contents_hex_size: usize,
    ) -> Self {
        Self {
            original,
            pending_objects: Vec::new(),
            sig_dict_id: None,
            contents_hex_size,
            prev_size,
            prev_xref_offset,
            root_id,
        }
    }

    /// Add an object to be written in the incremental update.
    pub fn add_object(&mut self, id: ObjectId, object: Object) {
        self.pending_objects.push(PendingObject { id, object });
    }

    /// Mark which object ID is the signature dictionary.
    /// This is needed so the writer can track its /ByteRange and /Contents offsets.
    pub fn set_sig_dict_id(&mut self, id: ObjectId) {
        self.sig_dict_id = Some(id);
    }

    /// Write the incremental update and return the complete PDF bytes
    /// along with the ByteRange tracking info needed for backpatching.
    pub fn write(self) -> Result<(Vec<u8>, ByteRange), CoreError> {
        let mut buf = self.original.clone();

        // Ensure we start on a newline
        if buf.last() != Some(&b'\n') {
            buf.push(b'\n');
        }

        let mut xref_entries: Vec<(ObjectId, usize)> = Vec::new();
        let mut byte_range = None;

        // Write each pending object
        for pending in &self.pending_objects {
            let offset = buf.len();
            xref_entries.push((pending.id, offset));

            if Some(pending.id) == self.sig_dict_id {
                // Special handling for signature dictionary — we need to track
                // exact offsets of ByteRange and Contents placeholders
                byte_range = Some(self.write_sig_dict(&mut buf, pending.id, &pending.object)?);
            } else {
                self.write_object(&mut buf, pending.id, &pending.object)?;
            }
        }

        let byte_range = byte_range.ok_or(CoreError::InvalidStructure(
            "no signature dictionary found in pending objects".into(),
        ))?;

        // Write xref table
        let xref_offset = buf.len();
        self.write_xref(&mut buf, &xref_entries)?;

        // Write trailer
        self.write_trailer(&mut buf, xref_entries.len() as u32, xref_offset)?;

        // Backpatch ByteRange with final values
        let total_len = buf.len();
        byte_range.backpatch(&mut buf, total_len)?;

        Ok((buf, byte_range))
    }

    /// Write a non-signature object.
    fn write_object(
        &self,
        buf: &mut Vec<u8>,
        id: ObjectId,
        object: &Object,
    ) -> Result<(), CoreError> {
        writeln!(buf, "{} {} obj", id.0, id.1)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        self.serialize_object(buf, object)?;
        write!(buf, "\nendobj\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        Ok(())
    }

    /// Write the signature dictionary with tracked offsets for ByteRange and Contents.
    fn write_sig_dict(
        &self,
        buf: &mut Vec<u8>,
        id: ObjectId,
        object: &Object,
    ) -> Result<ByteRange, CoreError> {
        writeln!(buf, "{} {} obj", id.0, id.1)
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        // We need to write the dictionary manually to track offsets
        let dict = match object {
            Object::Dictionary(d) => d,
            _ => {
                return Err(CoreError::InvalidStructure(
                    "signature dictionary is not a Dictionary".into(),
                ))
            }
        };

        writeln!(buf, "<<")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        let mut byte_range_offset = 0;
        let mut byte_range_length = 0;
        let mut contents_offset = 0;

        for (key, value) in dict.iter() {
            let key_str = std::str::from_utf8(key).unwrap_or("?");
            write!(buf, "/{key_str} ")
                .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

            if key_str == "ByteRange" {
                // Write the fixed-width placeholder and track its offset
                let placeholder = ByteRange::placeholder_string();
                byte_range_offset = buf.len();
                byte_range_length = placeholder.len();
                write!(buf, "{placeholder}")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            } else if key_str == "Contents" {
                // Write the hex placeholder and track its offset
                write!(buf, "<")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
                contents_offset = buf.len();
                // Write `contents_hex_size` zero hex chars
                let hex_placeholder = "0".repeat(self.contents_hex_size);
                write!(buf, "{hex_placeholder}")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
                write!(buf, ">")
                    .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            } else {
                self.serialize_object(buf, value)?;
            }
            writeln!(buf).map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        }

        write!(buf, ">>\nendobj\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        Ok(ByteRange {
            placeholder_offset: byte_range_offset,
            placeholder_length: byte_range_length,
            contents_offset,
            contents_length: self.contents_hex_size,
        })
    }

    /// Serialize a lopdf Object to bytes.
    fn serialize_object(&self, buf: &mut Vec<u8>, object: &Object) -> Result<(), CoreError> {
        match object {
            Object::Null => write!(buf, "null"),
            Object::Boolean(b) => write!(buf, "{}", if *b { "true" } else { "false" }),
            Object::Integer(i) => write!(buf, "{i}"),
            Object::Real(f) => write!(buf, "{f}"),
            Object::Name(n) => {
                write!(buf, "/")?;
                buf.extend_from_slice(n);
                Ok(())
            }
            Object::String(s, format) => match format {
                lopdf::StringFormat::Literal => {
                    write!(buf, "(")?;
                    buf.extend_from_slice(s);
                    write!(buf, ")")
                }
                lopdf::StringFormat::Hexadecimal => {
                    write!(buf, "<")?;
                    for byte in s {
                        write!(buf, "{byte:02X}")?;
                    }
                    write!(buf, ">")
                }
            },
            Object::Array(arr) => {
                write!(buf, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(buf, " ")?;
                    }
                    self.serialize_object(buf, item)?;
                }
                write!(buf, "]")
            }
            Object::Dictionary(dict) => {
                write!(buf, "<<")?;
                for (key, value) in dict.iter() {
                    write!(buf, "/")?;
                    buf.extend_from_slice(key);
                    write!(buf, " ")?;
                    self.serialize_object(buf, value)?;
                }
                write!(buf, ">>")
            }
            Object::Reference(id) => write!(buf, "{} {} R", id.0, id.1),
            Object::Stream(stream) => {
                self.serialize_object(buf, &Object::Dictionary(stream.dict.clone()))?;
                write!(buf, "\nstream\n")?;
                buf.extend_from_slice(&stream.content);
                write!(buf, "\nendstream")
            }
        }
        .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))
    }

    /// Write the cross-reference table for the new objects.
    fn write_xref(
        &self,
        buf: &mut Vec<u8>,
        entries: &[(ObjectId, usize)],
    ) -> Result<(), CoreError> {
        writeln!(buf, "xref")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        // Sort entries by object number for the xref table
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by_key(|(id, _)| id.0);

        // Write each entry individually (simple approach: one subsection per entry)
        // A more sophisticated approach would group consecutive object numbers.
        for (id, offset) in &sorted {
            writeln!(buf, "{} 1", id.0)
                .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
            writeln!(buf, "{:010} {:05} n ", offset, id.1)
                .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        }

        Ok(())
    }

    /// Write the trailer dictionary.
    fn write_trailer(
        &self,
        buf: &mut Vec<u8>,
        new_count: u32,
        xref_offset: usize,
    ) -> Result<(), CoreError> {
        let size = self.prev_size + new_count;

        let mut trailer = Dictionary::new();
        trailer.set("Size", Object::Integer(size as i64));
        trailer.set("Root", Object::Reference(self.root_id));
        trailer.set("Prev", Object::Integer(self.prev_xref_offset as i64));

        writeln!(buf, "trailer")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;
        self.serialize_object(buf, &Object::Dictionary(trailer))?;
        write!(buf, "\nstartxref\n{xref_offset}\n%%EOF\n")
            .map_err(|e| CoreError::InvalidStructure(format!("write error: {e}")))?;

        Ok(())
    }
}
