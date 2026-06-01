//! PDF signature structures and byte-level manipulation.
//!
//! This module handles low-level PDF structure manipulation on top of `lopdf`.
//! Uses lopdf for parsing and object model only; provides a custom byte-level
//! incremental writer for exact ByteRange control.

pub mod acroform;
pub mod byte_range;
pub mod doc_mdp;
pub mod doc_timestamp;
pub mod incremental;
pub mod parser;
pub mod revision;
pub mod sig_dict;
pub mod sig_field;
