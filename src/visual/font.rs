//! Standard fonts and TrueType/OpenType font subsetting.
//!
//! This module provides font metrics for the PDF standard 14 fonts,
//! which are guaranteed to be available in all PDF viewers without embedding.
//!
//! When the `visual` feature is enabled, it also supports embedded TrueType/OpenType
//! fonts via parsing with `ttf-parser` and subsetting with the `subsetter` crate.
//! Embedded fonts are written as CIDFont/Type0 fonts in PDF.
//!
//! The metrics are needed to compute text widths for proper layout and
//! alignment within signature appearance streams.

use super::layout::Standard14Font;

#[cfg(feature = "visual")]
use crate::error::VisualError;

/// Character width for a given font at a given size.
///
/// The widths are stored as integers in units of 1/1000 of the font's
/// unit size (standard PDF font metric convention). To get the actual
/// width in points: `width_units * font_size / 1000.0`
pub struct FontMetrics;

impl FontMetrics {
    /// Get the width of a character in the given font, in 1/1000 units.
    ///
    /// For characters outside WinAnsiEncoding (> 0xFF), returns the
    /// width of the replacement character (space).
    pub fn char_width(font: Standard14Font, ch: char) -> u16 {
        let code = ch as u32;
        if code > 255 {
            // Non-Latin character — return space width as fallback
            return Self::char_width(font, ' ');
        }
        let idx = code as usize;

        match font {
            Standard14Font::Helvetica => HELVETICA_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::HelveticaBold => HELVETICA_BOLD_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::HelveticaOblique => HELVETICA_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::HelveticaBoldOblique => {
                HELVETICA_BOLD_WIDTHS.get(idx).copied().unwrap_or(0)
            }
            Standard14Font::TimesRoman => TIMES_ROMAN_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::TimesBold => TIMES_BOLD_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::TimesItalic => TIMES_ROMAN_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::TimesBoldItalic => TIMES_BOLD_WIDTHS.get(idx).copied().unwrap_or(0),
            Standard14Font::Courier
            | Standard14Font::CourierBold
            | Standard14Font::CourierOblique
            | Standard14Font::CourierBoldOblique => 600, // Courier is monospaced
            Standard14Font::Symbol | Standard14Font::ZapfDingbats => 500, // rough average
        }
    }

    /// Compute the width of a string in the given font at the given size (in points).
    pub fn string_width(font: Standard14Font, text: &str, font_size: f32) -> f32 {
        let total_units: u32 = text
            .chars()
            .map(|ch| Self::char_width(font, ch) as u32)
            .sum();
        total_units as f32 * font_size / 1000.0
    }

    /// Get the font's ascent in 1/1000 units.
    ///
    /// The ascent is the distance from the baseline to the top of the tallest
    /// character (excluding accents for some fonts).
    pub fn ascent(font: Standard14Font) -> i16 {
        match font {
            Standard14Font::Helvetica | Standard14Font::HelveticaOblique => 718,
            Standard14Font::HelveticaBold | Standard14Font::HelveticaBoldOblique => 718,
            Standard14Font::TimesRoman | Standard14Font::TimesItalic => 683,
            Standard14Font::TimesBold | Standard14Font::TimesBoldItalic => 683,
            Standard14Font::Courier
            | Standard14Font::CourierBold
            | Standard14Font::CourierOblique
            | Standard14Font::CourierBoldOblique => 629,
            Standard14Font::Symbol => 0,
            Standard14Font::ZapfDingbats => 0,
        }
    }

    /// Get the font's descent in 1/1000 units (typically negative).
    pub fn descent(font: Standard14Font) -> i16 {
        match font {
            Standard14Font::Helvetica | Standard14Font::HelveticaOblique => -207,
            Standard14Font::HelveticaBold | Standard14Font::HelveticaBoldOblique => -207,
            Standard14Font::TimesRoman | Standard14Font::TimesItalic => -217,
            Standard14Font::TimesBold | Standard14Font::TimesBoldItalic => -217,
            Standard14Font::Courier
            | Standard14Font::CourierBold
            | Standard14Font::CourierOblique
            | Standard14Font::CourierBoldOblique => -157,
            Standard14Font::Symbol => 0,
            Standard14Font::ZapfDingbats => 0,
        }
    }
}

// ── Embedded Font Support (behind `visual` feature) ─────────────────

/// Parsed information about an embedded TrueType/OpenType font.
///
/// Contains the font metrics and character-to-glyph mapping needed for
/// text layout and PDF font dictionary construction.
#[cfg(feature = "visual")]
#[derive(Debug, Clone)]
pub struct EmbeddedFontInfo {
    /// Font name (PostScript-style, no spaces).
    pub name: String,
    /// Units per em from the head table (typically 1000 or 2048).
    pub units_per_em: u16,
    /// Ascent in font design units.
    pub ascent: i16,
    /// Descent in font design units (negative).
    pub descent: i16,
    /// Italic angle (0.0 for non-italic).
    pub italic_angle: f32,
    /// Font bounding box [xMin, yMin, xMax, yMax] in font design units.
    pub bbox: [i16; 4],
    /// CapHeight in font design units (height of capital letters).
    pub cap_height: i16,
    /// StemV (vertical stem width) — estimated from font weight or hardcoded.
    pub stem_v: i16,
    /// Flags for the font descriptor (see PDF spec Table 123).
    /// Bit 6 (0x20) = Nonsymbolic, Bit 3 (0x04) = Symbolic, etc.
    pub flags: u32,
}

/// Result of preparing an embedded font for a specific set of characters.
///
/// Contains the subsetted font data, glyph mapping, and width information
/// needed to create the CIDFont/Type0 PDF objects.
#[cfg(feature = "visual")]
#[derive(Debug)]
pub struct PreparedEmbeddedFont {
    /// Subsetted font file data (TrueType).
    pub subset_data: Vec<u8>,
    /// Font metadata.
    pub info: EmbeddedFontInfo,
    /// Mapping from Unicode code point to (original GID, remapped CID).
    /// Sorted by Unicode code point.
    pub char_to_cid: Vec<(char, u16)>,
    /// Width array entries: (CID, width_in_1000ths) for the /W array.
    /// Widths are scaled to 1/1000 units (PDF convention).
    pub cid_widths: Vec<(u16, u16)>,
    /// Default width in 1/1000 units (for the /DW entry).
    pub default_width: u16,
}

/// Parse an embedded font and extract its metrics.
///
/// This uses `ttf-parser` to read the font tables and extract the information
/// needed for text layout and PDF font dictionary construction.
#[cfg(feature = "visual")]
pub fn parse_embedded_font(data: &[u8], name: &str) -> Result<EmbeddedFontInfo, VisualError> {
    let face = ttf_parser::Face::parse(data, 0)
        .map_err(|e| VisualError::FontParsing(format!("failed to parse font '{}': {}", name, e)))?;

    let units_per_em = face.units_per_em();
    let ascent = face.ascender();
    let descent = face.descender();
    let italic_angle = face.italic_angle();
    let bbox = face.global_bounding_box();
    let cap_height = face.capital_height().unwrap_or(ascent);

    // Estimate StemV from font weight (rough heuristic used by many PDF tools)
    let stem_v = if face.is_bold() { 120 } else { 80 };

    // Font descriptor flags:
    // Bit 1 (0x01) = FixedPitch
    // Bit 3 (0x04) = Symbolic
    // Bit 4 (0x08) = Script
    // Bit 6 (0x20) = Nonsymbolic
    // Bit 7 (0x40) = Italic
    let mut flags: u32 = 0x20; // Nonsymbolic (Latin text font)
    if face.is_monospaced() {
        flags |= 0x01;
    }
    if italic_angle != 0.0 {
        flags |= 0x40;
    }

    Ok(EmbeddedFontInfo {
        name: name.to_string(),
        units_per_em,
        ascent,
        descent,
        italic_angle,
        bbox: [bbox.x_min, bbox.y_min, bbox.x_max, bbox.y_max],
        cap_height,
        stem_v,
        flags,
    })
}

/// Get the glyph ID for a character in an embedded font.
///
/// Returns `None` if the character is not present in the font's cmap.
#[cfg(feature = "visual")]
pub fn char_to_glyph_id(data: &[u8], ch: char) -> Result<Option<u16>, VisualError> {
    let face = ttf_parser::Face::parse(data, 0)
        .map_err(|e| VisualError::FontParsing(format!("failed to parse font: {}", e)))?;
    Ok(face.glyph_index(ch).map(|gid| gid.0))
}

/// Compute the width of a glyph in an embedded font, in font design units.
///
/// Returns `None` if the glyph doesn't have advance width information.
#[cfg(feature = "visual")]
pub fn glyph_advance_width(data: &[u8], glyph_id: u16) -> Result<Option<u16>, VisualError> {
    let face = ttf_parser::Face::parse(data, 0)
        .map_err(|e| VisualError::FontParsing(format!("failed to parse font: {}", e)))?;
    Ok(face.glyph_hor_advance(ttf_parser::GlyphId(glyph_id)))
}

/// Compute the width of a string in an embedded font at the given size (in points).
///
/// Characters not found in the font use the space width as fallback.
#[cfg(feature = "visual")]
pub fn embedded_string_width(data: &[u8], text: &str, font_size: f32) -> Result<f32, VisualError> {
    let face = ttf_parser::Face::parse(data, 0)
        .map_err(|e| VisualError::FontParsing(format!("failed to parse font: {}", e)))?;

    let upem = face.units_per_em() as f32;
    if upem == 0.0 {
        return Err(VisualError::FontParsing(
            "font has zero units_per_em".into(),
        ));
    }

    let space_gid = face.glyph_index(' ');
    let space_width = space_gid
        .and_then(|gid| face.glyph_hor_advance(gid))
        .unwrap_or(0);

    let total: u32 = text
        .chars()
        .map(|ch| {
            let w = face
                .glyph_index(ch)
                .and_then(|gid| face.glyph_hor_advance(gid))
                .unwrap_or(space_width);
            w as u32
        })
        .sum();

    // Convert from design units to points:
    // width_points = total_design_units * font_size / units_per_em
    Ok(total as f32 * font_size / upem)
}

/// Get the ascent of an embedded font in 1/1000 units (PDF convention).
#[cfg(feature = "visual")]
pub fn embedded_ascent_1000(info: &EmbeddedFontInfo) -> i16 {
    if info.units_per_em == 0 {
        return 0;
    }
    (info.ascent as i32 * 1000 / info.units_per_em as i32) as i16
}

/// Get the descent of an embedded font in 1/1000 units (PDF convention).
#[cfg(feature = "visual")]
pub fn embedded_descent_1000(info: &EmbeddedFontInfo) -> i16 {
    if info.units_per_em == 0 {
        return 0;
    }
    (info.descent as i32 * 1000 / info.units_per_em as i32) as i16
}

/// Prepare an embedded font for a specific set of characters.
///
/// This function:
/// 1. Parses the font to get char→glyph mappings
/// 2. Subsets the font to include only the needed glyphs
/// 3. Computes width information for the PDF /W array
/// 4. Returns everything needed to build the CIDFont/Type0 PDF objects
///
/// Characters not found in the font will use the `.notdef` glyph (GID 0).
#[cfg(feature = "visual")]
pub fn prepare_embedded_font(
    data: &[u8],
    name: &str,
    text: &str,
) -> Result<PreparedEmbeddedFont, VisualError> {
    use subsetter::GlyphRemapper;

    let face = ttf_parser::Face::parse(data, 0)
        .map_err(|e| VisualError::FontParsing(format!("failed to parse font '{}': {}", name, e)))?;

    let upem = face.units_per_em();
    if upem == 0 {
        return Err(VisualError::FontParsing(
            "font has zero units_per_em".into(),
        ));
    }

    // Collect unique characters and their glyph IDs
    let mut seen_chars = std::collections::BTreeSet::new();
    for ch in text.chars() {
        seen_chars.insert(ch);
    }

    // Map characters to glyph IDs, build the remapper
    let mut remapper = GlyphRemapper::new(); // already includes .notdef (GID 0)
    let mut char_gid_pairs: Vec<(char, u16)> = Vec::new();

    for ch in &seen_chars {
        let gid = face.glyph_index(*ch).map(|g| g.0).unwrap_or(0);
        remapper.remap(gid);
        char_gid_pairs.push((*ch, gid));
    }

    // Subset the font
    let subset_data = subsetter::subset(data, 0, &remapper).map_err(|e| {
        VisualError::FontSubsetting(format!("subsetting failed for '{}': {}", name, e))
    })?;

    // Build char→CID mapping (CID = remapped GID)
    let mut char_to_cid: Vec<(char, u16)> = Vec::new();
    for (ch, old_gid) in &char_gid_pairs {
        let cid = remapper.get(*old_gid).unwrap_or(0);
        char_to_cid.push((*ch, cid));
    }

    // Compute widths in PDF 1/1000 units
    let mut cid_widths: Vec<(u16, u16)> = Vec::new();
    let mut width_sum: u64 = 0;
    let mut width_count: u32 = 0;

    // Process all remapped GIDs (old GID → new CID)
    for old_gid in remapper.remapped_gids() {
        let new_cid = remapper.get(old_gid).unwrap_or(0);
        let advance = face
            .glyph_hor_advance(ttf_parser::GlyphId(old_gid))
            .unwrap_or(0);
        // Scale to 1/1000 units
        let width_1000 = (advance as u32 * 1000 / upem as u32) as u16;
        cid_widths.push((new_cid, width_1000));
        width_sum += width_1000 as u64;
        width_count += 1;
    }

    // Default width = average (or 1000 if no glyphs)
    let default_width = if width_count > 0 {
        (width_sum / width_count as u64) as u16
    } else {
        1000
    };

    let info = parse_embedded_font(data, name)?;

    Ok(PreparedEmbeddedFont {
        subset_data,
        info,
        char_to_cid,
        cid_widths,
        default_width,
    })
}

/// Encode text as a hex-encoded CID string for use with embedded fonts.
///
/// In CIDFont text rendering, each character is represented as a 2-byte
/// CID value, hex-encoded in angle brackets: `<004F0072006E>`
///
/// Characters not found in the char_to_cid mapping use CID 0 (.notdef).
#[cfg(feature = "visual")]
pub fn encode_cid_text(text: &str, char_to_cid: &[(char, u16)]) -> String {
    let mut result = String::with_capacity(text.len() * 5 + 2);
    result.push('<');
    for ch in text.chars() {
        let cid = char_to_cid
            .iter()
            .find(|(c, _)| *c == ch)
            .map(|(_, cid)| *cid)
            .unwrap_or(0);
        result.push_str(&format!("{:04X}", cid));
    }
    result.push('>');
    result
}

/// Build the PDF /W (width) array for a CIDFont.
///
/// The /W array defines individual glyph widths. Format:
/// `[ cid1 [w1] cid2 [w2] ... ]`
///
/// For simplicity, we use the individual CID format rather than ranges.
/// Returns the array as a string suitable for a PDF dictionary entry.
#[cfg(feature = "visual")]
pub fn build_w_array(cid_widths: &[(u16, u16)], default_width: u16) -> String {
    let mut parts = Vec::new();
    for (cid, width) in cid_widths {
        // Only include widths that differ from the default
        if *width != default_width {
            parts.push(format!("{} [{}]", cid, width));
        }
    }
    if parts.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", parts.join(" "))
    }
}

/// Build a /ToUnicode CMap stream for an embedded font.
///
/// The CMap maps CID values back to Unicode code points, enabling text
/// extraction and copy/paste from the PDF. This is required by the PDF/A
/// spec and strongly recommended otherwise.
///
/// Returns the CMap program as bytes.
#[cfg(feature = "visual")]
pub fn build_tounicode_cmap(font_name: &str, char_to_cid: &[(char, u16)]) -> Vec<u8> {
    let mut cmap = String::with_capacity(1024);

    cmap.push_str("/CIDInit /ProcSet findresource begin\n");
    cmap.push_str("12 dict begin\n");
    cmap.push_str("begincmap\n");
    cmap.push_str("/CIDSystemInfo\n");
    cmap.push_str("<< /Registry (Adobe)\n");
    cmap.push_str("/Ordering (UCS)\n");
    cmap.push_str("/Supplement 0\n");
    cmap.push_str(">> def\n");
    cmap.push_str(&format!(
        "/CMapName /Adobe-Identity-{} def\n",
        font_name.replace('-', "_")
    ));
    cmap.push_str("/CMapType 2 def\n");

    // Code space range: 2 bytes (0x0000 - 0xFFFF)
    cmap.push_str("1 begincodespacerange\n");
    cmap.push_str("<0000> <FFFF>\n");
    cmap.push_str("endcodespacerange\n");

    // Write char mappings in chunks of 100 (PDF limit per beginbfchar)
    let mappings: Vec<_> = char_to_cid
        .iter()
        .filter(|(_, cid)| *cid > 0) // skip .notdef
        .collect();

    for chunk in mappings.chunks(100) {
        cmap.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (ch, cid) in chunk {
            let unicode = *ch as u32;
            cmap.push_str(&format!("<{:04X}> <{:04X}>\n", cid, unicode));
        }
        cmap.push_str("endbfchar\n");
    }

    cmap.push_str("endcmap\n");
    cmap.push_str("CMapName currentdict /CMap defineresource pop\n");
    cmap.push_str("end\n");
    cmap.push_str("end\n");

    cmap.into_bytes()
}

// ── Standard 14 font support ────────────────────────────────────────

/// Encode a string for use in a PDF text string (Tj operator).
///
/// This handles basic escaping for the PDF literal string format: `(text)`
/// Characters that need escaping: `(`, `)`, `\`
/// Non-Latin characters outside WinAnsiEncoding are replaced with `?`.
pub fn encode_pdf_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len() + 2);
    result.push('(');
    for ch in text.chars() {
        let code = ch as u32;
        if code > 255 {
            result.push('?'); // replacement for non-Latin
        } else {
            match ch {
                '(' => result.push_str("\\("),
                ')' => result.push_str("\\)"),
                '\\' => result.push_str("\\\\"),
                _ => result.push(ch),
            }
        }
    }
    result.push(')');
    result
}

// Helvetica character widths (WinAnsiEncoding, indices 0-255).
// Source: Adobe Font Metrics (AFM) files.
// Only commonly used characters (32-126) are fully populated;
// others use 0 or approximate values.
#[rustfmt::skip]
static HELVETICA_WIDTHS: [u16; 256] = [
    // 0-31: control characters (width 0)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 32-47: space ! " # $ % & ' ( ) * + , - . /
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    // 48-63: 0 1 2 3 4 5 6 7 8 9 : ; < = > ?
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    // 64-79: @ A B C D E F G H I J K L M N O
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    // 80-95: P Q R S T U V W X Y Z [ \ ] ^ _
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    // 96-111: ` a b c d e f g h i j k l m n o
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    // 112-127: p q r s t u v w x y z { | } ~ DEL
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0,
    // 128-143: extended Latin (€, etc.)
    556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    // 144-159
    0, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667,
    // 160-175: NBSP ¡ ¢ £ ¤ ¥ ¦ § ¨ © ª « ¬ SHY ® ¯
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    // 176-191: ° ± ² ³ ´ µ ¶ · ¸ ¹ º » ¼ ½ ¾ ¿
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    // 192-207: À Á Â Ã Ä Å Æ Ç È É Ê Ë Ì Í Î Ï
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    // 208-223: Ð Ñ Ò Ó Ô Õ Ö × Ø Ù Ú Û Ü Ý Þ ß
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    // 224-239: à á â ã ä å æ ç è é ê ë ì í î ï
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    // 240-255: ð ñ ò ó ô õ ö ÷ ø ù ú û ü ý þ ÿ
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
];

#[rustfmt::skip]
static HELVETICA_BOLD_WIDTHS: [u16; 256] = [
    // 0-31: control characters
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 32-47: space ! " # $ % & ' ( ) * + , - . /
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    // 48-63: 0-9 : ; < = > ?
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    // 64-79: @ A-O
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    // 80-95: P-Z [ \ ] ^ _
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    // 96-111: ` a-o
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    // 112-127: p-z { | } ~ DEL
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 0,
    // 128-255: extended (same pattern as Helvetica, slightly wider where appropriate)
    556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,
    0, 278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667,
    278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,
    611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,
];

#[rustfmt::skip]
static TIMES_ROMAN_WIDTHS: [u16; 256] = [
    // 0-31: control characters
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 32-47: space ! " # $ % & ' ( ) * + , - . /
    250, 333, 408, 500, 500, 833, 778, 180, 333, 333, 500, 564, 250, 333, 250, 278,
    // 48-63: 0-9 : ; < = > ?
    500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 278, 278, 564, 564, 564, 444,
    // 64-79: @ A-O
    921, 722, 667, 667, 722, 611, 556, 722, 722, 333, 389, 722, 611, 889, 722, 722,
    // 80-95: P-Z [ \ ] ^ _
    556, 722, 667, 556, 611, 722, 722, 944, 722, 722, 611, 333, 278, 333, 469, 500,
    // 96-111: ` a-o
    333, 444, 500, 444, 500, 444, 333, 500, 500, 278, 278, 500, 278, 778, 500, 500,
    // 112-127: p-z { | } ~ DEL
    500, 500, 333, 389, 278, 500, 500, 722, 500, 500, 444, 480, 200, 480, 541, 0,
    // 128-255: extended
    500, 0, 333, 500, 444, 1000, 500, 500, 333, 1000, 556, 333, 889, 0, 611, 0,
    0, 333, 333, 444, 444, 350, 500, 1000, 333, 980, 389, 333, 722, 0, 444, 722,
    250, 333, 500, 500, 500, 500, 200, 500, 333, 760, 276, 500, 564, 333, 760, 333,
    400, 564, 300, 300, 333, 500, 453, 250, 333, 300, 310, 500, 750, 750, 750, 444,
    722, 722, 722, 722, 722, 722, 889, 667, 611, 611, 611, 611, 333, 333, 333, 333,
    722, 722, 722, 722, 722, 722, 722, 564, 722, 722, 722, 722, 722, 722, 556, 500,
    444, 444, 444, 444, 444, 444, 667, 444, 444, 444, 444, 444, 278, 278, 278, 278,
    500, 500, 500, 500, 500, 500, 500, 564, 500, 500, 500, 500, 500, 500, 500, 500,
];

#[rustfmt::skip]
static TIMES_BOLD_WIDTHS: [u16; 256] = [
    // 0-31: control characters
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 32-47: space ! " # $ % & ' ( ) * + , - . /
    250, 333, 555, 500, 500, 1000, 833, 278, 333, 333, 500, 570, 250, 333, 250, 278,
    // 48-63: 0-9 : ; < = > ?
    500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 333, 333, 570, 570, 570, 500,
    // 64-79: @ A-O
    930, 722, 667, 722, 722, 667, 611, 778, 778, 389, 500, 778, 667, 944, 722, 778,
    // 80-95: P-Z [ \ ] ^ _
    611, 778, 722, 556, 667, 722, 722, 1000, 722, 722, 667, 333, 278, 333, 581, 500,
    // 96-111: ` a-o
    333, 500, 556, 444, 556, 444, 333, 500, 556, 278, 333, 556, 278, 833, 556, 500,
    // 112-127: p-z { | } ~ DEL
    556, 556, 444, 389, 333, 556, 500, 722, 500, 500, 444, 394, 220, 394, 520, 0,
    // 128-255: extended
    500, 0, 333, 500, 500, 1000, 500, 500, 333, 1000, 556, 333, 1000, 0, 667, 0,
    0, 333, 333, 500, 500, 350, 500, 1000, 333, 1000, 389, 333, 722, 0, 444, 722,
    250, 333, 500, 500, 500, 500, 220, 500, 333, 747, 300, 500, 570, 333, 747, 333,
    400, 570, 300, 300, 333, 556, 540, 250, 333, 300, 330, 500, 750, 750, 750, 500,
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 389, 389, 389, 389,
    722, 722, 778, 778, 778, 778, 778, 570, 778, 722, 722, 722, 722, 722, 611, 556,
    500, 500, 500, 500, 500, 500, 722, 444, 444, 444, 444, 444, 278, 278, 278, 278,
    500, 556, 500, 500, 500, 500, 500, 570, 500, 556, 556, 556, 556, 500, 556, 500,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_helvetica_space_width() {
        assert_eq!(FontMetrics::char_width(Standard14Font::Helvetica, ' '), 278);
    }

    #[test]
    fn test_helvetica_uppercase_a() {
        assert_eq!(FontMetrics::char_width(Standard14Font::Helvetica, 'A'), 667);
    }

    #[test]
    fn test_courier_is_monospace() {
        let a = FontMetrics::char_width(Standard14Font::Courier, 'A');
        let m = FontMetrics::char_width(Standard14Font::Courier, 'm');
        let period = FontMetrics::char_width(Standard14Font::Courier, '.');
        assert_eq!(a, 600);
        assert_eq!(m, 600);
        assert_eq!(period, 600);
    }

    #[test]
    fn test_string_width() {
        // "Hello" in Helvetica at 10pt
        let width = FontMetrics::string_width(Standard14Font::Helvetica, "Hello", 10.0);
        // H=722 e=556 l=222 l=222 o=556 = 2278 units => 22.78 points
        assert!((width - 22.78).abs() < 0.01);
    }

    #[test]
    fn test_non_latin_falls_back_to_space() {
        let cjk_width = FontMetrics::char_width(Standard14Font::Helvetica, '\u{4e00}');
        let space_width = FontMetrics::char_width(Standard14Font::Helvetica, ' ');
        assert_eq!(cjk_width, space_width);
    }

    #[test]
    fn test_encode_pdf_text_simple() {
        assert_eq!(encode_pdf_text("Hello"), "(Hello)");
    }

    #[test]
    fn test_encode_pdf_text_escaping() {
        assert_eq!(encode_pdf_text("a(b)c\\d"), "(a\\(b\\)c\\\\d)");
    }

    #[test]
    fn test_encode_pdf_text_non_latin() {
        assert_eq!(encode_pdf_text("日本語"), "(???)");
    }

    #[test]
    fn test_ascent_descent() {
        let asc = FontMetrics::ascent(Standard14Font::Helvetica);
        let desc = FontMetrics::descent(Standard14Font::Helvetica);
        assert!(asc > 0);
        assert!(desc < 0);
        // Total height should be reasonable (roughly 925 units for Helvetica)
        assert!((asc - desc) > 800);
        assert!((asc - desc) < 1100);
    }

    #[test]
    fn test_times_roman_widths() {
        // Space in Times-Roman is 250 (narrower than Helvetica's 278)
        assert_eq!(
            FontMetrics::char_width(Standard14Font::TimesRoman, ' '),
            250
        );
        // M in Times-Roman is 889
        assert_eq!(
            FontMetrics::char_width(Standard14Font::TimesRoman, 'M'),
            889
        );
    }
}

#[cfg(all(test, feature = "visual"))]
mod embedded_tests {
    use super::*;

    #[test]
    fn test_encode_cid_text_basic() {
        let mapping = vec![('H', 1u16), ('i', 2)];
        let result = encode_cid_text("Hi", &mapping);
        assert_eq!(result, "<00010002>");
    }

    #[test]
    fn test_encode_cid_text_unknown_char() {
        let mapping = vec![('A', 1u16)];
        let result = encode_cid_text("AB", &mapping);
        // 'B' not found → CID 0 (.notdef)
        assert_eq!(result, "<00010000>");
    }

    #[test]
    fn test_encode_cid_text_empty() {
        let mapping: Vec<(char, u16)> = Vec::new();
        let result = encode_cid_text("", &mapping);
        assert_eq!(result, "<>");
    }

    #[test]
    fn test_build_w_array_empty() {
        let result = build_w_array(&[], 1000);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_build_w_array_with_entries() {
        let widths = vec![(0u16, 500u16), (1, 600), (2, 500)];
        let result = build_w_array(&widths, 500);
        // Only CID 1 differs from default
        assert_eq!(result, "[1 [600]]");
    }

    #[test]
    fn test_build_tounicode_cmap_structure() {
        let mapping = vec![('A', 1u16), ('B', 2)];
        let cmap = build_tounicode_cmap("TestFont", &mapping);
        let text = String::from_utf8(cmap).unwrap();
        assert!(text.contains("begincmap"));
        assert!(text.contains("endcmap"));
        assert!(text.contains("begincodespacerange"));
        assert!(text.contains("<0000> <FFFF>"));
        assert!(text.contains("beginbfchar"));
        // CID 1 → U+0041 ('A')
        assert!(text.contains("<0001> <0041>"));
        // CID 2 → U+0042 ('B')
        assert!(text.contains("<0002> <0042>"));
    }

    #[test]
    fn test_embedded_ascent_descent_1000() {
        let info = EmbeddedFontInfo {
            name: "Test".to_string(),
            units_per_em: 2048,
            ascent: 1900,
            descent: -500,
            italic_angle: 0.0,
            bbox: [-200, -500, 1800, 1900],
            cap_height: 1400,
            stem_v: 80,
            flags: 0x20,
        };
        // 1900 * 1000 / 2048 = 927
        assert_eq!(embedded_ascent_1000(&info), 927);
        // -500 * 1000 / 2048 = -244
        assert_eq!(embedded_descent_1000(&info), -244);
    }
}
