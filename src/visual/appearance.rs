//! Appearance stream generation (`/AP /N`).
//!
//! Generates PDF content streams and Form XObjects for visible signature
//! appearances. The appearance is a self-contained Form XObject that gets
//! referenced by the signature annotation's `/AP` dictionary.
//!
//! # PDF Content Stream Basics
//!
//! A signature appearance is a Form XObject (a mini-page) containing:
//! - A resource dictionary (fonts, images, etc.)
//! - A content stream with PDF drawing operators
//!
//! Key operators used:
//! - `BT` / `ET` — begin/end text block
//! - `Tf` — set font and size
//! - `Td` — move text position
//! - `Tj` — show text string
//! - `rg` / `RG` — set fill/stroke color
//! - `re` — rectangle path
//! - `f` / `S` — fill / stroke path
//! - `q` / `Q` — save/restore graphics state
//! - `cm` — concatenate transformation matrix

use super::font::{encode_pdf_text, FontMetrics};
use super::layout::*;
use crate::error::VisualError;

/// Result of generating an appearance stream.
///
/// Contains everything needed to embed the appearance as a Form XObject
/// in the PDF. The caller is responsible for adding this to the document
/// and referencing it from the signature annotation's `/AP /N` entry.
#[derive(Debug)]
pub struct AppearanceStream {
    /// The content stream bytes (PDF drawing operators).
    pub content: Vec<u8>,
    /// Font resources used in the content stream.
    /// Each entry is (resource_name, pdf_font_name) — e.g., ("F1", "Helvetica").
    pub font_resources: Vec<(String, String)>,
    /// The bounding box of the appearance [0, 0, width, height].
    pub bbox: [f32; 4],
}

/// Build an appearance stream for a text-only layout.
///
/// This generates the PDF content stream operators to render text lines
/// within the given rectangle dimensions.
pub fn build_text_appearance(
    config: &TextConfig,
    width: f32,
    height: f32,
    background: Option<&Color>,
    border: Option<&Border>,
) -> Result<AppearanceStream, VisualError> {
    let mut stream = Vec::with_capacity(1024);
    let mut fonts: Vec<(String, String)> = Vec::new();

    // Resolve fonts needed
    let base_font = match &config.font {
        FontSpec::Standard14(f) => *f,
    };
    let bold_font = base_font.bold_variant();

    // Register base font as F1
    let base_font_name = "F1".to_string();
    fonts.push((base_font_name.clone(), base_font.pdf_name().to_string()));

    // If bold variant is different, register as F2
    let bold_font_name = if bold_font != base_font {
        let name = "F2".to_string();
        fonts.push((name.clone(), bold_font.pdf_name().to_string()));
        name
    } else {
        base_font_name.clone()
    };

    // Save graphics state
    write_op(&mut stream, "q");

    // Background fill
    if let Some(bg) = background {
        write_color_fill(&mut stream, bg);
        write_fmt(&mut stream, &format!("0 0 {:.2} {:.2} re f", width, height));
    }

    // Border
    if let Some(border) = border {
        write_color_stroke(&mut stream, &border.color);
        write_fmt(
            &mut stream,
            &format!("{:.2} w 0 0 {:.2} {:.2} re S", border.width, width, height),
        );
    }

    // Text rendering
    if !config.lines.is_empty() {
        write_op(&mut stream, "BT");

        let padding = config.padding;
        let usable_width = width - 2.0 * padding;
        let font_size = config.font_size;
        let line_height = font_size * config.line_spacing;

        // Calculate total text height to position from the top
        let total_text_height = config.lines.len() as f32 * line_height;
        let ascent_ratio = FontMetrics::ascent(base_font) as f32 / 1000.0;

        // Start position: top of usable area, offset down by ascent
        let start_y = if total_text_height < (height - 2.0 * padding) {
            // Center vertically if text doesn't fill the area
            let extra = (height - 2.0 * padding) - total_text_height;
            height - padding - extra / 2.0 - font_size * ascent_ratio
        } else {
            height - padding - font_size * ascent_ratio
        };

        for (i, line) in config.lines.iter().enumerate() {
            let effective_size = line.font_size.unwrap_or(font_size);
            let effective_font = if line.bold { bold_font } else { base_font };
            let font_ref = if line.bold {
                &bold_font_name
            } else {
                &base_font_name
            };

            // Set font
            write_fmt(
                &mut stream,
                &format!("/{} {:.1} Tf", font_ref, effective_size),
            );

            // Set text color
            let text_color = line.color.as_ref().unwrap_or(&config.color);
            write_fmt(
                &mut stream,
                &format!(
                    "{:.3} {:.3} {:.3} rg",
                    text_color.r, text_color.g, text_color.b
                ),
            );

            // Calculate x position based on alignment
            let text_width = FontMetrics::string_width(effective_font, &line.text, effective_size);
            let x = match config.alignment {
                TextAlignment::Left => padding,
                TextAlignment::Center => padding + (usable_width - text_width) / 2.0,
                TextAlignment::Right => padding + usable_width - text_width,
            };

            let y = start_y - i as f32 * line_height;

            // Position and render text
            write_fmt(&mut stream, &format!("{:.2} {:.2} Td", x, y));
            write_fmt(&mut stream, &format!("{} Tj", encode_pdf_text(&line.text)));

            // Reset position (Td is relative, so we need to undo for next line)
            // Actually, we use absolute positioning by using a new Td each time
            // from (0,0), so we need to negate the previous Td first.
            if i + 1 < config.lines.len() {
                write_fmt(&mut stream, &format!("{:.2} {:.2} Td", -x, -y));
            }
        }

        write_op(&mut stream, "ET");
    }

    // Restore graphics state
    write_op(&mut stream, "Q");

    Ok(AppearanceStream {
        content: stream,
        font_resources: fonts,
        bbox: [0.0, 0.0, width, height],
    })
}

/// Build an appearance stream for the given visible signature configuration.
///
/// This is the main entry point. It dispatches to the appropriate builder
/// based on the layout type.
pub fn build_appearance(
    config: &VisibleSignatureConfig,
    page_width: f32,
    page_height: f32,
) -> Result<AppearanceStream, VisualError> {
    let rect = config.rect.to_absolute(page_width, page_height);
    let width = rect[2] - rect[0];
    let height = rect[3] - rect[1];

    if width <= 0.0 || height <= 0.0 {
        return Err(VisualError::InvalidDimensions(
            "Visible signature rect has zero or negative dimensions".into(),
        ));
    }

    match &config.layout {
        SignatureLayout::TextOnly(text_config) => build_text_appearance(
            text_config,
            width,
            height,
            config.background_color.as_ref(),
            config.border.as_ref(),
        ),
        #[cfg(feature = "visual")]
        SignatureLayout::ImageOnly(_image_config) => {
            // TODO: Implement image-only appearance
            Err(VisualError::AppearanceError(
                "Image-only appearance not yet implemented".into(),
            ))
        }
        #[cfg(feature = "visual")]
        SignatureLayout::ImageAndText { .. } => {
            // TODO: Implement combined image+text appearance
            Err(VisualError::AppearanceError(
                "Image+text appearance not yet implemented".into(),
            ))
        }
    }
}

/// Create a default text-based signature appearance from signing metadata.
///
/// This is a convenience function that creates a standard-looking signature
/// appearance showing signer name, reason, location, and date.
pub fn build_default_text_appearance(
    signer_name: &str,
    reason: Option<&str>,
    location: Option<&str>,
    date: Option<&str>,
    width: f32,
    height: f32,
) -> Result<AppearanceStream, VisualError> {
    let mut lines = Vec::new();

    // Line 1: "Digitally signed by <name>" (bold)
    lines.push(TextLine::new(format!("Digitally signed by {}", signer_name)).bold());

    // Optional lines
    if let Some(reason) = reason {
        lines.push(TextLine::new(format!("Reason: {}", reason)));
    }
    if let Some(location) = location {
        lines.push(TextLine::new(format!("Location: {}", location)));
    }
    if let Some(date) = date {
        lines.push(TextLine::new(format!("Date: {}", date)));
    }

    // Auto-size font to fit
    let padding = 4.0;
    let usable_height = height - 2.0 * padding;
    let line_count = lines.len() as f32;
    // Target: lines fit with 1.2x line spacing
    let max_font_size = usable_height / (line_count * 1.2);
    let font_size = max_font_size.min(10.0).max(5.0); // clamp between 5 and 10

    let config = TextConfig {
        lines,
        font_size,
        ..TextConfig::default()
    };

    build_text_appearance(&config, width, height, Some(&Color::white()), None)
}

// --- Internal helpers ---

fn write_op(stream: &mut Vec<u8>, op: &str) {
    stream.extend_from_slice(op.as_bytes());
    stream.push(b'\n');
}

fn write_fmt(stream: &mut Vec<u8>, text: &str) {
    stream.extend_from_slice(text.as_bytes());
    stream.push(b'\n');
}

fn write_color_fill(stream: &mut Vec<u8>, color: &Color) {
    write_fmt(
        stream,
        &format!("{:.3} {:.3} {:.3} rg", color.r, color.g, color.b),
    );
}

fn write_color_stroke(stream: &mut Vec<u8>, color: &Color) {
    write_fmt(
        stream,
        &format!("{:.3} {:.3} {:.3} RG", color.r, color.g, color.b),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_text_appearance_basic() {
        let config = TextConfig {
            lines: vec![
                TextLine::new("Signed by Test User").bold(),
                TextLine::new("Date: 2026-01-01"),
            ],
            font_size: 10.0,
            ..TextConfig::default()
        };

        let result = build_text_appearance(&config, 200.0, 50.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // Should contain text operators
        assert!(content.contains("BT"));
        assert!(content.contains("ET"));
        assert!(content.contains("Tj"));
        assert!(content.contains("Signed by Test User"));
        assert!(content.contains("Date: 2026-01-01"));

        // Should have font resources
        assert!(!result.font_resources.is_empty());
        assert_eq!(result.bbox, [0.0, 0.0, 200.0, 50.0]);
    }

    #[test]
    fn test_build_text_appearance_with_background_and_border() {
        let config = TextConfig {
            lines: vec![TextLine::new("Hello")],
            ..TextConfig::default()
        };

        let bg = Color::white();
        let border = Border::default();
        let result = build_text_appearance(&config, 100.0, 30.0, Some(&bg), Some(&border)).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // Should have fill for background
        assert!(content.contains("re f"));
        // Should have stroke for border
        assert!(content.contains("re S"));
    }

    #[test]
    fn test_build_text_appearance_empty_lines() {
        let config = TextConfig::default();
        let result = build_text_appearance(&config, 100.0, 30.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // Should not contain text block if no lines
        assert!(!content.contains("BT"));
    }

    #[test]
    fn test_build_text_appearance_bold_uses_two_fonts() {
        let config = TextConfig {
            lines: vec![
                TextLine::new("Bold line").bold(),
                TextLine::new("Normal line"),
            ],
            ..TextConfig::default()
        };

        let result = build_text_appearance(&config, 200.0, 50.0, None, None).unwrap();

        // Should have two font resources (F1=Helvetica, F2=Helvetica-Bold)
        assert_eq!(result.font_resources.len(), 2);
        assert_eq!(result.font_resources[0].1, "Helvetica");
        assert_eq!(result.font_resources[1].1, "Helvetica-Bold");
    }

    #[test]
    fn test_build_default_text_appearance() {
        let result = build_default_text_appearance(
            "John Doe",
            Some("Approval"),
            Some("Stockholm"),
            Some("2026-01-01"),
            200.0,
            80.0,
        )
        .unwrap();

        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("Digitally signed by John Doe"));
        assert!(content.contains("Reason: Approval"));
        assert!(content.contains("Location: Stockholm"));
        assert!(content.contains("Date: 2026-01-01"));
    }

    #[test]
    fn test_build_default_text_appearance_minimal() {
        let result = build_default_text_appearance("Alice", None, None, None, 150.0, 40.0).unwrap();

        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("Digitally signed by Alice"));
        // No reason/location/date lines
        assert!(!content.contains("Reason:"));
        assert!(!content.contains("Location:"));
    }

    #[test]
    fn test_build_appearance_zero_dimensions() {
        let config = VisibleSignatureConfig {
            page: 0,
            rect: SignatureRect::Absolute {
                llx: 50.0,
                lly: 50.0,
                urx: 50.0, // zero width
                ury: 100.0,
            },
            layout: SignatureLayout::TextOnly(TextConfig::default()),
            background_color: None,
            border: None,
        };

        let result = build_appearance(&config, 612.0, 792.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_appearance_dispatches_to_text() {
        let config = VisibleSignatureConfig {
            page: 0,
            rect: SignatureRect::Absolute {
                llx: 50.0,
                lly: 700.0,
                urx: 250.0,
                ury: 750.0,
            },
            layout: SignatureLayout::TextOnly(TextConfig {
                lines: vec![TextLine::new("Test")],
                ..TextConfig::default()
            }),
            background_color: Some(Color::white()),
            border: Some(Border::default()),
        };

        let result = build_appearance(&config, 612.0, 792.0).unwrap();
        assert!(!result.content.is_empty());
        assert_eq!(result.bbox[2], 200.0); // width = 250 - 50
        assert_eq!(result.bbox[3], 50.0); // height = 750 - 700
    }

    #[test]
    fn test_text_alignment_center() {
        let config = TextConfig {
            lines: vec![TextLine::new("Center")],
            alignment: TextAlignment::Center,
            font_size: 10.0,
            ..TextConfig::default()
        };

        let result = build_text_appearance(&config, 200.0, 30.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);
        // The x position should be centered
        assert!(content.contains("Td"));
        assert!(content.contains("Center"));
    }

    #[test]
    fn test_text_alignment_right() {
        let config = TextConfig {
            lines: vec![TextLine::new("Right")],
            alignment: TextAlignment::Right,
            font_size: 10.0,
            ..TextConfig::default()
        };

        let result = build_text_appearance(&config, 200.0, 30.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("Right"));
    }

    #[test]
    fn test_escaping_in_text() {
        let config = TextConfig {
            lines: vec![TextLine::new("Test (with) parens & backslash\\")],
            ..TextConfig::default()
        };

        let result = build_text_appearance(&config, 300.0, 30.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);
        // Parentheses and backslash should be escaped
        assert!(content.contains("\\(with\\)"));
        assert!(content.contains("backslash\\\\"));
    }
}
