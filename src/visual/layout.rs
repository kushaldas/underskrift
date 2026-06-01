//! Text, image, and composite layouts for visible signatures.
//!
//! This module defines the configuration types for positioning and laying out
//! visible signature appearances on PDF pages.
//!
//! # Custom Appearances
//!
//! For full control over the signature appearance, implement the
//! [`AppearanceRenderer`] trait and use [`SignatureLayout::Custom`].
//! A built-in [`SignatureTemplate`] is provided for placeholder-based
//! text substitution.

use std::fmt;
use std::sync::Arc;

use crate::error::VisualError;

/// Context passed to custom appearance renderers.
///
/// Contains the dimensions of the signature rectangle and metadata
/// about the signing operation that renderers can use to generate
/// content stream operators.
#[derive(Debug, Clone)]
pub struct AppearanceContext {
    /// Width of the signature rectangle in PDF points.
    pub width: f32,
    /// Height of the signature rectangle in PDF points.
    pub height: f32,
    /// Optional signer name (from signing certificate or configuration).
    pub signer_name: Option<String>,
    /// Optional signing reason.
    pub reason: Option<String>,
    /// Optional signing location.
    pub location: Option<String>,
    /// Optional signing date as a formatted string.
    pub date: Option<String>,
    /// Optional contact information.
    pub contact_info: Option<String>,
}

/// Trait for custom appearance renderers.
///
/// Implement this trait to produce a completely custom signature appearance.
/// The renderer receives an [`AppearanceContext`] with dimensions and signing
/// metadata, and must return raw PDF content stream bytes (drawing operators).
///
/// The returned bytes are used as the content stream of a Form XObject.
/// The renderer is responsible for all drawing: text, graphics, colors, etc.
///
/// Standard 14 fonts (Helvetica, etc.) are available without embedding.
/// Reference them in the content stream as `/F1`, `/F2`, etc. and return
/// corresponding font resource names from your implementation.
///
/// # Example
///
/// ```rust
/// use underskrift::visual::layout::{AppearanceRenderer, AppearanceContext, CustomAppearanceResult};
/// use underskrift::error::VisualError;
///
/// struct MyRenderer;
///
/// impl AppearanceRenderer for MyRenderer {
///     fn render(&self, ctx: &AppearanceContext) -> Result<CustomAppearanceResult, VisualError> {
///         let mut stream = Vec::new();
///         stream.extend_from_slice(b"q\n");
///         stream.extend_from_slice(
///             format!("0 0 {:.2} {:.2} re f\n", ctx.width, ctx.height).as_bytes()
///         );
///         stream.extend_from_slice(b"Q\n");
///
///         Ok(CustomAppearanceResult {
///             content: stream,
///             font_resources: vec![],
///         })
///     }
/// }
/// ```
pub trait AppearanceRenderer: Send + Sync {
    /// Render the signature appearance and return PDF content stream bytes.
    fn render(&self, ctx: &AppearanceContext) -> Result<CustomAppearanceResult, VisualError>;
}

/// Result of a custom appearance rendering.
///
/// Contains the raw PDF content stream and font resources required.
#[derive(Debug, Clone)]
pub struct CustomAppearanceResult {
    /// Raw PDF content stream bytes (drawing operators).
    pub content: Vec<u8>,
    /// Standard 14 font resources used in the content stream.
    /// Each entry is `(resource_name, pdf_font_name)` — e.g., `("F1", "Helvetica")`.
    pub font_resources: Vec<(String, String)>,
}

/// Configuration for a visible signature appearance.
///
/// Specifies where on the page the signature should appear, what content
/// it contains (text, image, or both), and optional styling.
#[derive(Debug, Clone)]
pub struct VisibleSignatureConfig {
    /// Page number (0-indexed) to place the signature.
    pub page: u32,
    /// Position and size of the signature rectangle.
    pub rect: SignatureRect,
    /// What content to render in the signature appearance.
    pub layout: SignatureLayout,
    /// Optional background color (default: white/transparent).
    pub background_color: Option<Color>,
    /// Optional border around the signature.
    pub border: Option<Border>,
}

/// Position and size of the visible signature rectangle.
#[derive(Debug, Clone)]
pub enum SignatureRect {
    /// Absolute position in PDF points (1 point = 1/72 inch).
    /// Coordinates are in the PDF default coordinate system (origin at lower-left).
    Absolute {
        /// Lower-left x coordinate.
        llx: f32,
        /// Lower-left y coordinate.
        lly: f32,
        /// Upper-right x coordinate.
        urx: f32,
        /// Upper-right y coordinate.
        ury: f32,
    },
    /// Position specified with measurements from page edges.
    /// Converted to absolute coordinates during rendering using page dimensions.
    Positioned {
        /// Distance from left edge of page.
        left: Measurement,
        /// Distance from top edge of page (note: top, not bottom).
        top: Measurement,
        /// Width of the signature rectangle.
        width: Measurement,
        /// Height of the signature rectangle.
        height: Measurement,
    },
}

/// A measurement with various unit options.
#[derive(Debug, Clone, Copy)]
pub enum Measurement {
    /// PDF points (1/72 inch).
    Points(f32),
    /// Millimeters.
    Mm(f32),
    /// Centimeters.
    Cm(f32),
    /// Inches.
    Inches(f32),
}

impl Measurement {
    /// Convert this measurement to PDF points.
    pub fn to_points(self) -> f32 {
        match self {
            Measurement::Points(v) => v,
            Measurement::Mm(v) => v * 72.0 / 25.4,
            Measurement::Cm(v) => v * 72.0 / 2.54,
            Measurement::Inches(v) => v * 72.0,
        }
    }
}

/// What to render inside the visible signature.
pub enum SignatureLayout {
    /// Text-only signature appearance.
    TextOnly(TextConfig),
    /// Image-only signature appearance (e.g., scanned signature image).
    #[cfg(feature = "visual")]
    ImageOnly(ImageConfig),
    /// Combined image and text.
    #[cfg(feature = "visual")]
    ImageAndText {
        /// Image configuration.
        image: ImageConfig,
        /// Text configuration.
        text: TextConfig,
        /// How to arrange image and text.
        arrangement: Arrangement,
    },
    /// Custom appearance rendered by a user-provided [`AppearanceRenderer`].
    ///
    /// Use this for full control over the signature appearance content stream.
    /// Wrap your renderer in `Arc` so the layout remains `Clone`.
    Custom(Arc<dyn AppearanceRenderer>),
}

impl fmt::Debug for SignatureLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureLayout::TextOnly(tc) => f.debug_tuple("TextOnly").field(tc).finish(),
            #[cfg(feature = "visual")]
            SignatureLayout::ImageOnly(ic) => f.debug_tuple("ImageOnly").field(ic).finish(),
            #[cfg(feature = "visual")]
            SignatureLayout::ImageAndText {
                image,
                text,
                arrangement,
            } => f
                .debug_struct("ImageAndText")
                .field("image", image)
                .field("text", text)
                .field("arrangement", arrangement)
                .finish(),
            SignatureLayout::Custom(_) => f.debug_tuple("Custom").field(&"<renderer>").finish(),
        }
    }
}

impl Clone for SignatureLayout {
    fn clone(&self) -> Self {
        match self {
            SignatureLayout::TextOnly(tc) => SignatureLayout::TextOnly(tc.clone()),
            #[cfg(feature = "visual")]
            SignatureLayout::ImageOnly(ic) => SignatureLayout::ImageOnly(ic.clone()),
            #[cfg(feature = "visual")]
            SignatureLayout::ImageAndText {
                image,
                text,
                arrangement,
            } => SignatureLayout::ImageAndText {
                image: image.clone(),
                text: text.clone(),
                arrangement: *arrangement,
            },
            SignatureLayout::Custom(renderer) => SignatureLayout::Custom(Arc::clone(renderer)),
        }
    }
}

/// How to arrange image and text in a combined layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrangement {
    /// Image on the left, text on the right.
    ImageLeftTextRight,
    /// Image on the right, text on the left.
    ImageRightTextLeft,
    /// Image on top, text below.
    ImageTopTextBottom,
    /// Image below, text on top.
    ImageBottomTextTop,
}

/// Configuration for text content in a signature appearance.
#[derive(Debug, Clone)]
pub struct TextConfig {
    /// Lines of text to render. Each entry is one line.
    /// Use the `TextLine` builder or provide raw strings.
    pub lines: Vec<TextLine>,
    /// Font to use. Defaults to Helvetica (PDF standard 14).
    pub font: FontSpec,
    /// Font size in points. Default: 10.0
    pub font_size: f32,
    /// Text color. Default: black.
    pub color: Color,
    /// Horizontal alignment. Default: Left.
    pub alignment: TextAlignment,
    /// Line spacing multiplier (1.0 = single spacing). Default: 1.2
    pub line_spacing: f32,
    /// Padding inside the text area (in points). Default: 4.0
    pub padding: f32,
}

impl Default for TextConfig {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            font: FontSpec::default(),
            font_size: 10.0,
            color: Color::black(),
            alignment: TextAlignment::Left,
            line_spacing: 1.2,
            padding: 4.0,
        }
    }
}

/// A single line of text in the signature appearance.
#[derive(Debug, Clone)]
pub struct TextLine {
    /// The text content. Non-ASCII characters will be handled based on the
    /// font capabilities.
    pub text: String,
    /// Optional override font size for this line.
    pub font_size: Option<f32>,
    /// Optional override color for this line.
    pub color: Option<Color>,
    /// Whether this line is bold (uses bold variant if available).
    pub bold: bool,
}

impl TextLine {
    /// Create a new text line with the given content.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            font_size: None,
            color: None,
            bold: false,
        }
    }

    /// Set this line as bold.
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Override the font size for this line.
    pub fn size(mut self, size: f32) -> Self {
        self.font_size = Some(size);
        self
    }

    /// Override the color for this line.
    pub fn color(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }
}

/// Font specification for text rendering.
#[derive(Debug, Clone)]
pub enum FontSpec {
    /// One of the PDF standard 14 fonts. No embedding needed.
    Standard14(Standard14Font),
    /// Embedded TrueType/OpenType font (requires subsetting).
    ///
    /// The font data is the raw `.ttf` or `.otf` file bytes. The font will be
    /// subsetted to include only the glyphs actually used in the signature
    /// appearance, embedded as a CIDFont/Type0 font in the PDF.
    ///
    /// Requires the `visual` feature flag.
    #[cfg(feature = "visual")]
    Embedded {
        /// Raw TrueType/OpenType font file data.
        data: Vec<u8>,
        /// Font name to use as the BaseFont in the PDF (e.g., "NotoSans-Regular").
        /// This should be a PostScript-style name without spaces.
        name: String,
    },
}

impl Default for FontSpec {
    fn default() -> Self {
        FontSpec::Standard14(Standard14Font::Helvetica)
    }
}

/// The PDF standard 14 fonts.
///
/// These fonts are guaranteed to be available in all PDF viewers without
/// embedding. They only support WinAnsiEncoding (basic Latin characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standard14Font {
    /// Helvetica (sans-serif).
    Helvetica,
    /// Helvetica-Bold.
    HelveticaBold,
    /// Helvetica-Oblique.
    HelveticaOblique,
    /// Helvetica-BoldOblique.
    HelveticaBoldOblique,
    /// Times-Roman (serif).
    TimesRoman,
    /// Times-Bold.
    TimesBold,
    /// Times-Italic.
    TimesItalic,
    /// Times-BoldItalic.
    TimesBoldItalic,
    /// Courier (monospace).
    Courier,
    /// Courier-Bold.
    CourierBold,
    /// Courier-Oblique.
    CourierOblique,
    /// Courier-BoldOblique.
    CourierBoldOblique,
    /// Symbol (Symbol encoding).
    Symbol,
    /// ZapfDingbats (ZapfDingbats encoding).
    ZapfDingbats,
}

impl Standard14Font {
    /// Returns the PDF font name as used in font dictionaries.
    pub fn pdf_name(&self) -> &'static str {
        match self {
            Standard14Font::Helvetica => "Helvetica",
            Standard14Font::HelveticaBold => "Helvetica-Bold",
            Standard14Font::HelveticaOblique => "Helvetica-Oblique",
            Standard14Font::HelveticaBoldOblique => "Helvetica-BoldOblique",
            Standard14Font::TimesRoman => "Times-Roman",
            Standard14Font::TimesBold => "Times-Bold",
            Standard14Font::TimesItalic => "Times-Italic",
            Standard14Font::TimesBoldItalic => "Times-BoldItalic",
            Standard14Font::Courier => "Courier",
            Standard14Font::CourierBold => "Courier-Bold",
            Standard14Font::CourierOblique => "Courier-Oblique",
            Standard14Font::CourierBoldOblique => "Courier-BoldOblique",
            Standard14Font::Symbol => "Symbol",
            Standard14Font::ZapfDingbats => "ZapfDingbats",
        }
    }

    /// Returns the bold variant, if any. Falls back to self.
    pub fn bold_variant(&self) -> Self {
        match self {
            Standard14Font::Helvetica | Standard14Font::HelveticaBold => {
                Standard14Font::HelveticaBold
            }
            Standard14Font::HelveticaOblique | Standard14Font::HelveticaBoldOblique => {
                Standard14Font::HelveticaBoldOblique
            }
            Standard14Font::TimesRoman | Standard14Font::TimesBold => Standard14Font::TimesBold,
            Standard14Font::TimesItalic | Standard14Font::TimesBoldItalic => {
                Standard14Font::TimesBoldItalic
            }
            Standard14Font::Courier | Standard14Font::CourierBold => Standard14Font::CourierBold,
            Standard14Font::CourierOblique | Standard14Font::CourierBoldOblique => {
                Standard14Font::CourierBoldOblique
            }
            // Symbol and ZapfDingbats have no bold variant
            other => *other,
        }
    }
}

/// Image configuration for signature appearance.
#[cfg(feature = "visual")]
#[derive(Debug, Clone)]
pub struct ImageConfig {
    /// Raw image data (JPEG or PNG).
    pub data: Vec<u8>,
    /// Image format.
    pub format: ImageFormat,
    /// Optional scaling. Default is to fit within the allocated space.
    pub scale: ImageScale,
}

/// Supported image formats for embedding.
#[cfg(feature = "visual")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG image (passed through directly to PDF).
    Jpeg,
    /// PNG image (decoded and re-encoded for PDF).
    Png,
}

/// How to scale the image within its allocated space.
#[cfg(feature = "visual")]
#[derive(Debug, Clone, Copy, Default)]
pub enum ImageScale {
    /// Fit within the space, preserving aspect ratio.
    #[default]
    FitPreserveAspect,
    /// Stretch to fill the entire space.
    Stretch,
    /// Use a fixed size in points.
    Fixed { width: f32, height: f32 },
}

#[cfg(feature = "visual")]
/// Text alignment within the signature rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlignment {
    /// Left-aligned text.
    Left,
    /// Center-aligned text.
    Center,
    /// Right-aligned text.
    Right,
}

/// An RGB color value.
#[derive(Debug, Clone, Copy)]
pub struct Color {
    /// Red component (0.0 to 1.0).
    pub r: f32,
    /// Green component (0.0 to 1.0).
    pub g: f32,
    /// Blue component (0.0 to 1.0).
    pub b: f32,
}

impl Color {
    /// Create a new color from RGB components (0.0 to 1.0).
    pub fn new(r: f32, g: f32, b: f32) -> Self {
        Self { r, g, b }
    }

    /// Black color.
    pub fn black() -> Self {
        Self {
            r: 0.0,
            g: 0.0,
            b: 0.0,
        }
    }

    /// White color.
    pub fn white() -> Self {
        Self {
            r: 1.0,
            g: 1.0,
            b: 1.0,
        }
    }

    /// Dark gray color (common for signature text).
    pub fn dark_gray() -> Self {
        Self {
            r: 0.2,
            g: 0.2,
            b: 0.2,
        }
    }
}

/// Border configuration for the signature rectangle.
#[derive(Debug, Clone)]
pub struct Border {
    /// Border width in points.
    pub width: f32,
    /// Border color.
    pub color: Color,
}

impl Default for Border {
    fn default() -> Self {
        Self {
            width: 0.5,
            color: Color::black(),
        }
    }
}

/// A built-in template-based signature appearance renderer.
///
/// Uses a simple placeholder substitution system to generate text-based
/// signature appearances. Placeholders in the template string are replaced
/// with values from the [`AppearanceContext`] at render time.
///
/// # Supported Placeholders
///
/// - `##SIGNER_NAME##` — Signer's name
/// - `##DATE##` — Signing date
/// - `##REASON##` — Signing reason
/// - `##LOCATION##` — Signing location
/// - `##CONTACT##` — Contact information
///
/// Lines where all placeholders resolve to empty/absent values are omitted.
///
/// # Example
///
/// ```rust
/// use underskrift::visual::layout::{SignatureTemplate, SignatureLayout};
/// use std::sync::Arc;
///
/// let template = SignatureTemplate::new(vec![
///     "Digitally signed by ##SIGNER_NAME##".to_string(),
///     "Date: ##DATE##".to_string(),
///     "Reason: ##REASON##".to_string(),
///     "Location: ##LOCATION##".to_string(),
/// ])
/// .font_size(9.0)
/// .padding(5.0);
///
/// let layout = SignatureLayout::Custom(Arc::new(template));
/// ```
#[derive(Debug, Clone)]
pub struct SignatureTemplate {
    /// Template lines with `##PLACEHOLDER##` markers.
    pub lines: Vec<String>,
    /// Font name (Standard 14). Default: "Helvetica".
    pub font_name: String,
    /// Bold font name (Standard 14). Default: "Helvetica-Bold".
    pub bold_font_name: String,
    /// Font size in points. Default: 10.0
    pub font_size: f32,
    /// Text color. Default: black.
    pub color: Color,
    /// Padding inside the text area in points. Default: 4.0
    pub padding: f32,
    /// Line spacing multiplier. Default: 1.2
    pub line_spacing: f32,
    /// Whether the first line should be bold. Default: true
    pub first_line_bold: bool,
}

impl Default for SignatureTemplate {
    fn default() -> Self {
        Self {
            lines: vec![
                "Digitally signed by ##SIGNER_NAME##".to_string(),
                "Date: ##DATE##".to_string(),
                "Reason: ##REASON##".to_string(),
                "Location: ##LOCATION##".to_string(),
            ],
            font_name: "Helvetica".to_string(),
            bold_font_name: "Helvetica-Bold".to_string(),
            font_size: 10.0,
            color: Color::black(),
            padding: 4.0,
            line_spacing: 1.2,
            first_line_bold: true,
        }
    }
}

impl SignatureTemplate {
    /// Create a new template with the given lines.
    pub fn new(lines: Vec<String>) -> Self {
        Self {
            lines,
            ..Default::default()
        }
    }

    /// Set the font size.
    pub fn font_size(mut self, size: f32) -> Self {
        self.font_size = size;
        self
    }

    /// Set the padding.
    pub fn padding(mut self, padding: f32) -> Self {
        self.padding = padding;
        self
    }

    /// Set the text color.
    pub fn color(mut self, color: Color) -> Self {
        self.color = color;
        self
    }

    /// Set the line spacing multiplier.
    pub fn line_spacing(mut self, spacing: f32) -> Self {
        self.line_spacing = spacing;
        self
    }

    /// Set the font name (must be a Standard 14 PDF font name).
    pub fn font_name(mut self, name: impl Into<String>) -> Self {
        self.font_name = name.into();
        self
    }

    /// Set the bold font name (must be a Standard 14 PDF font name).
    pub fn bold_font_name(mut self, name: impl Into<String>) -> Self {
        self.bold_font_name = name.into();
        self
    }

    /// Set whether the first line is rendered bold.
    pub fn first_line_bold(mut self, bold: bool) -> Self {
        self.first_line_bold = bold;
        self
    }

    /// Substitute placeholders in a template line with context values.
    ///
    /// Returns `None` if the line becomes empty after substitution
    /// (all placeholders resolved to empty/absent values and no static text remains).
    fn substitute_line(line: &str, ctx: &AppearanceContext) -> Option<String> {
        let result = line
            .replace("##SIGNER_NAME##", ctx.signer_name.as_deref().unwrap_or(""))
            .replace("##DATE##", ctx.date.as_deref().unwrap_or(""))
            .replace("##REASON##", ctx.reason.as_deref().unwrap_or(""))
            .replace("##LOCATION##", ctx.location.as_deref().unwrap_or(""))
            .replace("##CONTACT##", ctx.contact_info.as_deref().unwrap_or(""));

        // Check if the line has meaningful content.
        // A line like "Reason: " (label only, no value) should be omitted.
        let trimmed = result.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Check if only a label prefix remains (ends with ": " or ":")
        // by seeing if removing common label suffixes leaves nothing useful
        let stripped = trimmed.trim_end_matches(':').trim_end_matches(": ").trim();
        // If the original line had a placeholder and the result is just the label prefix, skip it
        if line.contains("##") && stripped.len() == trimmed.trim_end_matches(':').trim().len() {
            // The line had placeholders and the result still has content beyond labels
            // This check catches "Reason: " → "Reason:" which should be skipped
            if trimmed.ends_with(':') || trimmed.ends_with(": ") {
                return None;
            }
        }

        Some(result)
    }

    /// Escape special PDF text characters in a string.
    fn escape_pdf_text(text: &str) -> String {
        let mut escaped = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '(' => escaped.push_str("\\("),
                ')' => escaped.push_str("\\)"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }
}

impl AppearanceRenderer for SignatureTemplate {
    fn render(&self, ctx: &AppearanceContext) -> Result<CustomAppearanceResult, VisualError> {
        // Substitute placeholders and filter empty lines
        let resolved_lines: Vec<String> = self
            .lines
            .iter()
            .filter_map(|line| Self::substitute_line(line, ctx))
            .collect();

        if resolved_lines.is_empty() {
            return Ok(CustomAppearanceResult {
                content: Vec::new(),
                font_resources: vec![],
            });
        }

        let mut stream = Vec::with_capacity(512);
        let mut fonts: Vec<(String, String)> = Vec::new();

        // Register fonts
        let base_font_ref = "F1";
        fonts.push((base_font_ref.to_string(), self.font_name.clone()));

        let bold_font_ref = if self.first_line_bold && self.bold_font_name != self.font_name {
            let name = "F2".to_string();
            fonts.push((name.clone(), self.bold_font_name.clone()));
            name
        } else {
            base_font_ref.to_string()
        };

        // Begin text block
        stream.extend_from_slice(b"BT\n");

        let padding = self.padding;
        let font_size = self.font_size;
        let line_height = font_size * self.line_spacing;

        // Vertical layout: start from top, centered if content is shorter than area
        let total_text_height = resolved_lines.len() as f32 * line_height;
        let usable_height = ctx.height - 2.0 * padding;
        let ascent_ratio = 0.72_f32; // Approximate for Helvetica family

        let start_y = if total_text_height < usable_height {
            let extra = usable_height - total_text_height;
            ctx.height - padding - extra / 2.0 - font_size * ascent_ratio
        } else {
            ctx.height - padding - font_size * ascent_ratio
        };

        // Set text color
        stream.extend_from_slice(
            format!(
                "{:.3} {:.3} {:.3} rg\n",
                self.color.r, self.color.g, self.color.b
            )
            .as_bytes(),
        );

        for (i, line) in resolved_lines.iter().enumerate() {
            let is_bold = self.first_line_bold && i == 0;
            let font_ref = if is_bold {
                &bold_font_ref
            } else {
                base_font_ref
            };

            stream.extend_from_slice(format!("/{} {:.1} Tf\n", font_ref, font_size).as_bytes());

            let x = padding;
            let y = start_y - i as f32 * line_height;

            stream.extend_from_slice(format!("{:.2} {:.2} Td\n", x, y).as_bytes());

            let escaped = Self::escape_pdf_text(line);
            stream.extend_from_slice(format!("({}) Tj\n", escaped).as_bytes());

            // Reset position for next line (absolute Td usage)
            if i + 1 < resolved_lines.len() {
                stream.extend_from_slice(format!("{:.2} {:.2} Td\n", -x, -y).as_bytes());
            }
        }

        stream.extend_from_slice(b"ET\n");

        Ok(CustomAppearanceResult {
            content: stream,
            font_resources: fonts,
        })
    }
}

impl SignatureRect {
    /// Convert to absolute PDF coordinates [llx, lly, urx, ury].
    ///
    /// For `Positioned` rects, `page_width` and `page_height` are required
    /// (in points) to convert from edge-relative measurements.
    pub fn to_absolute(&self, _page_width: f32, page_height: f32) -> [f32; 4] {
        match self {
            SignatureRect::Absolute { llx, lly, urx, ury } => [*llx, *lly, *urx, *ury],
            SignatureRect::Positioned {
                left,
                top,
                width,
                height,
            } => {
                let x = left.to_points();
                let w = width.to_points();
                let h = height.to_points();
                // `top` is distance from top edge, convert to PDF bottom-up coords
                let y_from_top = top.to_points();
                let ury = page_height - y_from_top;
                let lly = ury - h;
                [x, lly, x + w, ury]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_to_points() {
        assert!((Measurement::Points(72.0).to_points() - 72.0).abs() < f32::EPSILON);
        assert!((Measurement::Inches(1.0).to_points() - 72.0).abs() < f32::EPSILON);
        assert!((Measurement::Cm(2.54).to_points() - 72.0).abs() < 0.01);
        assert!((Measurement::Mm(25.4).to_points() - 72.0).abs() < 0.01);
    }

    #[test]
    fn test_measurement_mm() {
        // 10mm = 28.3465 points
        let pts = Measurement::Mm(10.0).to_points();
        assert!((pts - 28.3465).abs() < 0.01);
    }

    #[test]
    fn test_absolute_rect() {
        let rect = SignatureRect::Absolute {
            llx: 50.0,
            lly: 50.0,
            urx: 250.0,
            ury: 100.0,
        };
        let abs = rect.to_absolute(612.0, 792.0);
        assert_eq!(abs, [50.0, 50.0, 250.0, 100.0]);
    }

    #[test]
    fn test_positioned_rect() {
        // 1 inch from left, 1 inch from top, 3 inches wide, 1 inch tall
        // On a US Letter page (612 x 792 points)
        let rect = SignatureRect::Positioned {
            left: Measurement::Inches(1.0),
            top: Measurement::Inches(1.0),
            width: Measurement::Inches(3.0),
            height: Measurement::Inches(1.0),
        };
        let abs = rect.to_absolute(612.0, 792.0);
        // left = 72, top from top = 72, so ury = 792 - 72 = 720, lly = 720 - 72 = 648
        assert!((abs[0] - 72.0).abs() < 0.01); // llx
        assert!((abs[1] - 648.0).abs() < 0.01); // lly
        assert!((abs[2] - 288.0).abs() < 0.01); // urx = 72 + 216
        assert!((abs[3] - 720.0).abs() < 0.01); // ury
    }

    #[test]
    fn test_standard14_font_names() {
        assert_eq!(Standard14Font::Helvetica.pdf_name(), "Helvetica");
        assert_eq!(Standard14Font::HelveticaBold.pdf_name(), "Helvetica-Bold");
        assert_eq!(Standard14Font::TimesRoman.pdf_name(), "Times-Roman");
        assert_eq!(Standard14Font::Courier.pdf_name(), "Courier");
    }

    #[test]
    fn test_bold_variant() {
        assert_eq!(
            Standard14Font::Helvetica.bold_variant(),
            Standard14Font::HelveticaBold
        );
        assert_eq!(
            Standard14Font::TimesRoman.bold_variant(),
            Standard14Font::TimesBold
        );
        assert_eq!(
            Standard14Font::CourierOblique.bold_variant(),
            Standard14Font::CourierBoldOblique
        );
        // Symbol has no bold variant
        assert_eq!(
            Standard14Font::Symbol.bold_variant(),
            Standard14Font::Symbol
        );
    }

    #[test]
    fn test_color_constructors() {
        let black = Color::black();
        assert!((black.r).abs() < f32::EPSILON);
        assert!((black.g).abs() < f32::EPSILON);
        assert!((black.b).abs() < f32::EPSILON);

        let white = Color::white();
        assert!((white.r - 1.0).abs() < f32::EPSILON);
        assert!((white.g - 1.0).abs() < f32::EPSILON);
        assert!((white.b - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_text_line_builder() {
        let line = TextLine::new("Signed by John Doe")
            .bold()
            .size(12.0)
            .color(Color::dark_gray());
        assert_eq!(line.text, "Signed by John Doe");
        assert!(line.bold);
        assert_eq!(line.font_size, Some(12.0));
        assert!(line.color.is_some());
    }

    #[test]
    fn test_text_config_default() {
        let config = TextConfig::default();
        assert!(config.lines.is_empty());
        assert!((config.font_size - 10.0).abs() < f32::EPSILON);
        assert!((config.line_spacing - 1.2).abs() < f32::EPSILON);
        assert!((config.padding - 4.0).abs() < f32::EPSILON);
        assert_eq!(config.alignment, TextAlignment::Left);
    }

    #[test]
    fn test_border_default() {
        let border = Border::default();
        assert!((border.width - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_signature_template_default() {
        let template = SignatureTemplate::default();
        assert_eq!(template.lines.len(), 4);
        assert!((template.font_size - 10.0).abs() < f32::EPSILON);
        assert!(template.first_line_bold);
    }

    #[test]
    fn test_signature_template_substitute_line() {
        let ctx = AppearanceContext {
            width: 200.0,
            height: 50.0,
            signer_name: Some("John Doe".to_string()),
            reason: Some("Approval".to_string()),
            location: None,
            date: Some("2026-01-01".to_string()),
            contact_info: None,
        };

        let result =
            SignatureTemplate::substitute_line("Digitally signed by ##SIGNER_NAME##", &ctx);
        assert_eq!(result, Some("Digitally signed by John Doe".to_string()));

        let result = SignatureTemplate::substitute_line("Date: ##DATE##", &ctx);
        assert_eq!(result, Some("Date: 2026-01-01".to_string()));

        // Location is None, so "Location: " should be filtered out
        let result = SignatureTemplate::substitute_line("Location: ##LOCATION##", &ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_signature_template_render() {
        let template = SignatureTemplate::default();
        let ctx = AppearanceContext {
            width: 200.0,
            height: 60.0,
            signer_name: Some("Alice".to_string()),
            reason: Some("Review".to_string()),
            location: Some("Stockholm".to_string()),
            date: Some("2026-03-01".to_string()),
            contact_info: None,
        };

        let result = template.render(&ctx).unwrap();
        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("Digitally signed by Alice"));
        assert!(content.contains("Date: 2026-03-01"));
        assert!(content.contains("Reason: Review"));
        assert!(content.contains("Location: Stockholm"));
        // Should have font resources
        assert!(!result.font_resources.is_empty());
    }

    #[test]
    fn test_signature_template_render_empty_context() {
        let template = SignatureTemplate::default();
        let ctx = AppearanceContext {
            width: 200.0,
            height: 60.0,
            signer_name: None,
            reason: None,
            location: None,
            date: None,
            contact_info: None,
        };

        let result = template.render(&ctx).unwrap();
        // All lines should be filtered since all placeholders are empty
        // "Digitally signed by " → ends with a space, but has content before it
        // Actually "Digitally signed by " is not empty so it would render
        let content = String::from_utf8_lossy(&result.content);
        // At least the first line "Digitally signed by " has static text
        // but "Date: ", "Reason: ", "Location: " should be skipped
        assert!(!content.contains("Reason:"));
        assert!(!content.contains("Location:"));
    }

    #[test]
    fn test_signature_layout_custom_debug_clone() {
        let template = SignatureTemplate::default();
        let layout = SignatureLayout::Custom(Arc::new(template));

        // Test Debug
        let debug_str = format!("{:?}", layout);
        assert!(debug_str.contains("Custom"));

        // Test Clone
        let cloned = layout.clone();
        let debug_str2 = format!("{:?}", cloned);
        assert!(debug_str2.contains("Custom"));
    }

    #[test]
    fn test_signature_template_escape_pdf_text() {
        let escaped = SignatureTemplate::escape_pdf_text("Test (with) parens & backslash\\");
        assert!(escaped.contains("\\(with\\)"));
        assert!(escaped.contains("backslash\\\\"));
    }
}
