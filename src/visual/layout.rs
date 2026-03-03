//! Text, image, and composite layouts for visible signatures.
//!
//! This module defines the configuration types for positioning and laying out
//! visible signature appearances on PDF pages.

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
#[derive(Debug, Clone)]
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
    // Future: Embedded TrueType/OpenType font (requires subsetting)
    // Embedded { data: Vec<u8>, name: String },
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
#[derive(Debug, Clone, Copy)]
pub enum ImageScale {
    /// Fit within the space, preserving aspect ratio.
    FitPreserveAspect,
    /// Stretch to fill the entire space.
    Stretch,
    /// Use a fixed size in points.
    Fixed { width: f32, height: f32 },
}

#[cfg(feature = "visual")]
impl Default for ImageScale {
    fn default() -> Self {
        ImageScale::FitPreserveAspect
    }
}

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
}
