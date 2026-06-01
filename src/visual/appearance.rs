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
//! - `Tj` — show text string (literal encoding)
//! - `TJ` — show text string (hex encoding, used for CID fonts)
//! - `rg` / `RG` — set fill/stroke color
//! - `re` — rectangle path
//! - `f` / `S` — fill / stroke path
//! - `q` / `Q` — save/restore graphics state
//! - `cm` — concatenate transformation matrix

use super::font::{encode_pdf_text, FontMetrics};
use super::layout::*;
use crate::error::VisualError;

#[cfg(feature = "visual")]
use super::font::{
    embedded_ascent_1000, embedded_string_width, encode_cid_text, prepare_embedded_font,
    PreparedEmbeddedFont,
};
#[cfg(feature = "visual")]
use super::image::{prepare_image, EmbeddedImage};

/// An image resource to be embedded in the Form XObject.
///
/// The caller (signer pipeline) must create a separate Image XObject
/// from this data and wire it into the Form XObject's resource dictionary.
#[cfg(feature = "visual")]
#[derive(Debug)]
pub struct ImageResource {
    /// Resource name used in the content stream (e.g., "Im1").
    pub resource_name: String,
    /// The prepared image data ready for PDF embedding.
    pub image: EmbeddedImage,
}

/// An embedded font resource to be added to the Form XObject.
///
/// Contains the subsetted font data and all metadata needed to create
/// the CIDFont/Type0 font dictionaries in the PDF.
#[cfg(feature = "visual")]
#[derive(Debug)]
pub struct EmbeddedFontResource {
    /// Resource name used in the content stream (e.g., "F1").
    pub resource_name: String,
    /// The prepared font with subsetted data, width info, and CID mapping.
    pub font: PreparedEmbeddedFont,
}

/// Result of generating an appearance stream.
///
/// Contains everything needed to embed the appearance as a Form XObject
/// in the PDF. The caller is responsible for adding this to the document
/// and referencing it from the signature annotation's `/AP /N` entry.
#[derive(Debug)]
pub struct AppearanceStream {
    /// The content stream bytes (PDF drawing operators).
    pub content: Vec<u8>,
    /// Font resources used in the content stream (Standard 14 fonts).
    /// Each entry is (resource_name, pdf_font_name) — e.g., ("F1", "Helvetica").
    pub font_resources: Vec<(String, String)>,
    /// Embedded font resources used in the content stream.
    /// The signer pipeline must create CIDFont/Type0 objects from these.
    #[cfg(feature = "visual")]
    pub embedded_font_resources: Vec<EmbeddedFontResource>,
    /// Image resources used in the content stream.
    /// The signer pipeline must create Image XObject streams from these.
    #[cfg(feature = "visual")]
    pub image_resources: Vec<ImageResource>,
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
    #[cfg(feature = "visual")]
    let mut embedded_fonts: Vec<EmbeddedFontResource> = Vec::new();

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
        match &config.font {
            FontSpec::Standard14(base_font_std14) => {
                let base_font = *base_font_std14;
                let bold_font = base_font.bold_variant();

                let base_font_name = "F1".to_string();
                fonts.push((base_font_name.clone(), base_font.pdf_name().to_string()));

                let bold_font_name = if bold_font != base_font {
                    let name = "F2".to_string();
                    fonts.push((name.clone(), bold_font.pdf_name().to_string()));
                    name
                } else {
                    base_font_name.clone()
                };

                render_standard14_text(
                    &mut stream,
                    config,
                    &base_font_name,
                    &bold_font_name,
                    base_font,
                    bold_font,
                    width,
                    height,
                    0.0,
                    0.0,
                );
            }
            #[cfg(feature = "visual")]
            FontSpec::Embedded { data, name } => {
                // Collect all text to prepare the font subset
                let all_text: String = config
                    .lines
                    .iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("");

                let prepared = prepare_embedded_font(data, name, &all_text)?;
                let font_name = "F1".to_string();

                render_embedded_text(
                    &mut stream,
                    config,
                    &font_name,
                    &prepared,
                    data,
                    width,
                    height,
                    0.0,
                    0.0,
                )?;

                embedded_fonts.push(EmbeddedFontResource {
                    resource_name: font_name,
                    font: prepared,
                });
            }
        }
    }

    // Restore graphics state
    write_op(&mut stream, "Q");

    Ok(AppearanceStream {
        content: stream,
        font_resources: fonts,
        #[cfg(feature = "visual")]
        embedded_font_resources: embedded_fonts,
        #[cfg(feature = "visual")]
        image_resources: Vec::new(),
        bbox: [0.0, 0.0, width, height],
    })
}

/// Build an appearance stream for the given visible signature configuration.
///
/// This is the main entry point. It dispatches to the appropriate builder
/// based on the layout type.
///
/// For `Custom` layouts, an [`AppearanceContext`] can be provided via
/// [`build_appearance_with_context`]. This function passes a default
/// (empty) context when encountering a `Custom` layout.
pub fn build_appearance(
    config: &VisibleSignatureConfig,
    page_width: f32,
    page_height: f32,
) -> Result<AppearanceStream, VisualError> {
    build_appearance_with_context(config, page_width, page_height, None)
}

/// Build an appearance stream with an optional [`AppearanceContext`] for custom renderers.
///
/// When `ctx` is `None` and the layout is `Custom`, a default context with
/// just the dimensions is created. For non-`Custom` layouts, `ctx` is ignored.
pub fn build_appearance_with_context(
    config: &VisibleSignatureConfig,
    page_width: f32,
    page_height: f32,
    ctx: Option<&AppearanceContext>,
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
        SignatureLayout::ImageOnly(image_config) => build_image_appearance(
            image_config,
            width,
            height,
            config.background_color.as_ref(),
            config.border.as_ref(),
        ),
        #[cfg(feature = "visual")]
        SignatureLayout::ImageAndText {
            image,
            text,
            arrangement,
        } => build_image_and_text_appearance(
            image,
            text,
            *arrangement,
            width,
            height,
            config.background_color.as_ref(),
            config.border.as_ref(),
        ),
        SignatureLayout::Custom(renderer) => {
            let default_ctx = AppearanceContext {
                width,
                height,
                signer_name: None,
                reason: None,
                location: None,
                date: None,
                contact_info: None,
            };
            let context = ctx.unwrap_or(&default_ctx);
            // Ensure context has correct dimensions
            let effective_ctx = AppearanceContext {
                width,
                height,
                signer_name: context.signer_name.clone(),
                reason: context.reason.clone(),
                location: context.location.clone(),
                date: context.date.clone(),
                contact_info: context.contact_info.clone(),
            };
            build_custom_appearance(
                renderer.as_ref(),
                &effective_ctx,
                width,
                height,
                config.background_color.as_ref(),
                config.border.as_ref(),
            )
        }
    }
}

/// Build an appearance stream from a custom [`AppearanceRenderer`].
///
/// Calls the renderer to produce PDF content stream bytes, then wraps
/// the result with optional background/border graphics. The renderer's
/// font resources are passed through to the returned [`AppearanceStream`].
fn build_custom_appearance(
    renderer: &dyn AppearanceRenderer,
    ctx: &AppearanceContext,
    width: f32,
    height: f32,
    background: Option<&Color>,
    border: Option<&Border>,
) -> Result<AppearanceStream, VisualError> {
    let custom_result = renderer.render(ctx)?;

    let mut stream = Vec::with_capacity(custom_result.content.len() + 256);

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

    // Append the renderer's content stream
    stream.extend_from_slice(&custom_result.content);

    // Restore graphics state
    write_op(&mut stream, "Q");

    Ok(AppearanceStream {
        content: stream,
        font_resources: custom_result.font_resources,
        #[cfg(feature = "visual")]
        embedded_font_resources: Vec::new(),
        #[cfg(feature = "visual")]
        image_resources: Vec::new(),
        bbox: [0.0, 0.0, width, height],
    })
}

/// Build an appearance stream for an image-only layout.
///
/// The image is scaled to fit within the given dimensions according to
/// the `ImageScale` setting. The content stream uses `cm` to transform
/// coordinates and `Do` to paint the image XObject.
#[cfg(feature = "visual")]
pub fn build_image_appearance(
    image_config: &ImageConfig,
    width: f32,
    height: f32,
    background: Option<&Color>,
    border: Option<&Border>,
) -> Result<AppearanceStream, VisualError> {
    let embedded = prepare_image(&image_config.data, image_config.format)?;

    let mut stream = Vec::with_capacity(512);

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

    // Calculate image placement based on scale mode
    let (img_w, img_h, img_x, img_y) =
        compute_image_placement(&image_config.scale, &embedded, width, height);

    // Transform: scale from 1x1 image space to display size and position
    write_fmt(
        &mut stream,
        &format!("{:.4} 0 0 {:.4} {:.4} {:.4} cm", img_w, img_h, img_x, img_y),
    );
    write_op(&mut stream, "/Im1 Do");

    // Restore graphics state
    write_op(&mut stream, "Q");

    let image_resource = ImageResource {
        resource_name: "Im1".to_string(),
        image: embedded,
    };

    Ok(AppearanceStream {
        content: stream,
        font_resources: Vec::new(),
        embedded_font_resources: Vec::new(),
        image_resources: vec![image_resource],
        bbox: [0.0, 0.0, width, height],
    })
}

/// Build an appearance stream for a combined image + text layout.
///
/// The image and text are arranged according to the `Arrangement` setting,
/// splitting the available space between them.
#[cfg(feature = "visual")]
pub fn build_image_and_text_appearance(
    image_config: &ImageConfig,
    text_config: &TextConfig,
    arrangement: Arrangement,
    width: f32,
    height: f32,
    background: Option<&Color>,
    border: Option<&Border>,
) -> Result<AppearanceStream, VisualError> {
    let embedded = prepare_image(&image_config.data, image_config.format)?;

    let mut stream = Vec::with_capacity(1024);

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

    // Split space between image and text based on arrangement.
    // Use 40% for image, 60% for text as a reasonable default ratio.
    let image_ratio = 0.4;

    let (img_area, text_area) = match arrangement {
        Arrangement::ImageLeftTextRight => {
            let img_w = width * image_ratio;
            let text_w = width - img_w;
            // (x, y, w, h) for each area
            ((0.0, 0.0, img_w, height), (img_w, 0.0, text_w, height))
        }
        Arrangement::ImageRightTextLeft => {
            let text_w = width * (1.0 - image_ratio);
            let img_w = width - text_w;
            ((text_w, 0.0, img_w, height), (0.0, 0.0, text_w, height))
        }
        Arrangement::ImageTopTextBottom => {
            let img_h = height * image_ratio;
            let text_h = height - img_h;
            // Image at top (higher y), text at bottom (lower y)
            ((0.0, text_h, width, img_h), (0.0, 0.0, width, text_h))
        }
        Arrangement::ImageBottomTextTop => {
            let text_h = height * (1.0 - image_ratio);
            let img_h = height - text_h;
            ((0.0, 0.0, width, img_h), (0.0, img_h, width, text_h))
        }
    };

    // Render image in its area
    let (img_w, img_h, img_x, img_y) =
        compute_image_placement(&image_config.scale, &embedded, img_area.2, img_area.3);
    // Offset by the area origin
    let img_x = img_x + img_area.0;
    let img_y = img_y + img_area.1;

    write_fmt(
        &mut stream,
        &format!("{:.4} 0 0 {:.4} {:.4} {:.4} cm", img_w, img_h, img_x, img_y),
    );
    write_op(&mut stream, "/Im1 Do");

    // Reset CTM for text rendering — we need to undo the cm transform.
    // Simplest: restore and save again.
    write_op(&mut stream, "Q");
    write_op(&mut stream, "q");

    // Render text in its area using a clipped/translated text block
    let text_result = render_text_in_area(
        &mut stream,
        text_config,
        text_area.0,
        text_area.1,
        text_area.2,
        text_area.3,
    )?;

    // Restore graphics state
    write_op(&mut stream, "Q");

    let image_resource = ImageResource {
        resource_name: "Im1".to_string(),
        image: embedded,
    };

    Ok(AppearanceStream {
        content: stream,
        font_resources: text_result.font_resources,
        embedded_font_resources: text_result.embedded_font_resources,
        image_resources: vec![image_resource],
        bbox: [0.0, 0.0, width, height],
    })
}

/// Compute image placement (display width, height, x, y) within available space.
#[cfg(feature = "visual")]
fn compute_image_placement(
    scale: &ImageScale,
    embedded: &EmbeddedImage,
    avail_width: f32,
    avail_height: f32,
) -> (f32, f32, f32, f32) {
    match scale {
        ImageScale::Stretch => (avail_width, avail_height, 0.0, 0.0),
        ImageScale::Fixed { width, height } => {
            // Center the fixed-size image in the available space
            let x = (avail_width - width) / 2.0;
            let y = (avail_height - height) / 2.0;
            (*width, *height, x.max(0.0), y.max(0.0))
        }
        ImageScale::FitPreserveAspect => {
            let img_w = embedded.width as f32;
            let img_h = embedded.height as f32;
            if img_w <= 0.0 || img_h <= 0.0 {
                return (avail_width, avail_height, 0.0, 0.0);
            }
            let aspect = img_w / img_h;
            let (disp_w, disp_h) = if avail_width / avail_height > aspect {
                // Available space is wider than image — fit to height
                let h = avail_height;
                let w = h * aspect;
                (w, h)
            } else {
                // Available space is taller than image — fit to width
                let w = avail_width;
                let h = w / aspect;
                (w, h)
            };
            // Center in available space
            let x = (avail_width - disp_w) / 2.0;
            let y = (avail_height - disp_h) / 2.0;
            (disp_w, disp_h, x, y)
        }
    }
}

/// Result of rendering text within a sub-area.
#[cfg(feature = "visual")]
struct TextInAreaResult {
    /// Standard 14 font resources used.
    font_resources: Vec<(String, String)>,
    /// Embedded font resources used.
    embedded_font_resources: Vec<EmbeddedFontResource>,
}

/// Render text lines within a sub-area, returning font resources used.
///
/// This is similar to `build_text_appearance` but renders at an offset
/// position within the parent content stream.
#[cfg(feature = "visual")]
fn render_text_in_area(
    stream: &mut Vec<u8>,
    config: &TextConfig,
    area_x: f32,
    area_y: f32,
    area_width: f32,
    area_height: f32,
) -> Result<TextInAreaResult, VisualError> {
    let mut fonts: Vec<(String, String)> = Vec::new();
    let mut embedded_fonts: Vec<EmbeddedFontResource> = Vec::new();

    match &config.font {
        FontSpec::Standard14(base_font_std14) => {
            let base_font = *base_font_std14;
            let bold_font = base_font.bold_variant();

            let base_font_name = "F1".to_string();
            fonts.push((base_font_name.clone(), base_font.pdf_name().to_string()));

            let bold_font_name = if bold_font != base_font {
                let name = "F2".to_string();
                fonts.push((name.clone(), bold_font.pdf_name().to_string()));
                name
            } else {
                base_font_name.clone()
            };

            render_standard14_text(
                stream,
                config,
                &base_font_name,
                &bold_font_name,
                base_font,
                bold_font,
                area_width,
                area_height,
                area_x,
                area_y,
            );
        }
        #[cfg(feature = "visual")]
        FontSpec::Embedded { data, name } => {
            let all_text: String = config
                .lines
                .iter()
                .map(|l| l.text.as_str())
                .collect::<Vec<_>>()
                .join("");

            let prepared = prepare_embedded_font(data, name, &all_text)?;
            let font_name = "F1".to_string();

            render_embedded_text(
                stream,
                config,
                &font_name,
                &prepared,
                data,
                area_width,
                area_height,
                area_x,
                area_y,
            )?;

            embedded_fonts.push(EmbeddedFontResource {
                resource_name: font_name,
                font: prepared,
            });
        }
    }

    Ok(TextInAreaResult {
        font_resources: fonts,
        embedded_font_resources: embedded_fonts,
    })
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
    let font_size = max_font_size.clamp(5.0, 10.0); // clamp between 5 and 10

    let config = TextConfig {
        lines,
        font_size,
        ..TextConfig::default()
    };

    build_text_appearance(&config, width, height, Some(&Color::white()), None)
}

// --- Text rendering helpers ---

/// Render text lines using a Standard 14 font into the given stream.
///
/// This handles font selection (base + bold variant), alignment, color,
/// and vertical centering within the available area.
#[allow(clippy::too_many_arguments)]
fn render_standard14_text(
    stream: &mut Vec<u8>,
    config: &TextConfig,
    base_font_name: &str,
    bold_font_name: &str,
    base_font: Standard14Font,
    bold_font: Standard14Font,
    width: f32,
    height: f32,
    offset_x: f32,
    offset_y: f32,
) {
    if config.lines.is_empty() {
        return;
    }

    write_op(stream, "BT");

    let padding = config.padding;
    let usable_width = width - 2.0 * padding;
    let font_size = config.font_size;
    let line_height = font_size * config.line_spacing;

    let total_text_height = config.lines.len() as f32 * line_height;
    let ascent_ratio = FontMetrics::ascent(base_font) as f32 / 1000.0;

    let start_y = if total_text_height < (height - 2.0 * padding) {
        let extra = (height - 2.0 * padding) - total_text_height;
        offset_y + height - padding - extra / 2.0 - font_size * ascent_ratio
    } else {
        offset_y + height - padding - font_size * ascent_ratio
    };

    for (i, line) in config.lines.iter().enumerate() {
        let effective_size = line.font_size.unwrap_or(font_size);
        let effective_font = if line.bold { bold_font } else { base_font };
        let font_ref = if line.bold {
            bold_font_name
        } else {
            base_font_name
        };

        write_fmt(stream, &format!("/{} {:.1} Tf", font_ref, effective_size));

        let text_color = line.color.as_ref().unwrap_or(&config.color);
        write_fmt(
            stream,
            &format!(
                "{:.3} {:.3} {:.3} rg",
                text_color.r, text_color.g, text_color.b
            ),
        );

        let text_width = FontMetrics::string_width(effective_font, &line.text, effective_size);
        let x = offset_x
            + match config.alignment {
                TextAlignment::Left => padding,
                TextAlignment::Center => padding + (usable_width - text_width) / 2.0,
                TextAlignment::Right => padding + usable_width - text_width,
            };

        let y = start_y - i as f32 * line_height;

        write_fmt(stream, &format!("{:.2} {:.2} Td", x, y));
        write_fmt(stream, &format!("{} Tj", encode_pdf_text(&line.text)));

        if i + 1 < config.lines.len() {
            write_fmt(stream, &format!("{:.2} {:.2} Td", -x, -y));
        }
    }

    write_op(stream, "ET");
}

/// Render text lines using an embedded CID font into the given stream.
///
/// Similar layout logic to `render_standard14_text` but uses `embedded_string_width()`
/// for width computation and `encode_cid_text()` for hex-encoded CID text rendering.
#[cfg(feature = "visual")]
#[allow(clippy::too_many_arguments)]
fn render_embedded_text(
    stream: &mut Vec<u8>,
    config: &TextConfig,
    font_name: &str,
    prepared: &PreparedEmbeddedFont,
    font_data: &[u8],
    width: f32,
    height: f32,
    offset_x: f32,
    offset_y: f32,
) -> Result<(), VisualError> {
    if config.lines.is_empty() {
        return Ok(());
    }

    write_op(stream, "BT");

    let padding = config.padding;
    let usable_width = width - 2.0 * padding;
    let font_size = config.font_size;
    let line_height = font_size * config.line_spacing;

    let total_text_height = config.lines.len() as f32 * line_height;
    let ascent_ratio = embedded_ascent_1000(&prepared.info) as f32 / 1000.0;

    let start_y = if total_text_height < (height - 2.0 * padding) {
        let extra = (height - 2.0 * padding) - total_text_height;
        offset_y + height - padding - extra / 2.0 - font_size * ascent_ratio
    } else {
        offset_y + height - padding - font_size * ascent_ratio
    };

    for (i, line) in config.lines.iter().enumerate() {
        let effective_size = line.font_size.unwrap_or(font_size);

        write_fmt(stream, &format!("/{} {:.1} Tf", font_name, effective_size));

        let text_color = line.color.as_ref().unwrap_or(&config.color);
        write_fmt(
            stream,
            &format!(
                "{:.3} {:.3} {:.3} rg",
                text_color.r, text_color.g, text_color.b
            ),
        );

        let text_width = embedded_string_width(font_data, &line.text, effective_size)?;
        let x = offset_x
            + match config.alignment {
                TextAlignment::Left => padding,
                TextAlignment::Center => padding + (usable_width - text_width) / 2.0,
                TextAlignment::Right => padding + usable_width - text_width,
            };

        let y = start_y - i as f32 * line_height;

        write_fmt(stream, &format!("{:.2} {:.2} Td", x, y));

        // Encode text as hex CID string and use Tj operator
        let cid_text = encode_cid_text(&line.text, &prepared.char_to_cid);
        write_fmt(stream, &format!("{} Tj", cid_text));

        if i + 1 < config.lines.len() {
            write_fmt(stream, &format!("{:.2} {:.2} Td", -x, -y));
        }
    }

    write_op(stream, "ET");
    Ok(())
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

#[cfg(all(test, feature = "visual"))]
mod image_tests {
    use super::*;

    /// Helper: create a small test JPEG in memory.
    fn test_jpeg_bytes() -> Vec<u8> {
        use image::{ImageFormat as ImgFmt, RgbImage};
        use std::io::Cursor;
        let img = RgbImage::from_pixel(10, 10, image::Rgb([0, 100, 200]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Jpeg).unwrap();
        buf.into_inner()
    }

    /// Helper: create a small test PNG (with alpha) in memory.
    fn test_png_rgba_bytes() -> Vec<u8> {
        use image::{ImageFormat as ImgFmt, RgbaImage};
        use std::io::Cursor;
        let img = RgbaImage::from_pixel(8, 8, image::Rgba([255, 0, 0, 180]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Png).unwrap();
        buf.into_inner()
    }

    /// Helper: create a small test PNG (no alpha) in memory.
    fn test_png_rgb_bytes() -> Vec<u8> {
        use image::{ImageFormat as ImgFmt, RgbImage};
        use std::io::Cursor;
        let img = RgbImage::from_pixel(6, 4, image::Rgb([0, 255, 0]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Png).unwrap();
        buf.into_inner()
    }

    #[test]
    fn test_build_image_appearance_jpeg() {
        let jpeg_data = test_jpeg_bytes();
        let config = ImageConfig {
            data: jpeg_data,
            format: ImageFormat::Jpeg,
            scale: ImageScale::FitPreserveAspect,
        };

        let result = build_image_appearance(&config, 200.0, 100.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // Should contain graphics state save/restore
        assert!(content.contains("q"));
        assert!(content.contains("Q"));
        // Should contain cm (transform) and Do (paint)
        assert!(content.contains("cm"));
        assert!(content.contains("/Im1 Do"));
        // Should have one image resource
        assert_eq!(result.image_resources.len(), 1);
        assert_eq!(result.image_resources[0].resource_name, "Im1");
        assert_eq!(result.image_resources[0].image.filter, "DCTDecode");
        // No fonts needed
        assert!(result.font_resources.is_empty());
        assert_eq!(result.bbox, [0.0, 0.0, 200.0, 100.0]);
    }

    #[test]
    fn test_build_image_appearance_png_rgba() {
        let png_data = test_png_rgba_bytes();
        let config = ImageConfig {
            data: png_data,
            format: ImageFormat::Png,
            scale: ImageScale::Stretch,
        };

        let result = build_image_appearance(&config, 150.0, 75.0, None, None).unwrap();

        assert_eq!(result.image_resources.len(), 1);
        let img = &result.image_resources[0].image;
        assert!(img.has_alpha);
        assert!(img.alpha_data.is_some());
        assert_eq!(img.filter, "FlateDecode");
        assert_eq!(img.color_space, "DeviceRGB");
    }

    #[test]
    fn test_build_image_appearance_with_background_and_border() {
        let jpeg_data = test_jpeg_bytes();
        let config = ImageConfig {
            data: jpeg_data,
            format: ImageFormat::Jpeg,
            scale: ImageScale::Stretch,
        };

        let bg = Color::white();
        let border = Border::default();
        let result =
            build_image_appearance(&config, 100.0, 50.0, Some(&bg), Some(&border)).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // Should have background fill
        assert!(content.contains("re f"));
        // Should have border stroke
        assert!(content.contains("re S"));
    }

    #[test]
    fn test_build_image_appearance_fixed_scale() {
        let jpeg_data = test_jpeg_bytes();
        let config = ImageConfig {
            data: jpeg_data,
            format: ImageFormat::Jpeg,
            scale: ImageScale::Fixed {
                width: 50.0,
                height: 30.0,
            },
        };

        let result = build_image_appearance(&config, 200.0, 100.0, None, None).unwrap();
        let content = String::from_utf8_lossy(&result.content);

        // The cm command should contain 50 and 30 as the display size
        assert!(content.contains("50.0000 0 0 30.0000"));
    }

    #[test]
    fn test_build_image_and_text_image_left_text_right() {
        let jpeg_data = test_jpeg_bytes();
        let image_config = ImageConfig {
            data: jpeg_data,
            format: ImageFormat::Jpeg,
            scale: ImageScale::FitPreserveAspect,
        };
        let text_config = TextConfig {
            lines: vec![
                TextLine::new("Signed by Test").bold(),
                TextLine::new("Date: 2026-01-01"),
            ],
            font_size: 8.0,
            ..TextConfig::default()
        };

        let result = build_image_and_text_appearance(
            &image_config,
            &text_config,
            Arrangement::ImageLeftTextRight,
            300.0,
            100.0,
            None,
            None,
        )
        .unwrap();

        let content = String::from_utf8_lossy(&result.content);

        // Should have image rendering
        assert!(content.contains("/Im1 Do"));
        // Should have text rendering
        assert!(content.contains("BT"));
        assert!(content.contains("ET"));
        assert!(content.contains("Signed by Test"));
        // Should have image resource
        assert_eq!(result.image_resources.len(), 1);
        // Should have font resources
        assert!(!result.font_resources.is_empty());
    }

    #[test]
    fn test_build_image_and_text_image_top_text_bottom() {
        let png_data = test_png_rgb_bytes();
        let image_config = ImageConfig {
            data: png_data,
            format: ImageFormat::Png,
            scale: ImageScale::FitPreserveAspect,
        };
        let text_config = TextConfig {
            lines: vec![TextLine::new("Approved")],
            ..TextConfig::default()
        };

        let result = build_image_and_text_appearance(
            &image_config,
            &text_config,
            Arrangement::ImageTopTextBottom,
            200.0,
            150.0,
            Some(&Color::white()),
            Some(&Border::default()),
        )
        .unwrap();

        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("/Im1 Do"));
        assert!(content.contains("Approved"));
        assert_eq!(result.bbox, [0.0, 0.0, 200.0, 150.0]);
    }

    #[test]
    fn test_build_image_and_text_all_arrangements() {
        let jpeg_data = test_jpeg_bytes();
        let text_config = TextConfig {
            lines: vec![TextLine::new("Test")],
            ..TextConfig::default()
        };

        for arrangement in [
            Arrangement::ImageLeftTextRight,
            Arrangement::ImageRightTextLeft,
            Arrangement::ImageTopTextBottom,
            Arrangement::ImageBottomTextTop,
        ] {
            let image_config = ImageConfig {
                data: jpeg_data.clone(),
                format: ImageFormat::Jpeg,
                scale: ImageScale::FitPreserveAspect,
            };

            let result = build_image_and_text_appearance(
                &image_config,
                &text_config,
                arrangement,
                200.0,
                100.0,
                None,
                None,
            );

            assert!(result.is_ok(), "Failed for arrangement {:?}", arrangement);
            let appearance = result.unwrap();
            assert!(!appearance.content.is_empty());
            assert_eq!(appearance.image_resources.len(), 1);
        }
    }

    #[test]
    fn test_compute_image_placement_stretch() {
        let embedded = EmbeddedImage {
            data: vec![],
            width: 100,
            height: 50,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "DCTDecode".to_string(),
            has_alpha: false,
            alpha_data: None,
        };

        let (w, h, x, y) = compute_image_placement(&ImageScale::Stretch, &embedded, 200.0, 100.0);
        assert_eq!((w, h, x, y), (200.0, 100.0, 0.0, 0.0));
    }

    #[test]
    fn test_compute_image_placement_fit_wider_image() {
        // Image is wider than available space (aspect ratio)
        let embedded = EmbeddedImage {
            data: vec![],
            width: 200,
            height: 100,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "DCTDecode".to_string(),
            has_alpha: false,
            alpha_data: None,
        };

        // Available space: 100x100 (square). Image 2:1 ratio → fits to width.
        let (w, h, x, y) =
            compute_image_placement(&ImageScale::FitPreserveAspect, &embedded, 100.0, 100.0);
        assert!((w - 100.0).abs() < 0.01);
        assert!((h - 50.0).abs() < 0.01);
        // Centered vertically: y = (100 - 50) / 2 = 25
        assert!((y - 25.0).abs() < 0.01);
        assert!((x - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_compute_image_placement_fit_taller_image() {
        // Image is taller than available space (aspect ratio)
        let embedded = EmbeddedImage {
            data: vec![],
            width: 50,
            height: 200,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "DCTDecode".to_string(),
            has_alpha: false,
            alpha_data: None,
        };

        // Available space: 100x100. Image 1:4 ratio → fits to height.
        let (w, h, x, _y) =
            compute_image_placement(&ImageScale::FitPreserveAspect, &embedded, 100.0, 100.0);
        assert!((h - 100.0).abs() < 0.01);
        assert!((w - 25.0).abs() < 0.01);
        // Centered horizontally: x = (100 - 25) / 2 = 37.5
        assert!((x - 37.5).abs() < 0.01);
    }

    #[test]
    fn test_compute_image_placement_fixed() {
        let embedded = EmbeddedImage {
            data: vec![],
            width: 100,
            height: 100,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "DCTDecode".to_string(),
            has_alpha: false,
            alpha_data: None,
        };

        let (w, h, x, y) = compute_image_placement(
            &ImageScale::Fixed {
                width: 60.0,
                height: 40.0,
            },
            &embedded,
            200.0,
            100.0,
        );
        assert_eq!(w, 60.0);
        assert_eq!(h, 40.0);
        // Centered: x = (200 - 60) / 2 = 70, y = (100 - 40) / 2 = 30
        assert!((x - 70.0).abs() < 0.01);
        assert!((y - 30.0).abs() < 0.01);
    }

    #[test]
    fn test_build_appearance_dispatches_to_image_only() {
        let jpeg_data = test_jpeg_bytes();
        let config = VisibleSignatureConfig {
            page: 0,
            rect: SignatureRect::Absolute {
                llx: 50.0,
                lly: 700.0,
                urx: 250.0,
                ury: 780.0,
            },
            layout: SignatureLayout::ImageOnly(ImageConfig {
                data: jpeg_data,
                format: ImageFormat::Jpeg,
                scale: ImageScale::FitPreserveAspect,
            }),
            background_color: None,
            border: None,
        };

        let result = build_appearance(&config, 612.0, 792.0).unwrap();
        assert!(!result.content.is_empty());
        assert_eq!(result.image_resources.len(), 1);
        assert!(result.font_resources.is_empty());
    }

    #[test]
    fn test_build_appearance_dispatches_to_image_and_text() {
        let jpeg_data = test_jpeg_bytes();
        let config = VisibleSignatureConfig {
            page: 0,
            rect: SignatureRect::Absolute {
                llx: 50.0,
                lly: 650.0,
                urx: 350.0,
                ury: 750.0,
            },
            layout: SignatureLayout::ImageAndText {
                image: ImageConfig {
                    data: jpeg_data,
                    format: ImageFormat::Jpeg,
                    scale: ImageScale::FitPreserveAspect,
                },
                text: TextConfig {
                    lines: vec![TextLine::new("Signed")],
                    ..TextConfig::default()
                },
                arrangement: Arrangement::ImageLeftTextRight,
            },
            background_color: Some(Color::white()),
            border: Some(Border::default()),
        };

        let result = build_appearance(&config, 612.0, 792.0).unwrap();
        let content = String::from_utf8_lossy(&result.content);
        assert!(content.contains("/Im1 Do"));
        assert!(content.contains("Signed"));
        assert_eq!(result.image_resources.len(), 1);
        assert!(!result.font_resources.is_empty());
    }
}
