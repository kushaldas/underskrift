//! JPEG/PNG embedding as PDF XObject.
//!
//! This module handles embedding images into PDF signature appearances.
//! JPEG images are passed through directly (PDF natively supports JPEG/DCT).
//! PNG images are decoded and re-encoded as raw samples with optional
//! deflate compression.
//!
//! Image support requires the `visual` feature flag.

#[cfg(feature = "visual")]
use super::layout::ImageFormat;

/// Information about an embedded image, ready for PDF XObject creation.
#[cfg(feature = "visual")]
#[derive(Debug)]
pub struct EmbeddedImage {
    /// Raw image data for the PDF stream.
    /// For JPEG: the original JPEG data (DCTDecode filter).
    /// For PNG: decoded RGB/RGBA samples (FlateDecode or raw).
    pub data: Vec<u8>,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Bits per color component (typically 8).
    pub bits_per_component: u8,
    /// PDF color space name ("DeviceRGB", "DeviceGray", "DeviceCMYK").
    pub color_space: String,
    /// PDF stream filter name ("DCTDecode" for JPEG, "FlateDecode" for PNG).
    pub filter: String,
    /// Whether the image has an alpha channel (requires SMask).
    pub has_alpha: bool,
    /// Alpha channel data (if has_alpha is true). Separate stream for SMask.
    pub alpha_data: Option<Vec<u8>>,
}

/// Decode image data and prepare it for PDF embedding.
///
/// For JPEG images, the data is passed through directly since PDF
/// natively supports DCT (JPEG) compressed streams.
///
/// For PNG images, the image crate decodes the PNG and we re-encode
/// the raw samples for PDF embedding.
#[cfg(feature = "visual")]
pub fn prepare_image(
    data: &[u8],
    format: ImageFormat,
) -> Result<EmbeddedImage, crate::error::VisualError> {
    match format {
        ImageFormat::Jpeg => prepare_jpeg(data),
        ImageFormat::Png => prepare_png(data),
    }
}

/// Prepare a JPEG image for PDF embedding.
///
/// JPEG is passed through directly since PDF supports DCTDecode.
/// We just need to extract dimensions and color space from the header.
#[cfg(feature = "visual")]
fn prepare_jpeg(data: &[u8]) -> Result<EmbeddedImage, crate::error::VisualError> {
    use image::ImageReader;
    use std::io::Cursor;

    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| {
            crate::error::VisualError::ImageError(format!("Failed to read JPEG: {}", e))
        })?;

    let img = reader.decode().map_err(|e| {
        crate::error::VisualError::ImageError(format!("Failed to decode JPEG: {}", e))
    })?;

    let width = img.width();
    let height = img.height();

    // Determine color space from the decoded image
    let color_space = match img.color() {
        image::ColorType::L8 | image::ColorType::L16 => "DeviceGray",
        _ => "DeviceRGB",
    };

    Ok(EmbeddedImage {
        data: data.to_vec(), // pass through original JPEG data
        width,
        height,
        bits_per_component: 8,
        color_space: color_space.to_string(),
        filter: "DCTDecode".to_string(),
        has_alpha: false,
        alpha_data: None,
    })
}

/// Prepare a PNG image for PDF embedding.
///
/// PNG is decoded into raw RGB samples and then stored with FlateDecode
/// compression. Alpha channel is separated into an SMask stream.
#[cfg(feature = "visual")]
fn prepare_png(data: &[u8]) -> Result<EmbeddedImage, crate::error::VisualError> {
    use image::ImageReader;
    use std::io::Cursor;

    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| crate::error::VisualError::ImageError(format!("Failed to read PNG: {}", e)))?;

    let img = reader.decode().map_err(|e| {
        crate::error::VisualError::ImageError(format!("Failed to decode PNG: {}", e))
    })?;

    let width = img.width();
    let height = img.height();
    let has_alpha = matches!(
        img.color(),
        image::ColorType::La8
            | image::ColorType::La16
            | image::ColorType::Rgba8
            | image::ColorType::Rgba16
    );

    if has_alpha {
        let rgba = img.into_rgba8();
        let mut rgb_data = Vec::with_capacity((width * height * 3) as usize);
        let mut alpha_data = Vec::with_capacity((width * height) as usize);

        for pixel in rgba.pixels() {
            rgb_data.push(pixel[0]);
            rgb_data.push(pixel[1]);
            rgb_data.push(pixel[2]);
            alpha_data.push(pixel[3]);
        }

        Ok(EmbeddedImage {
            data: rgb_data,
            width,
            height,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "FlateDecode".to_string(),
            has_alpha: true,
            alpha_data: Some(alpha_data),
        })
    } else {
        let rgb = img.into_rgb8();
        let rgb_data = rgb.into_raw();

        Ok(EmbeddedImage {
            data: rgb_data,
            width,
            height,
            bits_per_component: 8,
            color_space: "DeviceRGB".to_string(),
            filter: "FlateDecode".to_string(),
            has_alpha: false,
            alpha_data: None,
        })
    }
}

#[cfg(all(test, feature = "visual"))]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_jpeg_minimal() {
        // Create a minimal valid JPEG using the image crate
        use image::{ImageFormat as ImgFmt, RgbImage};
        use std::io::Cursor;

        let img = RgbImage::from_pixel(2, 2, image::Rgb([255, 0, 0]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Jpeg).unwrap();
        let jpeg_data = buf.into_inner();

        let embedded = prepare_image(&jpeg_data, ImageFormat::Jpeg).unwrap();
        assert_eq!(embedded.width, 2);
        assert_eq!(embedded.height, 2);
        assert_eq!(embedded.filter, "DCTDecode");
        assert_eq!(embedded.color_space, "DeviceRGB");
        assert!(!embedded.has_alpha);
    }

    #[test]
    fn test_prepare_png_rgb() {
        use image::{ImageFormat as ImgFmt, RgbImage};
        use std::io::Cursor;

        let img = RgbImage::from_pixel(3, 3, image::Rgb([0, 128, 255]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Png).unwrap();
        let png_data = buf.into_inner();

        let embedded = prepare_image(&png_data, ImageFormat::Png).unwrap();
        assert_eq!(embedded.width, 3);
        assert_eq!(embedded.height, 3);
        assert_eq!(embedded.filter, "FlateDecode");
        assert!(!embedded.has_alpha);
        assert_eq!(embedded.data.len(), 3 * 3 * 3); // 3x3 pixels, 3 channels
    }

    #[test]
    fn test_prepare_png_rgba() {
        use image::{ImageFormat as ImgFmt, RgbaImage};
        use std::io::Cursor;

        let img = RgbaImage::from_pixel(2, 2, image::Rgba([255, 0, 0, 128]));
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImgFmt::Png).unwrap();
        let png_data = buf.into_inner();

        let embedded = prepare_image(&png_data, ImageFormat::Png).unwrap();
        assert_eq!(embedded.width, 2);
        assert_eq!(embedded.height, 2);
        assert!(embedded.has_alpha);
        assert!(embedded.alpha_data.is_some());
        assert_eq!(embedded.data.len(), 2 * 2 * 3); // RGB only
        assert_eq!(embedded.alpha_data.unwrap().len(), 2 * 2); // Alpha only
    }
}
