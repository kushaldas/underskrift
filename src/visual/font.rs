//! Standard fonts and TrueType/OpenType font subsetting.
//!
//! This module provides font metrics for the PDF standard 14 fonts,
//! which are guaranteed to be available in all PDF viewers without embedding.
//!
//! The metrics are needed to compute text widths for proper layout and
//! alignment within signature appearance streams.

use super::layout::Standard14Font;

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
