//! High-level PDF signer builder and orchestrator.
//!
//! `PdfSigner` is the main entry point for signing PDFs. It uses a builder
//! pattern to configure signing options, then orchestrates the full flow:
//! parse PDF -> prepare signature structures -> compute hash -> sign -> embed.

use lopdf::{Document, Object};

#[cfg(feature = "visual")]
use lopdf::{Dictionary, Stream};

use crate::cms::builder::{CmsProfile, PdfCmsBuilder, SigningTimePlacement};
use crate::core::acroform;
use crate::core::incremental::IncrementalWriter;
use crate::core::parser;
use crate::core::sig_dict::{self, SigSubFilter};
use crate::core::sig_field::{self, SignatureFieldOptions};
use crate::crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm};
use crate::crypto::traits::CryptoSigner;
use crate::error::{CoreError, PdfSignError};

#[cfg(feature = "visual")]
use crate::visual::{self, AppearanceContext, SignatureLayout, VisibleSignatureConfig};

/// PAdES conformance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadesLevel {
    /// PAdES Baseline B-B (basic signature)
    BB,
    /// PAdES Baseline B-T (with timestamp)
    BT,
    /// PAdES Baseline B-LT (with LTV data)
    BLT,
    /// PAdES Baseline B-LTA (with archive timestamp)
    BLTA,
}

impl Default for PadesLevel {
    fn default() -> Self {
        Self::BB
    }
}

/// SubFilter selection for the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    /// PAdES: ETSI.CAdES.detached
    Pades,
    /// Traditional: adbe.pkcs7.detached
    Pkcs7,
}

impl Default for SubFilter {
    fn default() -> Self {
        Self::Pades
    }
}

impl From<SubFilter> for SigSubFilter {
    fn from(sf: SubFilter) -> Self {
        match sf {
            SubFilter::Pades => SigSubFilter::EtsiCadesDetached,
            SubFilter::Pkcs7 => SigSubFilter::AdbePkcs7Detached,
        }
    }
}

/// Configuration options for PDF signing.
#[derive(Debug, Clone)]
pub struct SigningOptions {
    /// The signature sub-filter to use
    pub sub_filter: SubFilter,
    /// PAdES conformance level (only relevant when sub_filter is Pades)
    pub pades_level: PadesLevel,
    /// Digest algorithm
    pub digest_algorithm: DigestAlgorithm,
    /// Signature field name
    pub field_name: String,
    /// Page to place the signature annotation (0-indexed)
    pub page: u32,
    /// Reason for signing
    pub reason: Option<String>,
    /// Signer location
    pub location: Option<String>,
    /// Signer contact info
    pub contact_info: Option<String>,
    /// Size to reserve for the /Contents hex string (in bytes, not hex chars).
    /// Default is 8192 bytes (16384 hex chars). Increase for large cert chains
    /// or if timestamps are included.
    pub content_size: usize,
    /// TSA URL for timestamping (required for B-T and above)
    #[cfg(feature = "tsp")]
    pub tsa_url: Option<String>,
    /// Whether this is a certification signature (first signature with DocMDP)
    pub certify: bool,
    /// Algorithm registry for validating that the signer's algorithms are allowed.
    ///
    /// When set, the signing pipeline will validate the signer's digest and
    /// signature algorithms against this registry before signing. If `None`,
    /// all algorithms are accepted (no validation).
    pub algorithm_registry: Option<AlgorithmRegistry>,
    /// Visible signature configuration.
    ///
    /// When set, a visible signature appearance is generated and embedded as
    /// a Form XObject in the signature annotation. The signature will be
    /// visible on the specified page at the specified rectangle.
    ///
    /// When `None`, an invisible signature is created (zero-size annotation).
    /// Requires the `visual` feature flag for image-based appearances.
    #[cfg(feature = "visual")]
    pub visible_signature: Option<VisibleSignatureConfig>,
    /// CMS signing time to embed in the CMS SignedData structure.
    ///
    /// When set, the `signingTime` attribute (OID 1.2.840.113549.1.9.5) is
    /// placed according to `signing_time_placement`. When `None` (default),
    /// no `signingTime` attribute is added to the CMS structure at all.
    ///
    /// This is distinct from the PDF `/M` dictionary field (which is unsigned).
    pub cms_signing_time: Option<chrono::NaiveDateTime>,
    /// Controls where the `signingTime` CMS attribute is placed.
    ///
    /// Only takes effect when `cms_signing_time` is set. See
    /// [`SigningTimePlacement`] for the available options.
    ///
    /// Defaults to `SigningTimePlacement::Signed`.
    pub signing_time_placement: SigningTimePlacement,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            sub_filter: SubFilter::default(),
            pades_level: PadesLevel::default(),
            digest_algorithm: DigestAlgorithm::default(),
            field_name: "Signature1".to_string(),
            page: 0,
            reason: None,
            location: None,
            contact_info: None,
            content_size: 8192,
            #[cfg(feature = "tsp")]
            tsa_url: None,
            certify: false,
            algorithm_registry: None,
            #[cfg(feature = "visual")]
            visible_signature: None,
            cms_signing_time: None,
            signing_time_placement: SigningTimePlacement::default(),
        }
    }
}

/// High-level PDF signer.
///
/// # Example
///
/// ```no_run
/// use underskrift::{PdfSigner, SigningOptions, SoftwareSigner};
///
/// # async fn example() -> Result<(), underskrift::PdfSignError> {
/// let pdf = std::fs::read("document.pdf")?;
/// let signer = SoftwareSigner::from_pkcs12_file("key.p12", "pass")?;
///
/// let signed = PdfSigner::new()
///     .options(SigningOptions::default())
///     .sign(&pdf, &signer)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct PdfSigner {
    options: SigningOptions,
}

impl PdfSigner {
    /// Create a new PdfSigner with default options.
    pub fn new() -> Self {
        Self {
            options: SigningOptions::default(),
        }
    }

    /// Set signing options.
    pub fn options(mut self, options: SigningOptions) -> Self {
        self.options = options;
        self
    }

    /// Sign a PDF document.
    ///
    /// Takes the original PDF bytes and a signer implementation.
    /// Returns the signed PDF bytes (original + incremental update).
    ///
    /// # Flow
    ///
    /// 1. Parse the PDF with lopdf
    /// 2. Create signature dictionary with ByteRange/Contents placeholders
    /// 3. Create signature field (combined form field + widget annotation)
    /// 4. Update AcroForm + page annotations
    /// 5. Write incremental update with custom byte-level writer
    /// 6. Compute hash of ByteRange-selected bytes
    /// 7. Build CMS SignedData with the hash
    /// 8. Inject signature into /Contents and backpatch ByteRange
    pub async fn sign(
        &self,
        pdf_data: &[u8],
        signer: &dyn CryptoSigner,
    ) -> Result<Vec<u8>, PdfSignError> {
        // Step 0: Validate algorithms against registry if configured
        if let Some(registry) = &self.options.algorithm_registry {
            registry
                .validate(signer.signature_algorithm(), signer.digest_algorithm())
                .map_err(|msg| PdfSignError::AlgorithmNotAllowed(msg))?;
        }

        // Step 1: Parse the PDF
        let mut doc = Document::load_mem(pdf_data)
            .map_err(|e| CoreError::Lopdf(e))?;

        // Step 2: Extract metadata needed for incremental writer
        let meta = parser::extract_metadata(&doc)?;
        log::debug!(
            "PDF metadata: xref_offset={}, trailer_size={}, root={:?}, max_id={}",
            meta.xref_offset,
            meta.trailer_size,
            meta.root_id,
            meta.max_id,
        );

        // Step 3: Build the signature dictionary
        let sub_filter: SigSubFilter = self.options.sub_filter.into();
        // contents_size is in bytes; hex encoding doubles it
        let contents_hex_size = self.options.content_size * 2;
        let mut sig_dict = sig_dict::build_sig_dict(sub_filter, self.options.content_size);

        // Add optional entries to the sig dict
        if let Some(reason) = &self.options.reason {
            sig_dict.set(
                "Reason",
                Object::String(reason.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }
        if let Some(location) = &self.options.location {
            sig_dict.set(
                "Location",
                Object::String(location.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }
        if let Some(contact) = &self.options.contact_info {
            sig_dict.set(
                "ContactInfo",
                Object::String(contact.as_bytes().to_vec(), lopdf::StringFormat::Literal),
            );
        }

        // Step 4: Add sig dict as a new object
        let sig_dict_id = doc.add_object(Object::Dictionary(sig_dict));

        // Step 4b: Generate visible signature appearance if configured
        #[cfg(feature = "visual")]
        let appearance_data = if let Some(vis_config) = &self.options.visible_signature {
            // Get page dimensions for coordinate conversion
            let (page_width, page_height) = get_page_dimensions(&doc, self.options.page)?;

            // For Custom layouts, build an AppearanceContext from signing options
            let appearance = if matches!(&vis_config.layout, SignatureLayout::Custom(_)) {
                let ctx = AppearanceContext {
                    width: 0.0,  // will be overridden by build_appearance_with_context
                    height: 0.0, // will be overridden by build_appearance_with_context
                    signer_name: None, // not easily available without parsing cert
                    reason: self.options.reason.clone(),
                    location: self.options.location.clone(),
                    date: Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()),
                    contact_info: self.options.contact_info.clone(),
                };
                visual::build_appearance_with_context(vis_config, page_width, page_height, Some(&ctx))?
            } else {
                visual::build_appearance(vis_config, page_width, page_height)?
            };

            // Compute the absolute rect for the annotation
            let abs_rect = vis_config.rect.to_absolute(page_width, page_height);

            Some((appearance, abs_rect))
        } else {
            None
        };

        // Step 5: Build the signature field
        #[cfg(feature = "visual")]
        let field_rect = if let Some((_, ref abs_rect)) = appearance_data {
            *abs_rect
        } else {
            [0.0, 0.0, 0.0, 0.0] // invisible signature
        };
        #[cfg(not(feature = "visual"))]
        let field_rect = [0.0, 0.0, 0.0, 0.0];

        let field_opts = SignatureFieldOptions {
            name: self.options.field_name.clone(),
            page: self.options.page,
            rect: field_rect,
        };
        #[allow(unused_mut)]
        let mut sig_field_dict = sig_field::build_sig_field(&field_opts, sig_dict_id);

        // Step 5b: Create Form XObject and wire /AP if visible
        #[cfg(feature = "visual")]
        let mut appearance_object_ids: Vec<lopdf::ObjectId> = Vec::new();
        #[cfg(feature = "visual")]
        if let Some((appearance, _)) = appearance_data {
            // Build font resource dictionaries for Standard 14 fonts
            let mut font_dict = Dictionary::new();
            for (res_name, pdf_font_name) in &appearance.font_resources {
                let mut fd = Dictionary::new();
                fd.set("Type", Object::Name(b"Font".to_vec()));
                fd.set("Subtype", Object::Name(b"Type1".to_vec()));
                fd.set(
                    "BaseFont",
                    Object::Name(pdf_font_name.as_bytes().to_vec()),
                );
                let font_id = doc.add_object(Object::Dictionary(fd));
                appearance_object_ids.push(font_id);
                font_dict.set(
                    res_name.as_bytes(),
                    Object::Reference(font_id),
                );
            }

            // Build CIDFont/Type0 font dictionaries for embedded fonts
            for emb_font_res in &appearance.embedded_font_resources {
                let prepared = &emb_font_res.font;
                let info = &prepared.info;

                // 1. Embed the subsetted font as a FontFile2 stream
                let mut font_file_dict = Dictionary::new();
                font_file_dict.set("Length1", Object::Integer(prepared.subset_data.len() as i64));
                let mut font_file_stream =
                    Stream::new(font_file_dict, prepared.subset_data.clone());
                let _ = font_file_stream.compress();
                let font_file_id = doc.add_object(Object::Stream(font_file_stream));
                appearance_object_ids.push(font_file_id);

                // 2. Build the FontDescriptor
                let ascent_1000 = visual::font::embedded_ascent_1000(info);
                let descent_1000 = visual::font::embedded_descent_1000(info);
                let mut font_desc = Dictionary::new();
                font_desc.set("Type", Object::Name(b"FontDescriptor".to_vec()));
                font_desc.set(
                    "FontName",
                    Object::Name(info.name.as_bytes().to_vec()),
                );
                font_desc.set("Flags", Object::Integer(info.flags as i64));
                font_desc.set(
                    "FontBBox",
                    Object::Array(vec![
                        Object::Integer(
                            info.bbox[0] as i64 * 1000 / info.units_per_em as i64,
                        ),
                        Object::Integer(
                            info.bbox[1] as i64 * 1000 / info.units_per_em as i64,
                        ),
                        Object::Integer(
                            info.bbox[2] as i64 * 1000 / info.units_per_em as i64,
                        ),
                        Object::Integer(
                            info.bbox[3] as i64 * 1000 / info.units_per_em as i64,
                        ),
                    ]),
                );
                font_desc.set(
                    "ItalicAngle",
                    Object::Real(info.italic_angle),
                );
                font_desc.set("Ascent", Object::Integer(ascent_1000 as i64));
                font_desc.set("Descent", Object::Integer(descent_1000 as i64));
                font_desc.set(
                    "CapHeight",
                    Object::Integer(
                        info.cap_height as i64 * 1000 / info.units_per_em as i64,
                    ),
                );
                font_desc.set("StemV", Object::Integer(info.stem_v as i64));
                font_desc.set("FontFile2", Object::Reference(font_file_id));
                let font_desc_id = doc.add_object(Object::Dictionary(font_desc));
                appearance_object_ids.push(font_desc_id);

                // 3. Build the CIDFont dictionary (CIDFontType2 for TrueType)
                let w_array_str =
                    visual::font::build_w_array(&prepared.cid_widths, prepared.default_width);
                // Parse the W array string into lopdf objects
                let w_array = parse_w_array_string(&w_array_str);

                let mut cid_system_info = Dictionary::new();
                cid_system_info.set(
                    "Registry",
                    Object::String(b"Adobe".to_vec(), lopdf::StringFormat::Literal),
                );
                cid_system_info.set(
                    "Ordering",
                    Object::String(b"Identity".to_vec(), lopdf::StringFormat::Literal),
                );
                cid_system_info.set("Supplement", Object::Integer(0));

                let mut cid_font = Dictionary::new();
                cid_font.set("Type", Object::Name(b"Font".to_vec()));
                cid_font.set("Subtype", Object::Name(b"CIDFontType2".to_vec()));
                cid_font.set(
                    "BaseFont",
                    Object::Name(info.name.as_bytes().to_vec()),
                );
                cid_font.set(
                    "CIDSystemInfo",
                    Object::Dictionary(cid_system_info),
                );
                cid_font.set("W", w_array);
                cid_font.set(
                    "DW",
                    Object::Integer(prepared.default_width as i64),
                );
                cid_font.set("FontDescriptor", Object::Reference(font_desc_id));
                // CIDToGIDMap: Identity mapping (CID = GID in the subsetted font)
                cid_font.set(
                    "CIDToGIDMap",
                    Object::Name(b"Identity".to_vec()),
                );
                let cid_font_id = doc.add_object(Object::Dictionary(cid_font));
                appearance_object_ids.push(cid_font_id);

                // 4. Build the ToUnicode CMap stream
                let tounicode_data =
                    visual::font::build_tounicode_cmap(&info.name, &prepared.char_to_cid);
                let tounicode_stream = Stream::new(Dictionary::new(), tounicode_data);
                let tounicode_id = doc.add_object(Object::Stream(tounicode_stream));
                appearance_object_ids.push(tounicode_id);

                // 5. Build the Type0 font dictionary
                let mut type0 = Dictionary::new();
                type0.set("Type", Object::Name(b"Font".to_vec()));
                type0.set("Subtype", Object::Name(b"Type0".to_vec()));
                type0.set(
                    "BaseFont",
                    Object::Name(info.name.as_bytes().to_vec()),
                );
                type0.set("Encoding", Object::Name(b"Identity-H".to_vec()));
                type0.set(
                    "DescendantFonts",
                    Object::Array(vec![Object::Reference(cid_font_id)]),
                );
                type0.set("ToUnicode", Object::Reference(tounicode_id));
                let type0_id = doc.add_object(Object::Dictionary(type0));
                appearance_object_ids.push(type0_id);

                // Wire the Type0 font into the font resource dictionary
                font_dict.set(
                    emb_font_res.resource_name.as_bytes(),
                    Object::Reference(type0_id),
                );
            }

            // Build Image XObject streams from image_resources
            let mut xobj_res_dict = Dictionary::new();
            for img_res in &appearance.image_resources {
                let img = &img_res.image;

                // If the image has alpha, create an SMask XObject first
                let smask_id = if img.has_alpha {
                    if let Some(ref alpha_data) = img.alpha_data {
                        let mut smask_dict = Dictionary::new();
                        smask_dict.set("Type", Object::Name(b"XObject".to_vec()));
                        smask_dict.set("Subtype", Object::Name(b"Image".to_vec()));
                        smask_dict.set("Width", Object::Integer(img.width as i64));
                        smask_dict.set("Height", Object::Integer(img.height as i64));
                        smask_dict.set("BitsPerComponent", Object::Integer(8));
                        smask_dict.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));

                        // Compress the alpha data with FlateDecode
                        let mut smask_stream = Stream::new(smask_dict, alpha_data.clone());
                        let _ = smask_stream.compress();
                        let sid = doc.add_object(Object::Stream(smask_stream));
                        appearance_object_ids.push(sid);
                        Some(sid)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Build the Image XObject
                let mut img_dict = Dictionary::new();
                img_dict.set("Type", Object::Name(b"XObject".to_vec()));
                img_dict.set("Subtype", Object::Name(b"Image".to_vec()));
                img_dict.set("Width", Object::Integer(img.width as i64));
                img_dict.set("Height", Object::Integer(img.height as i64));
                img_dict.set(
                    "BitsPerComponent",
                    Object::Integer(img.bits_per_component as i64),
                );
                img_dict.set(
                    "ColorSpace",
                    Object::Name(img.color_space.as_bytes().to_vec()),
                );

                if let Some(sid) = smask_id {
                    img_dict.set("SMask", Object::Reference(sid));
                }

                // For JPEG (DCTDecode), embed raw data with the filter set.
                // For PNG (FlateDecode), compress the raw sample data.
                let img_stream = if img.filter == "DCTDecode" {
                    // JPEG: set filter and use raw JPEG data as-is
                    img_dict.set(
                        "Filter",
                        Object::Name(b"DCTDecode".to_vec()),
                    );
                    Stream::new(img_dict, img.data.clone())
                } else {
                    // Raw pixel data: use lopdf's compress() to apply FlateDecode
                    let mut s = Stream::new(img_dict, img.data.clone());
                    let _ = s.compress(); // adds /Filter /FlateDecode automatically
                    s
                };

                let img_id = doc.add_object(Object::Stream(img_stream));
                appearance_object_ids.push(img_id);
                xobj_res_dict.set(
                    img_res.resource_name.as_bytes(),
                    Object::Reference(img_id),
                );
            }

            // Build the resource dictionary for the Form XObject
            let mut resources = Dictionary::new();
            if !font_dict.is_empty() {
                resources.set("Font", Object::Dictionary(font_dict));
            }
            if !xobj_res_dict.is_empty() {
                resources.set("XObject", Object::Dictionary(xobj_res_dict));
            }

            // Build the Form XObject stream
            let mut xobj_dict = Dictionary::new();
            xobj_dict.set("Type", Object::Name(b"XObject".to_vec()));
            xobj_dict.set("Subtype", Object::Name(b"Form".to_vec()));
            xobj_dict.set(
                "BBox",
                Object::Array(
                    appearance
                        .bbox
                        .iter()
                        .map(|&v| Object::Real(v))
                        .collect(),
                ),
            );
            xobj_dict.set("Resources", Object::Dictionary(resources));

            let xobj_stream = Stream::new(xobj_dict, appearance.content);
            let xobj_id = doc.add_object(Object::Stream(xobj_stream));
            appearance_object_ids.push(xobj_id);

            // Add /AP << /N <xobj_ref> >> to the signature field
            let mut ap_dict = Dictionary::new();
            ap_dict.set("N", Object::Reference(xobj_id));
            sig_field_dict.set("AP", Object::Dictionary(ap_dict));
        }

        let sig_field_id = doc.add_object(Object::Dictionary(sig_field_dict));

        // Step 6: Update AcroForm and page annotations
        acroform::ensure_acroform(&mut doc, sig_field_id, self.options.page)?;

        // Step 7: Build the incremental update
        // We need to collect all new/modified objects to write.
        // The IncrementalWriter takes the original PDF bytes and appends new objects.
        let mut writer = IncrementalWriter::new(
            pdf_data.to_vec(),
            meta.trailer_size,
            meta.xref_offset,
            meta.root_id,
            contents_hex_size,
        );

        // Add all objects that are new or modified.
        // New objects: sig_dict, sig_field
        // Modified objects: catalog (AcroForm reference), page (Annots), and possibly the AcroForm itself
        writer.set_sig_dict_id(sig_dict_id);

        // Add all objects from the document that have IDs > the original max
        // (these are the new objects we created), plus any modified objects.
        // For simplicity, we add the sig dict, sig field, and re-serialize
        // any objects that were modified (catalog, acroform, page).
        let catalog_id = meta.root_id;

        // Add sig dict
        if let Ok(obj) = doc.get_object(sig_dict_id) {
            writer.add_object(sig_dict_id, obj.clone());
        }

        // Add sig field
        if let Ok(obj) = doc.get_object(sig_field_id) {
            writer.add_object(sig_field_id, obj.clone());
        }

        // Add appearance objects (font dicts + Form XObject) if visible
        #[cfg(feature = "visual")]
        for obj_id in &appearance_object_ids {
            if let Ok(obj) = doc.get_object(*obj_id) {
                writer.add_object(*obj_id, obj.clone());
            }
        }

        // Add modified catalog (has new/updated AcroForm reference)
        if let Ok(obj) = doc.get_object(catalog_id) {
            writer.add_object(catalog_id, obj.clone());
        }

        // Add the AcroForm object if it's an indirect reference
        if let Ok(catalog_dict) = doc.get_object(catalog_id).and_then(|o| o.as_dict()) {
            if let Ok(Object::Reference(af_id)) = catalog_dict.get(b"AcroForm") {
                if let Ok(obj) = doc.get_object(*af_id) {
                    writer.add_object(*af_id, obj.clone());
                }
            }
        }

        // Add the modified page (has new Annots entry)
        let pages = doc.get_pages();
        let page_num = self.options.page + 1;
        if let Some(&page_id) = pages.get(&page_num) {
            if let Ok(obj) = doc.get_object(page_id) {
                writer.add_object(page_id, obj.clone());
            }
        }

        // Step 8: Write the incremental update
        let (mut output, byte_range) = writer.write()?;

        // Step 9: Compute hash of the byte-range-selected bytes
        let br_values = byte_range.compute(output.len());
        let range1 = &output[br_values[0]..br_values[0] + br_values[1]];
        let range2 = &output[br_values[2]..br_values[2] + br_values[3]];

        let digest_alg = signer.digest_algorithm();
        let mut hasher = digest_alg.new_hasher();
        hasher.update(range1);
        hasher.update(range2);
        let data_hash = hasher.finalize();

        // Step 10: Build the CMS SignedData
        let cms_profile = match self.options.sub_filter {
            SubFilter::Pades => CmsProfile::Pades,
            SubFilter::Pkcs7 => CmsProfile::Traditional,
        };
        let cms_builder = PdfCmsBuilder::new(signer)
            .profile(cms_profile)
            .signing_time_placement(self.options.signing_time_placement);
        let cms_builder = match self.options.cms_signing_time {
            Some(t) => cms_builder.signing_time(t),
            None => cms_builder,
        };
        let cms_der = cms_builder.build(&data_hash)?;

        // Step 11: Check that the CMS signature fits in the allocated space
        if cms_der.len() > self.options.content_size {
            return Err(PdfSignError::Core(CoreError::SignatureTooLarge {
                actual: cms_der.len(),
                allocated: self.options.content_size,
            }));
        }

        // Step 12: Inject the CMS signature into /Contents
        // The hex-encoded signature replaces the zero-placeholder
        let hex_sig = hex::encode_upper(&cms_der);
        let hex_bytes = hex_sig.as_bytes();

        // Write hex signature, left-aligned, zero-padded
        let start = byte_range.contents_offset;
        let end = byte_range.contents_offset + byte_range.contents_length;
        // Fill with zeros first (already there), then overwrite with actual signature
        output[start..start + hex_bytes.len()].copy_from_slice(hex_bytes);
        // Remaining bytes stay as '0' (padding)
        for b in &mut output[start + hex_bytes.len()..end] {
            *b = b'0';
        }

        Ok(output)
    }
}

impl Default for PdfSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the page dimensions (width, height) in points from a PDF document.
///
/// Looks up the `/MediaBox` of the specified page (0-indexed). Falls back to
/// US Letter (612 x 792) if no MediaBox is found or cannot be parsed.
#[cfg(feature = "visual")]
fn get_page_dimensions(doc: &Document, page_index: u32) -> Result<(f32, f32), PdfSignError> {
    let pages = doc.get_pages();
    let page_num = page_index + 1; // lopdf uses 1-indexed pages

    let page_id = pages
        .get(&page_num)
        .ok_or_else(|| CoreError::InvalidStructure(format!("Page {} not found", page_num)))?;

    let page_dict = doc
        .get_object(*page_id)
        .and_then(|o| o.as_dict())
        .map_err(|_| CoreError::InvalidStructure("Failed to get page dictionary".into()))?;

    // Try to get MediaBox from the page, then from its parent (Pages node)
    let media_box = if let Ok(mb) = page_dict.get(b"MediaBox") {
        Some(mb.clone())
    } else {
        // Walk up to the parent Pages node for inherited MediaBox
        page_dict
            .get(b"Parent")
            .ok()
            .and_then(|p| {
                if let Object::Reference(parent_id) = p {
                    doc.get_object(*parent_id).ok()
                } else {
                    None
                }
            })
            .and_then(|parent| parent.as_dict().ok())
            .and_then(|parent_dict| parent_dict.get(b"MediaBox").ok())
            .cloned()
    };

    if let Some(Object::Array(arr)) = media_box {
        if arr.len() == 4 {
            let get_f32 = |obj: &Object| -> f32 {
                match obj {
                    Object::Real(f) => *f,
                    Object::Integer(i) => *i as f32,
                    _ => 0.0,
                }
            };
            let width = get_f32(&arr[2]) - get_f32(&arr[0]);
            let height = get_f32(&arr[3]) - get_f32(&arr[1]);
            return Ok((width, height));
        }
    }

    // Fallback to US Letter
    log::warn!("Could not determine page dimensions, using US Letter (612x792)");
    Ok((612.0, 792.0))
}

/// Parse a /W array string (from `build_w_array`) into a lopdf Object.
///
/// The format is `[cid1 [w1] cid2 [w2] ...]` or `[]`.
/// We parse this manually since lopdf doesn't have a string parser.
#[cfg(feature = "visual")]
fn parse_w_array_string(w_str: &str) -> Object {
    // Simple parser for the W array format produced by build_w_array
    let trimmed = w_str.trim();
    if trimmed == "[]" {
        return Object::Array(Vec::new());
    }

    // Strip outer brackets
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);

    let mut result = Vec::new();
    let mut chars = inner.chars().peekable();

    while chars.peek().is_some() {
        // Skip whitespace
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }

        if chars.peek() == Some(&'[') {
            // Parse inner array [w]
            chars.next(); // consume '['
            let mut num_str = String::new();
            let mut inner_arr = Vec::new();
            while let Some(&ch) = chars.peek() {
                if ch == ']' {
                    chars.next();
                    if !num_str.is_empty() {
                        if let Ok(n) = num_str.trim().parse::<i64>() {
                            inner_arr.push(Object::Integer(n));
                        }
                    }
                    break;
                } else if ch == ' ' {
                    if !num_str.is_empty() {
                        if let Ok(n) = num_str.trim().parse::<i64>() {
                            inner_arr.push(Object::Integer(n));
                        }
                        num_str.clear();
                    }
                    chars.next();
                } else {
                    num_str.push(ch);
                    chars.next();
                }
            }
            result.push(Object::Array(inner_arr));
        } else {
            // Parse a number (CID)
            let mut num_str = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == ' ' || ch == '[' {
                    break;
                }
                num_str.push(ch);
                chars.next();
            }
            if let Ok(n) = num_str.parse::<i64>() {
                result.push(Object::Integer(n));
            }
        }
    }

    Object::Array(result)
}
