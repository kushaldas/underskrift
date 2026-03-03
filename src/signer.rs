//! High-level PDF signer builder and orchestrator.
//!
//! `PdfSigner` is the main entry point for signing PDFs. It uses a builder
//! pattern to configure signing options, then orchestrates the full flow:
//! parse PDF -> prepare signature structures -> compute hash -> sign -> embed.

use lopdf::{Document, Object};

#[cfg(feature = "visual")]
use lopdf::{Dictionary, Stream};

use crate::cms::builder::{CmsProfile, PdfCmsBuilder};
use crate::core::acroform;
use crate::core::incremental::IncrementalWriter;
use crate::core::parser;
use crate::core::sig_dict::{self, SigSubFilter};
use crate::core::sig_field::{self, SignatureFieldOptions};
use crate::crypto::algorithm::{AlgorithmRegistry, DigestAlgorithm};
use crate::crypto::traits::CryptoSigner;
use crate::error::{CoreError, PdfSignError};

#[cfg(feature = "visual")]
use crate::visual::{self, VisibleSignatureConfig};

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

            // Generate the appearance stream
            let appearance = visual::build_appearance(vis_config, page_width, page_height)?;

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
            // Build font resource dictionaries
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

            // Build the resource dictionary for the Form XObject
            let mut resources = Dictionary::new();
            resources.set("Font", Object::Dictionary(font_dict));

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
        let cms_builder = PdfCmsBuilder::new(signer).profile(cms_profile);
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
