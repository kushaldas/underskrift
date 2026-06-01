//! SACI AuthnContext X.509 extension parsing (RFC 7773).
//!
//! The SACI (SAML Authentication Context Information) extension embeds
//! SAML authentication context directly into X.509 certificates. This is
//! used in the Swedish electronic signing infrastructure (eduSign / Sweden
//! Connect) where short-lived signing certificates carry information about
//! how the signer was authenticated.
//!
//! ## Extension Structure
//!
//! The extension (OID `1.2.752.201.5.1`) contains:
//!
//! ```text
//! AuthenticationContexts ::= SEQUENCE SIZE (1..MAX) OF AuthenticationContext
//! AuthenticationContext  ::= SEQUENCE {
//!     contextType  UTF8String,
//!     contextInfo  UTF8String OPTIONAL
//! }
//! ```
//!
//! When `contextType` is `"http://id.elegnamnden.se/auth-cont/1.0/saci"`,
//! the `contextInfo` field contains XML conforming to the SACI schema.
//!
//! ## Usage
//!
//! ```no_run
//! use underskrift::saci;
//! use x509_cert::Certificate;
//! use der::Decode;
//!
//! # fn example(cert: &Certificate) -> Result<(), underskrift::error::SaciError> {
//! let contexts = saci::extract_authn_contexts(cert)?;
//! for ctx in &contexts {
//!     if let Some(info) = &ctx.auth_context_info {
//!         println!("IdP: {}", info.identity_provider);
//!         println!("LoA: {}", info.authn_context_class_ref);
//!     }
//!     if let Some(attrs) = &ctx.id_attributes {
//!         for mapping in &attrs.mappings {
//!             println!("{}: {} = {:?}",
//!                 mapping.mapping_type, mapping.reference,
//!                 mapping.attribute.values);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod parser;

// Re-exports
pub use parser::extract_authn_contexts;

/// OID for the AuthnContext X.509 extension (1.2.752.201.5.1).
pub const AUTHN_CONTEXT_OID: &str = "1.2.752.201.5.1";

/// Context type URI for SACI.
pub const SACI_CONTEXT_TYPE: &str = "http://id.elegnamnden.se/auth-cont/1.0/saci";

/// SACI XML namespace.
pub const SACI_NAMESPACE: &str = "http://id.elegnamnden.se/auth-cont/1.0/saci";

/// SAML 2.0 assertion namespace.
pub const SAML_NAMESPACE: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// A parsed SAML Authentication Context from an X.509 certificate.
///
/// Represents the top-level `<saci:SAMLAuthContext>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SAMLAuthContext {
    /// Authentication context information (the `<saci:AuthContextInfo>` element).
    pub auth_context_info: Option<AuthContextInfo>,
    /// Identity attribute mappings (the `<saci:IdAttributes>` element).
    pub id_attributes: Option<IdAttributes>,
}

/// Authentication context information — describes how the signer was authenticated.
///
/// Corresponds to `<saci:AuthContextInfo>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContextInfo {
    /// The identity provider that authenticated the signer (required).
    pub identity_provider: String,
    /// When authentication occurred, as ISO 8601 / xs:dateTime (required).
    pub authentication_instant: String,
    /// The authentication context class reference — typically a LoA URI (required).
    pub authn_context_class_ref: String,
    /// Reference to the SAML assertion (optional).
    pub assertion_ref: Option<String>,
    /// Service identifier (optional).
    pub service_id: Option<String>,
}

/// Collection of identity attribute mappings.
///
/// Corresponds to `<saci:IdAttributes>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdAttributes {
    /// One or more attribute mappings.
    pub mappings: Vec<AttributeMapping>,
}

/// Maps a SAML attribute to a certificate field.
///
/// Corresponds to `<saci:AttributeMapping>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeMapping {
    /// The type of certificate field: `rdn`, `san`, or `sda`.
    pub mapping_type: MappingType,
    /// OID or identifier of the target certificate field (e.g., `"2.5.4.5"`).
    pub reference: String,
    /// The SAML attribute.
    pub attribute: SamlAttribute,
}

/// Type of certificate field that a SAML attribute maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingType {
    /// Relative Distinguished Name (e.g., CN, serialNumber).
    Rdn,
    /// Subject Alternative Name.
    San,
    /// Subject Directory Attribute.
    Sda,
}

impl MappingType {
    /// Parse from the XML `Type` attribute value.
    ///
    /// Returns `None` (not a `Result`) for unknown values, so this is an
    /// inherent method rather than a `FromStr` implementation.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "rdn" => Some(Self::Rdn),
            "san" => Some(Self::San),
            "sda" => Some(Self::Sda),
            _ => None,
        }
    }

    /// Return the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rdn => "rdn",
            Self::San => "san",
            Self::Sda => "sda",
        }
    }
}

impl std::fmt::Display for MappingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A SAML 2.0 Attribute element.
///
/// Corresponds to `<saml:Attribute>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAttribute {
    /// The attribute name (e.g., `"urn:oid:1.2.752.29.4.13"`).
    pub name: Option<String>,
    /// The name format URI.
    pub name_format: Option<String>,
    /// A human-friendly name (e.g., `"personalIdentityNumber"`).
    pub friendly_name: Option<String>,
    /// The attribute values (typically strings).
    pub values: Vec<String>,
}

/// A raw AuthenticationContext entry (before XML parsing).
///
/// This is the ASN.1-level representation: a (contextType, contextInfo) pair.
#[derive(Debug, Clone)]
pub struct RawAuthenticationContext {
    /// The context type URI.
    pub context_type: String,
    /// The context info (XML string for SACI type, or other content).
    pub context_info: Option<String>,
}
