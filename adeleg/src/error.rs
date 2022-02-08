use core::fmt::Display;
use windows::core::alloc::fmt::Formatter;
use crate::utils::get_ldap_errmsg;

#[derive(Debug)]
pub enum LdapError {
    ConnectionFailed(u32),
    BindFailed(u32),
    UnbindFailed(u32),
    BerAllocFailed,
    BerPrintfFailed,
    BerFlattenFailed,
    SearchFailed {
        base: Option<String>,
        filter: Option<String>,
        only_attributes: Option<Vec<String>>,
        code: u32,
    },
    RequiredObjectCollision {
        dn: String,
    },
    RequiredObjectMissing {
        dn: String,
    },
    RequiredAttributeMissing {
        dn: String,
        name: String,
    },
    GetAttributeNamesFailed {
        dn: String,
        code: u32,
    },
    AttributeNamesCollision {
        dn: String,
        attr_name: String,
    },
    GetAttributeValuesFailed {
        dn: String,
        name: String,
        code: u32,
    },
    AttributeValuesCollision {
        dn: String,
        name: String,
        val1: String,
        val2: String,
    },
    GetDNFailed {
        code: u32,
    },
}

impl Display for LdapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConnectionFailed(code) => write!(f, "connection failed ({})", get_ldap_errmsg(*code)),
            Self::BindFailed(code) => write!(f, "bind failed ({})", get_ldap_errmsg(*code)),
            Self::UnbindFailed(code) => write!(f, "unbind failed ({})", get_ldap_errmsg(*code)),
            Self::SearchFailed { base, filter, only_attributes, code } => write!(f, "search in \"{}\" (filter={:?}) (attributes={:?}) failed ({})", base.as_ref().unwrap_or(&"".to_owned()), filter, only_attributes, get_ldap_errmsg(*code)),
            Self::GetAttributeNamesFailed { dn, code } => write!(f, "fetching attribute names of \"{}\" failed ({})", dn, get_ldap_errmsg(*code)),
            Self::AttributeNamesCollision { dn, attr_name } => write!(f, "{} has colliding values for attribute \"{}\"", dn, attr_name),
            Self::GetAttributeValuesFailed { dn, name, code } => write!(f, "fetching attribute values of \"{}\" in \"{}\" failed ({})", name, dn, get_ldap_errmsg(*code)),
            Self::GetDNFailed { code } => write!(f, "ldap_get_dnW() failed ({})", get_ldap_errmsg(*code)),
            Self::RequiredAttributeMissing { dn, name } => write!(f, "required attribute \"{}\" missing on {}", name, dn),
            Self::BerAllocFailed => write!(f, "ber_alloc() failed"),
            Self::BerPrintfFailed => write!(f, "ber_printf() failed"),
            Self::BerFlattenFailed => write!(f, "ber_flatten() failed"),
            Self::RequiredObjectCollision { dn } => write!(f, "unexpected object \"{}\" collision", dn),
            Self::RequiredObjectMissing { dn } => write!(f, "object \"{}\" not found, cannot proceed", dn),
            Self::AttributeValuesCollision { dn, name, val1, val2 } => write!(f, "unexpected value collision for {} on {} ({} / {})", name, dn, val1, val2),
        }
    }
}