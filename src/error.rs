use core::fmt::Display;
use windows::core::alloc::fmt::Formatter;
use crate::utils::get_ldap_errmsg;

#[derive(Debug)]
pub enum LdapError {
    ConnectionFailed(u32),
    BindFailed(u32),
    UnbindFailed(u32),
    RootDSEQueryFailed,
    RootDSEAttributeMissing,
    SearchFailed {

        code: u32,
    },
    GetAttributeNamesFailed {
        dn: String,
        code: u32,
    },
    GetAttributeValuesFailed {
        dn: String,
        name: String,
        code: u32,
    },
}

impl Display for LdapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConnectionFailed(code) => write!(f, "connection failed ({})", get_ldap_errmsg(*code)),
            Self::BindFailed(code) => write!(f, "bind failed ({})", get_ldap_errmsg(*code)),
            Self::UnbindFailed(code) => write!(f, "unbind failed ({})", get_ldap_errmsg(*code)),
            Self::SearchFailed { code } => write!(f, "search failed ({})", get_ldap_errmsg(*code)),
            Self::GetAttributeNamesFailed { dn, code } => write!(f, "fetching attribute names of \"{}\" failed ({})", dn, get_ldap_errmsg(*code)),
            Self::GetAttributeValuesFailed { dn, name, code} => write!(f, "fetching attribute values of \"{}\" in \"{}\" failed ({})", name, dn, get_ldap_errmsg(*code)),
            Self::RootDSEQueryFailed => write!(f, "rootdse query failed"),
            Self::RootDSEAttributeMissing => write!(f, "rootdse attribute missing"),
        }
    }
}