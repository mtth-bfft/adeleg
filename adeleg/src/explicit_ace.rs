use authz::SecurityDescriptor;
use crate::utils::get_attr_sd;
use crate::{connection::LdapConnection, utils::get_attr_strs};
use crate::error::LdapError;
use crate::search::LdapSearch;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;
use crate::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION};

pub(crate) fn get_explicit_aces(conn: &LdapConnection, naming_context: &str) -> Result<(), LdapError> {
    let sd_control = LdapControl::new(
        "1.2.840.113556.1.4.801",
        &BerVal::new().append(BerEncodable::Sequence(vec![BerEncodable::Integer((OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0).into())])),
        true)?;
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_SUBTREE,
                             Some("(objectClass=*)"),
                             Some(&[
        "nTSecurityDescriptor",
        "objectClass",
    ]), Some(&[&sd_control]))?;
    for entry in search {
        let mut entry = entry?;
        let classes = get_attr_strs(&[&entry], &entry.dn, "objectclass")?;
        let sd = get_attr_sd(&[&entry], &entry.dn, "ntsecuritydescriptor")?;
    }
    Ok(())
}