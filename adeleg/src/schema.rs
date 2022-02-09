use crate::connection::LdapConnection;
use crate::error::LdapError;
use crate::search::LdapSearch;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;
use authz::{SecurityDescriptor, Sid};
use std::collections::HashMap;
use crate::utils::get_attr_str;

pub(crate) fn get_default_sd(conn: &LdapConnection, domain_sid: &Sid) -> Result<HashMap<String, SecurityDescriptor>, LdapError> {
    let search = LdapSearch::new(&conn, Some(&conn.schema_naming_context), LDAP_SCOPE_SUBTREE,
                                 Some("(defaultSecurityDescriptor=*)"),
                                 Some(&[
                                     "defaultSecurityDescriptor",
                                     "objectClass",
                                 ]), &[]);
    let mut default_sd = HashMap::new();
    for entry in search {
        let entry = entry?;
        let dn = entry.dn.clone();
        let sddl = get_attr_str(&[entry], &dn, "defaultsecuritydescriptor").expect("unable to fetch defaultSecurityDescriptor");
        let sd = SecurityDescriptor::from_str(&sddl, domain_sid, &conn.forest_sid).expect("unable to parse defaultSecurityDescriptor in schema");
        default_sd.insert(dn, sd);
    }
    Ok(default_sd)
}