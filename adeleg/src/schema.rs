use winldap::connection::LdapConnection;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use winldap::utils::get_attr_str;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;
use authz::{SecurityDescriptor, Sid};
use std::collections::HashMap;

pub(crate) fn get_default_sd(conn: &LdapConnection, forest_sid: &Sid, domain_sid: &Sid) -> Result<HashMap<String, SecurityDescriptor>, LdapError> {
    let search = LdapSearch::new(&conn, Some(conn.get_schema_naming_context()), LDAP_SCOPE_SUBTREE,
                                 Some("(defaultSecurityDescriptor=*)"),
                                 Some(&[
                                     "defaultSecurityDescriptor",
                                     "lDAPDisplayName",
                                 ]), &[]);
    let mut default_sd = HashMap::new();
    for entry in search {
        let entry = entry?;
        let dn = entry.dn.clone();
        let class = get_attr_str(&[&entry], &dn, "ldapdisplayname").expect("unable to fetch ldapDisplayName");
        let sddl = get_attr_str(&[&entry], &dn, "defaultsecuritydescriptor").expect("unable to fetch defaultSecurityDescriptor");
        let sd = SecurityDescriptor::from_str(&sddl, domain_sid, forest_sid).expect("unable to parse defaultSecurityDescriptor in schema");
        default_sd.insert(class, sd);
    }
    Ok(default_sd)
}