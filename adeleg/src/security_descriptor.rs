use authz::SecurityDescriptor;
use crate::connection::LdapConnection;
use crate::error::LdapError;
use crate::search::LdapSearch;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;

pub(crate) fn dump_security_descriptors(conn: &LdapConnection, naming_context: &str) -> Result<(), LdapError> {
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_SUBTREE,
                             Some("(objectClass=classSchema)"),
                             Some(&[
        "nTSecurityDescriptor",
    ]))?;
    for entry in search {
        let mut entry = entry?;
        let sd = match entry.attrs.get_mut("ntsecuritydescriptor").and_then(|p| p.pop()) {
            Some(sd) => sd,
            _ => panic!("Assertion failed: {} has no security descriptor", entry.dn),
        };

        let sd = SecurityDescriptor::from(&sd[..]).expect("FIXME");
        println!(">> SD: {:?}", sd);
    }
    Ok(())
}