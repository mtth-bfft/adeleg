use authz::SecurityDescriptor;
use crate::connection::LdapConnection;
use crate::error::LdapError;
use crate::search::LdapSearch;
use std::convert::TryFrom;
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

        let sd = SecurityDescriptor::parse(&sd[..]).expect("FIXME");
        println!(">> OWNER: {}", sd.get_owner().expect("get_owner failed"));
        println!(">> GROUP: {}", sd.get_group().expect("get_owner failed"));
        println!(">> DACL: {}", sd.get_dacl().expect("get_dacl failed"));
    }
    Ok(())
}