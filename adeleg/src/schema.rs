use crate::connection::LdapConnection;
use crate::error::LdapError;
use crate::search::{LdapSearch, LdapEntry};
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;

pub(crate) fn dump_schema(conn: &LdapConnection) -> Result<(), LdapError> {
    println!("Dumping schema {}", &conn.schema_naming_context);
    let search = LdapSearch::new(&conn, Some(&conn.schema_naming_context), LDAP_SCOPE_SUBTREE,
                             Some("(objectClass=classSchema)"),
                             Some(&[
        "schemaIDGUID",
        "adminDisplayName",
    ]))?;
    let class_list = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    Ok(())
}