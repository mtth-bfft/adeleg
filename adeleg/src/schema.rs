use winldap::connection::LdapConnection;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use winldap::utils::get_attr_str;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;
use authz::Guid;
use std::collections::HashMap;
use crate::utils::get_attr_guid;

pub struct Schema {
    // Mapping from class GUID to lowercase class name
    pub(crate) class_guids: HashMap<String, Guid>,
    // Mapping from attribute GUID to attribute name
    pub(crate) attribute_guids: HashMap<Guid, String>,
    // Mapping from property set GUIDs to property set names
    pub(crate) property_set_names: HashMap<Guid, String>,
    // Mapping from validated write GUIDs to validated write names
    pub(crate) validated_write_names: HashMap<Guid, String>,
    // Mapping from control access GUIDs to control access names
    pub(crate) control_access_names: HashMap<Guid, String>,
}

impl Schema {
    pub fn query(conn: &LdapConnection) -> Result<Self, LdapError> {
        let mut class_guids = HashMap::new();
        let mut attribute_guids = HashMap::new();
        let mut property_set_names = HashMap::new();
        let mut validated_write_names = HashMap::new();
        let mut control_access_names = HashMap::new();

        // Fetch classes
        let search = LdapSearch::new(&conn, Some(conn.get_schema_naming_context()), LDAP_SCOPE_SUBTREE,
                                    Some("(objectClass=classSchema)"),
                                    Some(&[
                                        "schemaIDGUID",
                                        "lDAPDisplayName",
                                        "defaultSecurityDescriptor"
                                    ]), &[]);
        for entry in search {
            let entry = entry?;
            let guid = get_attr_guid(&[&entry], &entry.dn, "schemaidguid")?;
            let name = get_attr_str(&[&entry], &entry.dn, "ldapdisplayname")?;
            class_guids.insert(name.clone().to_ascii_lowercase(), guid);
        }

        // Fetch attribute types
        let search = LdapSearch::new(&conn, Some(conn.get_schema_naming_context()), LDAP_SCOPE_SUBTREE,
                                    Some("(objectClass=attributeSchema)"),
                                    Some(&[
                                        "schemaIDGUID",
                                        "lDAPDisplayName",
                                    ]), &[]);
        for entry in search {
            let entry = entry?;
            let guid = get_attr_guid(&[&entry], &entry.dn, "schemaidguid")?;
            let name = get_attr_str(&[&entry], &entry.dn, "ldapdisplayname")?;
            attribute_guids.insert(guid, name);
        }

        // Fetch property sets (validAccesses = READ_PROP | WRITE_PROP)
        let search = LdapSearch::new(&conn, Some(conn.get_configuration_naming_context()), LDAP_SCOPE_SUBTREE,
                                    Some("(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*))"),
                                    Some(&[
                                        "rightsGuid",
                                        "displayName",
                                    ]), &[]);
        for entry in search {
            let entry = entry?;
            let guid = get_attr_str(&[&entry], &entry.dn, "rightsguid")?;
            let guid = Guid::try_from(guid.as_str()).expect("unable to parse propertyset rightsGuid as GUID");
            let name = get_attr_str(&[&entry], &entry.dn, "displayname")?;
            property_set_names.insert(guid, name);
        }

        // Fetch validated writes (validAccesses = SELF)
        let search = LdapSearch::new(&conn, Some(conn.get_configuration_naming_context()), LDAP_SCOPE_SUBTREE,
        Some("(&(objectClass=controlAccessRight)(validAccesses=8)(rightsGuid=*))"),
        Some(&[
            "rightsGuid",
            "displayName",
        ]), &[]);
        for entry in search {
            let entry = entry?;
            let guid = get_attr_str(&[&entry], &entry.dn, "rightsguid")?;
            let guid = Guid::try_from(guid.as_str()).expect("unable to parse validated write rightsGuid as GUID");
            let name = get_attr_str(&[&entry], &entry.dn, "displayname")?;
            validated_write_names.insert(guid, name);
        }

        // Fetch control access rights (validAccesses = CONTROL_ACCESS)
        let search = LdapSearch::new(&conn, Some(conn.get_configuration_naming_context()), LDAP_SCOPE_SUBTREE,
                                    Some("(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*))"),
                                    Some(&[
                                        "rightsGuid",
                                        "displayName",
                                    ]), &[]);
        for entry in search {
            let entry = entry?;
            let guid = get_attr_str(&[&entry], &entry.dn, "rightsguid")?;
            let guid = Guid::try_from(guid.as_str()).expect("unable to parse propertyset rightsGuid as GUID");
            let name = get_attr_str(&[&entry], &entry.dn, "displayname")?;
            control_access_names.insert(guid, name);
        }

        Ok(Self {
            class_guids,
            attribute_guids,
            property_set_names,
            validated_write_names,
            control_access_names,
        })
    }
}
