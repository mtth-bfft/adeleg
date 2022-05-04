use winldap::connection::LdapConnection;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use winldap::utils::get_attr_str;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_SUBTREE;
use authz::{SecurityDescriptor, Sid, Guid};
use std::collections::HashMap;
use crate::utils::get_attr_guid;

pub struct Schema {
    // Mapping from class GUID to class name
    pub(crate) class_guids: HashMap<Guid, String>,
    // Default security descriptor, by domain sid then by class name
    // (they are stored in the schema as SDDL, so that they can be
    // specialized to the domain SID where objects are instantiated,
    // so that e.g. "DA" expands to the right "S-1-5-21-XXXXX-512").
    pub(crate) class_default_sd: HashMap<Sid, HashMap<String, SecurityDescriptor>>,
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
    pub fn query(conn: &LdapConnection, domain_sids: &[Sid], root_domain_sid: &Sid) -> Result<Self, LdapError> {
        let mut class_guids = HashMap::new();
        let mut class_default_sd = HashMap::new();
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
            class_guids.insert(guid, name.clone());
            // Not all classes have a default SDDL attribute (if they are not used as the most specialized class of any object)
            if let Ok(sddl) = get_attr_str(&[&entry], &entry.dn, "defaultsecuritydescriptor") {
                for domain_sid in domain_sids {
                    let sd = SecurityDescriptor::from_str(&sddl, &domain_sid, &root_domain_sid).expect("unable to parse defaultSecurityDescriptor in schema");
                    if let Some(default_acl) = &sd.dacl {
                        if let Err(ace) = default_acl.check_canonicality() {
                            eprintln!(" [!] Default ACL of class {} at {} is not in canonical order, fix ACE: {:?}", name, entry.dn, ace);
                        }
                    }
                    let mapping = class_default_sd.entry(domain_sid.to_owned()).or_insert(HashMap::new());
                    mapping.insert(name.clone(), sd);
                }
            }
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
            class_default_sd,
            attribute_guids,
            property_set_names,
            validated_write_names,
            control_access_names,
        })
    }
}
