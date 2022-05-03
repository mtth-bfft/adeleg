use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_CONTROL_ACCESS};
use authz::{Ace, AceType};
use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_DELETE, ADS_RIGHT_READ_CONTROL, ADS_RIGHT_WRITE_DAC, ADS_RIGHT_WRITE_OWNER, ADS_RIGHT_SYNCHRONIZE, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_GENERIC_READ, ADS_RIGHT_GENERIC_WRITE, ADS_RIGHT_GENERIC_EXECUTE, ADS_RIGHT_GENERIC_ALL, ADS_RIGHT_DS_CREATE_CHILD};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use winldap::control::{BerVal, BerEncodable};
use windows::Win32::Networking::Ldap::LDAP_SERVER_SD_FLAGS_OID;
use winldap::control::LdapControl;
use core::borrow::Borrow;
use authz::{Sid, SecurityDescriptor, Guid};
use winldap::connection::LdapConnection;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_BASE;

use crate::schema::Schema;

pub(crate) fn get_attr_sid<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Sid, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            Ok(Sid::from_bytes(&vals[0]).unwrap())
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_sd<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<SecurityDescriptor, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            Ok(SecurityDescriptor::from_bytes(&vals[0]).unwrap())
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_guid<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Guid, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            let bytes = &vals[0];
            if bytes.len() != 16 {
                return Err(LdapError::UnableToParseGuid { dn: base.to_owned(), attr_name: attr_name.to_owned(), bytes: bytes.to_owned() });
            }
            Ok(Guid::from_values(
                u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
                u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
                bytes[8..16].try_into().unwrap()))
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_forest_sid(conn: &LdapConnection) -> Result<Sid, LdapError> {
    let search = LdapSearch::new(&conn, Some(conn.get_root_domain_naming_context()), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
    let root_domain = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    let sid = get_attr_sid(&root_domain, conn.get_root_domain_naming_context(), "objectsid").expect("unable to parse forest SID");
    Ok(sid)
}

pub(crate) fn get_domain_sid(conn: &LdapConnection, naming_context: &str) -> Option<Sid> {
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
    let domain = match search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
        Ok(v) => v,
        _ => return None,
    };
    let sid = match get_attr_sid(&domain, &naming_context, "objectsid") {
        Ok(s) => s,
        _ => return None,
    };
    Some(sid)
}

pub(crate) fn get_adminsdholder_sd(conn: &LdapConnection) -> Result<SecurityDescriptor, LdapError> {
    for nc in conn.get_naming_contexts() {
        let dn = format!("CN=AdminSDHolder,CN=System,{}", nc);
        let mut sd_control_val = BerVal::new();
        sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((DACL_SECURITY_INFORMATION.0).into())]));
            let sd_control = LdapControl::new(
            LDAP_SERVER_SD_FLAGS_OID,
            &sd_control_val,
            true)?;
        let search = LdapSearch::new(&conn, Some(&dn),LDAP_SCOPE_BASE,
        Some("(objectClass=*)"),
        Some(&["nTSecurityDescriptor"]), &[&sd_control]);
        if let Ok(adminsdholder) = search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
            if let Ok(sd) = get_attr_sd(&adminsdholder[..],  &dn, "ntsecuritydescriptor") {
                return Ok(sd);
            }
        }
    }
    Err(LdapError::RequiredObjectMissing {
        dn: "CN=AdminSDHolder,CN=System,*".to_owned()
    })
}

pub(crate) fn pretty_print_access_rights(mask: u32) -> String {
    let mut res = vec![];
    let mut mask = mask as i32;
    if (mask & ADS_RIGHT_DELETE.0) != 0 {
        res.push("DELETE".to_owned());
        mask -= ADS_RIGHT_DELETE.0;
    }
    if (mask & ADS_RIGHT_READ_CONTROL.0) != 0 {
        res.push("READ_CONTROL".to_owned());
        mask -= ADS_RIGHT_READ_CONTROL.0;
    }
    if (mask & ADS_RIGHT_WRITE_DAC.0) != 0 {
        res.push("WRITE_DAC".to_owned());
        mask -= ADS_RIGHT_WRITE_DAC.0;
    }
    if (mask & ADS_RIGHT_WRITE_OWNER.0) != 0 {
        res.push("WRITE_OWNER".to_owned());
        mask -= ADS_RIGHT_WRITE_OWNER.0;
    }
    if (mask & ADS_RIGHT_SYNCHRONIZE.0) != 0 {
        res.push("WRITE_OWNER".to_owned());
        mask -= ADS_RIGHT_SYNCHRONIZE.0;
    }
    if (mask & ADS_RIGHT_ACCESS_SYSTEM_SECURITY.0) != 0 {
        res.push("ACCESS_SYSTEM_SECURITY".to_owned());
        mask -= ADS_RIGHT_ACCESS_SYSTEM_SECURITY.0;
    }
    if (mask & ADS_RIGHT_GENERIC_READ.0) != 0 {
        res.push("GENERIC_READ".to_owned());
        mask -= ADS_RIGHT_GENERIC_READ.0;
    }
    if (mask & ADS_RIGHT_GENERIC_WRITE.0) != 0 {
        res.push("GENERIC_WRITE".to_owned());
        mask -= ADS_RIGHT_GENERIC_WRITE.0;
    }
    if (mask & ADS_RIGHT_GENERIC_EXECUTE.0) != 0 {
        res.push("GENERIC_EXECUTE".to_owned());
        mask -= ADS_RIGHT_GENERIC_EXECUTE.0;
    }
    if (mask & ADS_RIGHT_GENERIC_ALL.0) != 0 {
        res.push("GENERIC_ALL".to_owned());
        mask -= ADS_RIGHT_GENERIC_ALL.0;
    }
    if (mask & ADS_RIGHT_DS_CREATE_CHILD.0) != 0 {
        res.push("CREATE_CHILD".to_owned());
        mask -= ADS_RIGHT_DS_CREATE_CHILD.0;
    }
    if (mask & ADS_RIGHT_DS_DELETE_CHILD.0) != 0 {
        res.push("DELETE_CHILD".to_owned());
        mask -= ADS_RIGHT_DS_DELETE_CHILD.0;
    }
    if (mask & ADS_RIGHT_ACTRL_DS_LIST.0) != 0 {
        res.push("LIST".to_owned());
        mask -= ADS_RIGHT_ACTRL_DS_LIST.0;
    }
    if (mask & ADS_RIGHT_DS_SELF.0) != 0 {
        res.push("SELF".to_owned());
        mask -= ADS_RIGHT_DS_SELF.0;
    }
    if (mask & ADS_RIGHT_DS_READ_PROP.0) != 0 {
        res.push("READ_PROP".to_owned());
        mask -= ADS_RIGHT_DS_READ_PROP.0;
    }
    if (mask & ADS_RIGHT_DS_WRITE_PROP.0) != 0 {
        res.push("WRITE_PROP".to_owned());
        mask -= ADS_RIGHT_DS_WRITE_PROP.0;
    }
    if (mask & ADS_RIGHT_DS_DELETE_TREE.0) != 0 {
        res.push("DELETE_TREE".to_owned());
        mask -= ADS_RIGHT_DS_DELETE_TREE.0;
    }
    if (mask & ADS_RIGHT_DS_LIST_OBJECT.0) != 0 {
        res.push("LIST_OBJECT".to_owned());
        mask -= ADS_RIGHT_DS_LIST_OBJECT.0;
    }
    if (mask & ADS_RIGHT_DS_CONTROL_ACCESS.0) != 0 {
        res.push("CONTROL_ACCESS".to_owned());
        mask -= ADS_RIGHT_DS_CONTROL_ACCESS.0;
    }
    if mask != 0 {
        res.push(format!("0x{:X}", mask));
    }
    res.join(" | ")
}

pub(crate) fn pretty_print_ace(ace: &Ace, schema: &Schema) -> String {
    let mut res = format!("{} {} access mask 0x{:X} ({})", if ace.grants_access() { "allow" } else { "deny " },
        &ace.trustee, &ace.access_mask,
        pretty_print_access_rights(ace.access_mask));
    if ace.get_inherit_only() {
        res.push_str(" inherit_only");
    }
    if ace.get_no_propagate() {
        res.push_str(" no_propagate");
    }
    if ace.get_container_inherit() {
        res.push_str(" container_inherit");
    }
    if ace.get_object_inherit() {
        res.push_str(" object_inherit");
    }
    match &ace.type_specific {
        AceType::AccessAllowedObject { object_type: Some(guid), .. } => {
            if let Some(name) = schema.class_guids.get(&guid) {
                res.push_str(&format!(" of class {}", name));
            }
            if let Some(name) = schema.property_set_names.get(&guid) {
                res.push_str(&format!(" on property set {}", name));
            }
            if let Some(name) = schema.attribute_guids.get(&guid) {
                res.push_str(&format!(" on attribute {}", name));
            }
            if let Some(name) = schema.control_access_names.get(&guid) {
                res.push_str(&format!(" perform {}", name));
            }
            res.push_str(&format!(" ({})", guid));
        },
        _ => (),
    }

    match &ace.type_specific {
        AceType::AccessAllowedObject { inherited_object_type: Some(guid), .. } => {
            if let Some(name) = schema.class_guids.get(&guid) {
                res.push_str(&format!(" inherit on class {}", name));
            }
            res.push_str(&format!(" ({})", guid));
        },
        _ => (),
    }
    res
}

pub(crate) fn strip_naming_context<'a>(dn: &'a str, naming_context: &str) -> &'a str {
    if dn.to_lowercase().ends_with(&naming_context.to_lowercase()) && dn.is_char_boundary(dn.len() - naming_context.len()) {
        &dn[..dn.len() - naming_context.len()].trim_end_matches(',')
    } else {
        &dn[..]
    }
}

pub(crate) fn ends_with_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().ends_with(&needle.to_lowercase())
}