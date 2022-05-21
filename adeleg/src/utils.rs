use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_DELETE, ADS_RIGHT_READ_CONTROL, ADS_RIGHT_WRITE_DAC, ADS_RIGHT_WRITE_OWNER, ADS_RIGHT_SYNCHRONIZE, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_GENERIC_READ, ADS_RIGHT_GENERIC_WRITE, ADS_RIGHT_GENERIC_EXECUTE, ADS_RIGHT_GENERIC_ALL, ADS_RIGHT_DS_CREATE_CHILD};
use windows::Win32::Security::{CONTAINER_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, INHERIT_ONLY_ACE};
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_BASE, LDAP_SCOPE_SUBTREE, LDAP_SCOPE_ONELEVEL};
use core::borrow::Borrow;
use authz::{Ace, Sid, SecurityDescriptor, Guid};
use winldap::connection::LdapConnection;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use winldap::utils::get_attr_str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub sid: Sid,
    pub distinguished_name: String,
    pub netbios_name: String,
}

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
    let (dn, attrs) = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        (&search_results[0].borrow().dn, &search_results[0].borrow().attrs)
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: dn.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            match SecurityDescriptor::from_bytes(&vals[0]) {
                Ok(sd) => Ok(sd),
                Err(e) => {
                    eprintln!(" [!] Unable to parse security descriptor at {} : {}", &dn, e);
                    return Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() });
                }
            }
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() })
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

pub(crate) fn get_domains(conn: &LdapConnection) -> Result<Vec<Domain>, LdapError> {
    let partitions_dn = format!("CN=Partitions,{}", conn.get_configuration_naming_context());
    let search = LdapSearch::new(&conn, Some(&partitions_dn), LDAP_SCOPE_ONELEVEL, Some("(&(nCName=*)(nETBIOSName=*))"), Some(&["nCName", "nETBIOSName"]), &[]);
    let partitions = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;

    let mut v = vec![];
    for partition in &partitions {
        let nc = get_attr_str(&[partition], &partition.dn, "ncname")?;
        let netbios_name = get_attr_str(&[partition], &partition.dn, "netbiosname")?;

        let mut search = LdapSearch::new(&conn, Some(&nc), LDAP_SCOPE_BASE, Some("(objectSid=*)"), Some(&["objectSid"]), &[]);
        let entry = search.next().ok_or(LdapError::RequiredObjectMissing { dn: nc.clone() })??;
        let sid = get_attr_sid(&[entry], &nc, "objectsid")?;

        v.push(Domain {
            distinguished_name: nc.to_owned(),
            sid,
            netbios_name,
        });
    }
    Ok(v)
}

pub(crate) fn get_ace_derived_by_inheritance_from_schema(parent_aces: &[Ace], child_owner: &Sid, child_object_type: &Guid, force_inheritance: bool) -> Vec<Ace> {
    let mut res = vec![];
    for parent_ace in parent_aces {
        if !force_inheritance && (parent_ace.flags & CONTAINER_INHERIT_ACE.0 as u8) == 0 {
            continue;
        }
        if let Some(guid) = parent_ace.get_inherited_object_type() {
            if guid != child_object_type && (parent_ace.flags & NO_PROPAGATE_INHERIT_ACE.0 as u8) != 0 {
                continue;
            }
        }

        let mut flags = parent_ace.flags;
        if (parent_ace.flags & NO_PROPAGATE_INHERIT_ACE.0 as u8) != 0 {
            flags &= !(CONTAINER_INHERIT_ACE.0 as u8 | OBJECT_INHERIT_ACE.0 as u8);
        }

        // Creator Owner SID gets replaced by the current owner
        if parent_ace.trustee == Sid::try_from("S-1-3-0").unwrap() {
            res.push(Ace {
                trustee: child_owner.clone(),
                access_mask: parent_ace.access_mask,
                flags: flags & !(CONTAINER_INHERIT_ACE.0 as u8 | OBJECT_INHERIT_ACE.0 as u8),
                type_specific: parent_ace.type_specific.clone(),
            });
            res.push(Ace {
                trustee: parent_ace.trustee.clone(),
                access_mask: parent_ace.access_mask,
                flags: flags | (INHERIT_ONLY_ACE.0 as u8),
                type_specific: parent_ace.type_specific.clone(),
            });
        } else {
            res.push(Ace {
                trustee: parent_ace.trustee.clone(),
                access_mask: parent_ace.access_mask,
                flags,
                type_specific: parent_ace.type_specific.clone(),
            });
        }
    }
    res
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

pub(crate) fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
    }
}

pub(crate) fn replace_suffix_case_insensitive<'a>(haystack: &'a str, suffix: &str, replacement: &str) -> String {
    if haystack.to_lowercase().ends_with(&suffix.to_lowercase()) && haystack.is_char_boundary(haystack.len() - suffix.len()) {
        format!("{}{}", &haystack[..haystack.len() - suffix.len()], replacement)
    } else {
        haystack.to_owned()
    }
}

pub(crate) fn ends_with_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().ends_with(&needle.to_lowercase())
}

pub(crate) fn resolve_samaccountname_to_sid(ldap: &LdapConnection, samaccountname: &str, domain: &Domain) -> Result<Sid, LdapError> {
    let search = LdapSearch::new(&ldap, Some(&domain.distinguished_name), LDAP_SCOPE_SUBTREE, Some(&format!("(samAccountName={})", samaccountname)), Some(&["objectSid"]), &[]);
    let res = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    get_attr_sid(&res, &domain.distinguished_name, "objectsid")
}

pub(crate) fn ace_equivalent(a: &Ace, b: &Ace) -> bool {
    if a == b {
        return true;
    }

    let mut a = a.clone();
    let mut b = b.clone();

    a.access_mask = a.access_mask & !(crate::engine::IGNORED_ACCESS_RIGHTS);
    b.access_mask = b.access_mask & !(crate::engine::IGNORED_ACCESS_RIGHTS);

    a == b
}

pub(crate) fn find_ace_positions(needle: &[Ace], haystack: &[Ace]) -> Option<Vec<usize>> {
    let mut res = vec![];
    let mut iter = haystack.iter().enumerate();
    for needle_ace in needle {
        let mut found = false;
        while let Some((haystack_pos, haystack_ace)) = iter.next() {
            if ace_equivalent(haystack_ace, needle_ace) {
                res.push(haystack_pos);
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }
    Some(res)
}