use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_CONTROL_ACCESS};
use authz::{Ace, AceType};
use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_DELETE, ADS_RIGHT_READ_CONTROL, ADS_RIGHT_WRITE_DAC, ADS_RIGHT_WRITE_OWNER, ADS_RIGHT_SYNCHRONIZE, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_GENERIC_READ, ADS_RIGHT_GENERIC_WRITE, ADS_RIGHT_GENERIC_EXECUTE, ADS_RIGHT_GENERIC_ALL, ADS_RIGHT_DS_CREATE_CHILD};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use winldap::control::{BerVal, BerEncodable};
use windows::Win32::Networking::Ldap::{LDAP_SERVER_SD_FLAGS_OID, LDAP_SCOPE_SUBTREE, LDAP_SCOPE_ONELEVEL};
use winldap::control::LdapControl;
use core::borrow::Borrow;
use authz::{Sid, SecurityDescriptor, Guid};
use winldap::connection::LdapConnection;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use winldap::utils::get_attr_str;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_BASE;

use crate::schema::Schema;

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

pub(crate) fn get_domains(conn: &LdapConnection) -> Result<Vec<Domain>, LdapError> {
    let partitions_dn = format!("CN=Partitions,{}", conn.get_configuration_naming_context());
    let search = LdapSearch::new(&conn, Some(&partitions_dn), LDAP_SCOPE_ONELEVEL, Some("(&(nCName=*)(nETBIOSName=*))"), Some(&["nCName", "nETBIOSName"]), &[]);
    let partitions = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;

    let mut v = vec![];
    for partition in &partitions {
        let nc = get_attr_str(&[partition], &partition.dn, "ncname")?;
        let netbios_name = get_attr_str(&[partition], &partition.dn, "netbiosname")?;
        let sid = match get_domain_sid(&conn, &nc) {
            Some(sid) => sid,
            None => continue,
        };

        v.push(Domain {
            distinguished_name: nc.to_owned(),
            sid,
            netbios_name,
        });
    }
    Ok(v)
}

pub(crate) fn get_adminsdholder_aces(conn: &LdapConnection, naming_context: &str, domains: &[Domain], root_domain: &Domain) -> Result<Vec<Ace>, LdapError> {
    let nc_holding_object = &domains.iter().find(|dom| dom.distinguished_name == naming_context).unwrap_or(root_domain).distinguished_name;
    let dn = format!("CN=AdminSDHolder,CN=System,{}", nc_holding_object);
    let mut sd_control_val = BerVal::new();
    sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((DACL_SECURITY_INFORMATION.0).into())]));
        let sd_control = LdapControl::new(
        LDAP_SERVER_SD_FLAGS_OID,
        &sd_control_val,
        true)?;
    let search = LdapSearch::new(&conn, Some(&dn),LDAP_SCOPE_BASE,
    Some("(objectClass=*)"),
    Some(&["nTSecurityDescriptor"]), &[&sd_control]);
    let res = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    let sd = get_attr_sd(&res[..],  &dn, "ntsecuritydescriptor")?;
    Ok(sd.dacl.map(|d| d.aces).unwrap_or(vec![]))
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
