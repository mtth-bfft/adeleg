use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use winldap::control::{BerVal, BerEncodable};
use windows::Win32::Networking::Ldap::LDAP_SERVER_SD_FLAGS_OID;
use winldap::control::LdapControl;
use core::borrow::Borrow;
use authz::{Sid, SecurityDescriptor};
use winldap::connection::LdapConnection;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use windows::Win32::Networking::Ldap::LDAP_SCOPE_BASE;

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

pub(crate) fn get_forest_sid(conn: &LdapConnection) -> Result<Sid, LdapError> {
    let search = LdapSearch::new(&conn, Some(conn.get_root_domain_naming_context()), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
    let root_domain = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    let sid = get_attr_sid(&root_domain, conn.get_root_domain_naming_context(), "objectsid").expect("unable to parse forest SID");
    Ok(sid)
}

pub(crate) fn get_domain_sid(conn: &LdapConnection, naming_context: &str, forest_sid: &Sid) -> Sid {
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
    let domain = match search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
        Ok(v) => v,
        _ => return forest_sid.clone(),
    };
    let sid = match get_attr_sid(&domain, &naming_context, "objectsid") {
        Ok(s) => s,
        _ => return forest_sid.clone(),
    };
    sid
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