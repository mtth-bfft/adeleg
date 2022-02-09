use core::borrow::Borrow;
use windows::Win32::Networking::Ldap::{LdapGetLastError, ldap_err2stringW, LDAP_SCOPE_BASE};
use authz::{Sid, SecurityDescriptor};
use crate::connection::LdapConnection;
use crate::search::{LdapSearch, LdapEntry};
use crate::error::LdapError;

pub(crate) fn str_to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn pwstr_to_str(ptr: *const u16) -> String {
    let mut len = 0;
    unsafe {
        while *(ptr.add(len)) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { &*(std::ptr::slice_from_raw_parts(ptr, len)) };
    String::from_utf16_lossy(slice)
}

pub(crate) fn get_ldap_errcode() -> u32 {
    unsafe { LdapGetLastError() }
}

pub(crate) fn get_ldap_errmsg(code: u32) -> String {
    let res = unsafe { ldap_err2stringW(code) };
    if res.is_null() {
        format!("unknown error, code {}", code)
    } else {
        pwstr_to_str(res.0)
    }
}

pub(crate) fn get_attr_strs<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Vec<String>, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        let mut strings = Vec::new();
        for val in vals {
            strings.push(String::from_utf8_lossy(val).to_string());
        }
        Ok(strings)
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_str<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<String, LdapError> {
    let mut strs = get_attr_strs(search_results, base, attr_name)?;
    if let Some(s) = strs.pop() {
        if let Some(s2) = strs.pop() {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: s, val2: s2 });
        }
        Ok(s)
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
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

pub(crate) fn get_domain_sid(conn: &LdapConnection, naming_context: &str) -> Sid {
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
    let domain = match search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
        Ok(v) => v,
        _ => return conn.forest_sid.clone(),
    };
    let sid = match get_attr_sid(&domain, &naming_context, "objectsid") {
        Ok(s) => s,
        _ => return conn.forest_sid.clone(),
    };
    sid
}