use windows::Win32::Networking::Ldap::{LdapGetLastError, ldap_err2stringW};
use std::collections::HashMap;

pub(crate) fn str_to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn pwstr_to_str(ptr: *mut u16) -> String {
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

pub(crate) fn get_attr_strs(attrs: &HashMap<String, Vec<Vec<u8>>>, attr_name: &str) -> Option<Vec<String>> {
    if let Some(vals) = attrs.get(attr_name) {
        let mut strings = Vec::new();
        for val in vals {
            strings.push(String::from_utf8_lossy(&val).to_string());
        }
        Some(strings)
    } else {
        None
    }
}

pub(crate) fn get_attr_str(attrs: &HashMap<String, Vec<Vec<u8>>>, attr_name: &str) -> Option<String> {
    let mut strs = get_attr_strs(attrs, attr_name)?;
    if strs.len() == 1 {
        strs.pop()
    } else {
        None
    }
}
