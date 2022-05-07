use crate::connection::LdapConnection;
use crate::error::LdapError;
use windows::Win32::Networking::Ldap::{LDAP_SUCCESS, LDAPMessage, ldap_first_entry, ldap_next_entry, ldap_memfree, ldap_get_dnW, ldap_msgfree, ldap_first_attributeW, ldap_get_values_lenW, ldap_next_attributeW, ldap_search_ext_sW, ldapcontrolW, LDAP_BERVAL, ldap_create_page_controlW, ldap_control_freeW, ldap_parse_resultW, ldap_parse_page_controlW, ber_bvfree, ldap_controls_freeW, LDAP_CONTROL_NOT_FOUND};
use windows::Win32::Foundation::{PSTR, PWSTR, BOOLEAN};
use std::ptr::{null_mut, null};
use std::collections::HashMap;
use crate::utils::{pwstr_to_str, str_to_wstr};
use crate::control::LdapControl;

#[derive(Debug)]
pub struct LdapSearch<'a> {
    connection: &'a LdapConnection,
    base: Option<String>,
    scope: u32,
    filter: Option<String>,
    attr_names: Option<Vec<String>>,
    attr_names_u16: Option<Vec<Vec<u16>>>,
    attr_names_ptrs: Option<Vec<*const u16>>,
    server_controls: Vec<LdapControl>,
    page_cookie: Vec<u8>,
    result_page: *mut LDAPMessage,
    cursor_entry: *mut LDAPMessage,
    // Boolean flag enabled when we returned an error in the past,
    // meaning we must stop returning the same error over and over,
    // otherwise callers which .collect() us would loop indefinitely.
    failed: bool,
}

#[derive(Debug, Clone)]
pub struct LdapEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl<'a> LdapSearch<'a> {
    pub fn new(connection: &'a LdapConnection,
               base: Option<&str>,
               scope: u32,
               filter: Option<&str>,
               only_attributes: Option<&[&str]>,
               server_controls: &[&LdapControl],
    ) -> Self {
        let mut res = Self {
            connection,
            base: base.map(|s| s.to_owned()),
            scope,
            filter: filter.map(|s| s.to_owned()),
            attr_names: only_attributes.map(|v| v.iter().map(|s| s.to_string()).collect()),
            attr_names_u16: only_attributes.map(|v| v.iter().map(|s| str_to_wstr(s)).collect()),
            attr_names_ptrs: None,
            server_controls: server_controls.iter().map(|c| (*c).to_owned()).collect(),
            page_cookie: vec![],
            result_page: null_mut(),
            cursor_entry: null_mut(),
            failed: false,
        };
        // Only compute pointers to individual attribute names once they are stored
        // in their definitive location and won't move anymore. 
        if let Some(vec) = &res.attr_names_u16 {
            res.attr_names_ptrs = Some(vec.iter().map(|v| v.as_ptr()).chain(std::iter::once(null())).collect());
        }
        res
    }
}

impl Drop for LdapSearch<'_> {
    fn drop(&mut self) {
        if !self.result_page.is_null() {
            unsafe { ldap_msgfree(self.result_page) };
            self.result_page = null_mut();
        }
    }
}

impl<'a> Iterator for LdapSearch<'a> {
    type Item = Result<LdapEntry, LdapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.cursor_entry.is_null() {
            // If we have previously queried the server, and have obtained results, it
            // means we have scanned them all and reached the end of this page.
            if !self.result_page.is_null() {
                // If we do not have a cookie, it means we reached the end of all results
                // and must stop returning anything.
                if self.page_cookie.is_empty() {
                    return None; // don't free the page yet, so we reach this line again on next calls
                }
                else {
                    unsafe { ldap_msgfree(self.result_page) };
                    self.result_page = null_mut();
                }
            }
            if self.result_page.is_null() {
                // Run a first/nth query if we do not have a result page to fetch from
                // Prepare attribute name array of pointers
                let attr_names: *const *const u16  = self.attr_names_ptrs.as_ref().map(|v| v.as_ptr()).unwrap_or(null());

                // Prepare server control array of pointers (at the last moment because of paging, which changes every time)
                let mut server_controls: Vec<ldapcontrolW> = Vec::new();
                for control in &self.server_controls {
                    server_controls.push(ldapcontrolW {
                        ldctl_oid: PWSTR(control.oid.as_ptr() as *mut _),
                        ldctl_value: LDAP_BERVAL {
                            bv_len: control.value.len() as u32,
                            bv_val: PSTR(control.value.as_ptr() as *mut _),
                        },
                        ldctl_iscritical: BOOLEAN(if control.critical { 1 } else { 0 })
                    });
                }
                let mut page_control: *mut ldapcontrolW = null_mut();
                let page_cookie = LDAP_BERVAL {
                    bv_len: self.page_cookie.len() as u32,
                    bv_val: PSTR(self.page_cookie.as_ptr()),
                };
                let res = unsafe { ldap_create_page_controlW(self.connection.handle, 999, if self.page_cookie.is_empty() { null_mut() } else { &page_cookie as *const _ as *mut _ }, 1, &mut page_control as *mut _) };
                if res != (LDAP_SUCCESS.0 as u32) {
                    self.failed = true;
                    return Some(Err(LdapError::CreatePageControlFailed {
                        code: res,
                    }));
                }
                let server_controls_ptrs: Vec<*const ldapcontrolW> = server_controls.iter()
                    .map(|c| c as *const ldapcontrolW)
                    .chain(std::iter::once(page_control as *const ldapcontrolW))
                    .chain(std::iter::once(null()))
                    .collect();
                let server_controls: *const *const ldapcontrolW = server_controls_ptrs.as_ptr();

                let res = unsafe {
                    match (&self.base, &self.filter) {
                        (Some(base), Some(filter)) => ldap_search_ext_sW(self.connection.handle, base.as_str(), self.scope, filter.as_str(), attr_names, 0, server_controls, null_mut(), null_mut(), 0, &mut self.result_page as *mut *mut LDAPMessage),
                        (Some(base), None) => ldap_search_ext_sW(self.connection.handle, base.as_str(), self.scope, None, attr_names, 0, server_controls, null_mut(), null_mut(), 0, &mut self.result_page as *mut *mut LDAPMessage),
                        (None, Some(filter)) => ldap_search_ext_sW(self.connection.handle, None, self.scope, filter.as_str(), attr_names, 0, server_controls, null_mut(), null_mut(), 0,&mut self.result_page as *mut *mut LDAPMessage),
                        (None, None) => ldap_search_ext_sW(self.connection.handle, None, self.scope, None, attr_names, 0, server_controls, null_mut(), null_mut(), 0, &mut self.result_page as *mut *mut LDAPMessage),
                    }
                };
                if !page_control.is_null() {
                    unsafe { ldap_control_freeW(page_control); }
                }
                if res != (LDAP_SUCCESS.0 as u32) || self.result_page.is_null() {
                    // Some return codes indicate failure, but some results were allocated
                    // and need to be freed anyway (e.g. LDAP_PARTIAL_RESULTS or LDAP_REFERRAL)
                    if !self.result_page.is_null() {
                        unsafe { ldap_msgfree(self.result_page) };
                        self.result_page = null_mut();
                    }
                    self.failed = true;
                    return Some(Err(LdapError::SearchFailed {
                        base: self.base.clone(),
                        filter: self.filter.clone(),
                        only_attributes: self.attr_names.clone(),
                        code: res,
                    }));
                }
                // We did get a result, parse the paging cookie from the controls in the response,
                // so that the next query starts back from there
                let mut response_controls: *mut *mut ldapcontrolW = null_mut();
                let res = unsafe { ldap_parse_resultW(self.connection.handle, self.result_page, null_mut(), null_mut(), null_mut(), null_mut(), &mut response_controls as *mut _, BOOLEAN(0)) };
                if res != (LDAP_SUCCESS.0 as u32) {
                    self.failed = true;
                    return Some(Err(LdapError::ParseResultFailed {
                        code: res,
                    }));
                }
                let mut cookie: *mut LDAP_BERVAL = null_mut();
                let res = unsafe { ldap_parse_page_controlW(self.connection.handle, response_controls, null_mut(), &mut cookie as *mut _) };
                if res == (LDAP_CONTROL_NOT_FOUND.0 as u32) {
                    // Server did not send any paging back, we have the last page of results
                    self.page_cookie = vec![];
                }
                else {
                    if res != (LDAP_SUCCESS.0 as u32) {
                        self.failed = true;
                        return Some(Err(LdapError::ParsePageControlFailed {
                            code: res,
                        }));
                    }
                    unsafe {
                        let slice = std::ptr::slice_from_raw_parts((*cookie).bv_val.0, (*cookie).bv_len as usize);
                        self.page_cookie = Vec::from(&*slice);
                        ber_bvfree(cookie);
                    }
                }
                unsafe {
                    ldap_controls_freeW(response_controls);
                }
            }
            self.cursor_entry = unsafe { ldap_first_entry(self.connection.handle, self.result_page) };
        }

        // If we could not fetch one more entry, we reached the end of results
        if self.cursor_entry.is_null() {
            if self.connection.get_errcode() != 0 {
                self.failed = true;
                return Some(Err(LdapError::GetFirstEntryFailed {
                    code: self.connection.get_errcode(),
                }))
            }
            return None;
        }

        // We have a new entry, get its DN
        let dn = unsafe {
            let ptr = ldap_get_dnW(self.connection.handle, self.cursor_entry);
            if ptr.is_null() {
                self.failed = true;
                return Some(Err(LdapError::GetDNFailed { code: self.connection.get_errcode() }));
            }
            let dn = pwstr_to_str(ptr.0);
            ldap_memfree(PSTR(ptr.0 as *mut u8));
            dn
        };
        // Then get all its attributes
        let mut attrs = HashMap::new();
        let mut cursor_attr = null_mut();
        let mut attr_name = unsafe { ldap_first_attributeW(self.connection.handle, self.cursor_entry, &mut cursor_attr as *mut _) };
        while !attr_name.is_null() {
            // Make attribute names lowercase, so that lookups can be performed quickly using hashmaps
            let name = pwstr_to_str(attr_name.0).to_lowercase();
            let mut values = Vec::new();

            let values_raw = unsafe { ldap_get_values_lenW(self.connection.handle, self.cursor_entry, attr_name) };
            if values_raw.is_null() {
                // ldap_get_values_lenW can return NULL if there is no value, or if an error
                // occured: we need to check the error flag in the connection
                if self.connection.get_errcode() != 0 {
                    self.failed = true;
                    return Some(Err(LdapError::GetAttributeValuesFailed {
                        dn,
                        name,
                        code: self.connection.get_errcode(),
                    }))
                }
            }
            else {
                for value_idx in 0isize.. {
                    let value_raw = unsafe { *(values_raw.offset(value_idx)) };
                    if value_raw.is_null() {
                        break; // the pointer list is terminated by a NULL pointer
                    }
                    let slice = unsafe { std::slice::from_raw_parts((*value_raw).bv_val.0, (*value_raw).bv_len as usize) };
                    values.push(slice.to_vec());
                }
            }

            if attrs.contains_key(&name) {
                self.failed = true;
                return Some(Err(LdapError::AttributeNamesCollision {
                    dn, attr_name: name,
                }));
            }
            attrs.insert(name, values);
            attr_name = unsafe { ldap_next_attributeW(self.connection.handle, self.cursor_entry, cursor_attr) };
        }
        // ldap_first_attributeW and ldap_next_attributeW can return NULL both to
        // mean "no more entry" or that an error occured. We need to check the error flag in the
        // connection.
        if self.connection.get_errcode() != 0 {
            self.failed = true;
            return Some(Err(LdapError::GetAttributeNamesFailed {
                dn,
                code: self.connection.get_errcode(),
            }))
        }

        // ldap_next_entry() can return NULL both to mean "no more entry" or that an error occured.
        // We need to check the error flag in the connection.
        self.cursor_entry = unsafe { ldap_next_entry(self.connection.handle, self.cursor_entry) };
        if self.connection.get_errcode() != 0 {
            self.failed = true;
            return Some(Err(LdapError::GetNextEntryFailed {
                code: self.connection.get_errcode(),
            }))
        }

        Some(Ok(LdapEntry {
            dn,
            attrs,
        }))
    }
}