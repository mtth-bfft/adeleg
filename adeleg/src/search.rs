use crate::connection::LdapConnection;
use crate::error::LdapError;
use windows::Win32::Networking::Ldap::{LDAP_PAGED_RESULT_OID_STRING, LDAP_SUCCESS, LDAPMessage, ldap_first_entry, ldap_next_entry, ldap_memfree, ldap_get_dnW, ldap_msgfree, ldap_first_attributeW, ldap_get_values_lenW, ldap_next_attributeW, ldap_search_ext_sW, ldapcontrolW, LDAP_BERVAL};
use windows::Win32::Foundation::{PSTR, PWSTR, BOOLEAN};
use std::ptr::{null_mut, null};
use std::collections::HashMap;
use crate::utils::pwstr_to_str;
use crate::control::LdapControl;

#[derive(Debug)]
pub struct LdapSearch<'a> {
    connection: &'a LdapConnection,
    result_page: *mut LDAPMessage,
    cursor_entry: *mut LDAPMessage,
}

#[derive(Debug)]
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
               server_controls: Option<&[&LdapControl]>,
    ) -> Result<Self, LdapError> {
        let mut result_page: *mut LDAPMessage = null_mut();
        let mut attr_names_vecs = Vec::new();
        let mut attr_names_ptrs  = Vec::new();
        let attr_names = if let Some(attr_list) = only_attributes {
            for attr_name in attr_list {
                let attr_name: Vec<u16> = attr_name.encode_utf16().chain(std::iter::once(0)).collect();
                attr_names_ptrs.push(attr_name.as_ptr());
                attr_names_vecs.push(attr_name);
            }
            attr_names_ptrs.push(null_mut()); // the pointer list needs to be NULL-terminated
            attr_names_ptrs.as_mut_ptr()
        } else {
            null_mut()
        };
        let mut server_controls_structs: Vec<ldapcontrolW> = Vec::new();
        let mut server_controls_ptrs: Vec<*const ldapcontrolW> = Vec::new();
        if let Some(server_controls) = server_controls {
            for control in server_controls {
                server_controls_structs.push(ldapcontrolW {
                    ldctl_oid: PWSTR(control.oid.as_ptr() as *mut _),
                    ldctl_value: LDAP_BERVAL {
                        bv_len: control.value.len() as u32,
                        bv_val: PSTR(control.value.as_ptr() as *mut _),
                    },
                    ldctl_iscritical: BOOLEAN(if control.critical { 1 } else { 0 })
                });
                server_controls_ptrs.push(&server_controls_structs[server_controls_structs.len() - 1] as *const _)
            }
        }
        let paginate = connection.supported_controls.contains(LDAP_PAGED_RESULT_OID_STRING);
        if paginate {

        }
        server_controls_ptrs.push(null() as *const ldapcontrolW);
        let res = unsafe {
            match (base, filter) {
                (Some(base), Some(filter)) => ldap_search_ext_sW(connection.handle, base, scope, filter, attr_names, 0, server_controls_ptrs.as_ptr(), null_mut(), null_mut(), 0, &mut result_page as *mut *mut LDAPMessage),
                (Some(base), None) => ldap_search_ext_sW(connection.handle, base, scope, None, attr_names, 0, server_controls_ptrs.as_ptr(), null_mut(), null_mut(), 0, &mut result_page as *mut *mut LDAPMessage),
                (None, Some(filter)) => ldap_search_ext_sW(connection.handle, None, scope, filter, attr_names, 0, server_controls_ptrs.as_ptr(), null_mut(), null_mut(), 0,&mut result_page as *mut *mut LDAPMessage),
                (None, None) => ldap_search_ext_sW(connection.handle, None, scope, None, attr_names, 0, server_controls_ptrs.as_ptr(), null_mut(), null_mut(), 0, &mut result_page as *mut *mut LDAPMessage),
            }
        };
        if res != (LDAP_SUCCESS.0 as u32) || result_page.is_null() {
            // Some return codes indicate failure, but some results were allocated
            // and need to be freed (e.g. LDAP_PARTIAL_RESULTS or LDAP_REFERRAL)
            if !result_page.is_null() {
                unsafe { ldap_msgfree(result_page) };
            }
            return Err(LdapError::SearchFailed {
                base: base.map(|v| v.to_owned()),
                filter: filter.map(|v| v.to_owned()),
                only_attributes: only_attributes.map(|v| v.iter().map(|w| (*w).to_owned()).collect::<Vec<String>>()),
                code: res,
            });
        }
        let cursor_entry = unsafe { ldap_first_entry(connection.handle, result_page) };
        Ok(Self {
            connection,
            result_page,
            cursor_entry,
        })
    }
}

impl Drop for LdapSearch<'_> {
    fn drop(&mut self) {
        if !self.result_page.is_null() {
            let res = unsafe { ldap_msgfree(self.result_page) };
            if res != (LDAP_SUCCESS.0 as u32) && !std::thread::panicking() {
                panic!("Unable to free result page {:?}", self.result_page);
            }
            self.result_page = null_mut();
        }
    }
}

impl<'a> Iterator for LdapSearch<'a> {
    type Item = Result<LdapEntry, LdapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor_entry.is_null() {
            return None;
        }
        // We have a new entry, get its DN
        let dn = unsafe {
            let ptr = ldap_get_dnW(self.connection.handle, self.cursor_entry);
            if ptr.is_null() {
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
            return Some(Err(LdapError::GetAttributeNamesFailed {
                dn,
                code: self.connection.get_errcode(),
            }))
        }

        self.cursor_entry = unsafe { ldap_next_entry(self.connection.handle, self.cursor_entry) };
        Some(Ok(LdapEntry {
            dn,
            attrs,
        }))
    }
}