use windows::Win32::Networking::Ldap::{ber_alloc_t, LBER_USE_DER, LDAP_BERVAL, ber_flatten, ber_free, ber_bvfree, berelement};

use crate::error::LdapError;
use std::ptr::null_mut;
use std::ffi::CString;
use std::collections::HashSet;

// See github.com/microsoft/windows-rs/issues
#[link(name = "Wldap32")]
extern "C" {
    fn ber_printf(pberelement: *mut berelement, fmt: *const u8, ...) -> i32;
}

#[derive(Debug, Clone)]
pub enum BerEncodable {
    Integer(i64),
    Boolean(bool),
    Null,
    Sequence(Vec<BerEncodable>),
    Set(HashSet<BerEncodable>),
}

impl BerEncodable {
    unsafe fn printf(&self, ber_element: *mut berelement) -> i32 {
        match self {
            BerEncodable::Integer(i) => {
                let fmt = CString::new("i").unwrap();
                ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr(), *i)
            },
            BerEncodable::Boolean(b) => {
                let fmt = CString::new("b").unwrap();
                ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr(), if *b { 1 } else { 0 })
            },
            BerEncodable::Null => {
                let fmt = CString::new("n").unwrap();
                ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr())
            },
            BerEncodable::Sequence(vec) => {
                let fmt = CString::new("{").unwrap();
                let res = ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr());
                if res < 0 {
                    return res;
                }
                for item in vec {
                    let res = item.printf(ber_element);
                    if res < 0 {
                        return res;
                    }
                }
                let fmt = CString::new("}").unwrap();
                ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr())
            },
            BerEncodable::Set(set) => {
                let fmt = CString::new("[").unwrap();
                let res = ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr());
                if res < 0 {
                    return res;
                }
                for item in set {
                    let res = item.printf(ber_element);
                    if res < 0 {
                        return res;
                    }
                }
                let fmt = CString::new("]").unwrap();
                ber_printf(ber_element, fmt.as_bytes_with_nul().as_ptr())
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct BerVal {
    elements: Vec<BerEncodable>,
}

impl BerVal {
    pub fn new() -> Self {
        Self {
            elements: Vec::new()
        }
    }

    pub fn append(&mut self, element: BerEncodable) -> &mut Self {
        self.elements.push(element);
        self
    }

    pub fn flatten(&self) -> Result<Vec<u8>, LdapError> {
        let ber_element = unsafe { ber_alloc_t(LBER_USE_DER as i32) };
        if ber_element.is_null() {
            return Err(LdapError::BerAllocFailed);
        }
        for item in &self.elements {
            let res = unsafe { item.printf(ber_element) };
            if res < 0 {
                unsafe { ber_free(ber_element, 1); }
                return Err(LdapError::BerPrintfFailed);
            }
        }

        unsafe {
            // ber_flatten() gives a privately allocated struct that needs to be
            // freed using ber_bvfree. Copy it to a simple Vec<>
            let mut ber_val: *mut LDAP_BERVAL = null_mut();
            let res = ber_flatten(ber_element, &mut ber_val as *mut _);
            if res < 0 {
                ber_free(ber_element, 1);
                return Err(LdapError::BerFlattenFailed);
            }

            let slice = std::ptr::slice_from_raw_parts((*ber_val).bv_val.0 as *const u8, (*ber_val).bv_len as usize);
            let res = Vec::from(&*slice);
            ber_bvfree(ber_val);
            Ok(res)
        }
    }
}

#[derive(Debug, Clone)]
pub struct LdapControl {
    pub(crate) oid: Vec<u16>,
    pub(crate) value: Vec<u8>,
    pub(crate) critical: bool,
}

impl LdapControl {
    pub fn new(oid: &str, value: &BerVal, critical: bool) -> Result<Self, LdapError> {
        let oid = oid.encode_utf16().chain(std::iter::once(0)).collect();
        let value = value.flatten()?;
        Ok(Self { oid, value, critical })
    }
}