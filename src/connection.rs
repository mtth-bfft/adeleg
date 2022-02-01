use core::ptr::null_mut;
use crate::error::LdapError;
use windows::Win32::Foundation::PSTR;
use windows::Win32::Networking::Ldap::{ldap_initW, ldap_unbind, ldap_connect, LDAP_TIMEVAL, LDAP_SUCCESS, ldap_bind_sA, ldap, LDAP_SCOPE_BASE};
use windows::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_W, SEC_WINNT_AUTH_IDENTITY_UNICODE};
use crate::utils::{get_ldap_errcode, str_to_wstr, get_attr_str, get_attr_strs};
use crate::search::{LdapSearch, LdapEntry};
use std::collections::HashSet;
use std::iter::FromIterator;

const LDAP_AUTH_NEGOTIATE: u32 = 1158;

pub struct LdapCredentials<'a> {
    pub domain: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

#[derive(Debug)]
pub struct LdapConnection {
    pub(crate) handle: *mut ldap,
    pub(crate) capabilities: HashSet<String>,
    pub(crate) schema_naming_context: String,
}

impl LdapConnection {
    pub fn new(server: Option<&str>, port: u16, credentials: Option<&LdapCredentials>) -> Result<Self, LdapError> {
        let handle = unsafe {
            if let Some(server) = server {
                ldap_initW(server, port as u32)
            } else {
                ldap_initW(None, port as u32)
            }
        };
        if handle.is_null() {
            return Err(LdapError::ConnectionFailed(get_ldap_errcode()));
        }

        // The actual connection timeout is much higher than that, since underlying
        // layers must fail before this timeout even starts: DNS, maybe mDNS, maybe
        // NBNS, etc. On a default Windows 10 install, that easily takes 1500 ms.
        let mut timeout = LDAP_TIMEVAL {
            tv_sec: 2,
            tv_usec: 0,
        };
        let conn = unsafe {
            ldap_connect(handle, &mut timeout)
        };
        if conn != (LDAP_SUCCESS as u32) {
            return Err(LdapError::ConnectionFailed(get_ldap_errcode()));
        }

        let mut domain_wstr;
        let mut username_wstr;
        let mut password_wstr;
        let creds= if let Some(creds) = credentials {
            domain_wstr = str_to_wstr(creds.domain);
            username_wstr = str_to_wstr(creds.username);
            password_wstr = str_to_wstr(creds.password);
            Some(SEC_WINNT_AUTH_IDENTITY_W {
                User: username_wstr.as_mut_ptr(),
                UserLength: (username_wstr.len() - 1) as u32,
                Domain: domain_wstr.as_mut_ptr(),
                DomainLength: (domain_wstr.len() - 1) as u32,
                Password: password_wstr.as_mut_ptr(),
                PasswordLength: (password_wstr.len() - 1) as u32,
                Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
            })
        } else {
            None
        };
        let creds = if let Some(creds) = creds {
            PSTR(&creds as *const _ as *mut _)
        } else {
            PSTR(null_mut())
        };

        let res = unsafe { ldap_bind_sA(handle, None, creds, LDAP_AUTH_NEGOTIATE) };
        if res != LDAP_SUCCESS as u32 {
            return Err(LdapError::BindFailed(get_ldap_errcode()));
        }

        let mut conn = Self {
            handle,
            capabilities: HashSet::new(),
            schema_naming_context: String::new(),
        };

        let search = LdapSearch::new(&conn, None, LDAP_SCOPE_BASE, None, Some(&["supportedCapabilities", "schemaNamingContext"]))?;
        let rootdse = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
        let rootdse = if rootdse.len() != 1 {
            return Err(LdapError::RootDSEQueryFailed);
        } else {
            &rootdse[0].attrs
        };

        if let Some(schema_naming_context) = get_attr_str(rootdse, "schemanamingcontext") {
            conn.schema_naming_context = schema_naming_context;
        } else {
            return Err(LdapError::RootDSEAttributeMissing);
        }
        let capabilities = get_attr_strs(rootdse, "supportedcapabilities");
        let capabilities = HashSet::from_iter(capabilities.unwrap().into_iter());
        conn.capabilities = capabilities;

        Ok(conn)
    }

    pub fn get_errcode(&self) -> u32 {
        unsafe { (*self.handle).ld_errno }
    }

    pub fn destroy(&self) -> Result<(), LdapError> {
        let res = unsafe { ldap_unbind(self.handle) };
                if res != LDAP_SUCCESS as u32 {
            return Err(LdapError::UnbindFailed(get_ldap_errcode()));
        }
        Ok(())
    }
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}
