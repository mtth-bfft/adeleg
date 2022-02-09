use core::ptr::null_mut;
use crate::error::LdapError;
use windows::Win32::Foundation::PWSTR;
use windows::Win32::Networking::Ldap::{ldap_initW, ldap_unbind, ldap_connect, LDAP_TIMEVAL, LDAP_SUCCESS, ldap_bind_sW, ldap, LDAP_SCOPE_BASE};
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
    pub(crate) supported_controls: HashSet<String>,
    pub(crate) naming_contexts: Vec<String>,
    pub(crate) root_domain_naming_context: String,
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
        if conn != (LDAP_SUCCESS.0 as u32) {
            return Err(LdapError::ConnectionFailed(get_ldap_errcode()));
        }

        let mut domain_wstr;
        let mut username_wstr;
        let mut password_wstr;
        let creds = if let Some(creds) = credentials {
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
        let creds_ptr = if let Some(c) = &creds {
            PWSTR(c as *const _ as *mut _)
        } else {
            PWSTR(null_mut())
        };

        let res = unsafe { ldap_bind_sW(handle, None, creds_ptr, LDAP_AUTH_NEGOTIATE) };
        if res != (LDAP_SUCCESS.0 as u32) {
            return Err(LdapError::BindFailed(get_ldap_errcode()));
        }

        let mut conn = Self {
            handle,
            supported_controls: HashSet::new(),
            naming_contexts: Vec::new(),
            root_domain_naming_context: String::new(),
            schema_naming_context: String::new(),
        };

        let search = LdapSearch::new(&conn, None, LDAP_SCOPE_BASE, None, Some(&["supportedControl", "schemaNamingContext", "namingContexts", "rootDomainNamingContext"]), &[]);
        let rootdse = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
        conn.naming_contexts = get_attr_strs(&rootdse, "(rootDSE)", "namingcontexts")?;
        conn.schema_naming_context = get_attr_str(&rootdse, "(rootDSE)", "schemanamingcontext")?;
        conn.root_domain_naming_context = get_attr_str(&rootdse, "(rootDSE)", "rootdomainnamingcontext")?;
        conn.supported_controls = HashSet::from_iter(get_attr_strs(&rootdse, "(rootDSE)", "supportedcontrol")?.into_iter());

        Ok(conn)
    }

    pub fn get_errcode(&self) -> u32 {
        unsafe { (*self.handle).ld_errno }
    }

    pub fn get_naming_contexts(&self) -> &[String] {
        &self.naming_contexts[..]
    }

    pub fn get_root_domain_naming_context(&self) -> &str {
        self.root_domain_naming_context.as_str()
    }

    pub fn get_schema_naming_context(&self) -> &str {
        self.schema_naming_context.as_str()
    }

    pub fn supports_control(&self, oid: &str) -> bool {
        self.supported_controls.contains(oid)
    }

    pub fn destroy(&self) -> Result<(), LdapError> {
        let res = unsafe { ldap_unbind(self.handle) };
                if res != LDAP_SUCCESS.0 as u32 {
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
