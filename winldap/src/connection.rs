use core::ptr::null;
use crate::error::LdapError;
use windows::core::PCWSTR;
use windows::Win32::Networking::Ldap::{LDAP, ldap_initW, ldap_unbind, ldap_connect, LDAP_OPT_REFERRALS, LDAP_TIMEVAL, LDAP_SUCCESS, ldap_bind_sW, LDAP_SCOPE_BASE, ldap_set_option};
use windows::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_W, SEC_WINNT_AUTH_IDENTITY_UNICODE};
use crate::utils::{get_ldap_errcode, str_to_wstr, get_attr_str, get_attr_strs};
use crate::search::{LdapSearch, LdapEntry};
use std::collections::HashSet;
use std::iter::FromIterator;

const LDAP_AUTH_NEGOTIATE: u32 = 1158;

#[derive(Debug)]
pub struct LdapConnection {
    pub(crate) handle: *mut LDAP,
    pub(crate) supported_controls: HashSet<String>,
    pub(crate) naming_contexts: Vec<String>,
    pub(crate) root_domain_naming_context: String,
    pub(crate) schema_naming_context: String,
    pub(crate) configuration_naming_context: String,
}

unsafe impl Send for LdapConnection { }

impl LdapConnection {
    pub fn new(server: &str, port: u16, credentials: Option<(&str, &str, &str)>) -> Result<Self, LdapError> {
        let server_u16: Vec<u16> = server.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { ldap_initW(PCWSTR(server_u16.as_ptr()), port as u32) };
        if handle.is_null() {
            return Err(LdapError::ConnectionFailed(get_ldap_errcode()));
        }

        // Server may return referrals to other naming contexts on itself
        // which triggers DNS resolution attempts on the client, which may hang.
        // Disable referrals altogether to allow using this tool from outside the domain.
        if unsafe { ldap_set_option(handle, LDAP_OPT_REFERRALS as i32, 0 as _) } != (LDAP_SUCCESS.0 as u32) {
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
        let creds = if let Some((domain, username, password)) = credentials {
            domain_wstr = str_to_wstr(&domain);
            username_wstr = str_to_wstr(&username);
            password_wstr = str_to_wstr(&password);
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
            PCWSTR(c as *const _ as *const _)
        } else {
            PCWSTR(null())
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
            configuration_naming_context: String::new(),
            schema_naming_context: String::new(),
        };

        let search = LdapSearch::new(&conn, None, LDAP_SCOPE_BASE, None, Some(&["supportedControl", "schemaNamingContext", "namingContexts", "configurationNamingContext", "rootDomainNamingContext"]), &[]);
        let rootdse = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
        conn.naming_contexts = get_attr_strs(&rootdse, "(rootDSE)", "namingcontexts")?;
        conn.schema_naming_context = get_attr_str(&rootdse, "(rootDSE)", "schemanamingcontext")?;
        conn.configuration_naming_context = get_attr_str(&rootdse, "(rootDSE)", "configurationnamingcontext")?;
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

    pub fn get_configuration_naming_context(&self) -> &str {
        self.configuration_naming_context.as_str()
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
