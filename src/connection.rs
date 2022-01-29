use core::ptr::null_mut;
use windows::Win32::Foundation::PSTR;
use windows::Win32::Networking::Ldap::{ldap_initW, ldap_unbind, LdapGetLastError, ldap_connect, LDAP_TIMEVAL, LDAP_SUCCESS, ldap_bind_sA, ldap_err2stringW, ldap};
use windows::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_W, SEC_WINNT_AUTH_IDENTITY_UNICODE};

const LDAP_AUTH_NEGOTIATE: u32 = 1158;

pub struct LdapCredentials<'a> {
    pub domain: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

pub struct LdapConnection {
    handle: *mut ldap,
}

impl LdapConnection {
    pub fn new(server: Option<&str>, port: u16, credentials: Option<&LdapCredentials>) -> Result<Self, (u32, String)> {
        let handle = unsafe {
            if let Some(server) = server {
                ldap_initW(server, port as u32)
            } else {
                ldap_initW(None, port as u32)
            }
        };
        if handle.is_null() {
            return Err((get_ldap_errcode(), get_ldap_errmsg()));
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
        if conn != LDAP_SUCCESS as u32 {
            return Err((get_ldap_errcode(), get_ldap_errmsg()));
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
            return Err((get_ldap_errcode(), get_ldap_errmsg()));
        }

        Ok(Self {
            handle,
        })
    }

    pub fn destroy(&self) -> Result<(), (u32, String)> {
        let res = unsafe { ldap_unbind(self.handle) };
                if res != LDAP_SUCCESS as u32 {
            return Err((get_ldap_errcode(), get_ldap_errmsg()));
        }
        Ok(())
    }
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

fn str_to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn get_ldap_errcode() -> u32 {
    unsafe { LdapGetLastError() }
}

pub(crate) fn get_ldap_errmsg() -> String {
    let code = get_ldap_errcode();
    let res = unsafe { ldap_err2stringW(code) };
    if res.is_null() {
        format!("Unknown error code {}", code)
    } else {
        let mut len = 0;
        unsafe {
            while *(res.0.add(len)) != 0 {
                len += 1;
            }
        }
        let slice = unsafe { &*(std::ptr::slice_from_raw_parts(res.0, len)) };
        String::from_utf16_lossy(slice)
    }
}
