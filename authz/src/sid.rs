use core::fmt::Debug;
use std::convert::TryFrom;
use windows::Win32::Security::EqualPrefixSid;
use windows::Win32::Security::GetSidIdentifierAuthority;
use windows::Win32::Security::GetSidSubAuthority;
use windows::Win32::Security::GetSidSubAuthorityCount;
use core::ptr::null_mut;
use core::fmt::Display;
use crate::error::AuthzError;
use windows::Win32::Security::{IsValidSid, GetLengthSid};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Foundation::{PSID, PWSTR};
use windows::Win32::System::Memory::LocalFree;
use windows::core::alloc::fmt::Formatter;
use crate::utils::{pwstr_to_str, get_last_error};

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Sid {
    bytes: Vec<u8>,
}

impl Sid {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, AuthzError> {
        let is_valid = unsafe { IsValidSid(PSID(slice.as_ptr() as isize)) };
        if !is_valid.as_bool() {
            return Err(AuthzError::InvalidSidBytes(slice.to_vec()));
        }

        let expected_size = unsafe { GetLengthSid(PSID(slice.as_ptr() as isize)) } as usize;
        if expected_size != slice.len() {
            return Err(AuthzError::UnexpectedSidSize { bytes: slice.to_vec(), expected_size });
        }

        let bytes = Vec::from(slice);
        Ok(Sid {
            bytes,
        })
    }

    pub(crate) unsafe fn from_ptr(sid: PSID) -> Result<Self, AuthzError> {
        let is_valid = IsValidSid(sid);
        if !is_valid.as_bool() {
            return Err(AuthzError::InvalidSidPointer(sid.0 as *const u8));
        }

        let size = GetLengthSid(sid);
        if size == 0 || size > 1024 {
            return Err(AuthzError::InvalidSidPointer(sid.0 as *const u8));
        }
        let slice = std::ptr::slice_from_raw_parts(sid.0 as *const u8, size as usize);
        let bytes = (*slice).to_vec();
        Ok(Sid {
            bytes,
        })
    }

    pub fn get_rid(&self) -> u32 {
        unsafe {
            let sub_auth_count =  *(GetSidSubAuthorityCount(PSID(self.bytes.as_ptr() as isize)));
            *(GetSidSubAuthority(PSID(self.bytes.as_ptr() as isize), (sub_auth_count - 1).into()))
        }
    }

    pub fn shares_prefix_with(&self, other: &Sid) -> bool {
        unsafe {
            EqualPrefixSid(PSID(self.as_bytes().as_ptr() as isize), PSID(other.as_bytes().as_ptr() as isize))
        }.as_bool()
    }

    // Returns true if and only if the SID starts with S-1-5-21-X-Y-Z
    pub fn is_domain_specific(&self) -> bool {
        unsafe {
            let sub_auth_count =  *(GetSidSubAuthorityCount(PSID(self.bytes.as_ptr() as isize)));
            if sub_auth_count < 4 {
                return false;
            }
            if (*GetSidIdentifierAuthority(PSID(self.bytes.as_ptr() as isize))).Value != [0, 0, 0, 0, 0, 5] { // SECURITY_NT_AUTHORITY
                return false;
            }
            if *(GetSidSubAuthority(PSID(self.bytes.as_ptr() as isize), 0)) != 21 {
                return false;
            }
        }
        true
    }

    pub fn with_rid(&self, rid: u32) -> Self {
        let s = format!("{}-{}", self, rid);
        Self::try_from(s.as_ref()).expect("invalid RID concatenation")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl TryFrom<&str> for Sid {
    type Error = AuthzError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut psid = PSID(0);
        let succeeded = unsafe { ConvertStringSidToSidW(s, &mut psid as *mut _) };
        if !succeeded.as_bool() {
            return Err(AuthzError::InvalidSidString { code: get_last_error(), str: s.to_owned() });
        }
        let res = unsafe { Self::from_ptr(psid) };
        unsafe { LocalFree(psid.0); }
        res
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        unsafe {
            let mut str = PWSTR(null_mut());
            let succeeded = ConvertSidToStringSidW(PSID(self.bytes.as_ptr() as isize), &mut str);
            if succeeded.as_bool() {
                let res = pwstr_to_str(str.0);
                LocalFree(str.0 as isize);
                f.write_str(&res)
            } else {
                write!(f, "SID={:?}", self)
            }
        }
    }
}

impl Debug for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str(&self.to_string())
    }
}
