use core::ptr::null_mut;
use core::fmt::Display;
use crate::error::AuthzError;
use windows::Win32::Security::{IsValidSid, GetLengthSid};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Foundation::{PSID, PWSTR};
use windows::Win32::System::Memory::LocalFree;
use windows::core::alloc::fmt::Formatter;
use crate::utils::pwstr_to_str;

#[derive(Debug)]
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
        let slice = std::ptr::slice_from_raw_parts(sid.0 as *const u8, size as usize);
        Self::from_bytes(&*slice)
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
                write!(f, "{}", res)
            } else {
                write!(f, "SID={:?}", self)
            }
        }
    }
}