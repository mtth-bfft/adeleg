use core::ptr::null_mut;
use core::fmt::Display;
use std::borrow::Cow;
use crate::error::AuthzError;
use windows::Win32::Security::{IsValidSid, GetLengthSid};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Foundation::{PSID, PWSTR};
use windows::Win32::System::Memory::LocalFree;
use windows::core::alloc::fmt::Formatter;
use crate::utils::pwstr_to_str;

#[derive(Debug)]
pub struct Sid<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> Sid<'a> {
    pub fn parse(slice: &'a [u8]) -> Result<Self, AuthzError> {
        let is_valid = unsafe { IsValidSid(PSID(slice.as_ptr() as isize)) };
        if !is_valid.as_bool() {
            return Err(AuthzError::InvalidSid { bytes: slice.to_vec() });
        }

        let expected_size = unsafe { GetLengthSid(PSID(slice.as_ptr() as isize)) };
        if expected_size != (slice.len() as u32) {
            return Err(AuthzError::UnexpectedSidSize { bytes: slice.to_vec(), expected_size: expected_size as usize });
        }

        Ok(Sid {
            bytes: Cow::Borrowed(slice),
        })
    }
}

impl Display for Sid<'_> {
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