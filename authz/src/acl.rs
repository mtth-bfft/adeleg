use core::ptr::null_mut;
use core::fmt::Display;
use std::borrow::Cow;
use crate::error::AuthzError;
use windows::Win32::Security::{IsValidSid, GetLengthSid, ACL_SIZE_INFORMATION, GetAclInformation, AclSizeInformation, ACL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Foundation::{PSID, PWSTR, GetLastError};
use windows::Win32::System::Memory::LocalFree;
use windows::core::alloc::fmt::Formatter;
use crate::utils::pwstr_to_str;

#[derive(Debug)]
pub struct Acl<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> Acl<'a> {
    pub fn parse(slice: &'a [u8]) -> Result<Self, AuthzError> {
        let expected_size = unsafe {
            let mut size_info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0
            };
            let succeeded = GetAclInformation(slice.as_ptr() as *mut ACL, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation);
            if !succeeded.as_bool() {
                return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: unsafe { GetLastError() } });
            }
            size_info.AclBytesInUse + size_info.AclBytesFree
        } as usize;
        if expected_size != slice.len() {
            return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size: expected_size as usize });
        }
        Ok(Acl {
            bytes: Cow::Borrowed(slice),
        })
    }
}

impl Display for Acl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ACL={:?}", self)
    }
}