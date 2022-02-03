use std::borrow::Cow;
use std::convert::TryFrom;
use windows::Win32::Security::{IsValidSecurityDescriptor, MakeAbsoluteSD, GetSecurityDescriptorLength, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, GetLengthSid, GetSecurityDescriptorGroup, GetSecurityDescriptorDacl, GetAclInformation, ACL_SIZE_INFORMATION, AclSizeInformation, ACL, GetSecurityDescriptorSacl};
use std::ptr::null_mut;
use windows::Win32::Foundation::{PSID, GetLastError, BOOL};
use crate::error::AuthzError;
use crate::{Sid, Acl};
use windows::Win32::System::Rpc::SEC_WINNT_AUTH_IDENTITY_A;

const SE_SELF_RELATIVE: u16 = 0x8000;

#[derive(Debug)]
pub struct SecurityDescriptor<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> SecurityDescriptor<'a> {
    pub fn parse(slice: &'a [u8]) -> Result<Self, AuthzError> {
        let is_valid = unsafe { IsValidSecurityDescriptor(slice.as_ptr() as *const _) };
        if !is_valid.as_bool() {
            return Err(AuthzError::InvalidSecurityDescriptor { bytes: slice.to_vec() });
        }

        let expected_size = unsafe { GetSecurityDescriptorLength(slice.as_ptr() as *const _) };
        if expected_size != (slice.len() as u32) {
            return Err(AuthzError::UnexpectedSecurityDescriptorSize { bytes: slice.to_vec(), expected_size: expected_size as usize });
        }

        let mut controls: u16 = 0;
        let mut revision: u32 = 0;
        let succeeded = unsafe { GetSecurityDescriptorControl(slice.as_ptr() as *const _, &mut controls as *mut _, &mut revision as *mut _) };
        if !succeeded.as_bool() {
            let code = unsafe { GetLastError() };
            return Err(AuthzError::GetSecurityDescriptorControlFailed { code, bytes: slice.to_vec() });
        }

        if (controls & SE_SELF_RELATIVE) == SE_SELF_RELATIVE {
            Ok(SecurityDescriptor {
                bytes: Cow::Borrowed(slice),
            })
        } else {
            // The slice given by our caller might point to memory outside. We need to take
            // ownership of the entire security descriptor to ensure memory safety. Since we
            // need to allocate memory, we might as well do it for an absolute-formatted security
            // descriptor at the same time.
            let mut sd_size: u32 = 0;
            let mut owner_size: u32 = 0;
            let mut group_size: u32 = 0;
            let mut dacl_size: u32 = 0;
            let mut sacl_size: u32 = 0;
            let succeeded = unsafe { MakeAbsoluteSD(slice.as_ptr() as *const _,
                null_mut(),
                &mut sd_size as *mut _,
                null_mut(),
                &mut dacl_size,
                null_mut(),
                &mut sacl_size,
                PSID(0),
                &mut owner_size,
                PSID(0),
                &mut group_size
            ) };
            if !succeeded.as_bool() {
                return Err(AuthzError::MakeAbsoluteSDFailed { code: unsafe { GetLastError() }, bytes: slice.to_vec() });
            }

            let mut sd = vec![0u8; (sd_size + owner_size + group_size + dacl_size + sacl_size) as usize];
            let succeeded = unsafe {
                let owner = sd.as_mut_ptr().add(sd_size as usize);
                let group = owner.add(owner_size as usize);
                let dacl = group.add(group_size as usize);
                let sacl = dacl.add(dacl_size as usize);
                MakeAbsoluteSD(slice.as_ptr() as *const _,
                sd.as_mut_ptr() as *mut _,
                &mut sd_size as *mut _,
                dacl as *mut _,
                &mut dacl_size,
                sacl as *mut _,
                &mut sacl_size,
                PSID(owner as isize),
                &mut owner_size,
                PSID(group as isize),
                &mut group_size
            ) };
            if !succeeded.as_bool() {
                return Err(AuthzError::MakeAbsoluteSDFailed { code: unsafe { GetLastError() }, bytes: slice.to_vec() });
            }
            Ok(SecurityDescriptor {
                bytes: Cow::Owned(sd),
            })
        }
    }

    pub fn get_owner(&self) -> Result<Sid, AuthzError> {
        let mut psid = PSID(0);
        let mut defaulted: i32 = 0;
        let succeeded = unsafe {
            GetSecurityDescriptorOwner(self.bytes.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _)
        };
        if !succeeded.as_bool() || !((psid.0 as usize) >= (self.bytes.as_ptr() as usize)) {
            return Err(AuthzError::GetSecurityDescriptorOwnerFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
        }
        let owner_offset = (psid.0 as usize) - (self.bytes.as_ptr() as usize);
        let sid_len = unsafe { GetLengthSid(psid) } as usize;
        if (owner_offset + sid_len) > self.bytes.len() {
            return Err(AuthzError::GetSecurityDescriptorOwnerFailed { bytes: self.bytes.to_vec(), code: 0 });
        }

        Sid::parse(&self.bytes[owner_offset .. owner_offset + sid_len])
    }

    pub fn get_group(&self) -> Result<Sid, AuthzError> {
        let mut psid = PSID(0);
        let mut defaulted: i32 = 0;
        let succeeded = unsafe {
            GetSecurityDescriptorGroup(self.bytes.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _)
        };
        if !succeeded.as_bool() || !((psid.0 as usize) >= (self.bytes.as_ptr() as usize)) {
            return Err(AuthzError::GetSecurityDescriptorGroupFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
        }
        let group_offset = (psid.0 as usize) - (self.bytes.as_ptr() as usize);
        let sid_len = unsafe { GetLengthSid(psid) } as usize;
        if (group_offset + sid_len) > self.bytes.len() {
            return Err(AuthzError::GetSecurityDescriptorGroupFailed { bytes: self.bytes.to_vec(), code: 0 });
        }

        Sid::parse(&self.bytes[group_offset .. group_offset + sid_len])
    }

    pub fn get_dacl(&self) -> Result<Acl, AuthzError> {
        let mut present: i32 = 0;
        let mut defaulted: i32 = 0;
        let mut acl: *mut ACL = null_mut();
        let succeeded = unsafe {
            GetSecurityDescriptorDacl(self.bytes.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _)
        };
        if !succeeded.as_bool() || !((acl as usize) >= (self.bytes.as_ptr() as usize)) {
            return Err(AuthzError::GetSecurityDescriptorDaclFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
        }
        let acl_offset = (acl as usize) - (self.bytes.as_ptr() as usize);
        let acl_len = unsafe {
            let mut size_info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            let succeeded = GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation);
            if !succeeded.as_bool() {
                return Err(AuthzError::GetAclInformationFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
            }
            size_info.AclBytesInUse + size_info.AclBytesFree
        } as usize;
        if (acl_offset + acl_len) > self.bytes.len() {
            return Err(AuthzError::GetSecurityDescriptorDaclFailed { bytes: self.bytes.to_vec(), code: 0 });
        }

        Acl::parse(&self.bytes[acl_offset .. acl_offset + acl_len])
    }

    pub fn get_sacl(&self) -> Result<Acl, AuthzError> {
        let mut present: i32 = 0;
        let mut defaulted: i32 = 0;
        let mut acl: *mut ACL = null_mut();
        let succeeded = unsafe {
            GetSecurityDescriptorSacl(self.bytes.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _)
        };
        if !succeeded.as_bool() || !((acl as usize) >= (self.bytes.as_ptr() as usize)) {
            return Err(AuthzError::GetSecurityDescriptorSaclFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
        }
        let acl_offset = (acl as usize) - (self.bytes.as_ptr() as usize);
        let acl_len = unsafe {
            let mut size_info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            let succeeded = GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation);
            if !succeeded.as_bool() {
                return Err(AuthzError::GetAclInformationFailed { bytes: self.bytes.to_vec(), code: unsafe { GetLastError() } });
            }
            size_info.AclBytesInUse + size_info.AclBytesFree
        } as usize;
        if (acl_offset + acl_len) > self.bytes.len() {
            return Err(AuthzError::GetSecurityDescriptorSaclFailed { bytes: self.bytes.to_vec(), code: 0 });
        }

        Acl::parse(&self.bytes[acl_offset .. acl_offset + acl_len])
    }

}