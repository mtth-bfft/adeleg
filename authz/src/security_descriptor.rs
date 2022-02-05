use windows::Win32::Security::{IsValidSecurityDescriptor, GetSecurityDescriptorLength, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, GetLengthSid, GetSecurityDescriptorGroup, GetSecurityDescriptorDacl, GetAclInformation, ACL_SIZE_INFORMATION, AclSizeInformation, ACL, GetSecurityDescriptorSacl};
use std::ptr::null_mut;
use windows::Win32::Foundation::{PSID, GetLastError};
use crate::error::AuthzError;
use crate::{Sid, Acl};

#[derive(Debug)]
pub struct SecurityDescriptor {
    revision: u32,
    controls: u16,
    owner: Option<Sid>,
    group: Option<Sid>,
    dacl: Option<Acl>,
    sacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn from(slice: &[u8]) -> Result<Self, AuthzError> {
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

        // Parse the owner from the SD
        let owner = Some(Sid::from_bytes({
            let mut psid = PSID(0);
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorOwner(slice.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() || (psid.0 as usize) < (slice.as_ptr() as usize) || (psid.0 as usize) >= (slice.as_ptr() as usize + slice.len()) {
                let code = unsafe { GetLastError() };
                return Err(AuthzError::GetSecurityDescriptorOwnerFailed { code, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
            }
            let expected_size = unsafe { GetLengthSid(psid) } as usize;
            let offset = (psid.0 as usize) - (slice.as_ptr() as usize);
            if (offset + expected_size) > slice.len() {
                return Err(AuthzError::UnexpectedSidSize { bytes: slice.to_vec(), expected_size });
            }
            &slice[offset..offset+expected_size]
        })?);

        // Parse the primary group, if any
        let group = Some(Sid::from_bytes({
            let mut psid = PSID(0);
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorGroup(slice.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() || (psid.0 as usize) < (slice.as_ptr() as usize) || (psid.0 as usize) >= (slice.as_ptr() as usize + slice.len()) {
                let code = unsafe { GetLastError() };
                return Err(AuthzError::GetSecurityDescriptorGroupFailed { code, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
            }
            let expected_size = unsafe { GetLengthSid(psid) } as usize;
            let offset = (psid.0 as usize) - (slice.as_ptr() as usize);
            if (offset + expected_size) > slice.len() {
                return Err(AuthzError::UnexpectedSidSize { bytes: slice.to_vec(), expected_size });
            }
            &slice[offset..offset+expected_size]
        })?);

        // Parse the DACL, if any
        let dacl = Some(Acl::from({
            let mut acl = null_mut() as *mut ACL;
            let mut present: i32 = 0;
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorDacl(slice.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() || (acl as usize) < (slice.as_ptr() as usize) || (acl as usize) >= (slice.as_ptr() as usize + slice.len()) {
                let code = unsafe { GetLastError() };
                return Err(AuthzError::GetSecurityDescriptorDaclFailed { code, ptr: acl as *const u8, bytes: slice.to_vec() });
            }
            let mut size_info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0
            };
            let succeeded = unsafe { GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: unsafe { GetLastError() } });
            }
            let expected_size = (size_info.AclBytesInUse + size_info.AclBytesFree) as usize;
            let offset = (acl as usize) - (slice.as_ptr() as usize);
            if (offset + expected_size) > slice.len() {
                return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size });
            }
            &slice[offset..offset+expected_size]
        })?);

        // Parse the SACL, if any
        let sacl = Some(Acl::from({
            let mut acl = null_mut() as *mut ACL;
            let mut present: i32 = 0;
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorSacl(slice.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() || (acl as usize) < (slice.as_ptr() as usize) || (acl as usize) >= (slice.as_ptr() as usize + slice.len()) {
                let code = unsafe { GetLastError() };
                return Err(AuthzError::GetSecurityDescriptorSaclFailed { code, ptr: acl as *const u8, bytes: slice.to_vec() });
            }
            let mut size_info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0
            };
            let succeeded = unsafe { GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: unsafe { GetLastError() } });
            }
            let expected_size = (size_info.AclBytesInUse + size_info.AclBytesFree) as usize;
            let offset = (acl as usize) - (slice.as_ptr() as usize);
            if (offset + expected_size) > slice.len() {
                return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size });
            }
            &slice[offset..offset+expected_size]
        })?);

        Ok(SecurityDescriptor {
            revision,
            controls,
            owner,
            group,
            dacl,
            sacl,
        })
    }
}