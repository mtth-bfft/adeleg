use windows::Win32::Security::{IsValidSecurityDescriptor, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, GetLengthSid, GetSecurityDescriptorGroup, GetSecurityDescriptorDacl, GetAclInformation, ACL_SIZE_INFORMATION, AclSizeInformation, ACL, GetSecurityDescriptorSacl, SECURITY_DESCRIPTOR};
use std::ptr::null_mut;
use windows::Win32::Foundation::PSID;
use crate::error::AuthzError;
use crate::utils::get_last_error;
use crate::{Sid, Acl};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::System::Memory::LocalFree;

#[derive(Debug)]
pub struct SecurityDescriptor {
    pub revision: u32,
    pub controls: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, AuthzError> {
        let is_valid = unsafe { IsValidSecurityDescriptor(slice.as_ptr() as *const _) };
        if !is_valid.as_bool() {
            return Err(AuthzError::InvalidSecurityDescriptor(slice.to_vec()));
        }

        let mut controls: u16 = 0;
        let mut revision: u32 = 0;
        let succeeded = unsafe { GetSecurityDescriptorControl(slice.as_ptr() as *const _, &mut controls as *mut _, &mut revision as *mut _) };
        if !succeeded.as_bool() {
            return Err(AuthzError::GetSecurityDescriptorControlFailed { code: get_last_error(), bytes: slice.to_vec() });
        }

        // Parse the owner from the SD
        let owner = {
            let mut psid = PSID(0);
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorOwner(slice.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetSecurityDescriptorOwnerFailed { code: get_last_error(), ptr: null_mut(), bytes: slice.to_vec() });
            }
            else if psid.0 == 0 {
                None // a NULL pointer is returned if there is no owner in this SD
            }
            else if (psid.0 as usize) < (slice.as_ptr() as usize) || (psid.0 as usize) >= (slice.as_ptr() as usize + slice.len()) {
                return Err(AuthzError::GetSecurityDescriptorOwnerFailed { code: u32::MAX, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
            }
            else {
                let expected_size = unsafe { GetLengthSid(psid) } as usize;
                if (psid.0 as usize + expected_size) > (slice.as_ptr() as usize + slice.len()) {
                    return Err(AuthzError::GetSecurityDescriptorOwnerFailed { code: u32::MAX, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
                }
                let offset = (psid.0 as usize) - (slice.as_ptr() as usize);
                Some(Sid::from_bytes(&slice[offset..offset+expected_size])?)
            }
        };

        // Parse the primary group, if any
        let group = {
            let mut psid = PSID(0);
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorGroup(slice.as_ptr() as *const _, &mut psid as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetSecurityDescriptorGroupFailed { code: get_last_error(), ptr: null_mut(), bytes: slice.to_vec() });
            }
            else if psid.0 == 0 {
                None // a NULL pointer is returned if there is no primary group in this SD
            }
            else if (psid.0 as usize) < (slice.as_ptr() as usize) || (psid.0 as usize) >= (slice.as_ptr() as usize + slice.len()) {
                return Err(AuthzError::GetSecurityDescriptorGroupFailed { code: u32::MAX, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
            }
            else {
                let expected_size = unsafe { GetLengthSid(psid) } as usize;
                let offset = (psid.0 as usize) - (slice.as_ptr() as usize);
                if (offset + expected_size) > slice.len() {
                    return Err(AuthzError::GetSecurityDescriptorGroupFailed { code: u32::MAX, ptr: psid.0 as *const u8, bytes: slice.to_vec() });
                }
                Some(Sid::from_bytes(&slice[offset..offset+expected_size])?)
            }
        };

        // Parse the DACL, if any
        let dacl = {
            let mut acl = null_mut() as *mut ACL;
            let mut present: i32 = 0;
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorDacl(slice.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetSecurityDescriptorDaclFailed { code: get_last_error(), ptr: null_mut(), bytes: slice.to_vec() });
            }
            else if acl.is_null() {
                None // a NULL pointer is returned if there is no DACL in this SD
            }
            else if (acl as usize) < (slice.as_ptr() as usize) || (acl as usize) >= (slice.as_ptr() as usize + slice.len()) {
                return Err(AuthzError::GetSecurityDescriptorDaclFailed { code: u32::MAX, ptr: acl as *const u8, bytes: slice.to_vec() });
            }
            else {
                let mut size_info = ACL_SIZE_INFORMATION {
                    AceCount: 0,
                    AclBytesInUse: 0,
                    AclBytesFree: 0
                };
                let succeeded = unsafe { GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation) };
                if !succeeded.as_bool() {
                    return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: get_last_error() });
                }
                let expected_size = (size_info.AclBytesInUse + size_info.AclBytesFree) as usize;
                let offset = (acl as usize) - (slice.as_ptr() as usize);
                if (offset + expected_size) > slice.len() {
                    return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size });
                }
                Some(Acl::from(&slice[offset..offset+expected_size])?)
            }
        };

        // Parse the SACL, if any
        let sacl = {
            let mut acl = null_mut() as *mut ACL;
            let mut present: i32 = 0;
            let mut defaulted: i32 = 0;
            let succeeded = unsafe { GetSecurityDescriptorSacl(slice.as_ptr() as *const _, &mut present as *mut _, &mut acl as *mut _, &mut defaulted as *mut _) };
            if !succeeded.as_bool() {
                return Err(AuthzError::GetSecurityDescriptorSaclFailed { code: get_last_error(), ptr: null_mut(), bytes: slice.to_vec() });
            }
            else if acl.is_null() {
                None // a NULL pointer is returned if there is no SACL in this SD
            }
            else if (acl as usize) < (slice.as_ptr() as usize) || (acl as usize) >= (slice.as_ptr() as usize + slice.len()) {
                return Err(AuthzError::GetSecurityDescriptorSaclFailed { code: 0, ptr: acl as *const u8, bytes: slice.to_vec() });
            }
            else {
                let mut size_info = ACL_SIZE_INFORMATION {
                    AceCount: 0,
                    AclBytesInUse: 0,
                    AclBytesFree: 0
                };
                let succeeded = unsafe { GetAclInformation(acl, &mut size_info as *mut _ as *mut _, std::mem::size_of_val(&size_info) as u32, AclSizeInformation) };
                if !succeeded.as_bool() {
                    return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: get_last_error() });
                }
                let expected_size = (size_info.AclBytesInUse + size_info.AclBytesFree) as usize;
                let offset = (acl as usize) - (slice.as_ptr() as usize);
                if (offset + expected_size) > slice.len() {
                    return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size });
                }
                Some(Acl::from(&slice[offset..offset+expected_size])?)
            }
        };

        Ok(SecurityDescriptor {
            revision,
            controls,
            owner,
            group,
            dacl,
            sacl,
        })
    }

    pub fn from_str(sddl: &str, domain_sid: &Sid, root_domain_sid: &Sid) -> Result<Self, AuthzError> {
        // First, we need to normalize the SDDL, in case it contains abbreviated
        // principals which depend on the domain within which the SDDL applies, and
        // depends on the root domain of the forest within which the SDDL applies.
        let sddl = sddl.replace( // Account Operators
            ";AO)",
            ";S-1-5-32-548)"
        ).replace( // Domain Admins
            ";DA)",
            &format!(";{}-512)", domain_sid.to_string())
        ).replace( // Domain Users
            ";DU)",
            &format!(";{}-513)", domain_sid.to_string())
        ).replace( // Domain Guests
            ";DG)",
            &format!(";{}-514)", domain_sid.to_string())
        ).replace( // Domain Computers
            ";DC)",
            &format!(";{}-515)", domain_sid.to_string())
        ).replace( // Domain Controllers
            ";DD)",
            &format!(";{}-516)", domain_sid.to_string())
        ).replace( // Certificate Publishers
            ";CA)",
            &format!(";{}-517)", domain_sid.to_string())
        ).replace( // RAS and IAS Servers
            ";RS)",
            &format!(";{}-553)", domain_sid.to_string())
        ).replace( // Group Policy Admins / Creator Owner
            ";PA)",
            &format!(";{}-520)", domain_sid.to_string())
        ).replace( // Enterprise Read-only Domain Controllers
            ";RO)",
            &format!(";{}-498)", root_domain_sid.to_string())
        ).replace( // Schema Admins
            ";SA)",
            &format!(";{}-518)", root_domain_sid.to_string())
        ).replace( // Enterprise Admins
            ";EA)",
            &format!(";{}-519)", root_domain_sid.to_string())
        );

        let mut psd: *mut SECURITY_DESCRIPTOR = null_mut();
        let mut sd_size: u32 = 0;
        let succeeded = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_str(), SDDL_REVISION_1, &mut psd as *mut _, &mut sd_size as *mut _) };
        if !succeeded.as_bool() {
            return Err(AuthzError::InvalidStringSecurityDescriptor { code: get_last_error(), str: sddl });
        }
        let slice = unsafe { &*std::ptr::slice_from_raw_parts(psd as *const u8, sd_size as usize) };
        let res = SecurityDescriptor::from_bytes(slice);
        unsafe { LocalFree(psd as isize); }
        res
    }
}