use core::fmt::Display;
use crate::error::AuthzError;
use crate::utils::get_last_error;
use windows::Win32::Security::{ACL_SIZE_INFORMATION, GetAclInformation, AclSizeInformation, ACL, GetAce, ACE_HEADER};
use windows::core::alloc::fmt::Formatter;
use crate::Ace;
use std::ptr::null;

#[derive(Debug)]
pub struct Acl {
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn from(slice: &[u8]) -> Result<Self, AuthzError> {
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0
        };
        let succeeded = unsafe { GetAclInformation(slice.as_ptr() as *mut ACL, &mut info as *mut _ as *mut _, std::mem::size_of_val(&info) as u32, AclSizeInformation) };
        if !succeeded.as_bool() {
            return Err(AuthzError::GetAclInformationFailed { bytes: slice.to_vec(), code: get_last_error() });
        }
        let expected_size = (info.AclBytesInUse + info.AclBytesFree) as usize;
        if expected_size != slice.len() {
            return Err(AuthzError::UnexpectedAclSize { bytes: slice.to_vec(), expected_size: expected_size as usize });
        }
        let mut aces = Vec::new();
        for ace_index in 0..info.AceCount {
            let mut ace: *const ACE_HEADER = null() as *const _;
            let succeeded = unsafe { GetAce(slice.as_ptr() as *const _, ace_index, &mut ace as *mut _ as *mut _) };
            if !succeeded.as_bool() || (ace as usize) < (slice.as_ptr() as usize) || (ace as usize + std::mem::size_of::<ACE_HEADER>()) > (slice.as_ptr() as usize + slice.len())  {
                return Err(AuthzError::GetAceFailed { bytes: slice.to_vec(), ace_index, code: get_last_error() });
            }
            let expected_size = unsafe { (*ace).AceSize } as usize;
            if (ace as usize + expected_size) > (slice.as_ptr() as usize + slice.len()) {
                return Err(AuthzError::UnexpectedAceSize { bytes: slice.to_vec(), ace_index, expected_size });
            }
            let offset = (ace as usize) - (slice.as_ptr() as usize);
            aces.push(Ace::from_bytes(&slice[offset..offset+expected_size])?);
        }

        Ok(Self {
            aces,
        })
    }

    pub fn check_canonicality(&self) -> Result<(), Ace> {
        let mut prev_ace: Option<&Ace> = None;
        for ace in &self.aces {
            if let Some(prev_ace) = prev_ace {
                // Bad patterns we are looking for:
                // Explicit ACE after an inherited one
                if !ace.is_inherited() && prev_ace.is_inherited() {
                    return Err(ace.to_owned());
                }
                // Deny ACE after an allow one, except when switching from explicit to inherited ACEs
                if !ace.grants_access() && prev_ace.grants_access() && !(!prev_ace.is_inherited() && ace.is_inherited()) {
                    return Err(ace.to_owned());
                }
            }

            prev_ace = Some(ace);
        }
        Ok(())
    }
}

impl Display for Acl {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ACL={:?}", self)
    }
}