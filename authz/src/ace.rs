use crate::error::AuthzError;
use windows::Win32::Security::{ACE_HEADER, ACCESS_ALLOWED_ACE};
use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use crate::Sid;
use windows::Win32::Foundation::PSID;

#[derive(Debug)]
pub struct Ace {
    flags: u8,
    type_specific: AceType,
}

#[derive(Debug)]
pub enum AceType {
    AccessAllowed {
        trustee: Sid,
        mask: u32,
    },
    Unsupported {
        bytes: Vec<u8>,
    },
}

impl Ace {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, AuthzError> {
        let header = unsafe { *(slice.as_ptr() as *const ACE_HEADER) };
        let type_specific = if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
            let ace = unsafe { *(slice.as_ptr() as *const ACCESS_ALLOWED_ACE) };
            let sid = PSID(&ace.SidStart as *const _ as isize);
            let sid = unsafe { Sid::from_ptr(sid)? };
            AceType::AccessAllowed {
                trustee: sid,
                mask: ace.Mask,
            }
        } else {
            AceType::Unsupported { bytes: slice.to_vec() }
        };
        Ok(Self {
            flags: header.AceFlags,
            type_specific,
        })
    }
}