use crate::error::AuthzError;
use windows::Win32::Security::{ACE_HEADER, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_MANDATORY_LABEL_ACE, INHERITED_ACE};
use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE};
use crate::{Sid, Guid};
use windows::Win32::Foundation::PSID;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Ace {
    pub flags: u8,
    pub type_specific: AceType,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AceType {
    // Discretionnary access ACEs
    AccessAllowed {
        trustee: Sid,
        mask: u32,
    },
    AccessAllowedObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessAllowedCallback {
        trustee: Sid,
        mask: u32,
    },
    AccessAllowedCallbackObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessDenied {
        trustee: Sid,
        mask: u32,
    },
    AccessDeniedObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessDeniedCallback {
        trustee: Sid,
        mask: u32,
    },
    AccessDeniedCallbackObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    // System ACEs
    Audit {
        trustee: Sid,
        mask: u32,
    },
    AuditCallback {
        trustee: Sid,
        mask: u32,
    },
    AuditObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AuditCallbackObject {
        trustee: Sid,
        mask: u32,
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    MandatoryLabel {
        trustee: Sid,
        mask: u32,
    },
}

impl Ace {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, AuthzError> {
        let header = unsafe { *(slice.as_ptr() as *const ACE_HEADER) };
        let acetype = u32::from(header.AceType);
        // Note: we copy the header locally here, but we cannot do that for type-specific
        // ACE structs, since their last variable-size SidStart field would only partially
        // be copied.
        // Note: parsing is tolerant in this case for other data appended after SIDs, but this
        // is actually a good thing since this possibility is explicitly allowed by specifications.
        let type_specific = if acetype == ACCESS_ALLOWED_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::AccessAllowed {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == ACCESS_ALLOWED_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AccessAllowedObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::AccessAllowedCallback {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AccessAllowedCallbackObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == ACCESS_DENIED_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::AccessDenied {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == ACCESS_DENIED_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AccessDeniedObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == ACCESS_DENIED_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::AccessDeniedCallback {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_CALLBACK_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AccessDeniedCallbackObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == SYSTEM_AUDIT_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::Audit {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == SYSTEM_AUDIT_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::AuditCallback {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else if acetype == SYSTEM_AUDIT_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AuditObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE;
            let (object_type, inherited_object_type, sid) = unsafe {
                if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 && ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), Some(Guid::from((*ace).InheritedObjectType)), &(*ace).SidStart as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_OBJECT_TYPE_PRESENT.0) != 0 {
                    (Some(Guid::from((*ace).ObjectType)), None, &(*ace).InheritedObjectType as *const _ as isize)
                } else if ((*ace).Flags.0 & ACE_INHERITED_OBJECT_TYPE_PRESENT.0) != 0 {
                    (None, Some(Guid::from((*ace).ObjectType)), &(*ace).InheritedObjectType as *const _ as isize)
                } else {
                    (None, None, &(*ace).ObjectType as *const _ as isize)
                }
            };
            let sid = unsafe { Sid::from_ptr(PSID(sid))? };
            AceType::AuditCallbackObject {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            }
        } else if acetype == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_MANDATORY_LABEL_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            AceType::MandatoryLabel {
                trustee: sid,
                mask: unsafe { (*ace).Mask },
            }
        } else {
            unimplemented!("unsupported ACE type {}, please contact project maintainers with the following debug information: {:?}", acetype, slice);
        };
        Ok(Self {
            flags: header.AceFlags,
            type_specific,
        })
    }

    pub fn is_inherited(&self) -> bool {
        (self.flags & (INHERITED_ACE.0 as u8)) != 0
    }

    pub fn get_trustee(&self) -> &Sid {
        match &self.type_specific {
            AceType::AccessAllowed { trustee, .. } => trustee,
            AceType::AccessAllowedObject { trustee, .. } => trustee,
            AceType::AccessAllowedCallback { trustee, .. } => trustee,
            AceType::AccessAllowedCallbackObject { trustee, .. } => trustee,
            AceType::AccessDenied { trustee, .. } => trustee,
            AceType::AccessDeniedObject { trustee, .. } => trustee,
            AceType::AccessDeniedCallback { trustee, .. } => trustee,
            AceType::AccessDeniedCallbackObject { trustee, .. } => trustee,
            AceType::Audit { trustee, .. } => trustee,
            AceType::AuditCallback { trustee, .. } => trustee,
            AceType::AuditObject { trustee, .. } => trustee,
            AceType::AuditCallbackObject { trustee, .. } => trustee,
            AceType::MandatoryLabel { trustee, .. } => trustee,
        }
    }

    pub fn get_mask(&self) -> u32 {
        match &self.type_specific {
            AceType::AccessAllowed { mask, .. } => *mask,
            AceType::AccessAllowedObject { mask, .. } => *mask,
            AceType::AccessAllowedCallback { mask, .. } => *mask,
            AceType::AccessAllowedCallbackObject { mask, .. } => *mask,
            AceType::AccessDenied { mask, .. } => *mask,
            AceType::AccessDeniedObject { mask, .. } => *mask,
            AceType::AccessDeniedCallback { mask, .. } => *mask,
            AceType::AccessDeniedCallbackObject { mask, .. } => *mask,
            AceType::Audit { mask, .. } => *mask,
            AceType::AuditCallback { mask, .. } => *mask,
            AceType::AuditObject { mask, .. } => *mask,
            AceType::AuditCallbackObject { mask, .. } => *mask,
            AceType::MandatoryLabel { mask, .. } => *mask,
        }
    }

    pub fn grants_access(&self) -> bool {
        match &self.type_specific {
            AceType::AccessAllowed { .. } => true,
            AceType::AccessAllowedObject { .. } => true,
            AceType::AccessAllowedCallback { .. } => true,
            AceType::AccessAllowedCallbackObject { .. } => true,
            AceType::AccessDenied { .. } => false,
            AceType::AccessDeniedObject { .. }=> false,
            AceType::AccessDeniedCallback { .. } => false,
            AceType::AccessDeniedCallbackObject { .. } => false,
            AceType::Audit { .. } => false,
            AceType::AuditCallback { .. } => false,
            AceType::AuditObject { .. } => false,
            AceType::AuditCallbackObject { .. } => false,
            AceType::MandatoryLabel { .. } => false,
        }
    }
}