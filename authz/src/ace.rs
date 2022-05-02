use core::fmt::Display;
use crate::error::AuthzError;
use windows::Win32::Security::{ACE_HEADER, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_MANDATORY_LABEL_ACE, INHERITED_ACE, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE};
use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE};
use crate::{Sid, Guid};
use windows::Win32::Foundation::PSID;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Ace {
    pub trustee: Sid,
    pub access_mask: u32,
    pub flags: u8,
    pub type_specific: AceType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AceType {
    // Discretionnary access ACEs
    AccessAllowed,
    AccessAllowedObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessAllowedCallback,
    AccessAllowedCallbackObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessDenied,
    AccessDeniedObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AccessDeniedCallback,
    AccessDeniedCallbackObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    // System ACEs
    Audit,
    AuditCallback,
    AuditObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    AuditCallbackObject {
        flags: u32,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    },
    MandatoryLabel,
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
        let (trustee, access_mask, type_specific) = if acetype == ACCESS_ALLOWED_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::AccessAllowed)
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
            (sid, unsafe { (*ace).Mask }, AceType::AccessAllowedObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
        } else if acetype == ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_ALLOWED_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::AccessAllowedCallback)
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
            (sid, unsafe { (*ace).Mask }, AceType::AccessAllowedCallbackObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
        } else if acetype == ACCESS_DENIED_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::AccessDenied)
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
            (sid, unsafe { (*ace).Mask }, AceType::AccessDeniedObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
        } else if acetype == ACCESS_DENIED_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const ACCESS_DENIED_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::AccessDeniedCallback)
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
            (sid, unsafe { (*ace).Mask }, AceType::AccessDeniedCallbackObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
        } else if acetype == SYSTEM_AUDIT_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::Audit)
        } else if acetype == SYSTEM_AUDIT_CALLBACK_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_AUDIT_CALLBACK_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::AuditCallback)
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
            (sid, unsafe { (*ace).Mask }, AceType::AuditObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
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
            (sid, unsafe { (*ace).Mask }, AceType::AuditCallbackObject {
                flags: unsafe { (*ace).Flags.0 },
                object_type,
                inherited_object_type,
            })
        } else if acetype == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            let ace = slice.as_ptr() as *const SYSTEM_MANDATORY_LABEL_ACE;
            let sid = unsafe { Sid::from_ptr(PSID(&(*ace).SidStart as *const _ as isize))? };
            (sid, unsafe { (*ace).Mask }, AceType::MandatoryLabel)
        } else {
            unimplemented!("unsupported ACE type {}, please contact project maintainers with the following debug information: {:?}", acetype, slice);
        };
        Ok(Self {
            trustee,
            access_mask,
            flags: header.AceFlags,
            type_specific,
        })
    }

    pub fn is_inherited(&self) -> bool {
        (self.flags & (INHERITED_ACE.0 as u8)) != 0
    }

    pub fn get_container_inherit(&self) -> bool {
        (self.flags & (CONTAINER_INHERIT_ACE.0 as u8)) != 0
    }

    pub fn get_object_inherit(&self) -> bool {
        (self.flags & (OBJECT_INHERIT_ACE.0 as u8)) != 0
    }

    pub fn get_inherit_only(&self) -> bool {
        (self.flags & (INHERIT_ONLY_ACE.0 as u8)) != 0
    }

    pub fn get_no_propagate(&self) -> bool {
        (self.flags & (NO_PROPAGATE_INHERIT_ACE.0 as u8)) != 0
    }

    pub fn get_object_type(&self) -> Option<&Guid> {
        match &self.type_specific {
            AceType::AccessAllowed { .. } => None,
            AceType::AccessAllowedObject { object_type, .. } => object_type.as_ref(),
            AceType::AccessAllowedCallback { .. } => None,
            AceType::AccessAllowedCallbackObject { object_type, .. } => object_type.as_ref(),
            AceType::AccessDenied {  .. } => None,
            AceType::AccessDeniedObject { object_type, .. } => object_type.as_ref(),
            AceType::AccessDeniedCallback { .. } => None,
            AceType::AccessDeniedCallbackObject { object_type, .. } => object_type.as_ref(),
            AceType::Audit { .. } => None,
            AceType::AuditCallback { .. } => None,
            AceType::AuditObject { object_type, .. } => object_type.as_ref(),
            AceType::AuditCallbackObject { object_type, .. } => object_type.as_ref(),
            AceType::MandatoryLabel { .. } => None,
        }
    }

    pub fn get_inherited_object_type(&self) -> Option<&Guid> {
        match &self.type_specific {
            AceType::AccessAllowed { .. } => None,
            AceType::AccessAllowedObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::AccessAllowedCallback { .. } => None,
            AceType::AccessAllowedCallbackObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::AccessDenied {  .. } => None,
            AceType::AccessDeniedObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::AccessDeniedCallback { .. } => None,
            AceType::AccessDeniedCallbackObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::Audit { .. } => None,
            AceType::AuditCallback { .. } => None,
            AceType::AuditObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::AuditCallbackObject { inherited_object_type, .. } => inherited_object_type.as_ref(),
            AceType::MandatoryLabel { .. } => None,
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

impl Display for Ace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{} access mask 0x{:X}", &self.trustee, &self.access_mask)?;
        if self.get_no_propagate() {
            write!(f, " no_propagate")?;
        }
        if self.get_inherit_only() {
            write!(f, " inherit_only")?;
        }
        if self.get_object_inherit() {
            write!(f, " object_inherit")?;
        }
        if self.get_container_inherit() {
            write!(f, " container_inherit")?;
        }
        if let AceType::AccessAllowedObject { object_type: Some(guid), .. } = &self.type_specific {
            write!(f, " obj_type={}", guid)?;
        }
        if let AceType::AccessAllowedObject { inherited_object_type: Some(guid), .. } = &self.type_specific {
            write!(f, " inh_obj_type={}", guid)?;
        }
        Ok(())
    }
}