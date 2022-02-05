use core::fmt::Display;
use windows::core::alloc::fmt::Formatter;

#[derive(Debug)]
pub enum AuthzError {
    InvalidSecurityDescriptor {
        bytes: Vec<u8>,
    },
    InvalidSidBytes(Vec<u8>),
    InvalidSidPointer(*const u8),
    UnexpectedSecurityDescriptorSize {
        bytes: Vec<u8>,
        expected_size: usize,
    },
    UnexpectedAclSize {
        bytes: Vec<u8>,
        expected_size: usize,
    },
    UnexpectedAceSize {
        bytes: Vec<u8>,
        ace_index: u32,
        expected_size: usize,
    },
    UnexpectedSidSize {
        bytes: Vec<u8>,
        expected_size: usize,
    },
    GetSecurityDescriptorControlFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    MakeAbsoluteSDFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    GetSecurityDescriptorOwnerFailed {
        bytes: Vec<u8>,
        ptr: *const u8,
        code: u32,
    },
    GetSecurityDescriptorGroupFailed {
        bytes: Vec<u8>,
        ptr: *const u8,
        code: u32,
    },
    GetSecurityDescriptorDaclFailed {
        bytes: Vec<u8>,
        ptr: *const u8,
        code: u32,
    },
    GetSecurityDescriptorSaclFailed {
        bytes: Vec<u8>,
        ptr: *const u8,
        code: u32,
    },
    GetAclInformationFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    GetAceFailed {
        bytes: Vec<u8>,
        ace_index: u32,
        code: u32,
    },
}

impl Display for AuthzError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSecurityDescriptor { bytes} => write!(f, "invalid security descriptor {:?}", bytes),
            Self::InvalidSidBytes(bytes) => write!(f, "invalid SID {:?}", bytes),
            Self::InvalidSidPointer(ptr) => write!(f, "invalid SID {:?}", ptr),
            Self::UnexpectedSecurityDescriptorSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after security descriptor {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedSecurityDescriptorSize { bytes, expected_size} => write!(f, "{} bytes truncated from security descriptor {:?}", bytes.len() - expected_size, bytes),
            Self::UnexpectedSidSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after SID {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedSidSize { bytes, expected_size } => write!(f, "{} bytes truncated from SID {:?}", bytes.len() - expected_size, bytes),
            Self::UnexpectedAclSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after ACL {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedAclSize { bytes, expected_size } => write!(f, "{} bytes truncated from ACL {:?}", bytes.len() - expected_size, bytes),
            Self::UnexpectedAceSize { bytes, ace_index, expected_size } => write!(f, "ACE #{} of {} bytes is out of bounds from ACL {:?}", ace_index, expected_size, bytes),
            Self::GetSecurityDescriptorControlFailed { bytes, code } => write!(f, "GetSecurityDescriptorControl({:?}) failed with code {}", bytes, code),
            Self::MakeAbsoluteSDFailed { bytes, code } => write!(f, "MakeAbsoluteSD({:?}) failed with code {}", bytes, code),
            Self::GetSecurityDescriptorOwnerFailed { bytes, ptr, code } => write!(f, "GetSecurityDescriptorOwner({:?}) failed with code {}, produced {:?}", bytes, code, ptr),
            Self::GetSecurityDescriptorGroupFailed { bytes, ptr, code } => write!(f, "GetSecurityDescriptorGroup({:?}) failed with code {}, produced {:?}", bytes, code, ptr),
            Self::GetSecurityDescriptorDaclFailed { bytes, ptr, code } => write!(f, "GetSecurityDescriptorDacl({:?}) failed with code {}, produced {:?}", bytes, code, ptr),
            Self::GetSecurityDescriptorSaclFailed { bytes, ptr, code } => write!(f, "GetSecurityDescriptorSacl({:?}) failed with code {}, produced {:?}", bytes, code, ptr),
            Self::GetAclInformationFailed { bytes, code } => write!(f, "GetAclInformation({:?}) failed with code {}", bytes, code),
            Self::GetAceFailed { bytes, ace_index, code } => write!(f, "GetAce({:?}, index={}) failed with code {}", bytes, ace_index, code),
        }
    }
}