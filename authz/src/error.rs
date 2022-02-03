use core::fmt::Display;
use windows::core::alloc::fmt::Formatter;

#[derive(Debug)]
pub enum AuthzError {
    InvalidSecurityDescriptor {
        bytes: Vec<u8>,
    },
    InvalidSid {
        bytes: Vec<u8>,
    },
    UnexpectedSecurityDescriptorSize {
        bytes: Vec<u8>,
        expected_size: usize,
    },
    UnexpectedAclSize {
        bytes: Vec<u8>,
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
        code: u32,
    },
    GetSecurityDescriptorGroupFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    GetSecurityDescriptorDaclFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    GetSecurityDescriptorSaclFailed {
        bytes: Vec<u8>,
        code: u32,
    },
    GetAclInformationFailed {
        bytes: Vec<u8>,
        code: u32,
    }
}

impl Display for AuthzError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSecurityDescriptor { bytes} => write!(f, "invalid security descriptor {:?}", bytes),
            Self::InvalidSid { bytes} => write!(f, "invalid SID {:?}", bytes),
            Self::UnexpectedSecurityDescriptorSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after security descriptor {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedSecurityDescriptorSize { bytes, expected_size} => write!(f, "{} bytes truncated from security descriptor {:?}", bytes.len() - expected_size, bytes),
            Self::UnexpectedSidSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after SID {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedSidSize { bytes, expected_size } => write!(f, "{} bytes truncated from SID {:?}", bytes.len() - expected_size, bytes),
            Self::UnexpectedAclSize { bytes, expected_size} if *expected_size > bytes.len() => write!(f, "{} leftover bytes after ACL {:?}", expected_size - bytes.len(), bytes),
            Self::UnexpectedAclSize { bytes, expected_size } => write!(f, "{} bytes truncated from ACL {:?}", bytes.len() - expected_size, bytes),
            Self::GetSecurityDescriptorControlFailed { bytes, code } => write!(f, "GetSecurityDescriptorControl({:?}) failed with code {}", bytes, code),
            Self::MakeAbsoluteSDFailed { bytes, code } => write!(f, "MakeAbsoluteSD({:?}) failed with code {}", bytes, code),
            Self::GetSecurityDescriptorOwnerFailed { bytes, code } => write!(f, "GetSecurityDescriptorOwner({:?}) failed with code {}", bytes, code),
            Self::GetSecurityDescriptorGroupFailed { bytes, code } => write!(f, "GetSecurityDescriptorGroup({:?}) failed with code {}", bytes, code),
            Self::GetSecurityDescriptorDaclFailed { bytes, code } => write!(f, "GetSecurityDescriptorDacl({:?}) failed with code {}", bytes, code),
            Self::GetSecurityDescriptorSaclFailed { bytes, code } => write!(f, "GetSecurityDescriptorSacl({:?}) failed with code {}", bytes, code),
            Self::GetAclInformationFailed { bytes, code } => write!(f, "GetAclInformationFailed({:?}) failed with code {}", bytes, code),
        }
    }
}