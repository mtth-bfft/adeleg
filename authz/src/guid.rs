use core::convert::TryFrom;
use core::fmt::{Debug, Display};
use windows::core::alloc::fmt::Formatter;
use windows::core::GUID;

// Simple in-between type exposed in our API, so that our
// dependency to windows-rs is transparent to our users
#[derive(PartialEq, Eq, Hash, Copy, Clone)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[derive(Debug, Copy, Clone)]
pub enum GuidParsingError {
    InvalidLength,
    InvalidDelimiter,
    NonHexadecimalCharacter,
}

impl From<std::num::ParseIntError> for GuidParsingError {
    fn from(_: std::num::ParseIntError) -> Self {
        Self::NonHexadecimalCharacter
    }
}

impl Guid {
    pub fn from_values(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }
}

impl From<GUID> for Guid {
    fn from(g: GUID) -> Self {
        Self::from_values(g.data1, g.data2, g.data3, g.data4)
    }
}

impl TryFrom<&str> for Guid {
    type Error = GuidParsingError;

    fn try_from(mut s: &str) -> Result<Self, Self::Error> {
        // Text GUIDs can look like 91e647de-d96f-4b70-9557-d63ff4f3ccd8
        // or like {91e647de-d96f-4b70-9557-d63ff4f3ccd8}
        if s.starts_with('{') && s.ends_with('}') {
            s = s.strip_prefix('{').unwrap().strip_suffix('}').unwrap();
        }
        let bytes = s.as_bytes();
        if bytes.len() != 36 {
            return Err(GuidParsingError::InvalidLength);
        }
        if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
            return Err(GuidParsingError::InvalidDelimiter);
        }
        let data1 = u32::from_str_radix(&s[0..8], 16)?;
        let data2 = u16::from_str_radix(&s[9..13], 16)?;
        let data3 = u16::from_str_radix(&s[14..18], 16)?;
        let data4 = [
            u8::from_str_radix(&s[19..21], 16)?,
            u8::from_str_radix(&s[21..23], 16)?,
            u8::from_str_radix(&s[24..26], 16)?,
            u8::from_str_radix(&s[26..28], 16)?,
            u8::from_str_radix(&s[28..30], 16)?,
            u8::from_str_radix(&s[30..32], 16)?,
            u8::from_str_radix(&s[32..34], 16)?,
            u8::from_str_radix(&s[34..36], 16)?,
        ];

        Ok(Guid { data1, data2, data3, data4 })
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let data1 = self.data1.to_be_bytes();
        let data2 = self.data2.to_be_bytes();
        let data3 = self.data3.to_be_bytes();
        write!(f, "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            data1[0], data1[1], data1[2], data1[3],
            data2[0], data2[1],
            data3[0], data3[1],
            self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7]
        )
    }
}

impl Debug for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str(&self.to_string())
    }
}
