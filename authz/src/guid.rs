use core::fmt::{Debug, Display};
use windows::core::alloc::fmt::Formatter;
use windows::core::GUID;

// Simple in-between type exposed in our API, so that our
// dependency to windows-rs is transparent to our users
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
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

impl Display for Guid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let data1 = self.data1.to_be_bytes();
        let data2 = self.data2.to_be_bytes();
        let data3 = self.data3.to_be_bytes();
        write!(f, "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            data1[0], data1[1], data1[2], data1[3],
            data2[0], data2[1],
            data3[0], data3[1],
            self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7]
        )
    }
}

impl Debug for Guid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}