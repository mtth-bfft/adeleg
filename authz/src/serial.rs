use std::convert::TryFrom;
use serde::de::Visitor;
use crate::Sid;
use crate::Guid;

impl serde::Serialize for Sid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

impl serde::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

struct SidStrVisitor;
struct GuidStrVisitor;

impl<'de> Visitor<'de> for SidStrVisitor {
    type Value = Sid;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expected a SID as string like S-1-X-Y-Z")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error,
    {
        match Sid::try_from(v) {
            Ok(s) => Ok(s),
            _ => Err(serde::de::Error::invalid_type(serde::de::Unexpected::Str(v), &self))
        }
    }
}

impl<'de> Visitor<'de> for GuidStrVisitor {
    type Value = Guid;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expected a GUID as hexadecimal string, optionally with brackets like {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}")
    }
    
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error,
    {
        match Guid::try_from(v) {
            Ok(s) => Ok(s),
            _ => Err(serde::de::Error::invalid_type(serde::de::Unexpected::Str(v), &self))
        }
    }
}

impl<'de> serde::Deserialize<'de> for Sid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        deserializer.deserialize_str(SidStrVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        deserializer.deserialize_str(GuidStrVisitor)
    }
}