//! JSON Schema integer is a mathematical type: `1`, `1.0`, and `1e0` must
//! decode consistently. Never truncate a fractional value or saturate a cast.

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Int32(i32);

impl Int32 {
    pub const fn new(value: i32) -> Self {
        Self(value)
    }
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl From<i32> for Int32 {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<Int32> for i32 {
    fn from(value: Int32) -> Self {
        value.0
    }
}

impl fmt::Display for Int32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

struct Int32Visitor;

impl<'de> Visitor<'de> for Int32Visitor {
    type Value = i32;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a finite integral JSON number within int32 range")
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<i32, E> {
        i32::try_from(value).map_err(|_| E::custom("JSON integer exceeds int32 range"))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<i32, E> {
        i32::try_from(value).map_err(|_| E::custom("JSON integer exceeds int32 range"))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<i32, E> {
        if !value.is_finite()
            || value.fract() != 0.0
            || value < f64::from(i32::MIN)
            || value > f64::from(i32::MAX)
        {
            return Err(E::custom(
                "JSON integer is fractional, nonfinite or outside int32 range",
            ));
        }
        Ok(value as i32)
    }
}

pub fn deserialize_i32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
    deserializer.deserialize_any(Int32Visitor)
}

pub fn deserialize_i32_vec3<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[i32; 3], D::Error> {
    <[Int32; 3]>::deserialize(deserializer).map(|values| values.map(Int32::get))
}

impl<'de> Deserialize<'de> for Int32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_i32(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mathematical_integer_lexemes_decode_equally() {
        for bytes in [b"1".as_slice(), b"1.0", b"1e0"] {
            assert_eq!(
                serde_json::from_slice::<Int32>(bytes).unwrap(),
                Int32::new(1)
            );
        }
        assert_eq!(
            serde_json::from_slice::<Int32>(b"-2147483648.0")
                .unwrap()
                .get(),
            i32::MIN
        );
        assert_eq!(
            serde_json::from_slice::<Int32>(b"2147483647.0")
                .unwrap()
                .get(),
            i32::MAX
        );
    }

    #[test]
    fn fractional_and_out_of_range_values_never_truncate_or_saturate() {
        for bytes in [
            b"1.5".as_slice(),
            b"2147483648",
            b"-2147483649.0",
            b"null",
            b"\"1\"",
        ] {
            assert!(serde_json::from_slice::<Int32>(bytes).is_err());
        }
    }
}
