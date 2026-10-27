//! Canonical decimal strings and exact, reduced rational time.
//!
//! Imported wire values are validated without repair. Arithmetic constructors
//! reduce newly computed values, keeping numerical conversion out of wire parsing.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    InvalidSignedDecimal,
    InvalidUnsignedDecimal,
    InvalidRationalText,
    NonPositiveDenominator,
    NotReduced,
    DivisionByZero,
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSignedDecimal => "signed decimal must match ^(0|-?[1-9][0-9]*)$",
            Self::InvalidUnsignedDecimal => "unsigned decimal must match ^(0|[1-9][0-9]*)$",
            Self::InvalidRationalText => {
                "rational text must contain one numerator/denominator pair"
            }
            Self::NonPositiveDenominator => "rational denominator must be greater than zero",
            Self::NotReduced => {
                "rational numerator and denominator must have greatest common divisor one"
            }
            Self::DivisionByZero => "cannot divide rational time by zero",
        })
    }
}

impl std::error::Error for TimeError {}

fn is_unsigned_decimal(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes[1..].iter().all(u8::is_ascii_digit)
}

fn is_signed_decimal(value: &str) -> bool {
    if let Some(magnitude) = value.strip_prefix('-') {
        magnitude != "0" && is_unsigned_decimal(magnitude)
    } else {
        is_unsigned_decimal(value)
    }
}

macro_rules! decimal {
    ($name:ident, $integer:ty, $validator:ident, $error:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TimeError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(TimeError::$error)
                }
            }

            pub fn from_integer(value: $integer) -> Self {
                Self(value.to_string())
            }

            pub fn to_integer(&self) -> $integer {
                <$integer>::parse_bytes(self.0.as_bytes(), 10)
                    .expect("private decimal construction guarantees a valid integer")
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = TimeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = TimeError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = TimeError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.to_integer().cmp(&other.to_integer())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

decimal!(
    SignedDecimal,
    BigInt,
    is_signed_decimal,
    InvalidSignedDecimal
);
decimal!(
    UnsignedDecimal,
    BigUint,
    is_unsigned_decimal,
    InvalidUnsignedDecimal
);

impl SignedDecimal {
    pub fn to_bigint(&self) -> BigInt {
        self.to_integer()
    }

    pub fn to_i64(&self) -> Option<i64> {
        self.to_integer().to_i64()
    }
}

impl UnsignedDecimal {
    pub fn to_biguint(&self) -> BigUint {
        self.to_integer()
    }

    pub fn to_bigint(&self) -> BigInt {
        BigInt::from(self.to_integer())
    }

    pub fn to_u64(&self) -> Option<u64> {
        self.to_integer().to_u64()
    }
}

impl From<i64> for SignedDecimal {
    fn from(value: i64) -> Self {
        Self(value.to_string())
    }
}

impl From<u64> for UnsignedDecimal {
    fn from(value: u64) -> Self {
        Self(value.to_string())
    }
}

/// An exact time value. Its stored form is always canonical and reduced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RationalTime {
    numerator: SignedDecimal,
    denominator: UnsignedDecimal,
}

impl RationalTime {
    /// Validate a canonical wire value without reducing or changing its text.
    pub fn new(
        numerator: impl AsRef<str>,
        denominator: impl AsRef<str>,
    ) -> Result<Self, TimeError> {
        let numerator = SignedDecimal::new(numerator.as_ref())?;
        let denominator = UnsignedDecimal::new(denominator.as_ref())?;
        Self::from_parts(numerator, denominator)
    }

    pub fn from_parts(
        numerator: SignedDecimal,
        denominator: UnsignedDecimal,
    ) -> Result<Self, TimeError> {
        let denominator_integer = denominator.to_bigint();
        if denominator_integer.is_zero() {
            return Err(TimeError::NonPositiveDenominator);
        }
        if numerator.to_bigint().gcd(&denominator_integer) != BigInt::one() {
            return Err(TimeError::NotReduced);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Reduce newly computed integers and put the sign in the numerator.
    /// This constructor is deliberately separate from wire deserialization.
    pub fn from_integers(
        mut numerator: BigInt,
        mut denominator: BigInt,
    ) -> Result<Self, TimeError> {
        if denominator.is_zero() {
            return Err(TimeError::NonPositiveDenominator);
        }
        if denominator.is_negative() {
            numerator = -numerator;
            denominator = -denominator;
        }
        let divisor = numerator.gcd(&denominator);
        numerator /= &divisor;
        denominator /= divisor;
        Ok(Self {
            numerator: SignedDecimal::from_integer(numerator),
            denominator: UnsignedDecimal::from_integer(
                denominator
                    .to_biguint()
                    .expect("computed denominator is positive"),
            ),
        })
    }

    pub fn from_integer(value: impl Into<BigInt>) -> Self {
        Self {
            numerator: SignedDecimal::from_integer(value.into()),
            denominator: UnsignedDecimal::from(1),
        }
    }

    pub fn zero() -> Self {
        Self::from_integer(0)
    }

    pub fn one() -> Self {
        Self::from_integer(1)
    }

    pub fn numerator(&self) -> &SignedDecimal {
        &self.numerator
    }

    pub fn denominator(&self) -> &UnsignedDecimal {
        &self.denominator
    }

    pub fn is_negative(&self) -> bool {
        self.numerator.as_str().starts_with('-')
    }

    pub fn is_zero(&self) -> bool {
        self.numerator.as_str() == "0"
    }

    pub fn is_positive(&self) -> bool {
        !self.is_negative() && !self.is_zero()
    }

    /// Approximate conversion for consumers that explicitly allow floating point.
    /// Returns `None` when conversion of either operand or the result is nonfinite.
    pub fn to_f64(&self) -> Option<f64> {
        let numerator = self.numerator.to_bigint().to_f64()?;
        let denominator = self.denominator.to_bigint().to_f64()?;
        if !numerator.is_finite() || !denominator.is_finite() {
            return None;
        }
        let value = numerator / denominator;
        value.is_finite().then_some(value)
    }

    pub fn checked_add(&self, other: &Self) -> Result<Self, TimeError> {
        let left_denominator = self.denominator.to_bigint();
        let right_denominator = other.denominator.to_bigint();
        Self::from_integers(
            self.numerator.to_bigint() * &right_denominator
                + other.numerator.to_bigint() * &left_denominator,
            left_denominator * right_denominator,
        )
    }

    pub fn checked_sub(&self, other: &Self) -> Result<Self, TimeError> {
        let left_denominator = self.denominator.to_bigint();
        let right_denominator = other.denominator.to_bigint();
        Self::from_integers(
            self.numerator.to_bigint() * &right_denominator
                - other.numerator.to_bigint() * &left_denominator,
            left_denominator * right_denominator,
        )
    }

    pub fn checked_mul(&self, other: &Self) -> Result<Self, TimeError> {
        Self::from_integers(
            self.numerator.to_bigint() * other.numerator.to_bigint(),
            self.denominator.to_bigint() * other.denominator.to_bigint(),
        )
    }

    pub fn checked_div(&self, other: &Self) -> Result<Self, TimeError> {
        if other.is_zero() {
            return Err(TimeError::DivisionByZero);
        }
        Self::from_integers(
            self.numerator.to_bigint() * other.denominator.to_bigint(),
            self.denominator.to_bigint() * other.numerator.to_bigint(),
        )
    }

    pub fn negated(&self) -> Self {
        Self {
            numerator: SignedDecimal::from_integer(-self.numerator.to_bigint()),
            denominator: self.denominator.clone(),
        }
    }

    pub fn floor(&self) -> BigInt {
        self.numerator
            .to_bigint()
            .div_floor(&self.denominator.to_bigint())
    }

    pub fn ceil(&self) -> BigInt {
        self.numerator
            .to_bigint()
            .div_ceil(&self.denominator.to_bigint())
    }

    pub fn round_ties_even(&self) -> BigInt {
        let denominator = self.denominator.to_bigint();
        let (floor, remainder) = self.numerator.to_bigint().div_mod_floor(&denominator);
        match (remainder * BigInt::from(2u8)).cmp(&denominator) {
            Ordering::Less => floor,
            Ordering::Greater => floor + 1u8,
            Ordering::Equal if floor.is_even() => floor,
            Ordering::Equal => floor + 1u8,
        }
    }
}

impl<'de> Deserialize<'de> for RationalTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireTime {
            numerator: SignedDecimal,
            denominator: UnsignedDecimal,
        }

        let wire = WireTime::deserialize(deserializer)?;
        Self::from_parts(wire.numerator, wire.denominator).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for RationalTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.numerator, self.denominator)
    }
}

impl FromStr for RationalTime {
    type Err = TimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (numerator, denominator) = value
            .split_once('/')
            .ok_or(TimeError::InvalidRationalText)?;
        if denominator.contains('/') {
            return Err(TimeError::InvalidRationalText);
        }
        Self::new(numerator, denominator)
    }
}

impl PartialOrd for RationalTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RationalTime {
    fn cmp(&self, other: &Self) -> Ordering {
        let left = self.numerator.to_bigint() * other.denominator.to_bigint();
        let right = other.numerator.to_bigint() * self.denominator.to_bigint();
        left.cmp(&right)
    }
}

impl Add<&RationalTime> for &RationalTime {
    type Output = RationalTime;

    fn add(self, other: &RationalTime) -> Self::Output {
        self.checked_add(other)
            .expect("addition preserves positive denominators")
    }
}

impl Sub<&RationalTime> for &RationalTime {
    type Output = RationalTime;

    fn sub(self, other: &RationalTime) -> Self::Output {
        self.checked_sub(other)
            .expect("subtraction preserves positive denominators")
    }
}

impl Mul<&RationalTime> for &RationalTime {
    type Output = RationalTime;

    fn mul(self, other: &RationalTime) -> Self::Output {
        self.checked_mul(other)
            .expect("multiplication preserves positive denominators")
    }
}

impl Neg for &RationalTime {
    type Output = RationalTime;

    fn neg(self) -> Self::Output {
        self.negated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_wire_forms_reject_repairs_and_numeric_json() {
        for invalid in [
            "", "00", "01", "+1", "-0", "-01", " 1", "1 ", "1.0", "1e2", "１",
        ] {
            assert!(SignedDecimal::new(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(SignedDecimal::new("-1").is_ok());
        assert!(UnsignedDecimal::new("-1").is_err());
        assert!(UnsignedDecimal::new("0").is_ok());
        assert!(serde_json::from_str::<UnsignedDecimal>("9007199254740992").is_err());
        let exact = UnsignedDecimal::new("9007199254740993").unwrap();
        assert_eq!(
            serde_json::to_string(&exact).unwrap(),
            "\"9007199254740993\""
        );
        assert_eq!(exact.to_u64(), Some(9_007_199_254_740_993));
        assert!(UnsignedDecimal::new("10").unwrap() > UnsignedDecimal::new("2").unwrap());
    }

    #[test]
    fn rational_deserialization_rejects_noncanonical_or_unreduced_values() {
        for invalid in [
            r#"{"numerator":"2","denominator":"4"}"#,
            r#"{"numerator":"0","denominator":"2"}"#,
            r#"{"numerator":"1","denominator":"0"}"#,
            r#"{"numerator":"1","denominator":"-2"}"#,
            r#"{"numerator":"01","denominator":"2"}"#,
            r#"{"numerator":"-0","denominator":"1"}"#,
            r#"{"numerator":1,"denominator":"2"}"#,
            r#"{"numerator":"1","denominator":"2","extra":0}"#,
            r#"{"numerator":"1","numerator":"3","denominator":"2"}"#,
        ] {
            assert!(
                serde_json::from_str::<RationalTime>(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        let input = r#"{"numerator":"-1","denominator":"2"}"#;
        let time: RationalTime = serde_json::from_str(input).unwrap();
        assert_eq!(serde_json::to_string(&time).unwrap(), input);
    }

    #[test]
    fn arithmetic_reduces_new_values_and_orders_without_float_rounding() {
        let one_third = RationalTime::new("1", "3").unwrap();
        let one_sixth = RationalTime::new("1", "6").unwrap();
        assert_eq!((&one_third + &one_sixth).to_string(), "1/2");
        assert_eq!((&one_sixth - &one_third).to_string(), "-1/6");
        assert_eq!((&one_third * &one_sixth).to_string(), "1/18");
        assert_eq!(
            one_third.checked_div(&one_sixth).unwrap().to_string(),
            "2/1"
        );
        assert_eq!(
            one_third.checked_div(&RationalTime::zero()),
            Err(TimeError::DivisionByZero)
        );
        let left = RationalTime::new("9007199254740993", "9007199254740992").unwrap();
        assert!(left > RationalTime::one());
        let huge = "9".repeat(100);
        let value = RationalTime::new(&huge, "2").unwrap();
        assert_eq!(value.numerator().as_str(), huge);
        assert!(value > left);
        assert_eq!(
            RationalTime::from_integers(0.into(), 37.into()).unwrap(),
            RationalTime::zero()
        );
        assert_eq!(
            RationalTime::from_integers(2.into(), (-4).into())
                .unwrap()
                .to_string(),
            "-1/2"
        );
    }

    #[test]
    fn exact_rounding_handles_negative_ties_and_sign_queries() {
        let value = RationalTime::new("-3", "2").unwrap();
        assert_eq!(value.floor(), BigInt::from(-2));
        assert_eq!(value.ceil(), BigInt::from(-1));
        assert_eq!(value.round_ties_even(), BigInt::from(-2));
        assert_eq!(
            RationalTime::new("-1", "2").unwrap().round_ties_even(),
            BigInt::zero()
        );
        assert_eq!(
            RationalTime::new("5", "2").unwrap().round_ties_even(),
            BigInt::from(2)
        );
        assert_eq!(
            RationalTime::new("7", "2").unwrap().round_ties_even(),
            BigInt::from(4)
        );
        assert!(value.is_negative());
        assert!(RationalTime::zero().is_zero());
        assert!(RationalTime::one().is_positive());
        assert_eq!(value.to_f64(), Some(-1.5));
        assert_eq!(
            RationalTime::new("9".repeat(400), "1").unwrap().to_f64(),
            None
        );
    }
}
