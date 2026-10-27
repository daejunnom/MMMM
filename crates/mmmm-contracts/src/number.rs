//! JSON Schema integer is a mathematical type: `1`, `1.0`, and `1e0` must
//! decode consistently. Never truncate a fractional value or saturate a cast.

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, Visitor},
};
use std::{convert::Infallible, fmt};

/// Parse the exact decimal value of one bounded JSON number lexeme as a
/// nonnegative safe integer. This helper validates the supplied lexeme, but
/// does not prove which source bytes or schema path it came from.
///
/// The input is bounded to the strict JSON byte budget. Its coefficient and
/// exponent are scanned without floating point or input-sized allocation.
pub fn exact_safe_u64_json_lexeme(lexeme: &str) -> Option<u64> {
    match exact_safe_u64_json_lexeme_with_control(lexeme, || Ok::<(), Infallible>(())) {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

/// The same bounded predicate with cooperative checks during every linear scan.
/// Cancellation is returned unchanged; the caller owns the final checkpoint.
pub(crate) fn exact_safe_u64_json_lexeme_with_control<E>(
    lexeme: &str,
    mut checkpoint: impl FnMut() -> Result<(), E>,
) -> Result<Option<u64>, E> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    const CONTROL_INTERVAL: usize = 4 * 1024;

    let bytes = lexeme.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Ok(None);
    }
    checkpoint()?;
    let mut remaining = CONTROL_INTERVAL;
    let mut failure = None;
    let result = {
        let mut tick = || -> Option<()> {
            if remaining == 0 {
                if let Err(error) = checkpoint() {
                    failure = Some(error);
                    return None;
                }
                remaining = CONTROL_INTERVAL;
            }
            remaining -= 1;
            Some(())
        };
        // Keep the original Option-based parsing and arithmetic separate from the
        // caller's error: a failed checkpoint ends the scan and is returned below.
        fn parse_lexeme(bytes: &[u8], tick: &mut impl FnMut() -> Option<()>) -> Option<u64> {
            const MAX_SAFE: u64 = 9_007_199_254_740_991;
            let mut pos = 0;
            tick()?;
            let negative = bytes[pos] == b'-';
            if negative {
                pos += 1;
            }
            let integer_start = pos;
            tick()?;
            match bytes.get(pos) {
                Some(b'0') => {
                    pos += 1;
                    tick()?;
                    if bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                        return None;
                    }
                }
                Some(b'1'..=b'9') => {
                    pos += 1;
                    loop {
                        tick()?;
                        if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                            break;
                        }
                        pos += 1;
                    }
                }
                _ => return None,
            }
            let integer_end = pos;
            let mut fraction_start = pos;
            let mut fraction_end = pos;
            tick()?;
            if bytes.get(pos) == Some(&b'.') {
                pos += 1;
                fraction_start = pos;
                loop {
                    tick()?;
                    if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                        break;
                    }
                    pos += 1;
                }
                fraction_end = pos;
                if fraction_start == fraction_end {
                    return None;
                }
            }

            let mut exponent = 0usize;
            let mut exponent_negative = false;
            tick()?;
            if matches!(bytes.get(pos), Some(b'e' | b'E')) {
                pos += 1;
                tick()?;
                if matches!(bytes.get(pos), Some(b'+' | b'-')) {
                    exponent_negative = bytes[pos] == b'-';
                    pos += 1;
                }
                let exponent_start = pos;
                // A magnitude above the input length plus 32 cannot change whether
                // a nonzero coefficient is fractional or exceeds the safe range.
                let cap = bytes.len().saturating_add(32);
                loop {
                    tick()?;
                    let Some(digit @ b'0'..=b'9') = bytes.get(pos).copied() else {
                        break;
                    };
                    exponent = exponent
                        .saturating_mul(10)
                        .saturating_add(usize::from(digit - b'0'))
                        .min(cap);
                    pos += 1;
                }
                if exponent_start == pos {
                    return None;
                }
            }
            if pos != bytes.len() {
                return None;
            }

            let digits = bytes[integer_start..integer_end]
                .iter()
                .chain(bytes[fraction_start..fraction_end].iter());
            let mut first = None;
            let mut last = 0usize;
            let mut count = 0usize;
            let mut inspection = digits.clone();
            loop {
                tick()?;
                let Some(&digit) = inspection.next() else {
                    break;
                };
                if digit != b'0' {
                    first.get_or_insert(count);
                    last = count;
                }
                count += 1;
            }
            let Some(first) = first else {
                return Some(0);
            };
            if negative {
                return None;
            }
            let trailing = count - last - 1;
            let exponent = i128::try_from(exponent).ok()?;
            let signed_exponent = if exponent_negative {
                -exponent
            } else {
                exponent
            };
            let scale = signed_exponent - i128::try_from(fraction_end - fraction_start).ok()?
                + i128::try_from(trailing).ok()?;
            let significant = last - first + 1;
            if scale < 0 || i128::try_from(significant).ok()? + scale > 16 {
                return None;
            }

            let mut value = 0u64;
            let mut conversion = digits.enumerate();
            loop {
                tick()?;
                let Some((index, &digit)) = conversion.next() else {
                    break;
                };
                if (first..=last).contains(&index) {
                    value = value
                        .checked_mul(10)?
                        .checked_add(u64::from(digit - b'0'))?;
                }
            }
            for _ in 0..usize::try_from(scale).ok()? {
                tick()?;
                value = value.checked_mul(10)?;
            }
            (value <= MAX_SAFE).then_some(value)
        }
        parse_lexeme(bytes, &mut tick)
    };
    match failure {
        Some(error) => Err(error),
        None => Ok(result),
    }
}

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

    #[test]
    fn exact_lexemes_accept_only_nonnegative_safe_mathematical_integers() {
        for (lexeme, expected) in [
            ("0", 0),
            ("-0.0", 0),
            ("1", 1),
            ("1.0", 1),
            ("1e0", 1),
            ("100e-2", 1),
            ("0.0001000e4", 1),
            ("9007199254740991", 9_007_199_254_740_991),
            ("90071992547409910e-1", 9_007_199_254_740_991),
        ] {
            assert_eq!(
                exact_safe_u64_json_lexeme(lexeme),
                Some(expected),
                "{lexeme}"
            );
        }
        for lexeme in [
            "1.0000000000000001",
            "9007199254740991.1",
            "90071992547409911e-1",
            "9007199254740992",
            "-1",
            "1e-10000",
            "-1e-10000",
            "0.5",
        ] {
            assert_eq!(exact_safe_u64_json_lexeme(lexeme), None, "{lexeme}");
        }
    }

    #[test]
    fn exact_lexemes_check_json_grammar_and_bound_huge_exponents() {
        for lexeme in [
            "", "-", "+1", "01", "-01", ".5", "1.", "1e", "1e+", "1e-", "1 0", " 1", "1 ", "NaN",
            "∞", "0x1",
        ] {
            assert_eq!(exact_safe_u64_json_lexeme(lexeme), None, "{lexeme}");
        }
        let huge_exponent = "9".repeat(4_096);
        assert_eq!(
            exact_safe_u64_json_lexeme(&format!("1e{huge_exponent}")),
            None
        );
        assert_eq!(
            exact_safe_u64_json_lexeme(&format!("1e-{huge_exponent}")),
            None
        );
        assert_eq!(
            exact_safe_u64_json_lexeme(&format!("-0e{huge_exponent}")),
            Some(0)
        );
    }

    #[test]
    fn controlled_exact_lexemes_preserve_the_existing_predicate() {
        for lexeme in [
            "0",
            "-0.0",
            "1.0",
            "100e-2",
            "9007199254740991",
            "1.0000000000000001",
            "9007199254740992",
            "1e-10000",
            "01",
            "1e+",
        ] {
            let controlled =
                exact_safe_u64_json_lexeme_with_control(lexeme, || Ok::<(), ()>(())).unwrap();
            assert_eq!(controlled, exact_safe_u64_json_lexeme(lexeme), "{lexeme}");
        }
    }

    #[test]
    fn controlled_exact_lexemes_preserve_cancellation_across_each_scan() {
        // This finite token forces a long lexical scan, coefficient inspection,
        // and coefficient conversion. No new fixture or input-sized helper
        // allocation is needed in the implementation itself.
        let lexeme = format!("0.{}1e8193", "0".repeat(8192));
        for cancel_at in [1, 2, 4, 6] {
            let marker = Box::new(7_u8);
            let pointer = marker.as_ref() as *const u8;
            let mut marker = Some(marker);
            let mut calls = 0;
            let result = exact_safe_u64_json_lexeme_with_control(&lexeme, || {
                calls += 1;
                if calls == cancel_at {
                    Err(marker.take().unwrap())
                } else {
                    Ok(())
                }
            });
            let error = result.unwrap_err();
            assert_eq!(error.as_ref() as *const u8, pointer);
            assert_eq!(calls, cancel_at, "no callbacks after cancellation");
        }

        let exponent = format!("1e{}", "9".repeat(8192));
        let mut calls = 0;
        let result = exact_safe_u64_json_lexeme_with_control(&exponent, || {
            calls += 1;
            if calls == 2 {
                Err("exponent cancelled")
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err("exponent cancelled"));
        assert_eq!(calls, 2);
    }
}
