//! Affine transforms in row-major storage with column-vector multiplication.
//!
//! Matrix values remain matrices: no decomposition, scale clamp, or automatic
//! quaternion normalization changes the authored transform.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;

/// Accepted floating-point error in the length of an authored unit quaternion.
pub const QUATERNION_NORM_TOLERANCE: f64 = 1e-9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    SchemaInvalid(String),
    UnsupportedTransform(String),
    NoninvertibleTransform,
}

impl TransformError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaInvalid(_) => "SCHEMA_INVALID",
            Self::UnsupportedTransform(_) => "UNSUPPORTED_TRANSFORM",
            Self::NoninvertibleTransform => "NONINVERTIBLE_TRANSFORM",
        }
    }
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaInvalid(message) | Self::UnsupportedTransform(message) => {
                write!(formatter, "{}: {message}", self.code())
            }
            Self::NoninvertibleTransform => {
                formatter.write_str("NONINVERTIBLE_TRANSFORM: parent matrix has no affine inverse")
            }
        }
    }
}

impl std::error::Error for TransformError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatrixLayout {
    #[serde(rename = "row_major_column_vector")]
    RowMajorColumnVector,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transform {
    Trs {
        translation: [f64; 3],
        #[serde(rename = "rotationXyzw")]
        rotation_xyzw: [f64; 4],
        scale: [f64; 3],
    },
    Matrix {
        layout: MatrixLayout,
        values: [f64; 16],
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TransformWire {
    Trs {
        translation: [f64; 3],
        #[serde(rename = "rotationXyzw")]
        rotation_xyzw: [f64; 4],
        scale: [f64; 3],
    },
    Matrix {
        layout: MatrixLayout,
        values: [f64; 16],
    },
}

impl TryFrom<TransformWire> for Transform {
    type Error = TransformError;

    fn try_from(wire: TransformWire) -> Result<Self, Self::Error> {
        let transform = match wire {
            TransformWire::Trs { translation, rotation_xyzw, scale } => {
                Self::Trs { translation, rotation_xyzw, scale }
            }
            TransformWire::Matrix { layout, values } => Self::Matrix { layout, values },
        };
        transform.validate()?;
        Ok(transform)
    }
}

impl<'de> Deserialize<'de> for Transform {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(TransformWire::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl Transform {
    pub fn identity() -> Self {
        Self::Trs {
            translation: [0.0; 3],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [1.0; 3],
        }
    }

    pub fn from_value(value: &Value) -> Result<Self, TransformError> {
        let wire = serde_json::from_value::<TransformWire>(value.clone())
            .map_err(|error| TransformError::SchemaInvalid(error.to_string()))?;
        Self::try_from(wire)
    }

    pub fn to_value(&self) -> Result<Value, TransformError> {
        self.validate()?;
        serde_json::to_value(self)
            .map_err(|error| TransformError::SchemaInvalid(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), TransformError> {
        match self {
            Self::Trs { translation, rotation_xyzw, scale } => {
                require_finite(translation, "translation")?;
                require_finite(rotation_xyzw, "rotationXyzw")?;
                require_finite(scale, "scale")?;
                let length = rotation_xyzw[0]
                    .hypot(rotation_xyzw[1])
                    .hypot(rotation_xyzw[2])
                    .hypot(rotation_xyzw[3]);
                if (length - 1.0).abs() > QUATERNION_NORM_TOLERANCE {
                    return Err(TransformError::SchemaInvalid(format!(
                        "rotationXyzw must be a unit quaternion within {QUATERNION_NORM_TOLERANCE}"
                    )));
                }
                Ok(())
            }
            Self::Matrix { values, .. } => Matrix4::from_values(*values).map(|_| ()),
        }
    }

    pub fn matrix(&self) -> Result<Matrix4, TransformError> {
        self.validate()?;
        match self {
            Self::Matrix { values, .. } => Matrix4::from_values(*values),
            Self::Trs { translation: t, rotation_xyzw: [x, y, z, w], scale: s } => {
                let [x, y, z, w] = [*x, *y, *z, *w];
                Matrix4::from_computed_values([
                    (1.0 - 2.0 * (y * y + z * z)) * s[0],
                    2.0 * (x * y - z * w) * s[1],
                    2.0 * (x * z + y * w) * s[2],
                    t[0],
                    2.0 * (x * y + z * w) * s[0],
                    (1.0 - 2.0 * (x * x + z * z)) * s[1],
                    2.0 * (y * z - x * w) * s[2],
                    t[1],
                    2.0 * (x * z - y * w) * s[0],
                    2.0 * (y * z + x * w) * s[1],
                    (1.0 - 2.0 * (x * x + y * y)) * s[2],
                    t[2],
                    0.0, 0.0, 0.0, 1.0,
                ])
            }
        }
    }

    pub fn from_matrix(matrix: Matrix4) -> Self {
        Self::Matrix { layout: MatrixLayout::RowMajorColumnVector, values: matrix.0 }
    }
}

/// A finite affine matrix. A singular linear part is valid until inversion.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Matrix4([f64; 16]);

impl Matrix4 {
    pub fn from_values(values: [f64; 16]) -> Result<Self, TransformError> {
        require_finite(&values, "matrix values")?;
        if values[12..] != [0.0, 0.0, 0.0, 1.0] {
            return Err(TransformError::UnsupportedTransform(
                "affine matrix must have final row [0,0,0,1]".to_owned(),
            ));
        }
        Ok(Self(values))
    }

    pub const fn identity() -> Self {
        Self([
            1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ])
    }

    pub const fn values(&self) -> &[f64; 16] {
        &self.0
    }

    fn from_computed_values(values: [f64; 16]) -> Result<Self, TransformError> {
        require_representable(&values)?;
        Self::from_values(values)
    }

    /// Composition `self * local`, with translation at indices 3, 7, and 11.
    pub fn multiply(&self, local: &Self) -> Result<Self, TransformError> {
        let mut result = [0.0; 16];
        for row in 0..4 {
            for column in 0..4 {
                result[row * 4 + column] = (0..4)
                    .map(|inner| self.0[row * 4 + inner] * local.0[inner * 4 + column])
                    .sum();
            }
        }
        Self::from_computed_values(result)
    }

    pub fn transform_point(&self, point: [f64; 3]) -> Result<[f64; 3], TransformError> {
        require_finite(&point, "point")?;
        let result = std::array::from_fn(|row| {
            self.0[row * 4] * point[0]
                + self.0[row * 4 + 1] * point[1]
                + self.0[row * 4 + 2] * point[2]
                + self.0[row * 4 + 3]
        });
        require_representable(&result)?;
        Ok(result)
    }

    /// Scaled partial-pivot inversion. Only a zero pivot is singular; no small
    /// nonzero pivot is clamped away. Unrepresentable arithmetic is rejected.
    pub fn inverse_affine(&self) -> Result<Self, TransformError> {
        let mut rows = [[0.0; 6]; 3];
        let mut scales = [0.0_f64; 3];
        for row in 0..3 {
            for column in 0..3 {
                rows[row][column] = self.0[row * 4 + column];
                scales[row] = scales[row].max(rows[row][column].abs());
            }
            rows[row][row + 3] = 1.0;
            if scales[row] == 0.0 {
                return Err(TransformError::NoninvertibleTransform);
            }
        }
        for column in 0..3 {
            let mut pivot_row = column;
            let mut best_ratio = -1.0_f64;
            for row in column..3 {
                if rows[row][column] != 0.0 {
                    let ratio = rows[row][column].abs() / scales[row];
                    if ratio > best_ratio {
                        best_ratio = ratio;
                        pivot_row = row;
                    }
                }
            }
            if best_ratio < 0.0 {
                return Err(TransformError::NoninvertibleTransform);
            }
            rows.swap(column, pivot_row);
            scales.swap(column, pivot_row);
            let pivot = rows[column][column];
            for item in &mut rows[column] {
                *item /= pivot;
            }
            require_representable(&rows[column])?;
            let normalized = rows[column];
            for row in 0..3 {
                if row != column {
                    let factor = rows[row][column];
                    for item in 0..6 {
                        rows[row][item] -= factor * normalized[item];
                    }
                    require_representable(&rows[row])?;
                }
            }
        }
        let mut result = [0.0; 16];
        result[15] = 1.0;
        for row in 0..3 {
            for column in 0..3 {
                result[row * 4 + column] = rows[row][column + 3];
            }
            result[row * 4 + 3] = -(rows[row][3] * self.0[3]
                + rows[row][4] * self.0[7]
                + rows[row][5] * self.0[11]);
        }
        Self::from_computed_values(result)
    }

    /// Exact right-handed Y rotation by an integer number of quarter turns.
    pub fn quarter_turn_y(quarter_turns: i32) -> Self {
        let (cosine, sine) = match quarter_turns.rem_euclid(4) {
            0 => (1.0, 0.0),
            1 => (0.0, 1.0),
            2 => (-1.0, 0.0),
            _ => (0.0, -1.0),
        };
        Self([
            cosine, 0.0, sine, 0.0,
            0.0, 1.0, 0.0, 0.0,
            -sine, 0.0, cosine, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ])
    }
}

/// The new local transform is `inverse(new_parent) * old_parent * local`.
/// Matrix output preserves shear, reflection, and singular child transforms.
pub fn reparent_keep_world(
    old_parent_world: &Matrix4,
    local: &Transform,
    new_parent_world: &Matrix4,
) -> Result<Transform, TransformError> {
    let world = old_parent_world.multiply(&local.matrix()?)?;
    let new_local = new_parent_world.inverse_affine()?.multiply(&world)?;
    Ok(Transform::from_matrix(new_local))
}

/// Rotate a unit block cell by its minimum corner. A negative rotated axis
/// changes the minimum by one cell; rotating the corner point alone is wrong.
pub fn rotate_block_cell_y(
    cell: [i64; 3],
    quarter_turns: i32,
    translation: [i64; 3],
) -> Result<[i64; 3], TransformError> {
    let [x, y, z] = cell.map(i128::from);
    let rotated = match quarter_turns.rem_euclid(4) {
        0 => [x, y, z],
        1 => [z, y, -x - 1],
        2 => [-x - 1, y, -z - 1],
        _ => [-z - 1, y, x],
    };
    let mut result = [0; 3];
    for axis in 0..3 {
        result[axis] = i64::try_from(rotated[axis] + i128::from(translation[axis]))
            .map_err(|_| TransformError::UnsupportedTransform(
                "integer block placement exceeds coordinate range".to_owned(),
            ))?;
    }
    Ok(result)
}

fn require_finite(values: &[f64], field: &str) -> Result<(), TransformError> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(TransformError::SchemaInvalid(format!(
            "{field} must contain finite numbers"
        )));
    }
    Ok(())
}

fn require_representable(values: &[f64]) -> Result<(), TransformError> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(TransformError::UnsupportedTransform(
            "transform arithmetic exceeds finite floating-point range".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assert_close(actual: &[f64], expected: &[f64]) {
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            let tolerance = 1e-11 * expected.abs().max(1.0);
            assert!((actual - expected).abs() <= tolerance,
                "component {index}: {actual} != {expected}");
        }
    }

    #[test]
    fn canonical_wire_is_closed_and_quaternion_is_validated_without_repair() {
        let value = json!({
            "kind": "trs", "translation": [2.0, 3.0, 4.0],
            "rotationXyzw": [0.0, 0.0, 0.0, 1.0], "scale": [1.0, 1.0, 1.0]
        });
        assert_eq!(Transform::from_value(&value).unwrap().to_value().unwrap(), value);
        let mut extra = value.clone();
        extra["pivot"] = json!([0, 0, 0]);
        assert!(Transform::from_value(&extra).is_err());
        let mut invalid = value;
        invalid["rotationXyzw"] = json!([0, 0, 0, 2]);
        assert_eq!(Transform::from_value(&invalid).unwrap_err().code(), "SCHEMA_INVALID");
        assert!(serde_json::from_value::<Transform>(invalid).is_err());
    }

    #[test]
    fn trs_rotation_scales_columns_and_translation_uses_last_column() {
        let half = 0.5_f64.sqrt();
        let transform = Transform::Trs {
            translation: [10.0, 20.0, 30.0],
            rotation_xyzw: [0.0, half, 0.0, half],
            scale: [2.0, 3.0, 4.0],
        };
        let matrix = transform.matrix().unwrap();
        assert_close(&matrix.transform_point([1.0, 2.0, 3.0]).unwrap(), &[22.0, 26.0, 28.0]);
    }

    #[test]
    fn raw_shear_reflection_and_thin_scale_round_trip_and_invert() {
        let values = [
            -2.0, 3.0, 0.0, 7.0,
            0.0, 4.0, 0.0, 8.0,
            0.0, 0.0, 0.00005, 9.0,
            0.0, 0.0, 0.0, 1.0,
        ];
        let matrix = Matrix4::from_values(values).unwrap();
        let transform = Transform::from_matrix(matrix);
        assert_eq!(Transform::from_value(&transform.to_value().unwrap()).unwrap().matrix().unwrap().values(), &values);
        let inverse = matrix.inverse_affine().unwrap();
        assert_close(inverse.values(), &[
            -0.5, 0.375, 0.0, 0.5,
            0.0, 0.25, 0.0, -2.0,
            0.0, 0.0, 20000.0, -180000.0,
            0.0, 0.0, 0.0, 1.0,
        ]);
        assert_close(matrix.multiply(&inverse).unwrap().values(), Matrix4::identity().values());
    }

    #[test]
    fn tiny_nonzero_scale_is_not_rejected_as_singular() {
        let matrix = Transform::Trs {
            translation: [0.0; 3], rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [1e-200, 1.0, 1.0],
        }.matrix().unwrap();
        assert_eq!(matrix.values()[0], 1e-200);
        assert_close(&[matrix.inverse_affine().unwrap().values()[0]], &[1e200]);
    }

    #[test]
    fn singular_child_is_renderable_but_new_singular_parent_cannot_reparent() {
        let child = Transform::Trs {
            translation: [3.0, 4.0, 5.0], rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [0.0, -1.0, 0.00005],
        };
        let singular = child.matrix().unwrap();
        assert_eq!(singular.transform_point([9.0, 2.0, 0.0]).unwrap(), [3.0, 2.0, 5.0]);
        let retained = reparent_keep_world(&Matrix4::identity(), &child, &Matrix4::identity()).unwrap();
        assert_eq!(retained.matrix().unwrap(), singular);
        assert_eq!(reparent_keep_world(&Matrix4::identity(), &child, &singular).unwrap_err().code(), "NONINVERTIBLE_TRANSFORM");
    }

    #[test]
    fn keep_world_retains_affine_shape_and_world_points() {
        let old_parent = Matrix4::from_values([
            1.0, 0.0, 0.0, 5.0, 0.0, 1.0, 0.0, -2.0,
            0.0, 0.0, 1.0, 3.0, 0.0, 0.0, 0.0, 1.0,
        ]).unwrap();
        let new_parent = Matrix4::quarter_turn_y(1);
        let child = Transform::from_matrix(Matrix4::from_values([
            -1.0, 0.25, 0.0, 4.0, 0.0, 2.0, 0.0, 1.0,
            0.0, 0.0, 0.00005, 2.0, 0.0, 0.0, 0.0, 1.0,
        ]).unwrap());
        let changed = reparent_keep_world(&old_parent, &child, &new_parent).unwrap();
        assert!(matches!(changed, Transform::Matrix { .. }));
        let old_world = old_parent.multiply(&child.matrix().unwrap()).unwrap();
        let new_world = new_parent.multiply(&changed.matrix().unwrap()).unwrap();
        assert_close(old_world.values(), new_world.values());
        assert_close(&old_world.transform_point([2.0, -3.0, 4.0]).unwrap(), &new_world.transform_point([2.0, -3.0, 4.0]).unwrap());
    }

    #[test]
    fn quarter_turn_block_placement_uses_rotated_cell_minimum() {
        assert_eq!(rotate_block_cell_y([2, 3, 4], 1, [10, 20, 30]).unwrap(), [14, 23, 27]);
        assert_eq!(rotate_block_cell_y([2, 3, 4], 2, [0; 3]).unwrap(), [-3, 3, -5]);
        assert_eq!(rotate_block_cell_y([2, 3, 4], -1, [0; 3]).unwrap(), [-5, 3, 2]);
        let mut cell = [2, 3, 4];
        for _ in 0..4 {
            cell = rotate_block_cell_y(cell, 1, [0; 3]).unwrap();
        }
        assert_eq!(cell, [2, 3, 4]);
        assert_eq!(rotate_block_cell_y([i64::MAX, 0, 0], 1, [0; 3]).unwrap(), [0, 0, i64::MIN]);
        assert!(rotate_block_cell_y([i64::MAX, 0, 0], 0, [1, 0, 0]).is_err());
    }

    #[test]
    fn nonfinite_and_nonaffine_values_are_rejected() {
        let mut values = *Matrix4::identity().values();
        values[0] = f64::NAN;
        assert_eq!(Matrix4::from_values(values).unwrap_err().code(), "SCHEMA_INVALID");
        values = *Matrix4::identity().values();
        values[12] = 0.5;
        assert_eq!(Matrix4::from_values(values).unwrap_err().code(), "UNSUPPORTED_TRANSFORM");
    }
}
