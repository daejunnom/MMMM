//! The exchange basis is dimensionless. Distance conversion occurs once at
//! this boundary; explicit SI velocity and gravity fields keep their SI size.

use crate::types::DomainError;
type DomainResult<T> = Result<T, DomainError>;
fn validate(definition: &str, value: &serde_json::Value) -> DomainResult<()> {
    mmmm_contracts::ContractValidator::shared()
        .and_then(|v| v.validate(definition, value))
        .map_err(|e| DomainError::new("SCHEMA_INVALID", e.to_string()))
}
use crate::transform::{Matrix4, Transform};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const BASIS_TOLERANCE: f64 = 1e-9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceUnit {
    Blocks,
    Meters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeDomain {
    GameSeconds,
    WallSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum MassUnit {
    #[serde(rename = "kilograms")]
    Kilograms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum AngleUnit {
    #[serde(rename = "radians")]
    Radians,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum QuaternionOrder {
    #[serde(rename = "xyzw")]
    Xyzw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ExchangeMatrixLayout {
    #[serde(rename = "row_major_column_vectors")]
    RowMajorColumnVectors,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CoordinateWire {
    basis_to_minecraft_row_major: [f64; 16],
    meters_per_block: f64,
    distance_unit: DistanceUnit,
    mass_unit: MassUnit,
    angle_unit: AngleUnit,
    quaternion_order: QuaternionOrder,
    matrix_layout: ExchangeMatrixLayout,
    time_domain: TimeDomain,
}

/// A semantically validated, immutable coordinate contract.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CoordinateSystem(CoordinateWire);

impl<'de> Deserialize<'de> for CoordinateSystem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CoordinateWire::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

impl CoordinateSystem {
    fn from_wire(wire: CoordinateWire) -> DomainResult<Self> {
        validate_basis(&wire.basis_to_minecraft_row_major)?;
        if !wire.meters_per_block.is_finite() || wire.meters_per_block <= 0.0 {
            return Err(DomainError::new(
                "INVALID_COORDINATES",
                "metersPerBlock must be finite and positive",
            ));
        }
        let result = Self(wire);
        // Reject units whose conversion cannot be represented, rather than
        // returning zeros or infinities in a later scene operation.
        result.conversion()?;
        Ok(result)
    }

    pub fn from_value(value: &Value) -> DomainResult<Self> {
        validate("CoordinateSystem", value)?;
        serde_json::from_value(value.clone())
            .map_err(|error| DomainError::new("INVALID_COORDINATES", error.to_string()))
    }

    pub fn to_value(&self) -> DomainResult<Value> {
        let value = serde_json::to_value(self)
            .map_err(|error| DomainError::new("SCHEMA_INVALID", error.to_string()))?;
        validate("CoordinateSystem", &value)?;
        Ok(value)
    }

    pub fn meters_per_block(&self) -> f64 {
        self.0.meters_per_block
    }

    pub fn distance_unit(&self) -> DistanceUnit {
        self.0.distance_unit
    }

    pub fn time_domain(&self) -> TimeDomain {
        self.0.time_domain
    }

    pub fn basis(&self) -> &[f64; 16] {
        &self.0.basis_to_minecraft_row_major
    }

    pub fn conversion(&self) -> DomainResult<CoordinateConversion> {
        let scale = match self.0.distance_unit {
            DistanceUnit::Blocks => 1.0,
            DistanceUnit::Meters => 1.0 / self.0.meters_per_block,
        };
        if !scale.is_finite() || scale <= 0.0 {
            return Err(DomainError::new(
                "INVALID_COORDINATES",
                "distance conversion exceeds finite floating-point range",
            ));
        }
        let basis =
            Matrix4::from_values(self.0.basis_to_minecraft_row_major).map_err(transform_error)?;
        let mut scale_values = *Matrix4::identity().values();
        scale_values[0] = scale;
        scale_values[5] = scale;
        scale_values[10] = scale;
        let conversion = basis
            .multiply(&Matrix4::from_values(scale_values).map_err(transform_error)?)
            .map_err(transform_error)?;
        let inverse = conversion.inverse_affine().map_err(transform_error)?;
        let determinant = determinant3(basis.values());
        Ok(CoordinateConversion {
            basis,
            conversion,
            inverse,
            reverses_handedness: determinant < 0.0,
            determinant,
            meters_per_block: self.0.meters_per_block,
        })
    }
}

/// This wrapper cannot be passed back to `point_to_minecraft`; callers must
/// explicitly cross the inverse boundary to obtain exchange coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinecraftPoint([f64; 3]);

impl MinecraftPoint {
    pub fn values(self) -> [f64; 3] {
        self.0
    }
}

/// SI polar and axial vectors have different behavior under reflection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinecraftSiPolarVector([f64; 3]);

impl MinecraftSiPolarVector {
    pub fn values(self) -> [f64; 3] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinecraftSiAxialVector([f64; 3]);

impl MinecraftSiAxialVector {
    pub fn values(self) -> [f64; 3] {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct CoordinateConversion {
    basis: Matrix4,
    conversion: Matrix4,
    inverse: Matrix4,
    reverses_handedness: bool,
    determinant: f64,
    meters_per_block: f64,
}

impl CoordinateConversion {
    pub fn point_to_minecraft(&self, point: [f64; 3]) -> DomainResult<MinecraftPoint> {
        self.conversion
            .transform_point(point)
            .map(MinecraftPoint)
            .map_err(transform_error)
    }

    pub fn point_from_minecraft(&self, point: MinecraftPoint) -> DomainResult<[f64; 3]> {
        self.inverse
            .transform_point(point.0)
            .map_err(transform_error)
    }

    /// `C * M * C^-1` changes both input and output basis. It preserves shear
    /// and reflections as a matrix and does not invent a reflection quaternion.
    pub fn affine_to_minecraft(&self, transform: &Transform) -> DomainResult<Transform> {
        let matrix = transform.matrix().map_err(transform_error)?;
        self.conversion
            .multiply(&matrix)
            .and_then(|matrix| matrix.multiply(&self.inverse))
            .map(Transform::from_matrix)
            .map_err(transform_error)
    }

    pub fn affine_from_minecraft(&self, transform: &Transform) -> DomainResult<Transform> {
        let matrix = transform.matrix().map_err(transform_error)?;
        self.inverse
            .multiply(&matrix)
            .and_then(|matrix| matrix.multiply(&self.conversion))
            .map(Transform::from_matrix)
            .map_err(transform_error)
    }

    /// Convert an authored orientation through its rotation matrix. A reflected
    /// geometry basis is handled separately from this proper rotation.
    pub fn rotation_to_minecraft(&self, xyzw: [f64; 4]) -> DomainResult<Matrix4> {
        self.affine_to_minecraft(&Transform::Trs {
            translation: [0.0; 3],
            rotation_xyzw: xyzw,
            scale: [1.0; 3],
        })?
        .matrix()
        .map_err(transform_error)
    }

    /// Velocity in meters/second and gravity in meters/second² use this method:
    /// the basis changes, while their explicitly declared SI magnitude remains.
    pub fn si_polar_to_minecraft(&self, vector: [f64; 3]) -> DomainResult<MinecraftSiPolarVector> {
        self.basis
            .transform_point(vector)
            .map(MinecraftSiPolarVector)
            .map_err(transform_error)
    }

    /// Angular velocity is axial: reflection requires `det(B) * B`.
    pub fn si_axial_to_minecraft(&self, vector: [f64; 3]) -> DomainResult<MinecraftSiAxialVector> {
        let mut vector = self
            .basis
            .transform_point(vector)
            .map_err(transform_error)?;
        vector = vector.map(|component| self.determinant * component);
        require_finite(&vector, "axial vector")?;
        Ok(MinecraftSiAxialVector(vector))
    }

    /// A separate target boundary requests block units explicitly. It accepts
    /// only an already basis-converted SI vector and cannot apply B twice.
    pub fn si_polar_to_block_units(
        &self,
        vector: MinecraftSiPolarVector,
    ) -> DomainResult<[f64; 3]> {
        let converted = vector.0.map(|component| component / self.meters_per_block);
        require_finite(&converted, "SI to block-unit vector")?;
        Ok(converted)
    }

    /// Normals use inverse-transpose, then normalization. Zero or overflowing
    /// normals are diagnosed, rather than silently assigned a default axis.
    pub fn normal_to_minecraft(&self, normal: [f64; 3]) -> DomainResult<[f64; 3]> {
        require_finite(&normal, "normal")?;
        let inverse = self.inverse.values();
        let result: [f64; 3] = std::array::from_fn(|row| {
            (0..3)
                .map(|column| inverse[column * 4 + row] * normal[column])
                .sum()
        });
        require_finite(&result, "inverse-transpose normal")?;
        let length = result[0].hypot(result[1]).hypot(result[2]);
        if !length.is_finite() || length == 0.0 {
            return Err(DomainError::new(
                "INVALID_NORMAL",
                "normal must have a finite nonzero length after conversion",
            ));
        }
        Ok(result.map(|component| component / length))
    }

    pub fn reverses_handedness(&self) -> bool {
        self.reverses_handedness
    }

    pub fn triangle_winding(&self, triangle: [u64; 3]) -> [u64; 3] {
        if self.reverses_handedness {
            [triangle[0], triangle[2], triangle[1]]
        } else {
            triangle
        }
    }
}

/// Source origin adjustments remain explicit transforms. World-to-parent-local
/// conversion never hides an offset and rejects a singular parent.
pub fn world_to_parent_local(parent_world: &Matrix4, world: &Matrix4) -> DomainResult<Transform> {
    parent_world
        .inverse_affine()
        .and_then(|inverse| inverse.multiply(world))
        .map(Transform::from_matrix)
        .map_err(transform_error)
}

fn validate_basis(values: &[f64; 16]) -> DomainResult<()> {
    require_finite(values, "basisToMinecraftRowMajor")?;
    if values[3] != 0.0
        || values[7] != 0.0
        || values[11] != 0.0
        || values[12..] != [0.0, 0.0, 0.0, 1.0]
    {
        return Err(DomainError::new(
            "INVALID_COORDINATES",
            "basis must have zero translation and final row [0,0,0,1]",
        ));
    }
    for left in 0..3 {
        for right in left..3 {
            let dot: f64 = (0..3)
                .map(|row| values[row * 4 + left] * values[row * 4 + right])
                .sum();
            let expected = if left == right { 1.0 } else { 0.0 };
            if !dot.is_finite() || (dot - expected).abs() > BASIS_TOLERANCE {
                return Err(DomainError::new(
                    "INVALID_COORDINATES",
                    "basis must be orthogonal and must not contain distance scaling",
                ));
            }
        }
    }
    let determinant = determinant3(values);
    if !determinant.is_finite() || (determinant.abs() - 1.0).abs() > BASIS_TOLERANCE {
        return Err(DomainError::new(
            "INVALID_COORDINATES",
            "basis determinant must be +1 or -1",
        ));
    }
    Ok(())
}

fn determinant3(matrix: &[f64; 16]) -> f64 {
    matrix[0] * (matrix[5] * matrix[10] - matrix[6] * matrix[9])
        - matrix[1] * (matrix[4] * matrix[10] - matrix[6] * matrix[8])
        + matrix[2] * (matrix[4] * matrix[9] - matrix[5] * matrix[8])
}

fn require_finite(values: &[f64], field: &str) -> DomainResult<()> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(DomainError::new(
            "INVALID_COORDINATES",
            format!("{field} contains nonfinite or unrepresentable values"),
        ));
    }
    Ok(())
}

fn transform_error(error: crate::transform::TransformError) -> DomainError {
    DomainError::new(error.code(), error.to_string())
}
