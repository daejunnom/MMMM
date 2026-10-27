//! Exchange-facing coordinate API backed by the shared domain contract.
use crate::{ExchangeError, ExchangeResult, validate};
use mmmm_domain::transform::{Matrix4, Transform};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub use mmmm_domain::coordinates::{
    BASIS_TOLERANCE, DistanceUnit, MinecraftPoint, MinecraftSiAxialVector, MinecraftSiPolarVector,
    TimeDomain,
};

fn from_domain_error(error: mmmm_domain::types::DomainError) -> ExchangeError {
    ExchangeError::new(error.code, error.message)
}

/// A semantically validated, immutable coordinate contract.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CoordinateSystem(mmmm_domain::coordinates::CoordinateSystem);

impl std::fmt::Debug for CoordinateSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}
impl<'de> Deserialize<'de> for CoordinateSystem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        mmmm_domain::coordinates::CoordinateSystem::deserialize(deserializer).map(Self)
    }
}
impl CoordinateSystem {
    pub(crate) fn from_domain(value: &mmmm_domain::coordinates::CoordinateSystem) -> Self {
        Self(value.clone())
    }
    pub fn from_value(value: &Value) -> ExchangeResult<Self> {
        validate("CoordinateSystem", value)?;
        serde_json::from_value(value.clone())
            .map_err(|error| ExchangeError::new("INVALID_COORDINATES", error.to_string()))
    }
    pub fn to_value(&self) -> ExchangeResult<Value> {
        let value = serde_json::to_value(self)
            .map_err(|error| ExchangeError::new("SCHEMA_INVALID", error.to_string()))?;
        validate("CoordinateSystem", &value)?;
        Ok(value)
    }
    pub fn meters_per_block(&self) -> f64 {
        self.0.meters_per_block()
    }
    pub fn distance_unit(&self) -> DistanceUnit {
        self.0.distance_unit()
    }
    pub fn time_domain(&self) -> TimeDomain {
        self.0.time_domain()
    }
    pub fn basis(&self) -> &[f64; 16] {
        self.0.basis()
    }
    pub fn conversion(&self) -> ExchangeResult<CoordinateConversion> {
        self.0
            .conversion()
            .map(CoordinateConversion)
            .map_err(from_domain_error)
    }
}

#[derive(Clone)]
pub struct CoordinateConversion(mmmm_domain::coordinates::CoordinateConversion);
impl std::fmt::Debug for CoordinateConversion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}
impl CoordinateConversion {
    pub fn point_to_minecraft(&self, point: [f64; 3]) -> ExchangeResult<MinecraftPoint> {
        self.0.point_to_minecraft(point).map_err(from_domain_error)
    }
    pub fn point_from_minecraft(&self, point: MinecraftPoint) -> ExchangeResult<[f64; 3]> {
        self.0
            .point_from_minecraft(point)
            .map_err(from_domain_error)
    }
    pub fn affine_to_minecraft(&self, transform: &Transform) -> ExchangeResult<Transform> {
        self.0
            .affine_to_minecraft(transform)
            .map_err(from_domain_error)
    }
    pub fn affine_from_minecraft(&self, transform: &Transform) -> ExchangeResult<Transform> {
        self.0
            .affine_from_minecraft(transform)
            .map_err(from_domain_error)
    }
    pub fn rotation_to_minecraft(&self, xyzw: [f64; 4]) -> ExchangeResult<Matrix4> {
        self.0
            .rotation_to_minecraft(xyzw)
            .map_err(from_domain_error)
    }
    pub fn si_polar_to_minecraft(
        &self,
        vector: [f64; 3],
    ) -> ExchangeResult<MinecraftSiPolarVector> {
        self.0
            .si_polar_to_minecraft(vector)
            .map_err(from_domain_error)
    }
    pub fn si_axial_to_minecraft(
        &self,
        vector: [f64; 3],
    ) -> ExchangeResult<MinecraftSiAxialVector> {
        self.0
            .si_axial_to_minecraft(vector)
            .map_err(from_domain_error)
    }
    pub fn si_polar_to_block_units(
        &self,
        vector: MinecraftSiPolarVector,
    ) -> ExchangeResult<[f64; 3]> {
        self.0
            .si_polar_to_block_units(vector)
            .map_err(from_domain_error)
    }
    pub fn normal_to_minecraft(&self, normal: [f64; 3]) -> ExchangeResult<[f64; 3]> {
        self.0
            .normal_to_minecraft(normal)
            .map_err(from_domain_error)
    }
    pub fn reverses_handedness(&self) -> bool {
        self.0.reverses_handedness()
    }
    pub fn triangle_winding(&self, triangle: [u64; 3]) -> [u64; 3] {
        self.0.triangle_winding(triangle)
    }
}

pub fn world_to_parent_local(parent_world: &Matrix4, world: &Matrix4) -> ExchangeResult<Transform> {
    mmmm_domain::coordinates::world_to_parent_local(parent_world, world).map_err(from_domain_error)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn system(basis: [f64; 16], distance: &str, meters_per_block: f64) -> CoordinateSystem {
        CoordinateSystem::from_value(&json!({
            "basisToMinecraftRowMajor": basis, "metersPerBlock": meters_per_block,
            "distanceUnit": distance, "massUnit": "kilograms", "angleUnit": "radians",
            "quaternionOrder": "xyzw", "matrixLayout": "row_major_column_vectors",
            "timeDomain": "game_seconds"
        }))
        .unwrap()
    }

    fn close(actual: &[f64], expected: &[f64]) {
        for (actual, expected) in actual.iter().zip(expected) {
            assert!((actual - expected).abs() < 1e-9 * expected.abs().max(1.0));
        }
    }

    #[test]
    fn z_up_meter_position_and_sheared_pose_round_trip_with_independent_expected_values() {
        // Z-up external (x,y,z) becomes Minecraft (x,z,-y).
        let basis = [
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ];
        let conversion = system(basis, "meters", 0.5).conversion().unwrap();
        let point = conversion.point_to_minecraft([1.0, 2.0, 3.0]).unwrap();
        assert_eq!(point.values(), [2.0, 6.0, -4.0]);
        assert_eq!(
            conversion.point_from_minecraft(point).unwrap(),
            [1.0, 2.0, 3.0]
        );
        let transform = Transform::from_matrix(
            Matrix4::from_values([
                1.0, 0.25, 0.0, 1.0, 0.0, 2.0, 0.0, 2.0, 0.0, 0.0, 3.0, 3.0, 0.0, 0.0, 0.0, 1.0,
            ])
            .unwrap(),
        );
        let converted = conversion.affine_to_minecraft(&transform).unwrap();
        close(
            converted.matrix().unwrap().values(),
            &[
                1.0, 0.0, -0.25, 2.0, 0.0, 3.0, 0.0, 6.0, 0.0, 0.0, 2.0, -4.0, 0.0, 0.0, 0.0, 1.0,
            ],
        );
        close(
            conversion
                .affine_from_minecraft(&converted)
                .unwrap()
                .matrix()
                .unwrap()
                .values(),
            transform.matrix().unwrap().values(),
        );
    }

    #[test]
    fn explicit_si_fields_keep_magnitude_and_block_conversion_is_separate() {
        let conversion = system(*Matrix4::identity().values(), "meters", 0.25)
            .conversion()
            .unwrap();
        let gravity = conversion.si_polar_to_minecraft([0.0, -9.81, 0.0]).unwrap();
        assert_eq!(gravity.values(), [0.0, -9.81, 0.0]);
        assert_eq!(
            conversion.si_polar_to_block_units(gravity).unwrap(),
            [0.0, -39.24, 0.0]
        );
        let block_conversion = system(*Matrix4::identity().values(), "blocks", 0.25)
            .conversion()
            .unwrap();
        assert_eq!(
            block_conversion
                .point_to_minecraft([1.0, 2.0, 3.0])
                .unwrap()
                .values(),
            [1.0, 2.0, 3.0]
        );
    }

    #[test]
    fn reflection_distinguishes_axial_vector_normal_winding_and_rotation() {
        let mut basis = *Matrix4::identity().values();
        basis[0] = -1.0;
        let conversion = system(basis, "meters", 2.0).conversion().unwrap();
        assert_eq!(
            conversion
                .si_polar_to_minecraft([1.0, 2.0, 3.0])
                .unwrap()
                .values(),
            [-1.0, 2.0, 3.0]
        );
        assert_eq!(
            conversion
                .si_axial_to_minecraft([1.0, 2.0, 3.0])
                .unwrap()
                .values(),
            [1.0, -2.0, -3.0]
        );
        assert_eq!(
            conversion.normal_to_minecraft([1.0, 0.0, 0.0]).unwrap(),
            [-1.0, 0.0, 0.0]
        );
        assert_eq!(conversion.triangle_winding([4, 5, 6]), [4, 6, 5]);
        let half = 0.5_f64.sqrt();
        let rotation = conversion
            .rotation_to_minecraft([0.0, half, 0.0, half])
            .unwrap();
        close(
            &rotation.transform_point([1.0, 0.0, 0.0]).unwrap(),
            &[0.0, 0.0, 1.0],
        );
        assert!(conversion.normal_to_minecraft([0.0; 3]).is_err());
    }

    #[test]
    fn coordinate_wire_rejects_scaled_basis_translation_and_layout_alias() {
        let coordinates = system(*Matrix4::identity().values(), "blocks", 1.0);
        let value = coordinates.to_value().unwrap();
        for (index, number) in [(0, 2.0), (3, 1.0), (12, 1.0)] {
            let mut changed = value.clone();
            changed["basisToMinecraftRowMajor"][index] = json!(number);
            assert!(CoordinateSystem::from_value(&changed).is_err());
        }
        let mut changed = value;
        changed["matrixLayout"] = json!("row_major_column_vector");
        assert!(CoordinateSystem::from_value(&changed).is_err());
    }

    #[test]
    fn world_pose_to_parent_local_preserves_offset_and_rejects_singular_parent() {
        let parent = Transform::Trs {
            translation: [10.0, 20.0, 30.0],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [1.0; 3],
        }
        .matrix()
        .unwrap();
        let world = Transform::Trs {
            translation: [13.0, 25.0, 37.0],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [1.0; 3],
        }
        .matrix()
        .unwrap();
        assert_eq!(
            world_to_parent_local(&parent, &world)
                .unwrap()
                .matrix()
                .unwrap()
                .transform_point([0.0; 3])
                .unwrap(),
            [3.0, 5.0, 7.0]
        );
        let singular = Transform::Trs {
            translation: [0.0; 3],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [0.0, 1.0, 1.0],
        }
        .matrix()
        .unwrap();
        assert!(world_to_parent_local(&singular, &world).is_err());
    }
}
