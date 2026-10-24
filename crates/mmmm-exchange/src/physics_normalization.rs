//! Derive a physics revision in another declared coordinate system. The source
//! bytes and authored SI quantities remain intact; unsupported geometry and
//! joint-axis codecs are rejected before a derivative is returned.

use crate::{
    ExchangeError, ExchangeResult,
    coordinates::{CoordinateSystem, DistanceUnit},
    normalization::transform_between,
    physics::PhysicsDefinition,
};
use mmmm_contracts::{projected_digest, verify_projected_digest};
use mmmm_domain::transform::{Matrix4, Transform};
use serde_json::{Value, json};

/// Normalize one immutable source revision, applying distance conversion once.
/// Equal contracts return the original JSON value exactly. Mesh payloads need a
/// registered codec for any spatial change; a numerically identical spatial
/// contract preserves their bytes without claiming a mesh transformation.
/// Joint basis changes require an explicit solver-axis convention, absent from
/// this wire profile. Unit-only joint frame changes preserve SI limit values.
pub fn normalize_physics(input: &Value, target: &CoordinateSystem) -> ExchangeResult<Value> {
    let definition = PhysicsDefinition::from_value(input)?;
    verify_projected_digest("PhysicsDefinition", input).map_err(digest_error)?;
    let source = definition.coordinates();
    if source == target {
        return Ok(input.clone());
    }
    if source.time_domain() != target.time_domain()
        || source.meters_per_block() != target.meters_per_block()
    {
        return Err(ExchangeError::new(
            "UNIT_MISMATCH",
            "physics normalization cannot change time domain or physical block size",
        ));
    }
    let basis_changed = source.basis() != target.basis();
    let relative = if basis_changed {
        let source_basis = Matrix4::from_values(*source.basis()).map_err(transform_error)?;
        let target_basis = Matrix4::from_values(*target.basis()).map_err(transform_error)?;
        target_basis
            .inverse_affine()
            .and_then(|inverse| inverse.multiply(&source_basis))
            .map_err(transform_error)?
    } else {
        Matrix4::identity()
    };
    let determinant = determinant3(relative.values());
    if basis_changed
        && (!crate::normalization::strict_orthogonal(source.basis())
            || !crate::normalization::strict_orthogonal(target.basis())
            || !crate::normalization::strict_orthogonal(relative.values()))
    {
        return Err(unavailable(
            "primitive and principal-inertia normalization cannot discard nonorthogonal basis components",
        ));
    }
    let reflected = determinant < 0.0;
    let permutation = signed_permutation(relative.values());
    let distance_ratio = distance_scale(source) / distance_scale(target);
    if !distance_ratio.is_finite() || distance_ratio <= 0.0 {
        return Err(unavailable("distance conversion is not representable"));
    }
    let spatial_changed = basis_changed || distance_ratio != 1.0;
    if basis_changed && !definition.joints().is_empty() {
        return Err(unavailable(
            "joint basis conversion requires a declared solver joint-axis codec",
        ));
    }
    for body in definition.bodies() {
        if reflected && body.inertia_orientation_xyzw.is_some() {
            return Err(unavailable(
                "reflected principal inertia orientation requires an explicit principal-axis codec",
            ));
        }
    }
    for collider in crate::array(input, "colliders")? {
        match collider["shape"]["shape"]["kind"].as_str() {
            Some("mesh") if spatial_changed => {
                return Err(unavailable(
                    "mesh coordinate conversion requires a registered mesh codec",
                ));
            }
            Some("box" | "capsule") if permutation.is_none() => {
                return Err(unavailable(
                    "primitive axis conversion requires an exact signed-axis permutation",
                ));
            }
            _ => {}
        }
    }

    let mut output = input.clone();
    output["gravityMetersPerSecondSquared"] = json!(polar(
        &relative,
        vector3(&input["gravityMetersPerSecondSquared"])?
    )?);
    for body in output["bodies"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "missing bodies"))?
    {
        body["transform"] = transform_between(&body["transform"], source, target)?;
        let center = source
            .conversion()?
            .point_to_minecraft(vector3(&body["centerOfMassLocal"])?)?;
        body["centerOfMassLocal"] = json!(target.conversion()?.point_from_minecraft(center)?);
        body["initialLinearVelocityMetersPerSecond"] = json!(polar(
            &relative,
            vector3(&body["initialLinearVelocityMetersPerSecond"])?
        )?);
        let angular = polar(
            &relative,
            vector3(&body["initialAngularVelocityRadiansPerSecond"])?,
        )?
        .map(|component| determinant * component);
        finite(&angular, "angular velocity")?;
        body["initialAngularVelocityRadiansPerSecond"] = json!(angular);
        if basis_changed && let Some(orientation) = body.get("inertiaOrientationXyzw") {
            // The moments retain their principal-axis ordering and kg·m²
            // magnitude. Their eigenvectors therefore change by R*Q, not
            // R*Q*R^-1, which would require transforming the diagonal too.
            body["inertiaOrientationXyzw"] =
                json!(principal_orientation(&relative, quaternion(orientation)?)?);
        }
        for binding in body["visualBindings"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "missing visual bindings"))?
        {
            binding["bodyToNode"] = transform_between(&binding["bodyToNode"], source, target)?;
        }
    }
    for collider in output["colliders"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "missing colliders"))?
    {
        collider["transform"] = transform_between(&collider["transform"], source, target)?;
        let shape = &mut collider["shape"]["shape"];
        match shape["kind"].as_str() {
            Some("box") => {
                let old = vector3(&shape["halfExtents"])?;
                let axes = permutation
                    .ok_or_else(|| unavailable("box basis is not an axis permutation"))?;
                let extents = axes.map(|source_axis| old[source_axis] * distance_ratio);
                positive(&extents, "box half extents")?;
                shape["halfExtents"] = json!(extents);
            }
            Some("sphere") => {
                shape["radius"] = json!(scaled_positive(
                    &shape["radius"],
                    distance_ratio,
                    "sphere radius"
                )?);
            }
            Some("capsule") => {
                shape["radius"] = json!(scaled_positive(
                    &shape["radius"],
                    distance_ratio,
                    "capsule radius"
                )?);
                let height = number(&shape["halfHeight"])? * distance_ratio;
                finite(&[height], "capsule half height")?;
                if height < 0.0 || (height == 0.0 && number(&shape["halfHeight"])? != 0.0) {
                    return Err(unavailable("capsule half height is not representable"));
                }
                shape["halfHeight"] = json!(height);
                let source_axis = match shape["axis"].as_str() {
                    Some("x") => 0,
                    Some("y") => 1,
                    Some("z") => 2,
                    _ => return Err(ExchangeError::new("SCHEMA_INVALID", "invalid capsule axis")),
                };
                let axes = permutation
                    .ok_or_else(|| unavailable("capsule basis is not an axis permutation"))?;
                let target_axis = axes
                    .iter()
                    .position(|axis| *axis == source_axis)
                    .ok_or_else(|| unavailable("capsule target axis is absent"))?;
                shape["axis"] = json!(["x", "y", "z"][target_axis]);
            }
            Some("mesh") if !spatial_changed => {}
            _ => return Err(unavailable("unsupported collider shape codec")),
        }
    }
    for joint in output["joints"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "missing joints"))?
    {
        joint["frameA"] = transform_between(&joint["frameA"], source, target)?;
        joint["frameB"] = transform_between(&joint["frameB"], source, target)?;
        // limits.unit is explicitly SI meters or radians, independent of the
        // scene distance unit. Do not rescale or negate authored limit values.
    }
    output["coordinates"] = target.to_value()?;
    output["revision"] =
        json!(projected_digest("PhysicsDefinition", &output).map_err(digest_error)?);
    PhysicsDefinition::from_value(&output)?;
    Ok(output)
}

fn distance_scale(coordinates: &CoordinateSystem) -> f64 {
    match coordinates.distance_unit() {
        DistanceUnit::Blocks => coordinates.meters_per_block(),
        DistanceUnit::Meters => 1.0,
    }
}

/// Row -> source-axis mapping. Exact comparisons deliberately avoid replacing
/// a small authored rotation/shear by a nearest axis permutation.
fn signed_permutation(matrix: &[f64; 16]) -> Option<[usize; 3]> {
    let mut result = [0; 3];
    let mut used = [false; 3];
    for row in 0..3 {
        let mut axis = None;
        for column in 0..3 {
            let value = matrix[row * 4 + column];
            if value == 1.0 || value == -1.0 {
                if axis.is_some() || used[column] {
                    return None;
                }
                axis = Some(column);
            } else if value != 0.0 {
                return None;
            }
        }
        let axis = axis?;
        used[axis] = true;
        result[row] = axis;
    }
    Some(result)
}

fn principal_orientation(relative: &Matrix4, orientation: [f64; 4]) -> ExchangeResult<[f64; 4]> {
    let authored = Transform::Trs {
        translation: [0.0; 3],
        rotation_xyzw: orientation,
        scale: [1.0; 3],
    }
    .matrix()
    .map_err(transform_error)?;
    let matrix = relative.multiply(&authored).map_err(transform_error)?;
    let m = matrix.values();
    let trace = m[0] + m[5] + m[10];
    let quaternion = if trace > 0.0 {
        let s = 2.0 * (trace + 1.0).sqrt();
        [
            (m[9] - m[6]) / s,
            (m[2] - m[8]) / s,
            (m[4] - m[1]) / s,
            s / 4.0,
        ]
    } else if m[0] > m[5] && m[0] > m[10] {
        let s = 2.0 * (1.0 + m[0] - m[5] - m[10]).sqrt();
        [
            s / 4.0,
            (m[1] + m[4]) / s,
            (m[2] + m[8]) / s,
            (m[9] - m[6]) / s,
        ]
    } else if m[5] > m[10] {
        let s = 2.0 * (1.0 + m[5] - m[0] - m[10]).sqrt();
        [
            (m[1] + m[4]) / s,
            s / 4.0,
            (m[6] + m[9]) / s,
            (m[2] - m[8]) / s,
        ]
    } else {
        let s = 2.0 * (1.0 + m[10] - m[0] - m[5]).sqrt();
        [
            (m[2] + m[8]) / s,
            (m[6] + m[9]) / s,
            s / 4.0,
            (m[4] - m[1]) / s,
        ]
    };
    Transform::Trs {
        translation: [0.0; 3],
        rotation_xyzw: quaternion,
        scale: [1.0; 3],
    }
    .validate()
    .map_err(|_| unavailable("principal orientation is not representable as a unit quaternion"))?;
    Ok(quaternion)
}

fn polar(relative: &Matrix4, vector: [f64; 3]) -> ExchangeResult<[f64; 3]> {
    relative.transform_point(vector).map_err(transform_error)
}

fn determinant3(m: &[f64; 16]) -> f64 {
    m[0] * (m[5] * m[10] - m[6] * m[9]) - m[1] * (m[4] * m[10] - m[6] * m[8])
        + m[2] * (m[4] * m[9] - m[5] * m[8])
}

fn vector3(value: &Value) -> ExchangeResult<[f64; 3]> {
    let values = value
        .as_array()
        .filter(|values| values.len() == 3)
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "expected three-component vector"))?;
    Ok([
        number(&values[0])?,
        number(&values[1])?,
        number(&values[2])?,
    ])
}

fn quaternion(value: &Value) -> ExchangeResult<[f64; 4]> {
    let values = value
        .as_array()
        .filter(|values| values.len() == 4)
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "expected xyzw quaternion"))?;
    Ok([
        number(&values[0])?,
        number(&values[1])?,
        number(&values[2])?,
        number(&values[3])?,
    ])
}

fn number(value: &Value) -> ExchangeResult<f64> {
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "expected finite number"))
}

fn scaled_positive(value: &Value, ratio: f64, label: &str) -> ExchangeResult<f64> {
    let result = number(value)? * ratio;
    positive(&[result], label)?;
    Ok(result)
}

fn finite(values: &[f64], label: &str) -> ExchangeResult<()> {
    if values.iter().any(|value| !value.is_finite()) {
        return Err(unavailable(format!(
            "{label} conversion exceeds finite range"
        )));
    }
    Ok(())
}

fn positive(values: &[f64], label: &str) -> ExchangeResult<()> {
    finite(values, label)?;
    if values.iter().any(|value| *value <= 0.0) {
        return Err(unavailable(format!(
            "{label} conversion is not finite and positive"
        )));
    }
    Ok(())
}

fn unavailable(message: impl Into<String>) -> ExchangeError {
    ExchangeError::new("CAPABILITY_UNAVAILABLE", message)
}
fn transform_error(error: mmmm_domain::transform::TransformError) -> ExchangeError {
    ExchangeError::new(error.code(), error.to_string())
}
fn digest_error(error: mmmm_contracts::DigestError) -> ExchangeError {
    ExchangeError::new("INPUT_DIGEST_MISMATCH", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn physics() -> Value {
        mmmm_contracts::parse_json(include_bytes!("../../../examples/physics-definition.json"))
            .unwrap()
    }
    fn coordinates(basis: [f64; 16], distance: &str, meters_per_block: f64) -> CoordinateSystem {
        CoordinateSystem::from_value(&json!({"basisToMinecraftRowMajor":basis,
            "metersPerBlock":meters_per_block,"distanceUnit":distance,"massUnit":"kilograms",
            "angleUnit":"radians","quaternionOrder":"xyzw","matrixLayout":"row_major_column_vectors",
            "timeDomain":"game_seconds"})).unwrap()
    }
    fn stamp(input: &mut Value) {
        input["revision"] = json!(projected_digest("PhysicsDefinition", input).unwrap());
    }
    fn close(actual: [f64; 3], expected: [f64; 3]) {
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert!(
                (actual - expected).abs() < 1e-9 * expected.abs().max(1.0),
                "{actual} != {expected}"
            );
        }
    }

    #[test]
    fn equal_coordinate_contract_preserves_original_value_and_revision_exactly() {
        let input = physics();
        let target = CoordinateSystem::from_value(&input["coordinates"]).unwrap();
        assert_eq!(normalize_physics(&input, &target).unwrap(), input);
    }

    #[test]
    fn proper_z_up_meter_conversion_scales_geometry_and_preserves_explicit_si_inertia() {
        let mut input = physics();
        input["coordinates"]["metersPerBlock"] = json!(0.5);
        input["bodies"][0]["transform"]["translation"] = json!([1, 2, 3]);
        input["bodies"][0]["centerOfMassLocal"] = json!([1, 2, 3]);
        input["bodies"][0]["initialLinearVelocityMetersPerSecond"] = json!([1, 2, 3]);
        input["bodies"][0]["initialAngularVelocityRadiansPerSecond"] = json!([4, 5, 6]);
        input["bodies"][0]["inertiaPolicy"] = json!("explicit");
        input["bodies"][0]["inertiaDiagonal"] = json!([2, 3, 4]);
        input["bodies"][0]["inertiaOrientationXyzw"] = json!([0, 0, 0, 1]);
        stamp(&mut input);
        // This external Z-up basis maps external (x,y,z) to MC (x,z,-y).
        let target = coordinates(
            [
                1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            ],
            "meters",
            0.5,
        );
        let result = normalize_physics(&input, &target).unwrap();
        close(
            vector3(&result["bodies"][0]["centerOfMassLocal"]).unwrap(),
            [0.5, -1.5, 1.0],
        );
        close(
            vector3(&result["bodies"][0]["initialLinearVelocityMetersPerSecond"]).unwrap(),
            [1.0, -3.0, 2.0],
        );
        close(
            vector3(&result["bodies"][0]["initialAngularVelocityRadiansPerSecond"]).unwrap(),
            [4.0, -6.0, 5.0],
        );
        close(
            vector3(&result["gravityMetersPerSecondSquared"]).unwrap(),
            [0.0, 0.0, -9.81],
        );
        close(
            vector3(&result["colliders"][0]["shape"]["shape"]["halfExtents"]).unwrap(),
            [0.25, 0.025, 0.5],
        );
        assert_eq!(
            result["bodies"][0]["inertiaDiagonal"],
            input["bodies"][0]["inertiaDiagonal"]
        );
        assert_eq!(result["bodies"][0]["massKg"], input["bodies"][0]["massKg"]);
        assert_eq!(result["materials"], input["materials"]);
        let orientation = Transform::Trs {
            translation: [0.0; 3],
            rotation_xyzw: quaternion(&result["bodies"][0]["inertiaOrientationXyzw"]).unwrap(),
            scale: [1.0; 3],
        }
        .matrix()
        .unwrap();
        close(
            orientation.transform_point([0.0, 1.0, 0.0]).unwrap(),
            [0.0, 0.0, 1.0],
        );
        verify_projected_digest("PhysicsDefinition", &result).unwrap();
        assert_ne!(result["revision"], input["revision"]);
        let source = CoordinateSystem::from_value(&input["coordinates"]).unwrap();
        let restored = normalize_physics(&result, &source).unwrap();
        close(
            vector3(&restored["bodies"][0]["centerOfMassLocal"]).unwrap(),
            [1.0, 2.0, 3.0],
        );
        close(
            vector3(&restored["colliders"][0]["shape"]["shape"]["halfExtents"]).unwrap(),
            [0.5, 1.0, 0.05],
        );
    }

    #[test]
    fn reflected_capsule_changes_axis_and_axial_sign_without_touching_material_claims() {
        let mut input = physics();
        input["colliders"][0]["shape"]["shape"] =
            json!({"kind":"capsule","radius":0.2,"halfHeight":1,"axis":"x"});
        input["bodies"][0]["initialLinearVelocityMetersPerSecond"] = json!([1, 2, 3]);
        input["bodies"][0]["initialAngularVelocityRadiansPerSecond"] = json!([1, 2, 3]);
        stamp(&mut input);
        let target = coordinates(
            [
                0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            ],
            "blocks",
            1.0,
        );
        let result = normalize_physics(&input, &target).unwrap();
        assert_eq!(result["colliders"][0]["shape"]["shape"]["axis"], "y");
        close(
            vector3(&result["bodies"][0]["initialLinearVelocityMetersPerSecond"]).unwrap(),
            [2.0, 1.0, 3.0],
        );
        close(
            vector3(&result["bodies"][0]["initialAngularVelocityRadiansPerSecond"]).unwrap(),
            [-2.0, -1.0, -3.0],
        );
        assert_eq!(
            result["colliders"][0]["shape"]["provenance"],
            "user_declared"
        );
    }

    #[test]
    fn unit_only_joint_frames_scale_translation_and_keep_si_limits() {
        let mut input = physics();
        input["coordinates"]["metersPerBlock"] = json!(0.5);
        let mut anchor = input["bodies"][0].clone();
        anchor["bodyId"] = json!("anchor");
        anchor["mode"] = json!("static");
        anchor["colliderIds"] = json!([]);
        anchor["visualBindings"] = json!([]);
        input["bodies"].as_array_mut().unwrap().push(anchor);
        input["joints"] = json!([{"jointId":"slider","kind":"slider","bodyA":"body-door","bodyB":"anchor",
            "frameA":{"kind":"trs","translation":[2,0,0],"rotationXyzw":[0,0,0,1],"scale":[1,1,1]},
            "frameB":Transform::identity(),"limits":{"lower":0,"upper":2,"unit":"meters"}}]);
        stamp(&mut input);
        let target = coordinates(*Matrix4::identity().values(), "meters", 0.5);
        let result = normalize_physics(&input, &target).unwrap();
        assert_eq!(result["joints"][0]["limits"], input["joints"][0]["limits"]);
        close(
            Transform::from_value(&result["joints"][0]["frameA"])
                .unwrap()
                .matrix()
                .unwrap()
                .transform_point([0.0; 3])
                .unwrap(),
            [1.0, 0.0, 0.0],
        );
        let reflected = coordinates(
            [
                -1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            ],
            "blocks",
            0.5,
        );
        assert_eq!(
            normalize_physics(&input, &reflected).unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
    }

    #[test]
    fn unsupported_mesh_arbitrary_box_and_stale_source_revision_fail_closed() {
        let mut input = physics();
        input["gravityMetersPerSecondSquared"] = json!([0, -1, 0]);
        let target = coordinates(*Matrix4::identity().values(), "meters", 1.0);
        assert_eq!(
            normalize_physics(&input, &target).unwrap_err().code,
            "INPUT_DIGEST_MISMATCH"
        );
        input = physics();
        input["coordinates"]["metersPerBlock"] = json!(0.5);
        input["colliders"][0]["shape"]["shape"] = json!({"kind":"mesh","geometry":{
            "resourceId":"mesh","sha256":"0".repeat(64),"sizeBytes":1,"mediaType":"application/octet-stream"},
            "topologyDigest":"0".repeat(64)});
        stamp(&mut input);
        let target = coordinates(*Matrix4::identity().values(), "meters", 0.5);
        assert_eq!(
            normalize_physics(&input, &target).unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
        input = physics();
        let half = 0.5_f64.sqrt();
        let rotated = coordinates(
            [
                half, -half, 0.0, 0.0, half, half, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            ],
            "blocks",
            1.0,
        );
        assert_eq!(
            normalize_physics(&input, &rotated).unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
        input["colliders"][0]["shape"]["shape"] = json!({"kind":"sphere","radius":1e12});
        input["bodies"][0]["inertiaPolicy"] = json!("explicit");
        input["bodies"][0]["inertiaDiagonal"] = json!([2, 3, 4]);
        input["bodies"][0]["inertiaOrientationXyzw"] = json!([0, 0, 0, 1]);
        stamp(&mut input);
        let mut near_basis = *Matrix4::identity().values();
        near_basis[0] = 1.0 + 2e-10;
        let near = coordinates(near_basis, "blocks", 1.0);
        assert_eq!(
            normalize_physics(&input, &near).unwrap_err().code,
            "CAPABILITY_UNAVAILABLE"
        );
    }
}
