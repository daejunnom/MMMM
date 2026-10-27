//! One spatial boundary for authored Minecraft selection, external working
//! variants, and imported animation. Source values and bytes remain immutable.
//! Geometry ResourceRefs keep their original canonical intrinsic coordinate
//! contract; decoding geometry needs a declared codec, never a unit relabel.
use crate::coordinates::CoordinateSystem;
use crate::{ExchangeError, ExchangeResult, array, text, validate};
use mmmm_contracts::{projected_digest, raw_digest};
use mmmm_domain::transform::{Matrix4, Transform};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const PROFILE: &str = "mmmm:canonical_selection_external_affine_v1";
pub const SOURCE_SELECTION_PATH: &str = "source/canonical-selection.json";
pub const WORKING_SELECTION_PATH: &str = "objects/selection.json";
pub const NORMALIZATION_MAP_PATH: &str = "source/normalization-map.json";
pub const PHYSICS_PROFILE: &str = "mmmm:declared_physics_coordinate_variant_v1";
pub const SOURCE_PHYSICS_PATH: &str = "source/declared-physics.json";

pub fn minecraft_coordinates(external: &CoordinateSystem) -> ExchangeResult<CoordinateSystem> {
    CoordinateSystem::from_value(
        &json!({"basisToMinecraftRowMajor":Matrix4::identity().values(),
        "metersPerBlock":external.meters_per_block(),"distanceUnit":"blocks","massUnit":"kilograms",
        "angleUnit":"radians","quaternionOrder":"xyzw","matrixLayout":"row_major_column_vectors",
        "timeDomain":external.time_domain()}),
    )
}

/// Exact affine change of basis. TRS stays TRS when the new scale tensor is
/// diagonal; otherwise the full matrix is retained, including every shear term.
pub fn transform_between(
    value: &Value,
    source: &CoordinateSystem,
    target: &CoordinateSystem,
) -> ExchangeResult<Value> {
    validate("Transform", value)?;
    let authored = Transform::from_value(value).map_err(transform_error)?;
    if source == target {
        return Ok(value.clone());
    }
    if source.time_domain() != target.time_domain()
        || source.meters_per_block() != target.meters_per_block()
    {
        return Err(ExchangeError::new(
            "UNIT_MISMATCH",
            "Spatial normalization cannot change time domain or physical block size",
        ));
    }
    let converted = target
        .conversion()?
        .affine_from_minecraft(&source.conversion()?.affine_to_minecraft(&authored)?)?;
    if let Transform::Trs {
        translation,
        rotation_xyzw,
        scale,
    } = authored
        && strict_orthogonal(source.basis())
        && strict_orthogonal(target.basis())
    {
        // R = target basis inverse * source basis; uniform distance factors
        // cancel from rotation/scale conjugation, and affect translation once.
        let bs = Matrix4::from_values(*source.basis()).map_err(transform_error)?;
        let bt = Matrix4::from_values(*target.basis()).map_err(transform_error)?;
        let r = bt
            .inverse_affine()
            .and_then(|inverse| inverse.multiply(&bs))
            .map_err(transform_error)?;
        let rv = r.values();
        let tensor: [[f64; 3]; 3] = if scale[0] == scale[1] && scale[1] == scale[2] {
            std::array::from_fn(|row| {
                std::array::from_fn(|column| if row == column { scale[row] } else { 0.0 })
            })
        } else {
            std::array::from_fn(|row| {
                std::array::from_fn(|column| {
                    (0..3)
                        .map(|axis| rv[row * 4 + axis] * scale[axis] * rv[column * 4 + axis])
                        .sum()
                })
            })
        };
        // Do not silently clamp a small authored off-diagonal scale/shear.
        if (0..3).all(|row| (0..3).all(|column| row == column || tensor[row][column] == 0.0)) {
            let determinant = rv[0] * (rv[5] * rv[10] - rv[6] * rv[9])
                - rv[1] * (rv[4] * rv[10] - rv[6] * rv[8])
                + rv[2] * (rv[4] * rv[9] - rv[5] * rv[8]);
            let xyz = r
                .transform_point([rotation_xyzw[0], rotation_xyzw[1], rotation_xyzw[2]])
                .map_err(transform_error)?
                .map(|component| component * determinant);
            let source_point = source.conversion()?.point_to_minecraft(translation)?;
            let translation = target.conversion()?.point_from_minecraft(source_point)?;
            let candidate = Transform::Trs {
                translation,
                rotation_xyzw: [xyz[0], xyz[1], xyz[2], rotation_xyzw[3]],
                scale: [tensor[0][0], tensor[1][1], tensor[2][2]],
            };
            let candidate_matrix = candidate.matrix().map_err(transform_error)?;
            let exact_matrix = converted.matrix().map_err(transform_error)?;
            if candidate_matrix
                .values()
                .iter()
                .zip(exact_matrix.values())
                .all(|(candidate, exact)| {
                    (candidate - exact).abs()
                        <= 16.0 * f64::EPSILON * candidate.abs().max(exact.abs()).max(1.0)
                })
            {
                return candidate.to_value().map_err(transform_error);
            }
        }
    }
    converted.to_value().map_err(transform_error)
}
pub(crate) fn strict_orthogonal(values: &[f64; 16]) -> bool {
    (0..3).all(|left| {
        (0..3).all(|right| {
            let dot: f64 = (0..3)
                .map(|row| values[row * 4 + left] * values[row * 4 + right])
                .sum();
            (dot - if left == right { 1.0 } else { 0.0 }).abs() <= 8.0 * f64::EPSILON
        })
    })
}

/// Working snapshots retain canonical resource references and intrinsic
/// geometry metadata. Only the declared affine codec fields change; an external
/// renderer must decode canonical geometry before crossing its geometry boundary.
pub fn external_selection(
    source: &Value,
    coordinates: &CoordinateSystem,
    map_resource: &Value,
) -> ExchangeResult<Value> {
    validate("SceneSelectionSnapshot", source)?;
    let canonical = minecraft_coordinates(coordinates)?;
    let mut result = source.clone();
    let mut revisions = BTreeMap::new();
    for prefab in result["prefabs"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing prefabs"))?
    {
        for node in prefab["nodes"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing nodes"))?
        {
            node["transform"] = transform_between(&node["transform"], &canonical, coordinates)?;
            // Authored node collider parameters are canonical intrinsic geometry.
            // Preserve them and their affine local frame as source data for a
            // codec; do not pretend integer cells or capsule axes were converted.
            for collider in node["colliders"]
                .as_array_mut()
                .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing colliders"))?
            {
                collider["transform"] =
                    transform_between(&collider["transform"], &canonical, coordinates)?;
            }
        }
        for port in prefab["ports"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing ports"))?
        {
            port["transform"] = transform_between(&port["transform"], &canonical, coordinates)?;
        }
        prefab["revision"] = json!(projected_digest("Prefab", prefab).map_err(digest_error)?);
        revisions.insert(
            text(prefab, "prefabId")?.to_owned(),
            prefab["revision"].clone(),
        );
    }
    for instance in result["instances"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing instances"))?
    {
        instance["placement"] = transform_between(&instance["placement"], &canonical, coordinates)?;
        for item in instance["overrides"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing overrides"))?
        {
            if item.get("transform").is_some() {
                item["transform"] = transform_between(&item["transform"], &canonical, coordinates)?;
            }
        }
        instance["prefabRevision"] = revisions
            .get(text(instance, "prefabId")?)
            .ok_or_else(|| ExchangeError::new("REFERENCE_UNRESOLVED", "Working prefab is absent"))?
            .clone();
        instance["revision"] = json!(projected_digest("Instance", instance).map_err(digest_error)?);
    }
    result["sourceMap"] = map_resource.clone();
    crate::selection::Selection::from_value(&result)?;
    Ok(result)
}

/// The map's output ID is derived before encoding the working selection, so its
/// SourceMap reference and its own resource identity never form a hash cycle.
pub fn working_resource_id(
    source: &Value,
    coordinates: &CoordinateSystem,
) -> ExchangeResult<String> {
    let bytes = crate::json_bytes(
        &json!({"source":source,"coordinates":coordinates.to_value()?,"profile":PROFILE}),
    )?;
    Ok(format!(
        "normalized-selection-{}",
        &raw_digest(&bytes).as_str()[..24]
    ))
}
pub fn selection_source_map(source: &Value, output_id: &str) -> ExchangeResult<Value> {
    let mut entries = Vec::new();
    for instance in array(source, "instances")? {
        let prefab = array(source, "prefabs")?
            .iter()
            .enumerate()
            .find(|(_, prefab)| prefab["prefabId"] == instance["prefabId"])
            .ok_or_else(|| ExchangeError::new("REFERENCE_UNRESOLVED", "Mapped prefab is absent"))?;
        for (index, node) in array(prefab.1, "nodes")?.iter().enumerate() {
            entries.push(json!({"sourceObjectId":instance["instanceId"],"sourceNodeId":node["nodeId"],"outputResourceId":output_id,"locator":format!("/prefabs/{}/nodes/{index}",prefab.0)}));
        }
    }
    let map = json!({"contractVersion":"0.2.0","generatorVersion":"mmmm-exchange-affine-0.1.0","inputRevision":source["projectRevision"],"entries":entries});
    validate("SourceMap", &map)?;
    Ok(map)
}

pub fn canonical_clip(clip: &Value, external: &CoordinateSystem) -> ExchangeResult<Value> {
    validate("AnimationClip", clip)?;
    if clip["timeDomain"] != external.to_value()?["timeDomain"] {
        return Err(ExchangeError::new(
            "UNIT_MISMATCH",
            "Clip time domain differs from its spatial coordinate contract",
        ));
    }
    let canonical = minecraft_coordinates(external)?;
    let mut result = clip.clone();
    for track in result["tracks"]
        .as_array_mut()
        .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing tracks"))?
    {
        let linear_trs = track["interpolation"] == "linear_trs";
        for key in track["keys"]
            .as_array_mut()
            .ok_or_else(|| ExchangeError::new("SCHEMA_INVALID", "Missing keys"))?
        {
            key["transform"] = transform_between(&key["transform"], external, &canonical)?;
            if linear_trs && key["transform"]["kind"] != "trs" {
                return Err(ExchangeError::new(
                    "UNSUPPORTED_TRANSFORM",
                    "Exact coordinate conversion requires an affine track codec; linear_trs cannot carry shear",
                ));
            }
        }
    }
    // Rational key/event/loop/FPS metadata is untouched. Clip ID and revision
    // identify a separate derivative; the raw external artifact keeps its pins.
    let seed = crate::json_bytes(&result)?;
    if external != &canonical {
        result["clipId"] = json!(format!(
            "clip-normalized-{}",
            &raw_digest(&seed).as_str()[..24]
        ));
    }
    result["revision"] = json!(projected_digest("AnimationClip", &result).map_err(digest_error)?);
    validate("AnimationClip", &result)?;
    Ok(result)
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
    fn external(basis: [f64; 16]) -> CoordinateSystem {
        CoordinateSystem::from_value(&json!({"basisToMinecraftRowMajor":basis,"metersPerBlock":0.5,"distanceUnit":"meters","massUnit":"kilograms","angleUnit":"radians","quaternionOrder":"xyzw","matrixLayout":"row_major_column_vectors","timeDomain":"game_seconds"})).unwrap()
    }
    fn close(left: &Value, right: &Value) {
        let left = Transform::from_value(left).unwrap().matrix().unwrap();
        let right = Transform::from_value(right).unwrap().matrix().unwrap();
        for (left, right) in left.values().iter().zip(right.values()) {
            assert!((left - right).abs() < 1e-10);
        }
    }
    #[test]
    fn scaled_trs_and_scalar_rotation_cross_the_same_distance_and_basis_boundary() {
        let coordinates = external([
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ]);
        let canonical = minecraft_coordinates(&coordinates).unwrap();
        let half = 0.5_f64.sqrt();
        let original = Transform::Trs {
            translation: [3.0, 1.0, 0.0],
            rotation_xyzw: [0.0, half, 0.0, half],
            scale: [2.0, 3.0, 4.0],
        }
        .to_value()
        .unwrap();
        let converted = transform_between(&original, &canonical, &coordinates).unwrap();
        assert_eq!(converted["kind"], "trs");
        assert_eq!(converted["translation"], json!([1.5, 0.0, 0.5]));
        assert_eq!(converted["scale"], json!([2.0, 4.0, 3.0]));
        assert_eq!(converted["rotationXyzw"], json!([0.0, 0.0, half, half]));
        close(
            &transform_between(&converted, &coordinates, &canonical).unwrap(),
            &original,
        );
    }
    #[test]
    fn arbitrary_basis_nonuniform_scale_and_raw_shear_remain_exact_affine_matrices() {
        let h = 0.5_f64.sqrt();
        let coordinates = external([
            h, -h, 0.0, 0.0, h, h, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
        ]);
        let canonical = minecraft_coordinates(&coordinates).unwrap();
        for original in [
            Transform::Trs {
                translation: [2.0, 4.0, 6.0],
                rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
                scale: [2.0, 1.0, 3.0],
            }
            .to_value()
            .unwrap(),
            json!({"kind":"matrix","layout":"row_major_column_vector","values":[1,0.25,0,2,0,2,0,4,0,0,-3,6,0,0,0,1]}),
        ] {
            let converted = transform_between(&original, &canonical, &coordinates).unwrap();
            assert_eq!(converted["kind"], "matrix");
            close(
                &transform_between(&converted, &coordinates, &canonical).unwrap(),
                &original,
            );
        }
        let isotropic = Transform::Trs {
            translation: [2.0, 4.0, 6.0],
            rotation_xyzw: [0.0, 0.0, 0.0, 1.0],
            scale: [3.0; 3],
        }
        .to_value()
        .unwrap();
        assert_eq!(
            transform_between(&isotropic, &canonical, &coordinates).unwrap()["kind"],
            "trs"
        );
    }
    #[test]
    fn reflection_conjugates_rotation_without_turning_reflection_into_a_quaternion() {
        let mut basis = *Matrix4::identity().values();
        basis[0] = -1.0;
        let coordinates = external(basis);
        let canonical = minecraft_coordinates(&coordinates).unwrap();
        let half = 0.5_f64.sqrt();
        let original = Transform::Trs {
            translation: [1.0, 2.0, 3.0],
            rotation_xyzw: [0.0, half, 0.0, half],
            scale: [-2.0, 3.0, 4.0],
        }
        .to_value()
        .unwrap();
        let converted = transform_between(&original, &canonical, &coordinates).unwrap();
        assert_eq!(converted["scale"], json!([-2.0, 3.0, 4.0]));
        assert_eq!(converted["rotationXyzw"][1], json!(-half));
        close(
            &transform_between(&converted, &coordinates, &canonical).unwrap(),
            &original,
        );
    }
    #[test]
    fn tolerated_coordinate_basis_error_is_not_silently_removed_from_large_affine_values() {
        let mut basis = *Matrix4::identity().values();
        basis[0] = 1.0 + 2e-10;
        let coordinates = external(basis);
        let canonical = minecraft_coordinates(&coordinates).unwrap();
        let h = 0.5_f64.sqrt();
        let source = Transform::Trs {
            translation: [0.0; 3],
            rotation_xyzw: [0.0, h, 0.0, h],
            scale: [1e12; 3],
        }
        .to_value()
        .unwrap();
        let actual = transform_between(&source, &canonical, &coordinates).unwrap();
        assert_eq!(actual["kind"], "matrix");
        let expected = coordinates
            .conversion()
            .unwrap()
            .affine_from_minecraft(&Transform::from_value(&source).unwrap())
            .unwrap()
            .to_value()
            .unwrap();
        assert_eq!(actual, expected);
    }
}
