//! Private host observations only. Archive links are report consistency checks,
//! never approved sources, effective pack identities or resource permissions.

use super::{MAX_SOURCES, error};
use mmmm_application::{AppError, AppResult};
use serde_json::Value;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

pub(super) fn validate(
    facts: &Value,
    archives: &BTreeMap<String, &Value>,
    total_work: &mut usize,
) -> AppResult<()> {
    closed(
        facts,
        &["format", "status", "reason", "rootNode", "nodes", "filter"],
    )?;
    if facts["format"] != "mmmm.native.pack-facts/1" {
        return Err(invalid());
    }
    let filter = &facts["filter"];
    closed(filter, &["status", "reason"])?;
    if filter["status"] != "unknown" || filter["reason"] != "NATIVE_FILTER_MAPPING_UNOBSERVED" {
        return Err(invalid());
    }
    let nodes = array(&facts["nodes"])?;
    match facts["status"].as_str() {
        Some("unknown") => {
            if !nodes.is_empty()
                || !facts["rootNode"].is_null()
                || !matches!(
                    facts["reason"].as_str(),
                    Some(
                        "PACK_IMPLEMENTATION_UNSUPPORTED"
                            | "NATIVE_PACK_ACCESS_UNAVAILABLE"
                            | "PACK_FACTS_LIMIT"
                            | "PACK_GRAPH_CYCLE"
                            | "PACK_TYPE_UNSUPPORTED"
                            | "PACK_FACTS_UNAVAILABLE"
                    )
                )
            {
                return Err(invalid());
            }
            return Ok(());
        }
        Some("observed")
            if !nodes.is_empty()
                && facts["reason"].is_null()
                && facts["rootNode"].as_u64() == Some(0) => {}
        _ => return Err(invalid()),
    }
    charge(total_work, nodes.len())?;
    let mut edges = vec![Vec::new(); nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        if node["nodeIndex"].as_u64() != Some(index as u64) {
            return Err(invalid());
        }
        match node["kind"].as_str() {
            Some("fixed_path") => {
                closed(node, &["nodeIndex", "kind", "packRoots", "typeRoots"])?;
                roots(&node["packRoots"], "pack_root", archives, total_work)?;
                let typed = array(&node["typeRoots"])?;
                if typed.len() > 2 {
                    return Err(invalid());
                }
                let mut previous = None;
                for item in typed {
                    closed(item, &["packType", "roots"])?;
                    let ordinal = pack_type(&item["packType"])?;
                    if previous.is_some_and(|p| p >= ordinal) {
                        return Err(invalid());
                    }
                    previous = Some(ordinal);
                    roots(&item["roots"], "type_root", archives, total_work)?;
                }
            }
            Some("mod_nio") => {
                closed(node, &["nodeIndex", "kind", "packType", "roots"])?;
                pack_type(&node["packType"])?;
                roots(&node["roots"], "pack_root", archives, total_work)?;
            }
            Some("overlayed") => {
                closed(node, &["nodeIndex", "kind", "primaryNode", "resourceStack"])?;
                let stack = array(&node["resourceStack"])?;
                charge(total_work, 1)?;
                charge(total_work, stack.len())?;
                edges[index].push(node_index(&node["primaryNode"], nodes.len())?);
                for child in stack {
                    edges[index].push(node_index(child, nodes.len())?);
                }
            }
            _ => return Err(invalid()),
        }
    }
    // An iterative DFS permits shared DAG children and repeated stack entries,
    // while rejecting cycles and any detached nodes without recursive input.
    let mut colors = vec![0_u8; nodes.len()];
    colors[0] = 1;
    let mut pending = vec![(0, 0)];
    while let Some((node, next)) = pending.last_mut() {
        if *next == edges[*node].len() {
            colors[*node] = 2;
            pending.pop();
            continue;
        }
        let child = edges[*node][*next];
        *next += 1;
        match colors[child] {
            1 => return Err(invalid()),
            0 => {
                colors[child] = 1;
                pending.push((child, 0));
            }
            _ => {}
        }
    }
    if colors.contains(&0) {
        return Err(invalid());
    }
    Ok(())
}

fn roots(
    value: &Value,
    scope: &str,
    archives: &BTreeMap<String, &Value>,
    work: &mut usize,
) -> AppResult<()> {
    let roots = array(value)?;
    charge(work, roots.len())?;
    for root in roots {
        closed(
            root,
            &["scope", "status", "reason", "sourceId", "memberPrefix"],
        )?;
        if root["scope"] != scope {
            return Err(invalid());
        }
        match root["status"].as_str() {
            Some("observed") => {
                let id = root["sourceId"].as_str().ok_or_else(invalid)?;
                let prefix = root["memberPrefix"].as_str().ok_or_else(invalid)?;
                if !root["reason"].is_null() || !archives.contains_key(id) || !safe_prefix(prefix) {
                    return Err(invalid());
                }
            }
            Some("unknown")
                if root["sourceId"].is_null()
                    && root["memberPrefix"].is_null()
                    && matches!(
                        root["reason"].as_str(),
                        Some(
                            "PACK_ROOT_NOT_ZIPFS"
                                | "PACK_ROOT_UNMAPPED"
                                | "PACK_ROOT_PREFIX_UNSAFE"
                        )
                    ) => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

fn safe_prefix(prefix: &str) -> bool {
    // Match the producer's literal policy. Do not normalize or resolve a path,
    // and bound bytes before invoking Unicode normalization or case folding.
    if prefix.len() > 1024
        || !prefix.nfc().eq(prefix.chars())
        || prefix.chars().any(|c| {
            matches!(c,
                '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
                | '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'
            )
        })
    {
        return false;
    }
    if prefix.is_empty() {
        return true;
    }
    prefix.split('/').all(|part| {
        let lower = part.to_lowercase();
        let device = lower.split('.').next().unwrap_or_default();
        let numbered_device = device.len() == 4
            && (device.starts_with("com") || device.starts_with("lpt"))
            && matches!(device.as_bytes()[3], b'1'..=b'9');
        !part.is_empty()
            && !matches!(part, "." | "..")
            && !part.ends_with('.')
            && !part.ends_with(' ')
            && !matches!(device, "con" | "prn" | "aux" | "nul")
            && !numbered_device
            && !matches!(
                lower.as_str(),
                ".env" | ".ssh" | "id_rsa" | "id_ecdsa" | "id_ed25519"
            )
            && !lower.starts_with(".env.")
            && ![
                "credential",
                "service-account",
                "service_account",
                "api-key",
                "api_key",
                "ssh-key",
            ]
            .iter()
            .any(|pattern| lower.contains(*pattern))
    })
}

fn closed(value: &Value, fields: &[&str]) -> AppResult<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}

fn array(value: &Value) -> AppResult<&Vec<Value>> {
    value.as_array().ok_or_else(invalid)
}

fn pack_type(value: &Value) -> AppResult<u8> {
    match value.as_str() {
        Some("client_resources") => Ok(0),
        Some("server_data") => Ok(1),
        _ => Err(invalid()),
    }
}

fn node_index(value: &Value, count: usize) -> AppResult<usize> {
    let index = value.as_u64().ok_or_else(invalid)?;
    if index >= count as u64 {
        return Err(invalid());
    }
    Ok(index as usize)
}

fn charge(total: &mut usize, amount: usize) -> AppResult<()> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= MAX_SOURCES)
        .ok_or_else(invalid)?;
    Ok(())
}

fn invalid() -> AppError {
    error(
        "SOURCE_INVALID",
        "Private native pack facts are inconsistent or unbounded",
    )
}
