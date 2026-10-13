use mmmm_xtask::{policy, process, storage};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

fn main() {
    match entry() {
        Ok(exit) => std::process::exit(exit),
        Err(error) => {
            eprintln!("mmmm-xtask: {error}");
            std::process::exit(2);
        }
    }
}

fn entry() -> Result<i32, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or("expected run, check-repository or bootstrap-complete")?;
    let mut flags = BTreeMap::new();
    let mut child_args = Vec::new();
    while let Some(flag) = args.next() {
        if flag == "--" {
            child_args.extend(args);
            break;
        }
        if !flag.starts_with("--") || flags.contains_key(&flag) {
            return Err("unknown positional argument or duplicate flag".into());
        }
        let value = args.next().ok_or("flag requires value")?;
        flags.insert(flag, value);
    }
    let checkout = optional_path(&mut flags, "--checkout").unwrap_or(std::env::current_dir()?);
    match command.as_str() {
        "run" => run_managed(checkout, flags, child_args),
        "check-repository" => {
            if !child_args.is_empty() {
                return Err("check-repository has no child command".into());
            }
            reject_remaining(&flags)?;
            let report = policy::check_repository(&checkout)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.passed() { 0 } else { 1 })
        }
        "bootstrap-complete" => {
            if !child_args.is_empty() {
                return Err("bootstrap-complete has no child command".into());
            }
            complete_bootstrap(checkout, flags)
        }
        _ => Err("unknown command".into()),
    }
}

fn write_new_json(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn export_log(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Managed storage resolves local Windows paths to VerbatimDisk paths.
    // Public bootstrap inputs keep the stricter drive-only admission below.
    validate_local_ancestry(source, false, true)?;
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() || is_link(&metadata) || metadata.len() > 64 * 1024 * 1024 {
        return Err("managed command log kind or size invalid".into());
    }
    let mut input = fs::File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn run_managed(
    checkout: PathBuf,
    mut flags: BTreeMap<String, String>,
    child_args: Vec<String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let evidence_root = required_path(&mut flags, "--evidence-root")?;
    let output_root = optional_path(&mut flags, "--output-root");
    let purpose = flags
        .remove("--purpose")
        .ok_or("required flag: --purpose")?;
    let timeout = flags
        .remove("--timeout-seconds")
        .map(|v| v.parse::<u64>())
        .transpose()?
        .unwrap_or(1200);
    if !(1..=3600).contains(&timeout) {
        return Err("timeout must be 1..3600 seconds".into());
    }
    let tail_policy = match flags.remove("--owned-tail-policy").as_deref() {
        None | Some("reject") => process::TailPolicy::Reject,
        Some("terminate-build") => process::TailPolicy::TerminateForBuild,
        Some(_) => return Err("owned tail policy must be reject or terminate-build".into()),
    };
    reject_remaining(&flags)?;
    let program = child_args
        .first()
        .ok_or("run requires -- followed by absolute executable and arguments")?;
    let program = PathBuf::from(program);
    if !program.is_absolute() {
        return Err("managed executable must be resolved absolute path".into());
    }
    let build = storage::ManagedBuild::acquire(
        storage::StorageConfig {
            output_root,
            evidence_root,
            purpose,
            budgets: storage::Budgets::default(),
        },
        &checkout,
    )?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.store(true, std::sync::atomic::Ordering::Release))?;
    let stdout = build.paths().scratch.join("command.stdout.log");
    let stderr = build.paths().scratch.join("command.stderr.log");
    let mut spec = process::ProcessSpec::new(
        program,
        fs::canonicalize(&checkout)?,
        stdout.clone(),
        stderr.clone(),
    );
    spec.args = child_args
        .iter()
        .skip(1)
        .map(std::ffi::OsString::from)
        .collect();
    spec.env = build
        .environment()
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    spec.env.insert("CARGO_BUILD_JOBS".into(), "2".into());
    spec.timeout = Duration::from_secs(timeout);
    spec.tail_policy = tail_policy;
    let result = process::supervise(&spec, &cancellation, || {
        let measurement = build.measure().map_err(|error| error.to_string())?;
        if !measurement.within_budget {
            return Err("managed disk budget exceeded".into());
        }
        Ok(())
    });
    let (command_exit, drained, mut supervisor_errors, command_success, report) = match result {
        Ok(outcome) => {
            let success = outcome.command_exit == Some(0)
                && outcome.drained
                && outcome.output_complete
                && outcome.supervisor_errors.is_empty();
            (
                outcome.command_exit,
                outcome.drained,
                outcome.supervisor_errors.clone(),
                success,
                serde_json::to_value(outcome)?,
            )
        }
        Err(error) => (
            None,
            error.drained,
            vec![error.to_string()],
            false,
            serde_json::json!({"kind": error.kind, "message": error.message, "drained": error.drained}),
        ),
    };
    let mut exported = false;
    let export = (|| -> Result<(), Box<dyn std::error::Error>> {
        write_new_json(&build.paths().evidence.join("process.json"), &report)?;
        if !drained {
            return Err("unconfirmed drain prevents command log export and cleanup".into());
        }
        build.measure()?;
        for (source, name) in [
            (&stdout, "command.stdout.log"),
            (&stderr, "command.stderr.log"),
        ] {
            if source.try_exists()? {
                export_log(source, &build.paths().evidence.join(name))?;
            }
        }
        Ok(())
    })();
    match export {
        Ok(()) => exported = true,
        Err(error) => supervisor_errors.push(format!("evidence export: {error}")),
    }
    write_new_json(
        &build.paths().evidence.join("finalization-input.json"),
        &serde_json::json!({
            "schema": "mmmm-build-finalization-input/1",
            "command_exit": command_exit,
            "drained": drained,
            "evidence_exported": exported,
            "supervisor_errors": supervisor_errors,
        }),
    )?;
    let receipt = build.finish(storage::FinishOutcome {
        command_exit,
        supervisor_errors,
        drained,
        evidence_exported: exported,
    })?;
    let success = command_success
        && receipt.lease_released
        && receipt.supervisor_errors.is_empty()
        && receipt.cleanup_errors.is_empty();
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(if success { 0 } else { 1 })
}

fn optional_path(flags: &mut BTreeMap<String, String>, key: &str) -> Option<PathBuf> {
    flags.remove(key).map(PathBuf::from)
}

fn required_path(
    flags: &mut BTreeMap<String, String>,
    key: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    optional_path(flags, key).ok_or_else(|| format!("required flag: {key}").into())
}

fn reject_remaining(flags: &BTreeMap<String, String>) -> Result<(), Box<dyn std::error::Error>> {
    if !flags.is_empty() {
        return Err("unsupported flag".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapProof {
    schema: String,
    token: String,
    command_exit: i32,
    drained: bool,
    evidence_exported: bool,
    supervisor_errors: Vec<String>,
    #[serde(default)]
    owned_tail_terminated: bool,
}

fn bounded_record(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_link(&metadata) || metadata.len() > 8192 {
        return Err("invalid bootstrap record kind or size".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || is_link(&opened) || opened.len() > 8192 {
        return Err("opened bootstrap record changed kind or size".into());
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("bootstrap record exceeded limit".into());
    }
    Ok(bytes)
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn validate_record_ancestry(
    path: &Path,
    directory: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_local_ancestry(path, directory, false)
}

fn validate_local_ancestry(
    path: &Path,
    directory: bool,
    managed_verbatim_disk: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(windows))]
    let _ = managed_verbatim_disk;
    if !path.is_absolute() {
        return Err("bootstrap evidence path must be absolute".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err("bootstrap evidence contains relative component".into());
            }
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                if !(matches!(prefix.kind(), std::path::Prefix::Disk(_))
                    || managed_verbatim_disk
                        && matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
                {
                    return Err("bootstrap evidence requires a local drive path".into());
                }
                current.push(prefix.as_os_str());
                continue;
            }
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                let lower = name.to_string_lossy().to_ascii_lowercase();
                if lower == ".env"
                    || lower.starts_with(".env.")
                    || lower == ".ssh"
                    || lower.contains("credential")
                    || lower.contains("service-account")
                    || lower.contains("service_account")
                    || lower.starts_with("id_rsa")
                    || lower.starts_with("id_ed25519")
                    || [".pem", ".key", ".p12", ".pfx"]
                        .iter()
                        .any(|suffix| lower.ends_with(suffix))
                {
                    return Err("secret-named evidence path is not accessed".into());
                }
                current.push(name);
            }
        }
        let metadata = fs::symlink_metadata(&current)?;
        if is_link(&metadata) || ((current != path || directory) && !metadata.is_dir()) {
            return Err("bootstrap evidence ancestry is not a regular local directory".into());
        }
    }
    Ok(())
}

fn complete_bootstrap(
    checkout: PathBuf,
    mut flags: BTreeMap<String, String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let ownership_path = required_path(&mut flags, "--ownership")?;
    let proof_path = required_path(&mut flags, "--proof")?;
    let evidence_root = required_path(&mut flags, "--evidence-root")?;
    let output_root = optional_path(&mut flags, "--output-root");
    let purpose = flags
        .remove("--purpose")
        .ok_or("required flag: --purpose")?;
    reject_remaining(&flags)?;
    // Exact public filenames are checked before opening any caller-selected file.
    if ownership_path.file_name().and_then(|v| v.to_str()) != Some("bootstrap-ownership.json")
        || proof_path.file_name().and_then(|v| v.to_str()) != Some("bootstrap-process.json")
    {
        return Err("unexpected bootstrap record filename".into());
    }
    if ownership_path != evidence_root.join("bootstrap-ownership.json")
        || proof_path != evidence_root.join("bootstrap-process.json")
    {
        return Err("bootstrap records must be direct evidence root files".into());
    }
    // Reject lexical secret names and every reparse ancestor before resolving or reading.
    validate_record_ancestry(&evidence_root, true)?;
    validate_record_ancestry(&ownership_path, false)?;
    validate_record_ancestry(&proof_path, false)?;
    let evidence = fs::canonicalize(&evidence_root)?;
    for input in [&ownership_path, &proof_path] {
        let canonical = fs::canonicalize(input)?;
        if !canonical.starts_with(&evidence) {
            return Err("bootstrap record outside evidence root".into());
        }
    }
    let ownership: storage::BootstrapOwnership =
        serde_json::from_slice(&bounded_record(&ownership_path)?)?;
    let proof: BootstrapProof = serde_json::from_slice(&bounded_record(&proof_path)?)?;
    if proof.schema != "mmmm-bootstrap-process/1"
        || proof.token != ownership.token
        || proof.command_exit != 0
        || !proof.drained
        || !proof.evidence_exported
        || !proof.supervisor_errors.is_empty()
    {
        return Err("bootstrap process and export proof does not permit adoption".into());
    }
    let token = ownership.token.clone();
    let build = storage::ManagedBuild::adopt_bootstrap(
        storage::StorageConfig {
            output_root,
            evidence_root,
            purpose,
            budgets: storage::Budgets::default(),
        },
        &checkout,
        ownership,
        true,
        true,
    )?;
    let receipt = build.finish(storage::FinishOutcome {
        command_exit: Some(0),
        supervisor_errors: vec![],
        drained: true,
        evidence_exported: true,
    })?;
    let success = receipt.lease_released && receipt.cleanup_errors.is_empty();
    let complete = serde_json::json!({
        "schema": "mmmm-bootstrap-complete/1", "token": token,
        "slot_id": receipt.slot_id, "lease_released": receipt.lease_released,
        "receipt": receipt,
        "owned_tail_terminated": proof.owned_tail_terminated,
    });
    let destination = evidence.join("bootstrap-complete.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    file.write_all(&serde_json::to_vec_pretty(&complete)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!("{}", serde_json::to_string_pretty(&complete)?);
    Ok(if success { 0 } else { 1 })
}
