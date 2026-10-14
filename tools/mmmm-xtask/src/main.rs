use mmmm_xtask::{definition_startup, policy, process, storage};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
        .ok_or("expected run, definition-startup, check-repository or bootstrap-complete")?;
    let mut flags = BTreeMap::new();
    let mut child_args = Vec::new();
    let mut child_separator = false;
    while let Some(flag) = args.next() {
        if flag == "--" {
            child_separator = true;
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
        "definition-startup" => {
            if child_separator || !child_args.is_empty() {
                return Err("definition-startup accepts no child command or arguments".into());
            }
            run_definition_startup(checkout, flags)
        }
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
    let managed_jvm_helper = purpose == "jvm";
    let resource_policy = process::ResourcePolicy::for_managed_purpose(&purpose);
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
    if managed_jvm_helper {
        // This owned build helper does not use managed attach/profiling.
        // Override before CoreCLR starts, without reading inherited values.
        // Unknown special entries still fail closed in managed storage.
        spec.env
            .insert("DOTNET_EnableDiagnostics".into(), "0".into());
    }
    spec.env.insert("CARGO_BUILD_JOBS".into(), "2".into());
    spec.timeout = Duration::from_secs(timeout);
    spec.tail_policy = tail_policy;
    spec.resource_policy = resource_policy;
    let mut observation_retries = storage::ObservationRetryLog::default();
    let result =
        process::supervise_with_progress_phased(&spec, &cancellation, |phase, checkpoint| {
            let measurement = match phase {
                process::ObservationPhase::PreSpawn => build.measure_with_progress(checkpoint),
                process::ObservationPhase::Running => build
                    .measure_with_progress_and_diagnostics(checkpoint, &mut observation_retries),
            }
            .map_err(|error| error.to_string())?;
            if !measurement.within_budget {
                return Err("managed disk budget exceeded".into());
            }
            Ok(())
        });
    let (command_exit, drained, mut supervisor_errors, command_success, mut report) = match result {
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
    let (retry_summary, retry_export) =
        export_observation_retries(&build.paths().evidence, &observation_retries);
    report["storage_observation_retries"] = retry_summary;
    if let Err(error) = &retry_export {
        // Preserve this independent failure even if process.json also fails.
        supervisor_errors.push(format!("retry companion export: {error}"));
    }
    let mut exported = false;
    let export = (|| -> Result<(), Box<dyn std::error::Error>> {
        write_new_json(&build.paths().evidence.join("process.json"), &report)?;
        retry_export?;
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

fn export_observation_retries(
    evidence: &Path,
    retries: &storage::ObservationRetryLog,
) -> (serde_json::Value, Result<(), Box<dyn std::error::Error>>) {
    // Required companion, even when empty. A failed write remains an export
    // failure and cannot authorize finish/cleanup. First/last facts also stay
    // in process.json if this independent evidence destination fails.
    let mut summary = retries.summary();
    summary["write_confirmed"] = false.into();
    let encoded = match retries.encoded_evidence() {
        Ok(encoded) => encoded,
        Err(error) => {
            summary["status"] = "encoding_failed".into();
            summary["byte_length"] = serde_json::Value::Null;
            summary["sha256"] = serde_json::Value::Null;
            return (summary, Err(Box::new(error)));
        }
    };
    // Encode once including newline; the digest and CreateNew writer use this
    // exact buffer. Pins describe this buffer; only write_confirmed certifies
    // that the complete companion was written, flushed and synced.
    summary["byte_length"] = encoded.len().into();
    summary["sha256"] = format!("{:x}", Sha256::digest(&encoded)).into();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(evidence.join("observation-retries.json"))?;
        file.write_all(&encoded)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    summary["write_confirmed"] = result.is_ok().into();
    summary["status"] = if result.is_ok() {
        "created"
    } else {
        "write_unconfirmed"
    }
    .into();
    (summary, result)
}

#[cfg(test)]
mod observation_evidence_tests {
    use super::*;

    #[test]
    fn required_retry_companion_failure_preserves_the_owned_lease_and_scratch() {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!("mmmm-retry-export-{}-{stamp}", std::process::id()));
        assert!(root.is_absolute() && !root.exists());
        fs::create_dir(&root).unwrap();
        let checkout = root.join("checkout");
        fs::create_dir(&checkout).unwrap();
        let build = storage::ManagedBuild::acquire(
            storage::StorageConfig {
                output_root: Some(root.join("output")),
                evidence_root: root.join("evidence"),
                purpose: "retry-export-fixture".into(),
                budgets: storage::Budgets::default(),
            },
            &checkout,
        )
        .unwrap();
        let paths = build.paths().clone();
        let retries = storage::ObservationRetryLog::default();
        let (summary, exported) = export_observation_retries(&paths.evidence, &retries);
        exported.unwrap();
        let bytes = fs::read(paths.evidence.join("observation-retries.json")).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["schema"], "mmmm-managed-observation-retries/1");
        assert_eq!(report["records"], serde_json::json!([]));
        assert_eq!(summary["records"], 0);
        assert_eq!(summary["write_confirmed"], true);
        assert_eq!(summary["byte_length"], bytes.len());
        assert_eq!(summary["sha256"], format!("{:x}", Sha256::digest(&bytes)));
        assert_eq!(bytes.last(), Some(&b'\n'));
        let (failed, result) = export_observation_retries(&paths.evidence, &retries);
        let error = result.unwrap_err();
        assert_eq!(failed["write_confirmed"], false);
        assert_eq!(failed["status"], "write_unconfirmed");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(paths.evidence.join("observation-retries.json")).unwrap(),
            bytes
        );
        let finish = build
            .finish(storage::FinishOutcome {
                command_exit: Some(0),
                drained: true,
                evidence_exported: false,
                supervisor_errors: vec!["required retry evidence export failed".into()],
            })
            .unwrap_err();
        assert_eq!(finish.kind, "evidence");
        assert!(paths.catalog.join("lease.json").exists() && paths.scratch.exists());
        // This is a newly owned outer test fixture, not general build cleanup.
        let physical = fs::canonicalize(&root).unwrap();
        assert_eq!(physical.parent(), Some(parent.as_path()));
        assert!(!is_link(&fs::symlink_metadata(&root).unwrap()));
        fs::remove_dir_all(physical).unwrap();
    }
}

fn run_definition_startup(
    checkout: PathBuf,
    mut flags: BTreeMap<String, String>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use definition_startup::{
        DefinitionSourceInput, DefinitionSourceRole, DefinitionStartupSelection,
    };
    let evidence_root = required_path(&mut flags, "--evidence-root")?;
    let output_root = optional_path(&mut flags, "--output-root");
    let java = required_path(&mut flags, "--java-executable")?;
    let library = required_path(&mut flags, "--observer-library")?;
    let jar = required_path(&mut flags, "--observer-jar")?;
    let mut sources = Vec::new();
    for (flag, role) in [
        ("--jdk-archive", DefinitionSourceRole::JdkArchive),
        ("--jdk-modules", DefinitionSourceRole::JdkModules),
        (
            "--build-source-manifest",
            DefinitionSourceRole::BuildSourceManifest,
        ),
    ] {
        sources.push(DefinitionSourceInput::new(
            role,
            required_path(&mut flags, flag)?,
        ));
    }
    // Three primary inputs and three mandatory source inputs leave at most 26
    // explicit library selections. No delimiter, wildcard or child argv codec.
    let mut gap = false;
    let mut libraries = 0;
    for index in 1..=26 {
        match optional_path(&mut flags, &format!("--jdk-library-{index}")) {
            Some(path) if !gap => {
                sources.push(DefinitionSourceInput::new(
                    DefinitionSourceRole::JdkLibrary,
                    path,
                ));
                libraries += 1;
            }
            Some(_) => {
                return Err("JDK library flags must be contiguous from --jdk-library-1".into());
            }
            None => gap = true,
        }
    }
    if libraries == 0 {
        return Err("required flag: --jdk-library-1".into());
    }
    reject_remaining(&flags)?;
    let selection = DefinitionStartupSelection::new(java, library, jar, sources)?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.store(true, std::sync::atomic::Ordering::Release))?;
    let build = storage::ManagedBuild::acquire(
        storage::StorageConfig {
            output_root,
            evidence_root,
            purpose: "definition-startup".into(),
            budgets: storage::Budgets::default(),
        },
        &checkout,
    )?;
    let result = definition_startup::run_owned(&build, &selection, &cancellation);
    let outcome = match &result {
        Ok(observed) => Some(observed.outcome()),
        Err(error) => error.outcome(),
    };
    // Supervision records pre-spawn cancellation too. Only the private capture
    // receipt establishes actual creation; a ProcessError alone stays unknown.
    let started = match &result {
        Ok(observed) => Some(observed.process_started()),
        Err(error) => error.process_started(),
    };
    let command_exit = outcome.and_then(|value| value.command_exit);
    let drained = outcome.map(|value| value.drained).unwrap_or_else(|| {
        result.as_ref().err().is_some_and(|error| {
            error.process_started() == Some(false)
                || error.process_error().is_some_and(|error| error.drained)
        })
    });
    let mut supervisor_errors = outcome
        .map(|value| value.supervisor_errors.clone())
        .unwrap_or_default();
    let process_report = match (&result, outcome) {
        (_, Some(value)) => serde_json::to_value(value)?,
        (Err(error), None) => definition_startup_error_json(error),
        (Ok(_), None) => return Err("observed startup has no original process outcome".into()),
    };
    let (status, observation, raw) = match &result {
        Ok(observed) => (
            "observed",
            serde_json::json!({
                "schema": "mmmm-definition-startup-observation/1",
                "scope": "development_fixture",
                "status": "observed",
                "process_started": started,
                "source_pins": observed.source_pins(),
                "diagnostics": observed.diagnostics(),
                "raw_sha256": observed.raw_sha256(),
                "summary": observed.summary(),
            }),
            Some(observed.raw_abi2()),
        ),
        Err(error) => {
            supervisor_errors.push(error.to_string());
            (
                "failed",
                serde_json::json!({
                    "schema": "mmmm-definition-startup-observation/1",
                    "scope": "development_fixture",
                    "status": "failed",
                    "process_started": started,
                    "source_pins": error.source_pins(),
                    "diagnostics": error.diagnostics(),
                    "error": definition_startup_error_json(error),
                    "raw_candidate_present": error.raw_candidate().is_some(),
                }),
                error.raw_candidate(),
            )
        }
    };
    let mut exported = false;
    let export = (|| -> Result<(), Box<dyn std::error::Error>> {
        build.check_current_ownership()?;
        write_new_json(
            &build.paths().evidence.join("process.json"),
            &process_report,
        )?;
        write_new_json(
            &build.paths().evidence.join("definition-startup.json"),
            &observation,
        )?;
        if !drained {
            return Err("unconfirmed drain prevents startup log export and cleanup".into());
        }
        build.measure()?;
        if let Some(bytes) = raw {
            let name = if result.is_ok() {
                "definition-startup.abi2.bin"
            } else {
                "definition-startup.candidate.bin"
            };
            export_definition_frame(
                &build,
                &cancellation,
                &build.paths().evidence.join(name),
                bytes,
            )?;
        }
        for name in [
            "definition-startup.stdout.bin",
            "definition-startup.stderr.log",
        ] {
            let source = build.paths().scratch.join(name);
            if source.try_exists()? {
                export_log(&source, &build.paths().evidence.join(name))?;
            }
        }
        build.check_current_ownership()?;
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
    let observed = result.is_ok();
    let receipt = build.finish(storage::FinishOutcome {
        command_exit,
        supervisor_errors,
        drained,
        evidence_exported: exported,
    })?;
    let success = observed
        && receipt.lease_released
        && receipt.supervisor_errors.is_empty()
        && receipt.cleanup_errors.is_empty();
    // Raw frames and original diagnostics stay in the owned evidence root.
    // Public stdout contains the observation scope, path-free pins and summary.
    let public_observation = match &result {
        Ok(value) => {
            serde_json::json!({"source_pins": value.source_pins(), "raw_sha256": value.raw_sha256(), "summary": value.summary(), "diagnostics": value.diagnostics()})
        }
        Err(value) => {
            serde_json::json!({"source_pins": value.source_pins(), "error_kind": value.kind(), "native_os_code": value.native_os_code(), "diagnostics": value.diagnostics()})
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "mmmm-definition-startup-result/1",
            "scope": "development_fixture",
            "status": status,
            "process_started": started,
            "observation": public_observation,
            "receipt": receipt,
        }))?
    );
    Ok(if success { 0 } else { 1 })
}

fn definition_startup_error_json(
    error: &definition_startup::DefinitionStartupError,
) -> serde_json::Value {
    serde_json::json!({
        "kind": error.kind(),
        "native_os_code": error.native_os_code(),
        "process_error": error.process_error().map(|value| serde_json::json!({"kind":value.kind,"message":value.message,"drained":value.drained})),
        "storage_error": error.storage_error().map(|value| serde_json::json!({"kind":value.kind,"message":value.message})),
        "post_check_error": error.post_check_error().map(definition_startup_error_json),
        "diagnostics": error.diagnostics(),
        "post_check_diagnostics": error.post_check_diagnostics(),
    })
}

fn export_definition_frame(
    build: &storage::ManagedBuild,
    cancellation: &AtomicBool,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if bytes.is_empty() || bytes.len() > 18 * 1024 * 1024 {
        return Err("startup frame export exceeds the original 18 MiB cap".into());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let check = || -> Result<(), Box<dyn std::error::Error>> {
        if cancellation.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= deadline
        {
            return Err("startup frame export cancelled or deadline expired".into());
        }
        build.check_current_ownership()?;
        if cancellation.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= deadline
        {
            return Err("startup frame export cancelled or deadline expired".into());
        }
        Ok(())
    };
    check()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    for chunk in bytes.chunks(64 * 1024) {
        check()?;
        file.write_all(chunk)?;
        check()?;
    }
    file.sync_all()?;
    check()
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
