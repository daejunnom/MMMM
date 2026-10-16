//! Own one fixed Rust CLI build and preserve an explicitly incomplete candidate.
//! This module neither imports release claims nor issues product acceptance proof.

use mmmm_xtask::{process, storage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct CandidateFailures {
    failures: Vec<(String, Box<dyn std::error::Error>)>,
}

impl std::fmt::Display for CandidateFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, (stage, error)) in self.failures.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{stage}: {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CandidateFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failures.first().map(|(_, error)| error.as_ref())
    }
}

const PURPOSE: &str = "candidate";
const MAX_INPUT_FILES: usize = 4096;
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SOURCE_FILE: u64 = 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 16 * 1024 * 1024;
// Initial candidate-command limits include the locked SQLite amalgamation.
// They do not alter native process memory or managed slot/catalog budgets.
const MAX_DEPENDENCY_FILES: usize = 65_536;
const MAX_DEPENDENCY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DEPENDENCY_FILE: u64 = 16 * 1024 * 1024;
const CACHE_POINTER: &str = ".mmmm-rust-cli-cache.json";
const MAX_CACHE_FILES: usize = 100_000;
const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CACHE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const INPUT_ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates",
    "apps/mmmm",
    "tools/mmmm-xtask",
    "contracts",
    "examples",
    "tests",
    ".cargo",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SourcePins {
    source_sha: String,
    files: Vec<Pin>,
}

struct Tools {
    git: PathBuf,
    cargo: PathBuf,
    rustc: PathBuf,
    producer: PathBuf,
}

struct Run {
    build: storage::ManagedBuild,
    cancellation: Arc<AtomicBool>,
    deadline: Instant,
    commands: Vec<Value>,
    drained: bool,
    last_exit: Option<i32>,
    evidence_complete: bool,
    supervisor_errors: Vec<String>,
    target: PathBuf,
    preserve_cache: bool,
}

impl Run {
    fn check(&self) -> std::result::Result<(), String> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err("candidate request cancelled".into());
        }
        if Instant::now() >= self.deadline {
            return Err("original candidate request deadline exceeded".into());
        }
        self.build
            .check_current_ownership()
            .map_err(|e| e.to_string())
    }

    fn environment(&self, rustc: Option<&Path>) -> BTreeMap<OsString, OsString> {
        let mut env = BTreeMap::new();
        // Only OS discovery/toolchain variables needed by native compilation.
        // No inherited Cargo flags, wrappers, CL/LINK flags or credential values.
        for name in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "USERPROFILE",
            "HOME",
            "RUSTUP_HOME",
        ] {
            if let Some(value) = std::env::var_os(name) {
                env.insert(name.into(), value);
            }
        }
        env.extend(
            self.build
                .environment()
                .into_iter()
                .map(|(k, v)| (k.into(), v.into())),
        );
        env.insert(
            "CARGO_TARGET_DIR".into(),
            self.target.as_os_str().to_owned(),
        );
        env.insert("CARGO_BUILD_JOBS".into(), "1".into());
        env.insert("RUSTUP_TOOLCHAIN".into(), "1.96.0".into());
        env.insert("CARGO_NET_OFFLINE".into(), "true".into());
        env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        env.insert(
            "GIT_CONFIG_GLOBAL".into(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
        );
        env.insert("GIT_ATTR_NOSYSTEM".into(), "1".into());
        if let Some(rustc) = rustc {
            env.insert("RUSTC".into(), rustc.as_os_str().to_owned());
        }
        env
    }

    fn capture(
        &mut self,
        label: &str,
        program: &Path,
        cwd: &Path,
        args: &[OsString],
        rustc: Option<&Path>,
    ) -> Result<Vec<u8>> {
        self.check()?;
        if self.commands.len() >= 16 {
            return Err("candidate command count exceeded".into());
        }
        let ordinal = self.commands.len();
        let stdout = self
            .build
            .paths()
            .scratch
            .join(format!("candidate-{ordinal}.stdout"));
        let stderr = self
            .build
            .paths()
            .scratch
            .join(format!("candidate-{ordinal}.stderr"));
        let mut spec = process::ProcessSpec::new(
            program.to_path_buf(),
            cwd.to_path_buf(),
            stdout.clone(),
            stderr.clone(),
        );
        spec.args = args.to_vec();
        spec.inherit_environment = false;
        spec.env = self.environment(rustc);
        spec.timeout = self.deadline.saturating_duration_since(Instant::now());
        spec.absolute_deadline = Some(self.deadline);
        spec.max_log_bytes = MAX_COMMAND_BYTES as u64;
        spec.tail_policy = process::TailPolicy::TerminateForBuild;
        spec.resource_policy = process::ResourcePolicy::for_managed_purpose(PURPOSE);
        let observed =
            process::supervise_with_progress_captured(&spec, &self.cancellation, |checkpoint| {
                checkpoint()?;
                self.check()?;
                let measurement = self
                    .build
                    .measure_with_progress(checkpoint)
                    .map_err(|e| e.to_string())?;
                if !measurement.within_budget {
                    return Err("candidate managed disk budget exceeded".into());
                }
                Ok(())
            });
        match observed {
            Ok(mut capture) => {
                self.drained &= capture.outcome().drained;
                self.last_exit = capture.outcome().command_exit;
                self.supervisor_errors
                    .extend(capture.outcome().supervisor_errors.iter().cloned());
                let outcome = serde_json::to_value(capture.outcome())?;
                self.commands.push(json!({"ordinal":ordinal,"label":label,"process_started":capture.process_started(),"process":outcome}));
                let read = capture.read_stdout(MAX_COMMAND_BYTES, || self.check());
                self.commands[ordinal]["stdout_read"] = match &read {
                    Ok(bytes) => json!({"status":"verified","bytes":bytes.len()}),
                    Err(error) => json!({"status":"failed","error":local_error(error)}),
                };
                let mut export_failures = Vec::new();
                let mut exports = Vec::new();
                // Original raw logs remain local evidence, including failed commands.
                // Keep both original capture handles: reopening their paths would
                // conflict with the Windows writer-sharing boundary and would
                // replace their identity with a later pathname observation.
                if capture.outcome().drained {
                    for (stream, suffix) in [
                        (process::CaptureStream::Stdout, "stdout"),
                        (process::CaptureStream::Stderr, "stderr"),
                    ] {
                        let mut stage = "read_held_capture";
                        let exported = (|| -> Result<usize> {
                            // Preserve the exact stdout bytes consumed by the
                            // strict reader, including on Unix where another
                            // writer could change the same held file afterward.
                            let bytes: std::borrow::Cow<'_, [u8]> = match (stream, &read) {
                                (process::CaptureStream::Stdout, Ok(bytes)) => {
                                    std::borrow::Cow::Borrowed(bytes.as_slice())
                                }
                                _ => std::borrow::Cow::Owned(capture.read_drained_log(
                                    stream,
                                    MAX_COMMAND_BYTES,
                                    || self.check(),
                                )?),
                            };
                            stage = "check_export_ownership";
                            self.check()?;
                            stage = "create_destination";
                            let destination = self
                                .build
                                .paths()
                                .evidence
                                .join(format!("candidate-{ordinal}.{suffix}"));
                            let mut file = OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(destination)?;
                            for chunk in bytes.chunks(65_536) {
                                stage = "check_write_ownership";
                                self.check()?;
                                stage = "write_destination";
                                file.write_all(chunk)?;
                                stage = "check_write_ownership";
                                self.check()?;
                            }
                            stage = "check_sync_ownership";
                            self.check()?;
                            stage = "sync_destination";
                            file.sync_all()?;
                            stage = "check_sync_ownership";
                            self.check()?;
                            Ok(bytes.len())
                        })();
                        match exported {
                            Ok(bytes) => exports.push(json!({
                                "stream":suffix,"status":"exported","bytes":bytes,
                            })),
                            Err(error) => {
                                exports.push(json!({
                                    "stream":suffix,"status":"failed","stage":stage,
                                    "error":local_error(error.as_ref()),
                                }));
                                export_failures.push((
                                    format!("command {ordinal} ({label}) {suffix} {stage}"),
                                    error,
                                ));
                            }
                        }
                    }
                } else {
                    for stream in ["stdout", "stderr"] {
                        exports.push(json!({
                            "stream":stream,"status":"not_attempted","stage":"unconfirmed_drain",
                        }));
                    }
                    self.evidence_complete = false;
                }
                self.commands[ordinal]["raw_exports"] = json!(exports);
                if !export_failures.is_empty() {
                    self.evidence_complete = false;
                }
                match read {
                    Ok(bytes) if export_failures.is_empty() => Ok(bytes),
                    Ok(_) => Err(Box::new(CandidateFailures {
                        failures: export_failures,
                    })),
                    Err(error) if export_failures.is_empty() => Err(Box::new(error)),
                    Err(error) => {
                        export_failures.insert(
                            0,
                            (
                                format!("command {ordinal} ({label}) strict_stdout_read"),
                                Box::new(error),
                            ),
                        );
                        Err(Box::new(CandidateFailures {
                            failures: export_failures,
                        }))
                    }
                }
            }
            Err(error) => {
                self.drained &= error.drained;
                self.last_exit = None;
                self.evidence_complete = false;
                self.commands.push(json!({"ordinal":ordinal,"label":label,"process_started":Value::Null,"error":{"kind":error.kind,"message":error.message.clone(),"drained":error.drained}}));
                Err(Box::new(error))
            }
        }
    }
}

pub(super) fn run(checkout: PathBuf, mut flags: BTreeMap<String, String>) -> Result<i32> {
    let evidence_root = crate::required_path(&mut flags, "--evidence-root")?;
    let output_root = crate::optional_path(&mut flags, "--output-root");
    let expected = flags
        .remove("--expected-source")
        .ok_or("required flag: --expected-source")?;
    if expected.len() != 40
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("candidate expected source must be an exact lowercase Git SHA-1".into());
    }
    let tools = Tools {
        git: selected_tool(crate::required_path(&mut flags, "--git")?, "git")?,
        cargo: selected_tool(crate::required_path(&mut flags, "--cargo")?, "cargo")?,
        rustc: selected_tool(crate::required_path(&mut flags, "--rustc")?, "rustc")?,
        producer: selected_image(std::env::current_exe()?, true)?,
    };
    let seconds = flags
        .remove("--timeout-seconds")
        .map(|v| v.parse::<u64>())
        .transpose()?
        .unwrap_or(1200);
    if !(1..=3600).contains(&seconds) {
        return Err("candidate timeout must be 1..3600 seconds".into());
    }
    crate::reject_remaining(&flags)?;
    let checkout = fs::canonicalize(checkout)?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let build = storage::ManagedBuild::acquire(
        storage::StorageConfig {
            output_root,
            evidence_root,
            purpose: PURPOSE.into(),
            budgets: storage::Budgets::default(),
        },
        &checkout,
    )?;
    let target = build.paths().cargo_target.clone();
    let mut run = Run {
        build,
        cancellation,
        deadline: Instant::now() + Duration::from_secs(seconds),
        commands: Vec::new(),
        drained: true,
        last_exit: None,
        evidence_complete: true,
        supervisor_errors: Vec::new(),
        target,
        preserve_cache: false,
    };
    let result = produce(&mut run, &checkout, &tools, &expected);
    if let Err(error) = &result {
        eprintln!("candidate production failure (local diagnostics): {error}");
    }
    // A failed candidate is still finalized only with observed drain and exported diagnostics.
    let evidence = run.build.paths().evidence.clone();
    let private_audit = crate::write_new_json(
        &evidence.join("candidate-private-diagnostics.json"),
        &json!({
            "schema":"mmmm-rust-cli-candidate-private-diagnostics/1", "local_only":true,
            "commands":run.commands, "error":result.as_ref().err().map(|e| e.to_string()),
            "supervisor_errors":run.supervisor_errors,
            "strict_stdout_read_error_count":strict_stdout_read_error_count(&run.commands),
            "raw_export_error_count":raw_export_error_count(&run.commands),
        }),
    );
    let report = json!({
        "schema":"mmmm-rust-cli-candidate-attempt/1", "scope":"development_candidate",
        "candidate_prepared":result.is_ok(), "commands":public_commands(&run.commands),
        "result":if result.is_ok() { "prepared" } else { "production_failed" },
        "required_evidence_exported":run.evidence_complete && private_audit.is_ok(),
        "supervisor_error_count":run.supervisor_errors.len(), "drained":child_observations(&run.commands, run.drained)["scope_drained"],"last_command_exit":run.last_exit,
        "strict_stdout_read_error_count":strict_stdout_read_error_count(&run.commands),
        "raw_export_error_count":raw_export_error_count(&run.commands),
        "child_observations":child_observations(&run.commands, run.drained),
        "cache_preservation_requested":run.preserve_cache,
        "product_proof_issued":false, "acceptance_verification":"not_run", "release_verification":"not_run",
    });
    let exported = crate::write_new_json(&evidence.join("candidate-attempt.json"), &report);
    if run.preserve_cache {
        // An unadmitted target is not a normal failed build. Normal finish may
        // evict its own slot, so deliberately preserve exact owner and lease.
        // This does not disguise a completed export as an export failure.
        let preserved = json!({
            "schema":"mmmm-rust-cli-candidate-storage-preserved/1","status":"storage_preserved","scope":"development_candidate",
            "acquisition":{"owner_state_written":"active","lease_acquired":true},"current_owner_and_lease":"not_revalidated",
            "preservation_phase":{"finish_called":false,"lease_release_attempted":false,"cache_cleanup_attempted":false,"owner_mutation_attempted":false},
            "cache_preservation_requested":true,
            "child_observations":child_observations(&run.commands, run.drained),
            "last_command_exit":run.last_exit,"commands":public_commands(&run.commands),
            "required_evidence_exported":run.evidence_complete && private_audit.is_ok() && exported.is_ok(),
            "next_action":"explicit_owned_cache_lifecycle_required_before_retry","product_proof_issued":false,
        });
        let preserved_export = crate::write_new_json(
            &evidence.join("candidate-storage-preserved.json"),
            &preserved,
        );
        println!("{}", serde_json::to_string_pretty(&preserved)?);
        let mut failures = Vec::new();
        if let Err(error) = result {
            failures.push(("production".into(), error));
        }
        for (stage, export) in [
            ("private_diagnostics_export", private_audit),
            ("attempt_export", exported),
            ("storage_preservation_export", preserved_export),
        ] {
            if let Err(error) = export {
                failures.push((stage.into(), error));
            }
        }
        if failures.is_empty() {
            failures.push((
                "storage_preservation".into(),
                "candidate cache preservation requires explicit owned lifecycle handling; no completion issued".into(),
            ));
        }
        return Err(Box::new(CandidateFailures { failures }));
    }
    let finish = run.build.finish(storage::FinishOutcome {
        command_exit: run.last_exit,
        supervisor_errors: run.supervisor_errors,
        drained: run.drained,
        evidence_exported: exported.is_ok() && private_audit.is_ok() && run.evidence_complete,
    });
    let incomplete_finish = finish.as_ref().is_ok_and(|receipt| {
        !receipt.lease_released
            || !receipt.cleanup_errors.is_empty()
            || !receipt.supervisor_errors.is_empty()
    });
    if private_audit.is_err() || exported.is_err() || finish.is_err() || incomplete_finish {
        // Preserve every original cause. Evidence or finalization failures must
        // not replace a command/read/export failure with a generic last error.
        let failure_export = crate::write_new_json(
            &evidence.join("candidate-finalization-failure.private.json"),
            &json!({
                "schema":"mmmm-rust-cli-candidate-finalization-failure/1","local_only":true,
                "production_error":result.as_ref().err().map(|error| error.to_string()),
                "production_error_detail":result.as_ref().err().map(|error| local_error(error.as_ref())),
                "private_diagnostics_export_error":private_audit.as_ref().err().map(|error| local_error(error.as_ref())),
                "attempt_export_error":exported.as_ref().err().map(|error| local_error(error.as_ref())),
                "finish_error":finish.as_ref().err().map(|error| error.to_string()),
                "finish_error_detail":finish.as_ref().err().map(|error| local_error(error)),
                "finish_receipt":finish.as_ref().ok(),
            }),
        );
        let mut failures = Vec::new();
        if let Err(error) = result {
            failures.push(("production".into(), error));
        }
        for (stage, export) in [
            ("private_diagnostics_export", private_audit),
            ("attempt_export", exported),
        ] {
            if let Err(error) = export {
                failures.push((stage.into(), error));
            }
        }
        match finish {
            Err(error) => failures.push(("managed_finalization".into(), Box::new(error))),
            Ok(receipt) if incomplete_finish => failures.push((
                "managed_finalization".into(),
                format!(
                    "lease_released={}, supervisor_errors={:?}, cleanup_errors={:?}",
                    receipt.lease_released, receipt.supervisor_errors, receipt.cleanup_errors,
                )
                .into(),
            )),
            Ok(_) => {}
        }
        if let Err(error) = failure_export {
            failures.push(("finalization_diagnostics_export".into(), error));
        }
        return Err(Box::new(CandidateFailures { failures }));
    }
    let receipt = finish?;
    let prepared = result?;
    if Instant::now() >= run.deadline || run.cancellation.load(Ordering::Acquire) {
        return Err("candidate completed storage after its request deadline or cancellation; candidate completion withheld".into());
    }
    let complete = json!({
        "schema":"mmmm-rust-cli-candidate-complete/1", "scope":"development_candidate", "candidate":prepared,
        "managed_completion":{"schema":receipt.schema,"slot_id":receipt.slot_id,"command_exit":receipt.command_exit,
            "drained":true,"scratch_removed":receipt.scratch_removed,"lease_released":receipt.lease_released,
            "supervisor_error_count":receipt.supervisor_errors.len(),"cleanup_error_count":receipt.cleanup_errors.len()},
        "product_proof_issued":false,
        "acceptance_verification":"not_run", "release_verification":"not_run",
    });
    crate::write_new_json(&evidence.join("candidate-complete.json"), &complete)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"mmmm-rust-cli-candidate-result/1","scope":"development_candidate","candidate":complete["candidate"],"product_proof_issued":false,"acceptance_verification":"not_run","release_verification":"not_run"})
        )?
    );
    Ok(0)
}

fn produce(run: &mut Run, checkout: &Path, tools: &Tools, expected: &str) -> Result<Value> {
    let source = run.build.paths().scratch.join("source");
    run.check()?;
    verify_plain_ancestors(&run.target)?;
    // Fixed slot and fixed target: prior products require an actual completed
    // same-input producer record. Unknown or failed products are preserved.
    let prior = match previous_cache(run) {
        Ok(previous) => previous,
        Err(error) => {
            run.preserve_cache = true;
            return Err(error);
        }
    };
    // Until the current inputs admit reuse, any preflight failure preserves the
    // previously completed target instead of letting normal finish evict it.
    run.preserve_cache = prior.is_some();
    fs::create_dir(&source)?;
    let before = source_pins(run, checkout, tools, expected, Some(&source))?;
    let source_bytes = serde_json::to_vec(&before)?;
    write_new(
        &run.build
            .paths()
            .evidence
            .join("candidate-source-inputs.json"),
        &source_bytes,
    )?;
    reject_cargo_configs(&source, &run.build.paths().cargo_home)?;
    let mut images = Vec::new();
    for (role, path) in [
        ("git", &tools.git),
        ("cargo", &tools.cargo),
        ("rustc", &tools.rustc),
        ("producer", &tools.producer),
    ] {
        let bytes = read_plain(path, MAX_IMAGE_BYTES, || run.check())?;
        images.push(Pin {
            path: role.into(),
            sha256: sha(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    let selected_environment_sha = environment_digest(&run.environment(Some(&tools.rustc)))?;
    let selected_program_paths_sha = environment_digest(&BTreeMap::from([
        (OsString::from("cargo"), tools.cargo.as_os_str().to_owned()),
        (OsString::from("rustc"), tools.rustc.as_os_str().to_owned()),
        (OsString::from("git"), tools.git.as_os_str().to_owned()),
        (
            OsString::from("producer"),
            tools.producer.as_os_str().to_owned(),
        ),
        (OsString::from("build_cwd"), source.as_os_str().to_owned()),
    ]))?;
    if let Some(previous) = prior.as_ref()
        && (previous.binding.inputs["source_sha"] != expected
            || previous.binding.inputs["source_inputs_sha256"] != sha(&source_bytes)
            || previous.binding.inputs["selected_tool_images"] != serde_json::to_value(&images)?
            || previous.binding.inputs["environment_sha256"] != selected_environment_sha
            || previous.binding.inputs["selected_program_paths_sha256"]
                != selected_program_paths_sha)
    {
        return Err("known completed candidate cache is incompatible with current source, tools or selected environment; no Cargo mutation admitted".into());
    }
    let rustc = run.capture(
        "rustc_version",
        &tools.rustc,
        &source,
        &args(&["-vV"]),
        None,
    )?;
    let version = std::str::from_utf8(&rustc)?;
    let target = native_target()?;
    if !version.lines().any(|line| line == "release: 1.96.0")
        || !version
            .lines()
            .any(|line| line == format!("host: {target}"))
    {
        return Err(
            "selected compiler version/host differs from the fixed candidate toolchain".into(),
        );
    }
    let cargo_version = run.capture(
        "cargo_version",
        &tools.cargo,
        &source,
        &args(&["-vV"]),
        Some(&tools.rustc),
    )?;
    if !std::str::from_utf8(&cargo_version)?.starts_with("cargo 1.96.0 ") {
        return Err("selected Cargo differs from the fixed candidate toolchain".into());
    }
    let metadata = run.capture(
        "cargo_resolved_inputs",
        &tools.cargo,
        &source,
        &args(&[
            "metadata",
            "--offline",
            "--locked",
            "--filter-platform",
            target,
            "--format-version",
            "1",
        ]),
        Some(&tools.rustc),
    )?;
    let package_id = cli_package_id(&metadata, &source.join("apps/mmmm/Cargo.toml"))?;
    let dependency_before = dependency_pins(run, &metadata, &package_id, &source)?;
    let dependency_bytes = serde_json::to_vec(&dependency_before)?;
    if dependency_bytes.len() as u64 > MAX_CACHE_MANIFEST_BYTES {
        return Err("candidate dependency manifest exceeds its byte cap".into());
    }
    write_new(
        &run.build
            .paths()
            .evidence
            .join("candidate-dependency-inputs.json"),
        &dependency_bytes,
    )?;
    check_snapshot_inputs(run, &source, &before)?;
    let build_args = [
        "build",
        "--offline",
        "--locked",
        "--release",
        "--target",
        target,
        "-p",
        "mmmm",
        "--bin",
        "mmmm",
        "--message-format=json-render-diagnostics",
    ];
    let cache_inputs = json!({
        "source_sha":expected,"source_inputs_sha256":sha(&source_bytes),"dependency_inputs_sha256":sha(&dependency_bytes),
        "selected_tool_images":images,"rustc_version_sha256":sha(&rustc),"cargo_version_sha256":sha(&cargo_version),
        "target":target,"profile":"release","arguments":build_args,"environment_sha256":selected_environment_sha,
        "selected_program_paths_sha256":selected_program_paths_sha,
        "source_layout":"fixed_slot_scratch_source","product_version":"0.1.0",
    });
    let cache_inputs_sha = sha(&serde_json::to_vec(&cache_inputs)?);
    let expected_binary = run
        .target
        .join(target)
        .join("release")
        .join(if cfg!(windows) { "mmmm.exe" } else { "mmmm" });
    let cache_reuse = match prior.as_ref() {
        None => json!({"status":"cold_empty_target"}),
        Some(previous) => {
            if previous.binding.inputs != cache_inputs {
                return Err("fixed candidate target has products from different inputs; preserve it for explicit owned cache lifecycle handling".into());
            }
            if compiler_artifact(
                &previous.build_stdout,
                &package_id,
                &source.join("apps/mmmm/Cargo.toml"),
                &expected_binary,
            )? {
                return Err(
                    "prior candidate did not produce its CLI after the closed package clean".into(),
                );
            }
            json!({"status":"verified_previous_success","previous_binding_sha256":previous.pointer.binding_sha256,
                "previous_inventory_sha256":previous.inventory_sha256,"actual_workproducts_sha256":sha(&serde_json::to_vec(&previous.binding.workproducts)?)})
        }
    };
    run.preserve_cache = false;
    // Closed cleanup of this CLI package only. Dependencies, other targets,
    // slots and global caches are never selected by this command.
    run.capture(
        "rust_cli_package_clean",
        &tools.cargo,
        &source,
        &args(&["clean", "--release", "--target", target, "-p", "mmmm"]),
        Some(&tools.rustc),
    )?;
    let output = run.capture(
        "rust_cli_build",
        &tools.cargo,
        &source,
        &args(&build_args),
        Some(&tools.rustc),
    )?;
    let fresh = compiler_artifact(
        &output,
        &package_id,
        &source.join("apps/mmmm/Cargo.toml"),
        &expected_binary,
    )?;
    if fresh {
        return Err(
            "candidate CLI unexpectedly reused a product after its closed package clean".into(),
        );
    }
    run.check()?;
    verify_plain_ancestors(&expected_binary)?;
    let executable = read_plain(&expected_binary, MAX_IMAGE_BYTES, || run.check())?;
    if executable.is_empty() {
        return Err("candidate CLI executable is empty".into());
    }
    let after = source_pins(run, checkout, tools, expected, None)?;
    if before != after {
        return Err("candidate source inputs changed during the owned build".into());
    }
    if dependency_before != dependency_pins(run, &metadata, &package_id, &source)? {
        return Err(
            "candidate resolved dependency source inputs changed during the owned build".into(),
        );
    }
    check_snapshot_inputs(run, &source, &before)?;
    for (index, path) in [&tools.git, &tools.cargo, &tools.rustc, &tools.producer]
        .into_iter()
        .enumerate()
    {
        let bytes = read_plain(path, MAX_IMAGE_BYTES, || run.check())?;
        if sha(&bytes) != images[index].sha256 {
            return Err("candidate tool image changed".into());
        }
    }
    if cache_inputs["environment_sha256"]
        != environment_digest(&run.environment(Some(&tools.rustc)))?
    {
        return Err("candidate selected environment changed during the owned build".into());
    }
    let workproducts = cache_workproducts(run)?;
    let build_ordinal = run
        .commands
        .iter()
        .position(|record| record["label"] == "rust_cli_build")
        .ok_or("candidate build command record missing")?;
    let binding = CacheBinding {
        schema: "mmmm-rust-cli-cache-binding/1".into(),
        inputs: cache_inputs,
        workproducts,
        build_ordinal,
        build_stdout_sha256: sha(&output),
    };
    let binding_bytes = serde_json::to_vec(&binding)?;
    if binding_bytes.len() as u64 > MAX_CACHE_MANIFEST_BYTES {
        return Err("candidate cache binding exceeds its byte cap".into());
    }
    write_new(
        &run.build
            .paths()
            .evidence
            .join("candidate-cache-binding.json"),
        &binding_bytes,
    )?;
    let archive_path = run
        .build
        .paths()
        .evidence
        .join("rust-cli-development-candidate.zip");
    let entry = if cfg!(windows) {
        "bin/mmmm.exe"
    } else {
        "bin/mmmm"
    };
    run.check()?;
    write_archive(&archive_path, entry, &executable, || run.check())?;
    let archive = read_plain(&archive_path, MAX_IMAGE_BYTES + 4096, || run.check())?;
    verify_archive(&archive, entry, &executable, || run.check())?;
    let inventory = json!({
        "schema":"mmmm-rust-cli-candidate-inventory/1", "scope":"development_candidate", "source_sha":expected,
        "source_inputs_sha256":sha(&source_bytes), "os":std::env::consts::OS, "arch":std::env::consts::ARCH,
        "dependency_inputs_sha256":sha(&dependency_bytes),
        "cache_inputs_sha256":cache_inputs_sha,"cache_binding_sha256":sha(&binding_bytes),
        "archive":{"path":"rust-cli-development-candidate.zip","sha256":sha(&archive),"bytes":archive.len()},
        "entries":[{"path":entry,"role":"rust_cli","sha256":sha(&executable),"bytes":executable.len()}],
        "build":{"action":"owned_fixed_cargo_build","cargo_reported_fresh":fresh,
            "cli_codegen_status":"cargo_reported_compiled_after_closed_package_clean","previous_build_products":cache_reuse,
            "target":target,"profile":"release","rustc_version_sha256":sha(&rustc),"cargo_version_sha256":sha(&cargo_version),"selected_tool_images":images},
        "missing_roles":["jvm_host","native_observer","other_os_platform_bundles","sbom","notice_review","vanilla_output","actual_acceptance_results"],
        "limitations":["Selected tool executable images and versions are observed; Rust sysroot, codegen backends, native linker, SDK and system libraries are not independently authenticated by this candidate.","Resolved registry source bytes are observed before and after this build in its managed Cargo home; their derivation from a registry archive is not independently authenticated by this candidate.","Filesystem identity checks are cooperative; no hostile same-user mutation resistance is claimed."],
        "product_proof_issued":false,"acceptance_verification":"not_run","release_verification":"not_run",
    });
    let mut inventory = inventory;
    inventory["cache_observation"] =
        json!("bounded_sequential_digest_not_atomic_or_continuous_immutability");
    inventory["product_authority"] =
        json!("immutable_candidate_bytes_do_not_grant_resource_access_or_release_authority");
    let bytes = serde_json::to_vec(&inventory)?;
    write_new(
        &run.build.paths().evidence.join("candidate-inventory.json"),
        &bytes,
    )?;
    run.check()?;
    let measurement = run.build.measure_with_progress(&mut || run.check())?;
    if !measurement.within_budget {
        return Err("candidate final managed disk budget exceeded".into());
    }
    run.check()?;
    publish_pending_cache(run, prior.as_ref(), &sha(&binding_bytes))?;
    Ok(
        json!({"archive_sha256":sha(&archive),"archive_bytes":archive.len(),"inventory_sha256":sha(&bytes),"source_sha":expected,"source_inputs_sha256":sha(&source_bytes),"dependency_inputs_sha256":sha(&dependency_bytes),"cache_binding_sha256":sha(&binding_bytes),"cargo_reported_fresh":fresh}),
    )
}

fn source_pins(
    run: &mut Run,
    checkout: &Path,
    tools: &Tools,
    expected: &str,
    copy: Option<&Path>,
) -> Result<SourcePins> {
    let head = run.capture(
        "git_head",
        &tools.git,
        checkout,
        &args(&["--no-optional-locks", "rev-parse", "--verify", "HEAD"]),
        None,
    )?;
    if std::str::from_utf8(&head)?.trim() != expected {
        return Err("candidate source differs from expected HEAD".into());
    }
    let mut list_args = args(&[
        "--no-optional-locks",
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        "HEAD",
        "--",
    ]);
    list_args.extend(INPUT_ROOTS.iter().map(OsString::from));
    let list = run.capture("git_tracked_inputs", &tools.git, checkout, &list_args, None)?;
    let mut paths = std::str::from_utf8(&list)?
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    paths.sort();
    if paths.len() > MAX_INPUT_FILES {
        return Err("candidate tracked input count exceeded".into());
    }
    // Reject secret names before Git status or any content read under these roots.
    for path in &paths {
        safe_relative(path)?;
    }
    let mut status_args = args(&[
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
        "--",
    ]);
    status_args.extend(INPUT_ROOTS.iter().map(OsString::from));
    if !run
        .capture("git_source_clean", &tools.git, checkout, &status_args, None)?
        .is_empty()
    {
        return Err("candidate tracked source is not clean at HEAD".into());
    }
    let mut archive_args = args(&[
        "--no-optional-locks",
        "-c",
        if cfg!(windows) {
            "core.attributesFile=NUL"
        } else {
            "core.attributesFile=/dev/null"
        },
        "archive",
        "--format=zip",
        "HEAD",
        "--",
    ]);
    // `git archive` rejects a pathspec absent from HEAD; only include existing
    // fixed roots, still using the already checked complete HEAD filename list.
    archive_args.extend(
        INPUT_ROOTS
            .iter()
            .filter(|root| {
                paths
                    .iter()
                    .any(|path| path == **root || path.starts_with(&format!("{root}/")))
            })
            .map(OsString::from),
    );
    let archived = run.capture(
        "git_head_source_bytes",
        &tools.git,
        checkout,
        &archive_args,
        None,
    )?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archived))?;
    if archive.len() > MAX_INPUT_FILES * 8 {
        return Err("candidate HEAD archive entry limit exceeded".into());
    }
    let mut pins = Vec::new();
    let mut total = 0u64;
    for path in paths {
        if !source_input(&path) {
            continue;
        }
        run.check()?;
        let full = checkout.join(&path);
        verify_plain_ancestors(&full)?;
        let workspace_bytes = read_plain(&full, MAX_SOURCE_FILE, || run.check())?;
        let mut entry = archive.by_name(&path)?;
        if !entry.is_file() || entry.size() > MAX_SOURCE_FILE {
            return Err("candidate HEAD source entry rejected".into());
        }
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 65_536];
        loop {
            run.check()?;
            let n = entry.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if bytes.len() as u64 + n as u64 > MAX_SOURCE_FILE {
                return Err("candidate HEAD source entry grew".into());
            }
            bytes.extend_from_slice(&buffer[..n]);
        }
        if bytes != workspace_bytes {
            return Err("candidate tracked workspace bytes differ from exact HEAD".into());
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("candidate source byte overflow")?;
        if total > MAX_INPUT_BYTES {
            return Err("candidate source byte budget exceeded".into());
        }
        if path == "rust-toolchain.toml"
            && !std::str::from_utf8(&bytes)?
                .lines()
                .any(|line| line.trim() == "channel = \"1.96.0\"")
        {
            return Err("candidate toolchain declaration is unsupported".into());
        }
        if let Some(root) = copy {
            let target = root.join(&path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            write_new(&target, &bytes)?;
        }
        pins.push(Pin {
            path,
            sha256: sha(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "apps/mmmm/Cargo.toml",
        "apps/mmmm/src/main.rs",
        "tools/mmmm-xtask/src/candidate.rs",
    ] {
        if !pins.iter().any(|pin| pin.path == required) {
            return Err("required tracked candidate input is missing".into());
        }
    }
    Ok(SourcePins {
        source_sha: expected.into(),
        files: pins,
    })
}

fn source_input(path: &str) -> bool {
    path == "Cargo.lock"
        || ["rs", "toml", "json", "c", "h"]
            .iter()
            .any(|ext| path.ends_with(&format!(".{ext}")))
}

fn public_commands(commands: &[Value]) -> Vec<Value> {
    commands.iter().map(|record| json!({
        "ordinal":record["ordinal"],"label":record["label"],
        "process_started":record["process_started"],"command_exit":record["process"]["command_exit"],
        "drained":record["process"]["drained"].as_bool().or_else(|| record["error"]["drained"].as_bool()),
        "output_complete":record["process"]["output_complete"],"error_kind":record["error"]["kind"],
        "stdout_read_status":record["stdout_read"]["status"],
        "stdout_read_error_kind":record["stdout_read"]["error"]["kind"],
        "raw_exports":record["raw_exports"].as_array().map(|exports| exports.iter().map(|export| json!({
            "stream":export["stream"],"status":export["status"],"stage":export["stage"],
            "bytes":export["bytes"],"error_kind":export["error"]["kind"],
        })).collect::<Vec<_>>()),
    })).collect()
}

fn local_error(error: &(dyn std::error::Error + 'static)) -> Value {
    let mut diagnostic = json!({"message":error.to_string()});
    if let Some(error) = error.downcast_ref::<process::ProcessError>() {
        diagnostic["kind"] = json!(error.kind);
        diagnostic["drained"] = json!(error.drained);
    } else if let Some(error) = error.downcast_ref::<std::io::Error>() {
        diagnostic["kind"] = json!("io");
        diagnostic["io_kind"] = json!(format!("{:?}", error.kind()));
        diagnostic["raw_os_error"] = json!(error.raw_os_error());
    } else if let Some(error) = error.downcast_ref::<storage::StorageError>() {
        diagnostic["kind"] = json!(error.kind);
    } else {
        diagnostic["kind"] = json!("candidate");
    }
    diagnostic
}

fn strict_stdout_read_error_count(commands: &[Value]) -> usize {
    commands
        .iter()
        .filter(|command| command["stdout_read"]["status"] == "failed")
        .count()
}

fn raw_export_error_count(commands: &[Value]) -> usize {
    commands
        .iter()
        .filter_map(|command| command["raw_exports"].as_array())
        .flat_map(|exports| exports.iter())
        .filter(|export| export["status"] == "failed")
        .count()
}

fn child_observations(commands: &[Value], drained: bool) -> Value {
    let started = commands
        .iter()
        .filter(|command| command["process_started"] == true)
        .count();
    let unknown = commands
        .iter()
        .filter(|command| command["process_started"].is_null())
        .count();
    json!({"started_count":started,"start_unknown_count":unknown,
        "status":if unknown != 0 { "child_start_observation_incomplete" } else if started == 0 { "no_child_started" } else if drained { "started_children_observed_drained" } else { "started_child_drain_unconfirmed" },
        "scope_drained":if started == 0 && unknown == 0 { Value::Null } else { json!(drained) },
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePointer {
    schema: String,
    previous_evidence_leaf: String,
    binding_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheBinding {
    schema: String,
    inputs: Value,
    workproducts: Vec<Pin>,
    build_ordinal: usize,
    build_stdout_sha256: String,
}

struct PreviousCache {
    pointer: CachePointer,
    pointer_bytes: Vec<u8>,
    binding: CacheBinding,
    build_stdout: Vec<u8>,
    inventory_sha256: String,
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn previous_cache(run: &Run) -> Result<Option<PreviousCache>> {
    run.check()?;
    verify_plain_ancestors(&run.target)?;
    match fs::read_dir(&run.target)?.next() {
        None => return Ok(None),
        Some(Err(error)) => return Err(Box::new(error)),
        Some(Ok(_)) => {}
    }
    let pointer_path = run.target.join(CACHE_POINTER);
    match fs::symlink_metadata(&pointer_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("fixed candidate target contains products without a completed producer locator; unknown cache preserved".into()),
        Err(error) => return Err(Box::new(error)),
        Ok(_) => {},
    }
    verify_plain_ancestors(&pointer_path)?;
    let pointer_bytes = read_plain(&pointer_path, 8192, || run.check())?;
    let current_leaf = run
        .build
        .paths()
        .evidence
        .file_name()
        .ok_or("candidate current evidence identity missing")?;
    let pointer = parse_cache_pointer(&pointer_bytes, current_leaf)?;
    // The locator has no absolute path authority. Resolve only in this admitted
    // evidence root's same slot, never another run root or a global cache.
    let previous = run
        .build
        .paths()
        .evidence
        .parent()
        .ok_or("candidate evidence slot missing")?
        .join(&pointer.previous_evidence_leaf);
    verify_plain_ancestors(&previous)?;
    let read = |name: &str, cap| -> Result<Vec<u8>> {
        let path = previous.join(name);
        verify_plain_ancestors(&path)?;
        read_plain(&path, cap, || run.check())
    };
    let binding_bytes = read("candidate-cache-binding.json", MAX_CACHE_MANIFEST_BYTES)?;
    if sha(&binding_bytes) != pointer.binding_sha256 {
        return Err(
            "previous candidate cache binding digest mismatch; unknown cache preserved".into(),
        );
    }
    let binding: CacheBinding = serde_json::from_slice(&binding_bytes)?;
    if binding.schema != "mmmm-rust-cli-cache-binding/1"
        || !binding.inputs.is_object()
        || binding.workproducts.len() > MAX_CACHE_FILES
        || binding.build_ordinal >= 16
        || !hex64(&binding.build_stdout_sha256)
    {
        return Err("previous candidate cache binding is invalid; unknown cache preserved".into());
    }
    for (name, field) in [
        ("candidate-source-inputs.json", "source_inputs_sha256"),
        (
            "candidate-dependency-inputs.json",
            "dependency_inputs_sha256",
        ),
    ] {
        let bytes = read(name, MAX_CACHE_MANIFEST_BYTES)?;
        if binding.inputs[field] != sha(&bytes) {
            return Err(
                "previous candidate immutable input digest mismatch; unknown cache preserved"
                    .into(),
            );
        }
    }
    let complete: Value =
        serde_json::from_slice(&read("candidate-complete.json", MAX_CACHE_MANIFEST_BYTES)?)?;
    let finish: Value = serde_json::from_slice(&read("finish.json", 8192)?)?;
    let attempt: Value = serde_json::from_slice(&read("candidate-attempt.json", 65_536)?)?;
    let slot_id = run
        .build
        .paths()
        .slot
        .file_name()
        .ok_or("candidate slot identity missing")?
        .to_str()
        .ok_or("candidate slot identity is not UTF-8")?;
    if complete["schema"] != "mmmm-rust-cli-candidate-complete/1"
        || complete["scope"] != "development_candidate"
        || complete["product_proof_issued"] != false
        || complete["acceptance_verification"] != "not_run"
        || complete["release_verification"] != "not_run"
        || complete["candidate"]["cache_binding_sha256"] != pointer.binding_sha256
        || complete["candidate"]["source_sha"] != binding.inputs["source_sha"]
        || complete["candidate"]["source_inputs_sha256"] != binding.inputs["source_inputs_sha256"]
        || complete["candidate"]["dependency_inputs_sha256"]
            != binding.inputs["dependency_inputs_sha256"]
        || finish["schema"] != "mmmm-managed-build/1"
        || finish["slot_id"] != slot_id
        || finish["command_exit"] != 0
        || finish["lease_released"] != true
        || finish["scratch_removed"] != true
        || finish["slot_evicted"] != false
        || finish["supervisor_errors"]
            .as_array()
            .is_none_or(|items| !items.is_empty())
        || finish["cleanup_errors"]
            .as_array()
            .is_none_or(|items| !items.is_empty())
        || complete["managed_completion"]["slot_id"] != slot_id
        || complete["managed_completion"]["drained"] != true
        || complete["managed_completion"]["lease_released"] != true
        || complete["managed_completion"]["scratch_removed"] != true
        || complete["managed_completion"]["supervisor_error_count"] != 0
        || complete["managed_completion"]["cleanup_error_count"] != 0
        || attempt["schema"] != "mmmm-rust-cli-candidate-attempt/1"
        || attempt["candidate_prepared"] != true
        || attempt["required_evidence_exported"] != true
        || attempt["drained"] != true
    {
        return Err("previous candidate success and actual managed completion do not agree; cache preserved".into());
    }
    let inventory_bytes = read("candidate-inventory.json", MAX_CACHE_MANIFEST_BYTES)?;
    let inventory_sha256 = sha(&inventory_bytes);
    let inventory: Value = serde_json::from_slice(&inventory_bytes)?;
    if complete["candidate"]["inventory_sha256"] != inventory_sha256
        || inventory["cache_binding_sha256"] != pointer.binding_sha256
        || inventory["cache_inputs_sha256"] != sha(&serde_json::to_vec(&binding.inputs)?)
        || inventory["source_sha"] != binding.inputs["source_sha"]
        || inventory["source_inputs_sha256"] != binding.inputs["source_inputs_sha256"]
        || inventory["dependency_inputs_sha256"] != binding.inputs["dependency_inputs_sha256"]
    {
        return Err(
            "previous candidate inventory does not bind its cache producer; cache preserved".into(),
        );
    }
    let archive_bytes = read("rust-cli-development-candidate.zip", MAX_IMAGE_BYTES + 4096)?;
    if complete["candidate"]["archive_sha256"] != sha(&archive_bytes)
        || inventory["archive"]["sha256"] != sha(&archive_bytes)
        || complete["candidate"]["archive_bytes"] != archive_bytes.len()
        || inventory["archive"]["bytes"] != archive_bytes.len()
    {
        return Err(
            "previous candidate actual archive differs from its completed record; cache preserved"
                .into(),
        );
    }
    let cli_path = format!(
        "{}/release/{}",
        native_target()?,
        if cfg!(windows) { "mmmm.exe" } else { "mmmm" }
    );
    let cli_pin = binding
        .workproducts
        .iter()
        .find(|pin| pin.path == cli_path)
        .ok_or("previous candidate CLI workproduct pin missing")?;
    if inventory["entries"]
        .as_array()
        .is_none_or(|items| items.len() != 1)
        || inventory["entries"][0]["sha256"] != cli_pin.sha256
        || inventory["entries"][0]["bytes"] != cli_pin.bytes
    {
        return Err(
            "previous candidate inventory does not identify its actual cached CLI; cache preserved"
                .into(),
        );
    }
    let audit: Value = serde_json::from_slice(&read(
        "candidate-private-diagnostics.json",
        MAX_CACHE_MANIFEST_BYTES,
    )?)?;
    let commands = audit["commands"]
        .as_array()
        .ok_or("previous candidate command evidence missing")?;
    if audit["schema"] != "mmmm-rust-cli-candidate-private-diagnostics/1"
        || audit["local_only"] != true
        || commands.len() > 16
        || !audit.get("error").is_some_and(Value::is_null)
        || audit["supervisor_errors"]
            .as_array()
            .is_none_or(|items| !items.is_empty())
    {
        return Err(
            "previous candidate command evidence is not successful; cache preserved".into(),
        );
    }
    let command = commands
        .get(binding.build_ordinal)
        .ok_or("previous candidate build command missing")?;
    if command["ordinal"] != binding.build_ordinal
        || command["label"] != "rust_cli_build"
        || !successful_command(command)
    {
        return Err("previous candidate actual build did not succeed; cache preserved".into());
    }
    let cleans = commands
        .iter()
        .filter(|record| record["label"] == "rust_cli_package_clean")
        .collect::<Vec<_>>();
    if cleans.len() != 1
        || !successful_command(cleans[0])
        || cleans[0]["ordinal"]
            .as_u64()
            .is_none_or(|ordinal| ordinal >= binding.build_ordinal as u64)
    {
        return Err(
            "previous candidate closed CLI cleanup did not succeed; cache preserved".into(),
        );
    }
    let build_stdout = read(
        &format!("candidate-{}.stdout", binding.build_ordinal),
        MAX_COMMAND_BYTES as u64,
    )?;
    if sha(&build_stdout) != binding.build_stdout_sha256 {
        return Err("previous candidate actual Cargo output differs; cache preserved".into());
    }
    // Validate existing products before any Cargo version/metadata/clean/build
    // call may alter this fixed target. The pointer is checked separately.
    if cache_workproducts(run)? != binding.workproducts {
        return Err("fixed candidate target no longer matches the completed producer; unknown cache preserved".into());
    }
    Ok(Some(PreviousCache {
        pointer,
        pointer_bytes,
        binding,
        build_stdout,
        inventory_sha256,
    }))
}

fn parse_cache_pointer(bytes: &[u8], current_leaf: &std::ffi::OsStr) -> Result<CachePointer> {
    if bytes.len() > 8192 {
        return Err("candidate cache locator byte cap exceeded".into());
    }
    let pointer: CachePointer = serde_json::from_slice(bytes)?;
    if pointer.schema != "mmmm-rust-cli-cache-pointer/1"
        || !hex64(&pointer.previous_evidence_leaf)
        || !hex64(&pointer.binding_sha256)
    {
        return Err(
            "fixed candidate cache has an invalid producer locator; unknown cache preserved".into(),
        );
    }
    if current_leaf == std::ffi::OsStr::new(&pointer.previous_evidence_leaf) {
        return Err("pending current candidate record cannot authorize cache reuse".into());
    }
    Ok(pointer)
}

fn successful_command(command: &Value) -> bool {
    command["process_started"] == true
        && command["process"]["command_exit"] == 0
        && command["process"]["drained"] == true
        && command["process"]["output_complete"] == true
        && command["process"]["supervisor_errors"]
            .as_array()
            .is_some_and(|items| items.is_empty())
        && command["error"].is_null()
}

fn cache_workproducts(run: &Run) -> Result<Vec<Pin>> {
    let mut pins = Vec::new();
    // Reserve bounded space for the fixed binding inputs and JSON envelope.
    cache_tree(run, &run.target, &mut pins, &mut 0, &mut 0, &mut 65_536)?;
    pins.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(pins)
}

fn cache_tree(
    run: &Run,
    directory: &Path,
    pins: &mut Vec<Pin>,
    total: &mut u64,
    entries: &mut usize,
    manifest_bytes: &mut usize,
) -> Result<()> {
    run.check()?;
    if directory
        .components()
        .count()
        .saturating_sub(run.target.components().count())
        > 64
    {
        return Err("candidate cache depth cap exceeded".into());
    }
    let mut children = Vec::new();
    for entry in fs::read_dir(directory)? {
        run.check()?;
        *entries += 1;
        if *entries > MAX_CACHE_FILES {
            return Err("candidate cache entry cap exceeded".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("candidate cache entry is not UTF-8")?;
        admit_relative(name, true)?;
        if directory == run.target && name == CACHE_POINTER {
            continue;
        }
        let path = entry.path();
        admit_relative(&relative_cache_path(&path, &run.target)?, true)?;
        children.push(path);
    }
    children.sort();
    for path in children {
        run.check()?;
        verify_plain_ancestors(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            cache_tree(run, &path, pins, total, entries, manifest_bytes)?;
        } else if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .ok_or("candidate cache byte count overflow")?;
            if *total > MAX_CACHE_BYTES {
                return Err("candidate cache byte cap exceeded".into());
            }
            let relative = relative_cache_path(&path, &run.target)?;
            admit_relative(&relative, true)?;
            let (digest, bytes) = stream_digest(&path, metadata.len(), || run.check())?;
            let pin = Pin {
                path: relative,
                sha256: digest,
                bytes,
            };
            *manifest_bytes = manifest_bytes
                .checked_add(serde_json::to_vec(&pin)?.len() + 1)
                .ok_or("candidate cache manifest size overflow")?;
            if *manifest_bytes as u64 > MAX_CACHE_MANIFEST_BYTES {
                return Err("candidate cache manifest byte cap exceeded before retention".into());
            }
            pins.push(pin);
        } else {
            return Err("candidate cache special entry rejected".into());
        }
    }
    Ok(())
}

fn relative_cache_path(path: &Path, root: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .components()
        .map(|part| {
            part.as_os_str()
                .to_str()
                .ok_or("candidate cache path is not UTF-8")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("/"))
}

fn stream_digest(
    path: &Path,
    expected: u64,
    mut check: impl FnMut() -> std::result::Result<(), String>,
) -> Result<(String, u64)> {
    check()?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != expected {
        return Err("candidate cache file changed before read".into());
    }
    let mut digests = Vec::new();
    for pass in 0..2 {
        if pass != 0 {
            file.seek(SeekFrom::Start(0))?;
        }
        let mut digest = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 65_536];
        loop {
            check()?;
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .ok_or("candidate cache file count overflow")?;
            if count > expected {
                return Err("candidate cache file grew during read".into());
            }
            digest.update(&buffer[..n]);
        }
        if count != expected {
            return Err("candidate cache file was truncated".into());
        }
        digests.push(format!("{:x}", digest.finalize()));
    }
    let after = file.metadata()?;
    check()?;
    if digests[0] != digests[1]
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err("candidate same-handle cache bytes changed".into());
    }
    Ok((digests.remove(0), expected))
}

fn environment_digest(environment: &BTreeMap<OsString, OsString>) -> Result<String> {
    let mut digest = Sha256::new();
    let mut total = 0usize;
    for (key, value) in environment {
        for field in [key, value] {
            #[cfg(unix)]
            let bytes = {
                use std::os::unix::ffi::OsStrExt;
                field.as_os_str().as_bytes().to_vec()
            };
            #[cfg(windows)]
            let bytes = {
                use std::os::windows::ffi::OsStrExt;
                field
                    .as_os_str()
                    .encode_wide()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            };
            #[cfg(not(any(unix, windows)))]
            let bytes = field
                .to_str()
                .ok_or("candidate environment encoding unsupported")?
                .as_bytes()
                .to_vec();
            total = total
                .checked_add(bytes.len())
                .ok_or("candidate selected environment overflow")?;
            if total > 262_144 || bytes.len() > 65_536 {
                return Err("candidate selected environment cap exceeded".into());
            }
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn publish_pending_cache(
    run: &Run,
    previous: Option<&PreviousCache>,
    binding_sha256: &str,
) -> Result<()> {
    run.check()?;
    verify_plain_ancestors(&run.target)?;
    let path = run.target.join(CACHE_POINTER);
    match previous {
        Some(previous) => {
            verify_plain_ancestors(&path)?;
            if read_plain(&path, 8192, || run.check())? != previous.pointer_bytes {
                return Err("candidate producer locator changed during owned build".into());
            }
        }
        None => match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Box::new(error)),
            Ok(_) => return Err("unexpected candidate producer locator appeared".into()),
        },
    }
    let leaf = run
        .build
        .paths()
        .evidence
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("candidate evidence leaf missing")?;
    if !hex64(leaf) || !hex64(binding_sha256) {
        return Err("candidate producer locator identity invalid".into());
    }
    let pointer = CachePointer {
        schema: "mmmm-rust-cli-cache-pointer/1".into(),
        previous_evidence_leaf: leaf.into(),
        binding_sha256: binding_sha256.into(),
    };
    let bytes = serde_json::to_vec(&pointer)?;
    let temporary = run
        .build
        .paths()
        .scratch
        .join("candidate-cache-pointer.next.json");
    write_new(&temporary, &bytes)?;
    run.check()?;
    fs::rename(temporary, &path)?;
    #[cfg(unix)]
    {
        std::fs::File::open(&run.target)?.sync_all()?;
    }
    run.check()?;
    // This pointer is pending until the referenced actual managed finish and
    // candidate-complete exist. A failed finalization never grants cache reuse.
    Ok(())
}

fn safe_relative(path: &str) -> Result<()> {
    admit_relative(path, false)
}

fn admit_relative(path: &str, owned_cargo_target: bool) -> Result<()> {
    if path.len() > 1024
        || path.split('/').count() > 64
        || path.contains(['\\', '\0', '\r', '\n', ':'])
        || Path::new(path).is_absolute()
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("unsafe candidate source path".into());
    }
    for component in path.split('/') {
        let name = component.to_ascii_lowercase();
        if name == ".env"
            || name.starts_with(".env.")
            || name == ".ssh"
            || name.contains("credential")
            || name.contains("api_key")
            || name.contains("api-key")
            || name.contains("apikey")
            || name.contains("service-account")
            || name.contains("service_account")
            || name.contains("serviceaccount")
            || ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"].contains(&name.as_str())
            || [".pem", ".key", ".p12", ".pfx", ".keystore"]
                .iter()
                .any(|s| name.ends_with(s))
            || [
                "node_modules",
                "dist",
                "dist-server",
                "coverage",
                "models",
                "checkpoints",
                ".cache",
            ]
            .contains(&name.as_str())
            || (name == "build" && !owned_cargo_target)
        {
            return Err("forbidden candidate source path".into());
        }
    }
    Ok(())
}

fn selected_tool(path: PathBuf, name: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path.file_stem().and_then(|v| v.to_str()) != Some(name)
    {
        return Err("candidate tools require exact absolute executable paths".into());
    }
    selected_image(path, false)
}

fn selected_image(path: PathBuf, owned_self_image: bool) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("candidate image requires an exact absolute path".into());
    }
    for component in path.components() {
        if let Component::Normal(value) = component {
            admit_relative(
                value.to_str().ok_or("candidate tool path is not UTF-8")?,
                owned_self_image,
            )?;
        }
    }
    verify_plain_ancestors(&path)?;
    Ok(fs::canonicalize(path)?)
}

fn verify_plain_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            return Err("candidate link path rejected".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("candidate reparse path rejected".into());
            }
        }
    }
    Ok(())
}

fn read_plain(
    path: &Path,
    cap: u64,
    mut check: impl FnMut() -> std::result::Result<(), String>,
) -> Result<Vec<u8>> {
    check()?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny concurrent writers/deletion while this exact image is consumed.
        options.share_mode(1);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > cap {
        return Err("candidate file kind/byte cap rejected".into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 65_536];
    loop {
        check()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 + n as u64 > cap {
            return Err("candidate file grew beyond cap".into());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    if bytes.len() as u64 != before.len() {
        return Err("candidate file length changed".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0usize;
    loop {
        check()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if bytes.get(offset..offset + n) != Some(&buffer[..n]) {
            return Err("candidate same-handle bytes changed".into());
        }
        offset += n;
    }
    let after = file.metadata()?;
    check()?;
    if offset != bytes.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err("candidate file metadata changed".into());
    }
    Ok(bytes)
}

fn reject_cargo_configs(source: &Path, cargo_home: &Path) -> Result<()> {
    // Cargo traverses ancestor configs even with explicit args and CARGO_HOME.
    for root in source.ancestors().chain(std::iter::once(cargo_home)) {
        for path in [
            root.join(".cargo/config"),
            root.join(".cargo/config.toml"),
            root.join("config"),
            root.join("config.toml"),
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Err("candidate refuses external Cargo configuration".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
    Ok(())
}

fn cli_package_id(metadata: &[u8], manifest: &Path) -> Result<String> {
    let value: Value = serde_json::from_slice(metadata)?;
    let packages = value["packages"]
        .as_array()
        .ok_or("candidate package metadata missing")?;
    if packages.len() > 512 {
        return Err("candidate resolved package limit exceeded".into());
    }
    let mut matched = packages.iter().filter(|package| {
        package["name"] == "mmmm"
            && package["version"] == "0.1.0"
            && package["manifest_path"].as_str().map(Path::new) == Some(manifest)
    });
    let package = matched
        .next()
        .ok_or("candidate exact workspace CLI package missing")?;
    if matched.next().is_some() {
        return Err("candidate exact workspace CLI package repeated".into());
    }
    Ok(package["id"]
        .as_str()
        .ok_or("candidate workspace package ID missing")?
        .to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DependencyPins {
    schema: &'static str,
    // Public package names/versions and paths relative to each registry package.
    packages: BTreeMap<String, Vec<Pin>>,
}

fn dependency_pins(
    run: &Run,
    metadata: &[u8],
    root_id: &str,
    source: &Path,
) -> Result<DependencyPins> {
    use std::collections::BTreeSet;
    let value: Value = serde_json::from_slice(metadata)?;
    let packages = value["packages"]
        .as_array()
        .ok_or("candidate packages missing")?;
    let nodes = value["resolve"]["nodes"]
        .as_array()
        .ok_or("candidate resolved dependency graph missing")?;
    if packages.len() > 512 || nodes.len() > 512 {
        return Err("candidate resolved package count exceeded".into());
    }
    let mut selected = BTreeSet::new();
    let mut pending = vec![root_id.to_owned()];
    while let Some(id) = pending.pop() {
        run.check()?;
        if !selected.insert(id.clone()) {
            continue;
        }
        if selected.len() > 512 {
            return Err("candidate dependency closure exceeded".into());
        }
        let mut matched = nodes.iter().filter(|node| node["id"] == id);
        let node = matched
            .next()
            .ok_or("candidate resolved package node missing")?;
        if matched.next().is_some() {
            return Err("candidate resolved package node repeated".into());
        }
        let dependencies = node["deps"]
            .as_array()
            .ok_or("candidate resolved dependency edges missing")?;
        if dependencies.len() > 512 {
            return Err("candidate dependency edge count exceeded".into());
        }
        for dependency in dependencies {
            let kinds = dependency["dep_kinds"]
                .as_array()
                .ok_or("candidate dependency kinds missing")?;
            if kinds.len() > 32 {
                return Err("candidate dependency kinds exceeded".into());
            }
            if kinds
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
            {
                pending.push(
                    dependency["pkg"]
                        .as_str()
                        .ok_or("candidate dependency package ID missing")?
                        .to_owned(),
                );
            }
        }
    }
    let registry = run.build.paths().cargo_home.join("registry/src");
    let mut result = DependencyPins {
        schema: "mmmm-rust-cli-dependency-inputs/1",
        packages: BTreeMap::new(),
    };
    let mut total = 0u64;
    let mut entries = 0usize;
    for id in selected {
        run.check()?;
        let mut matched = packages.iter().filter(|package| package["id"] == id);
        let package = matched
            .next()
            .ok_or("candidate resolved package metadata missing")?;
        if matched.next().is_some() {
            return Err("candidate resolved package metadata repeated".into());
        }
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("candidate resolved manifest missing")?,
        );
        if package["source"].is_null() {
            if !manifest.starts_with(source) {
                return Err("candidate external path dependency rejected".into());
            }
            continue; // Every tracked workspace source was copied and pinned above.
        }
        if package["source"] != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err("candidate unregistered dependency source rejected".into());
        }
        let name = package["name"]
            .as_str()
            .ok_or("candidate dependency name missing")?;
        let version = package["version"]
            .as_str()
            .ok_or("candidate dependency version missing")?;
        if [name, version].iter().any(|part| {
            part.is_empty()
                || part.len() > 128
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        }) {
            return Err("candidate dependency public identity rejected".into());
        }
        let package_name = format!("{name}-{version}");
        let relative = manifest
            .strip_prefix(&registry)
            .map_err(|_| "candidate dependency is outside its managed registry source")?;
        let parts = relative.components().collect::<Vec<_>>();
        if parts.len() != 3
            || parts
                .iter()
                .any(|part| !matches!(part, Component::Normal(_)))
            || parts[1].as_os_str() != std::ffi::OsStr::new(&package_name)
            || parts[2].as_os_str() != std::ffi::OsStr::new("Cargo.toml")
        {
            return Err("candidate dependency registry package path rejected".into());
        }
        for part in &parts {
            safe_relative(
                part.as_os_str()
                    .to_str()
                    .ok_or("candidate dependency path is not UTF-8")?,
            )?;
        }
        let root = manifest
            .parent()
            .ok_or("candidate dependency root missing")?;
        verify_plain_ancestors(root)?;
        let mut files = Vec::new();
        pin_input_tree(run, root, root, &mut files, &mut total, &mut entries)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        if result
            .packages
            .insert(format!("{name}@{version}"), files)
            .is_some()
        {
            return Err("candidate dependency public identity repeated".into());
        }
    }
    Ok(result)
}

fn check_snapshot_inputs(run: &Run, source: &Path, expected: &SourcePins) -> Result<()> {
    let mut files = Vec::new();
    pin_input_tree(run, source, source, &mut files, &mut 0, &mut 0)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    if files != expected.files {
        return Err(
            "actual candidate source snapshot changed or gained unregistered inputs".into(),
        );
    }
    Ok(())
}

fn pin_input_tree(
    run: &Run,
    root: &Path,
    directory: &Path,
    files: &mut Vec<Pin>,
    total: &mut u64,
    entries: &mut usize,
) -> Result<()> {
    run.check()?;
    if directory
        .components()
        .count()
        .saturating_sub(root.components().count())
        > 32
    {
        return Err("candidate dependency depth exceeded".into());
    }
    let mut children = Vec::new();
    for entry in fs::read_dir(directory)? {
        run.check()?;
        *entries += 1;
        if *entries > MAX_DEPENDENCY_FILES {
            return Err("candidate dependency entry budget exceeded".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        safe_relative(
            name.to_str()
                .ok_or("candidate dependency entry is not UTF-8")?,
        )?;
        children.push(entry.path());
    }
    children.sort();
    for path in children {
        run.check()?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("candidate dependency link rejected".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("candidate dependency reparse entry rejected".into());
            }
        }
        if metadata.is_dir() {
            pin_input_tree(run, root, &path, files, total, entries)?;
        } else if metadata.is_file() {
            let bytes = read_plain(&path, MAX_DEPENDENCY_FILE, || run.check())?;
            *total = total
                .checked_add(bytes.len() as u64)
                .ok_or("candidate dependency byte overflow")?;
            if *total > MAX_DEPENDENCY_BYTES {
                return Err("candidate dependency byte budget exceeded".into());
            }
            let relative = path
                .strip_prefix(root)?
                .components()
                .map(|part| {
                    part.as_os_str()
                        .to_str()
                        .ok_or("candidate dependency path is not UTF-8")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
                .join("/");
            files.push(Pin {
                path: relative,
                sha256: sha(&bytes),
                bytes: bytes.len() as u64,
            });
        } else {
            return Err("candidate dependency special entry rejected".into());
        }
    }
    Ok(())
}

fn compiler_artifact(
    stdout: &[u8],
    package_id: &str,
    manifest: &Path,
    executable: &Path,
) -> Result<bool> {
    let mut artifact = None;
    let mut finished = false;
    for line in stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 1024 * 1024 || finished {
            return Err("candidate Cargo record budget/order invalid".into());
        }
        let value: Value = serde_json::from_slice(line)?;
        match value["reason"].as_str() {
            Some("compiler-artifact")
                if value["target"]["name"] == "mmmm"
                    && value["target"]["kind"] == json!(["bin"]) =>
            {
                if artifact.is_some()
                    || value["manifest_path"].as_str().map(Path::new) != Some(manifest)
                    || value["executable"].as_str().map(Path::new) != Some(executable)
                    || value["profile"]["test"] != false
                    || value["package_id"] != package_id
                {
                    return Err(
                        "candidate executable is not the one exact owned CLI artifact".into(),
                    );
                }
                artifact = Some(
                    value["fresh"]
                        .as_bool()
                        .ok_or("candidate Cargo freshness missing")?,
                );
            }
            Some("build-finished") => {
                if value["success"] != true {
                    return Err("candidate Cargo build did not finish successfully".into());
                }
                finished = true;
            }
            Some("compiler-artifact" | "compiler-message" | "build-script-executed") => {}
            _ => return Err("candidate Cargo record kind invalid".into()),
        }
    }
    if !finished {
        return Err("candidate Cargo completion record missing".into());
    }
    artifact.ok_or_else(|| "candidate exact CLI artifact is missing".into())
}

fn write_archive(
    path: &Path,
    entry: &str,
    bytes: &[u8],
    mut check: impl FnMut() -> std::result::Result<(), String>,
) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(path)?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o755);
    writer.start_file(entry, options)?;
    for chunk in bytes.chunks(65_536) {
        check()?;
        writer.write_all(chunk)?;
    }
    check()?;
    writer.finish()?.sync_all()?;
    Ok(())
}

fn verify_archive(
    bytes: &[u8],
    entry: &str,
    executable: &[u8],
    mut check: impl FnMut() -> std::result::Result<(), String>,
) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    if archive.len() != 1 {
        return Err("candidate archive entry count changed".into());
    }
    let mut file = archive.by_index(0)?;
    if file.name() != entry
        || file.size() != executable.len() as u64
        || !file.is_file()
        || file.compression() != zip::CompressionMethod::Stored
    {
        return Err("candidate archive inventory changed".into());
    }
    let mut buffer = [0u8; 65_536];
    let mut offset = 0usize;
    loop {
        check()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if executable.get(offset..offset + n) != Some(&buffer[..n]) {
            return Err("candidate archive bytes changed".into());
        }
        offset += n;
    }
    if offset != executable.len() {
        return Err("candidate archive payload truncated".into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
fn native_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        _ => Err("candidate native target is unsupported".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_path_admission_rejects_secret_and_heavy_components() {
        for path in [
            "crates/x/.env",
            "crates/x/service-account.json",
            "crates/x/node_modules/a.rs",
            "../a.rs",
            "crates/x/api_key.json",
        ] {
            assert!(safe_relative(path).is_err());
        }
        assert!(safe_relative("crates/mmmm-runtime/src/storage/journal.rs").is_ok());
        assert!(!source_input("docs/private.md"));
    }

    #[test]
    fn cargo_artifact_requires_owned_path_identity_and_actual_completion() {
        let manifest = Path::new("source/apps/mmmm/Cargo.toml");
        let executable = Path::new("target/release/mmmm");
        let artifact = json!({"reason":"compiler-artifact","package_id":"path+file:///source/apps/mmmm#mmmm@0.1.0","manifest_path":manifest,"target":{"name":"mmmm","kind":["bin"]},"executable":executable,"profile":{"test":false},"fresh":true});
        let complete = json!({"reason":"build-finished","success":true});
        let bytes = format!("{artifact}\n{complete}\n");
        let package = artifact["package_id"].as_str().unwrap();
        assert!(compiler_artifact(bytes.as_bytes(), package, manifest, executable).unwrap());
        assert!(
            compiler_artifact(
                artifact.to_string().as_bytes(),
                package,
                manifest,
                executable
            )
            .is_err()
        );
        assert!(
            compiler_artifact(
                bytes.as_bytes(),
                package,
                manifest,
                Path::new("foreign/mmmm")
            )
            .is_err()
        );
        assert!(
            compiler_artifact(
                format!("{artifact}\n{artifact}\n{complete}\n").as_bytes(),
                package,
                manifest,
                executable
            )
            .is_err()
        );
    }

    #[test]
    fn cache_locator_cannot_escape_its_slot_or_admit_the_pending_run() {
        let leaf = "a".repeat(64);
        let pointer = json!({"schema":"mmmm-rust-cli-cache-pointer/1","previous_evidence_leaf":leaf,"binding_sha256":"b".repeat(64)});
        assert!(
            parse_cache_pointer(
                pointer.to_string().as_bytes(),
                std::ffi::OsStr::new(&"c".repeat(64))
            )
            .is_ok()
        );
        assert!(
            parse_cache_pointer(pointer.to_string().as_bytes(), std::ffi::OsStr::new(&leaf))
                .is_err()
        );
        let mut escaped = pointer;
        escaped["previous_evidence_leaf"] = json!("../foreign");
        assert!(
            parse_cache_pointer(
                escaped.to_string().as_bytes(),
                std::ffi::OsStr::new("current")
            )
            .is_err()
        );
        assert!(safe_relative("release/build").is_err());
        assert!(admit_relative("release/build", true).is_ok());
        assert!(admit_relative("release/build/.env", true).is_err());
    }

    #[test]
    fn cache_producer_success_keeps_native_failures_distinct() {
        let good = json!({"process_started":true,"process":{"command_exit":0,"drained":true,"output_complete":true,"supervisor_errors":[]}});
        assert!(successful_command(&good));
        for field in ["drained", "output_complete"] {
            let mut bad = good.clone();
            bad["process"][field] = json!(false);
            assert!(!successful_command(&bad));
        }
        let mut bad = good;
        bad["process"]["supervisor_errors"] = json!(["actual supervision failure"]);
        assert!(!successful_command(&bad));
        assert_eq!(child_observations(&[], true)["status"], "no_child_started");
        assert!(child_observations(&[], true)["scope_drained"].is_null());
        assert_eq!(
            child_observations(&[json!({"process_started":true})], true)["status"],
            "started_children_observed_drained"
        );
    }
}
