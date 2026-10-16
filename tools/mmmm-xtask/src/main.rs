use mmmm_xtask::{definition_startup, policy, process, storage};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

mod candidate;

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
    let command = args.next().ok_or(
        "expected run, candidate-build, definition-startup, check-repository or bootstrap-complete",
    )?;
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
        "candidate-build" => {
            if child_separator || !child_args.is_empty() {
                return Err("candidate-build accepts no child command or arguments".into());
            }
            candidate::run(checkout, flags)
        }
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

fn export_retained_log(
    source: &Path,
    destination: &Path,
    checkpoint: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), Box<dyn std::error::Error>> {
    checkpoint()?;
    validate_local_ancestry(source, false, true)?;
    checkpoint()?;
    let metadata = fs::symlink_metadata(source)?;
    checkpoint()?;
    if !metadata.is_file() || is_link(&metadata) || metadata.len() > 64 * 1024 * 1024 {
        return Err("managed command log kind or size invalid".into());
    }
    let mut input = fs::File::open(source)?;
    checkpoint()?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    checkpoint()?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        checkpoint()?;
        let count = input.read(&mut buffer)?;
        checkpoint()?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or("managed log byte count overflow")?;
        if copied > metadata.len() {
            return Err("managed command log size changed during export".into());
        }
        output.write_all(&buffer[..count])?;
        checkpoint()?;
    }
    if copied != metadata.len() {
        return Err("managed command log size changed during export".into());
    }
    checkpoint()?;
    output.sync_all()?;
    checkpoint()?;
    Ok(())
}

fn write_new_json_with_checkpoint(
    path: &Path,
    value: &serde_json::Value,
    checkpoint: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), Box<dyn std::error::Error>> {
    checkpoint()?;
    let encoded = serde_json::to_vec_pretty(value)?;
    checkpoint()?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    checkpoint()?;
    for chunk in encoded.chunks(64 * 1024) {
        checkpoint()?;
        file.write_all(chunk)?;
        checkpoint()?;
    }
    file.write_all(b"\n")?;
    checkpoint()?;
    file.sync_all()?;
    checkpoint()?;
    Ok(())
}

struct RetainedPreservation {
    started: Instant,
}

impl RetainedPreservation {
    fn check(&self) -> Result<(), String> {
        if self.started.elapsed() >= Duration::from_secs(30) {
            return Err("retained post-drain preservation deadline exceeded".into());
        }
        Ok(())
    }

    fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "phase": "post_drain_preservation",
            "clock_origin": "confirmed_native_drain_result_received",
            "budget_ms": 30_000,
            "elapsed_ms": u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "original_cancel_ignored_for_preservation_only": true,
            "game_execution_permitted": false,
            "os_io_preemptible": false,
        })
    }
}

struct RetainedRunOptions {
    root: PathBuf,
    launch_directory: Option<PathBuf>,
    stop_after: Option<Duration>,
}

fn retained_run_options(
    flags: &mut BTreeMap<String, String>,
    purpose: &str,
    tail_policy: process::TailPolicy,
    timeout: u64,
) -> Result<Option<RetainedRunOptions>, Box<dyn std::error::Error>> {
    let root = optional_path(flags, "--retained-game-root");
    let launch_directory = optional_path(flags, "--retained-game-launch-directory");
    let stop_after = flags
        .remove("--minecraft-stop-after-seconds")
        .map(|value| value.parse::<u64>())
        .transpose()?;
    let Some(root) = root else {
        if stop_after.is_some() {
            return Err("Minecraft stop requires --retained-game-root".into());
        }
        if launch_directory.is_some() {
            return Err("retained game launch directory requires --retained-game-root".into());
        }
        return Ok(None);
    };
    if !root.is_absolute() {
        return Err("retained game root must be absolute".into());
    }
    if launch_directory
        .as_ref()
        .is_some_and(|directory| !directory.is_absolute())
    {
        return Err("retained game launch directory must be absolute".into());
    }
    if purpose != "jvm" {
        return Err("retained game mode requires purpose jvm".into());
    }
    if tail_policy != process::TailPolicy::Reject {
        return Err("retained game mode requires owned tail policy reject".into());
    }
    if stop_after.is_some_and(|seconds| !(1..=3600).contains(&seconds) || seconds >= timeout) {
        return Err(
            "Minecraft stop must be 1..3600 seconds and less than the command timeout".into(),
        );
    }
    Ok(Some(RetainedRunOptions {
        root,
        launch_directory,
        stop_after: stop_after.map(Duration::from_secs),
    }))
}

struct MinecraftStopSchedule {
    handle: process::MinecraftStopHandle,
    after: Duration,
    requested_at_elapsed_ms: Option<u64>,
}

impl MinecraftStopSchedule {
    fn request_if_due(
        &mut self,
        phase: process::ObservationPhase,
        elapsed: Duration,
    ) -> Result<(), String> {
        if phase == process::ObservationPhase::Running
            && self.requested_at_elapsed_ms.is_none()
            && elapsed >= self.after
        {
            self.handle.request().map_err(|error| error.to_string())?;
            self.requested_at_elapsed_ms =
                Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
        }
        Ok(())
    }

    fn report(&self, observation_interval: Duration) -> serde_json::Value {
        serde_json::json!({
            "after_seconds": self.after.as_secs(),
            "clock_origin": "supervision_request_start_before_retained_admission",
            "pre_spawn_observation_included": true,
            "exact_spawn_clock": false,
            "request_phase": "running_observation",
            "observation_interval_ms": u64::try_from(observation_interval.as_millis()).unwrap_or(u64::MAX),
            "measurement_work_may_delay_request": true,
            "requested_at_elapsed_ms": self.requested_at_elapsed_ms,
            "acknowledgement": "not_observed",
        })
    }
}

fn process_error_report(error: &process::ProcessError) -> serde_json::Value {
    let mut report = serde_json::json!({
        "kind": error.kind,
        "message": error.message,
        "drained": error.drained,
    });
    if let Some(stop) = &error.minecraft_stop {
        report["minecraft_stop"] = serde_json::json!(stop);
    }
    report
}

fn storage_error_report(error: &storage::StorageError) -> serde_json::Value {
    let mut report = serde_json::json!({"kind": error.kind, "message": error.message});
    let mut cause = std::error::Error::source(error);
    let mut causes = Vec::new();
    // 실제 오류 연결을 유한하게 보존하며 파일이나 환경을 추가로 조회하지 않는다.
    for _ in 0..16 {
        let Some(current) = cause else { break };
        causes.push(
            if let Some(typed) = current.downcast_ref::<storage::StorageError>() {
                serde_json::json!({"kind": typed.kind, "message": typed.message})
            } else {
                serde_json::json!({"message": current.to_string()})
            },
        );
        cause = current.source();
    }
    if !causes.is_empty() {
        report["causes"] = causes.into();
    }
    if cause.is_some() {
        report["causes_truncated"] = true.into();
    }
    report
}

fn retained_completion_report(
    completion: &storage::retained_game::RetainedCompletion,
    supervisor_errors: &mut Vec<String>,
) -> serde_json::Value {
    let within_budget = completion.observed_before_release.within_budget;
    let mut report = serde_json::json!({
        "schema": "mmmm-retained-game-completion/1",
        "status": if within_budget { "released" } else { "released_over_budget" },
        "completion": completion,
        "game_save_acknowledgement": "not_observed",
    });
    if !within_budget {
        let message = "final retained game and managed disk measurement exceeds resource budget";
        report["error"] = serde_json::json!({"kind": "resource_budget", "message": message});
        supervisor_errors.push(format!("resource_budget: {message}"));
    }
    report
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
    let retained_options = retained_run_options(&mut flags, &purpose, tail_policy, timeout)?;
    let managed_jvm_helper = purpose == "jvm" && retained_options.is_none();
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
    // retained 입장과 spawn 전 관측도 같은 요청 기한을 소비한다. 일반 run의 시계는 바꾸지 않는다.
    let supervision_requested_at = retained_options.as_ref().map(|_| Instant::now());
    let request_deadline =
        supervision_requested_at.map(|start| start + Duration::from_secs(timeout));
    let mut original_checkpoint = || {
        if cancellation.load(std::sync::atomic::Ordering::Acquire) {
            return Err("managed command cancelled".into());
        }
        if request_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err("original managed command deadline exceeded".into());
        }
        Ok(())
    };
    let explicit_alias_requested = retained_options
        .as_ref()
        .is_some_and(|options| options.launch_directory.is_some());
    let mut explicit_alias_validated = false;
    let (mut retained, retained_launch_directory) = if let Some(options) = &retained_options {
        let admission = storage::retained_game::RetainedGame::acquire(
            &build,
            &checkout,
            &options.root,
            &mut original_checkpoint,
        )
        .and_then(|retained| {
            let directory = retained.game_directory_for_launch(
                options.launch_directory.as_deref(),
                &mut original_checkpoint,
            )?;
            explicit_alias_validated = explicit_alias_requested;
            Ok((retained, directory))
        });
        match admission {
            Ok((retained, directory)) => (Some(retained), Some(directory)),
            Err(error) => {
                let report = serde_json::json!({
                    "schema": "mmmm-retained-game-admission/1",
                    "status": "admission_failed",
                    "error": storage_error_report(&error),
                    "explicit_alias_requested": explicit_alias_requested,
                    "explicit_alias_validated": explicit_alias_validated,
                    "build_lease_release_attempted": false,
                });
                if let Err(export) =
                    write_new_json(&build.paths().evidence.join("game-admission.json"), &report)
                {
                    eprintln!("retained admission evidence export: {export}");
                }
                return Err(Box::new(error));
            }
        }
    } else {
        (None, None)
    };
    let mut stop_schedule = retained_options
        .as_ref()
        .and_then(|options| options.stop_after)
        .map(|after| MinecraftStopSchedule {
            handle: process::MinecraftStopHandle::new(),
            after,
            requested_at_elapsed_ms: None,
        });
    let stdout = build.paths().scratch.join("command.stdout.log");
    let stderr = build.paths().scratch.join("command.stderr.log");
    let cwd = match retained_launch_directory {
        Some(directory) => directory,
        None => fs::canonicalize(&checkout)?,
    };
    let mut spec = process::ProcessSpec::new(program, cwd, stdout.clone(), stderr.clone());
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
    if retained.is_some() {
        spec.env.insert(
            "MMMM_RETAINED_GAME_DIR".into(),
            spec.cwd.clone().into_os_string(),
        );
    }
    spec.env.insert("CARGO_BUILD_JOBS".into(), "2".into());
    spec.timeout = Duration::from_secs(timeout);
    spec.tail_policy = tail_policy;
    spec.resource_policy = resource_policy;
    spec.absolute_deadline = request_deadline;
    spec.minecraft_stop = stop_schedule
        .as_ref()
        .map(|schedule| schedule.handle.clone());
    let mut observation_retries = storage::ObservationRetryLog::default();
    let mut retained_measurement = None;
    let result =
        process::supervise_with_progress_phased(&spec, &cancellation, |phase, checkpoint| {
            if let Some(retained) = &retained {
                let mut current = || {
                    checkpoint()?;
                    original_checkpoint()
                };
                let measurement = retained
                    .measure_with_progress(&mut current)
                    .map_err(|error| error.to_string())?;
                let within_budget = measurement.within_budget;
                retained_measurement = Some(measurement);
                if !within_budget {
                    return Err("combined retained game and managed disk budget exceeded".into());
                }
                current()?;
                if let (Some(schedule), Some(started)) =
                    (&mut stop_schedule, supervision_requested_at)
                {
                    schedule.request_if_due(phase, started.elapsed())?;
                }
                return Ok(());
            }
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
    // 원 실행 결과는 그대로 두고, 확인된 drain 뒤의 보존에만 별도 유한 기한을 사용한다.
    let native_drained = match &result {
        Ok(outcome) => outcome.drained,
        Err(error) => error.drained,
    };
    let preservation = if retained.is_some() && native_drained {
        Some(RetainedPreservation {
            started: Instant::now(),
        })
    } else {
        None
    };
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
        // Display의 기존 Linux 진단도 원 supervisor_errors에 그대로 보존한다.
        Err(error) => (
            None,
            error.drained,
            vec![error.to_string()],
            false,
            process_error_report(&error),
        ),
    };
    let mut preservation_checkpoint = || {
        preservation
            .as_ref()
            .ok_or("native drain is unconfirmed; preservation was not admitted")?
            .check()
    };
    if retained.is_some() {
        report["retained_game"] = serde_json::json!({
            "schema": "mmmm-retained-game-run/1",
            "working_directory": "validated_retained_game_directory",
            "working_directory_scope": "direct_child_only",
            "explicit_alias_requested": explicit_alias_requested,
            "explicit_alias_validated": explicit_alias_validated,
            "native_resource_policy_scope": "managed_jvm",
            "last_measurement": retained_measurement,
            "minecraft_stop_schedule": stop_schedule.as_ref().map(|schedule| schedule.report(spec.observation_interval)),
            "preservation": preservation.as_ref().map(RetainedPreservation::report),
            "game_save_acknowledgement": "not_observed",
        });
    }
    let (retry_summary, retry_export) =
        export_observation_retries(&build.paths().evidence, &observation_retries);
    report["storage_observation_retries"] = retry_summary;
    if let Err(error) = &retry_export {
        // Preserve this independent failure even if process.json also fails.
        supervisor_errors.push(format!("retry companion export: {error}"));
    }
    let mut exported = false;
    let export = (|| -> Result<(), Box<dyn std::error::Error>> {
        if let (Some(retained), Some(_)) = (&retained, &preservation) {
            let mut current = || {
                preservation_checkpoint()?;
                retained
                    .check_current_ownership()
                    .map_err(|error| storage_error_report(&error).to_string())?;
                preservation_checkpoint()
            };
            write_new_json_with_checkpoint(
                &build.paths().evidence.join("process.json"),
                &report,
                &mut current,
            )?;
        } else {
            // 미drain의 원 결과 진단은 남기되 retained 측정/완료/로그 복사는 시작하지 않는다.
            write_new_json(&build.paths().evidence.join("process.json"), &report)?;
        }
        retry_export?;
        if !drained {
            return Err("unconfirmed drain prevents command log export and cleanup".into());
        }
        if let Some(retained) = &retained {
            let measurement = retained.measure_with_progress(&mut preservation_checkpoint)?;
            if !measurement.within_budget {
                return Err("combined retained game and managed disk budget exceeded".into());
            }
        } else {
            build.measure()?;
        }
        for (source, name) in [
            (&stdout, "command.stdout.log"),
            (&stderr, "command.stderr.log"),
        ] {
            if let Some(retained) = &retained {
                let mut current = || {
                    preservation_checkpoint()?;
                    retained
                        .check_current_ownership()
                        .map_err(|error| storage_error_report(&error).to_string())?;
                    preservation_checkpoint()
                };
                current()?;
                let exists = source.try_exists()?;
                current()?;
                if exists {
                    export_retained_log(source, &build.paths().evidence.join(name), &mut current)?;
                }
            } else if source.try_exists()? {
                export_log(source, &build.paths().evidence.join(name))?;
            }
        }
        Ok(())
    })();
    match export {
        Ok(()) => exported = true,
        Err(error) => supervisor_errors.push(format!("evidence export: {error}")),
    }
    let mut finish_outcome = storage::FinishOutcome {
        command_exit,
        supervisor_errors,
        drained,
        evidence_exported: exported,
    };
    let mut game_completion = None;
    if let Some(retained) = retained.take() {
        if finish_outcome.drained && finish_outcome.evidence_exported {
            // 원시 로그 export가 늘린 저장량도 lease 해제 전에 같은 합산 예산으로 확인한다.
            match retained.measure_with_progress(&mut preservation_checkpoint) {
                Ok(measurement) if measurement.within_budget => {}
                Ok(_) => {
                    finish_outcome.evidence_exported = false;
                    finish_outcome.supervisor_errors.push(
                        "retained completion preparation: combined disk budget exceeded".into(),
                    );
                }
                Err(error) => {
                    finish_outcome.evidence_exported = false;
                    finish_outcome.supervisor_errors.push(format!(
                        "retained completion preparation: {}",
                        storage_error_report(&error),
                    ));
                }
            }
        }
        let mut completion_report = if !drained {
            // Drop만으로 lease나 game 자료를 변경하지 않는다. 미확인 scope의 정리는 입장시키지 않는다.
            drop(retained);
            serde_json::json!({
                "schema": "mmmm-retained-game-completion/1",
                "status": "not_attempted_undrained",
                "game_removal_attempted": false,
                "build_lease_release_attempted": false,
            })
        } else {
            match retained.complete(&finish_outcome, &mut preservation_checkpoint) {
                Ok(completion) => {
                    retained_completion_report(&completion, &mut finish_outcome.supervisor_errors)
                }
                Err(error) => {
                    finish_outcome.evidence_exported = false;
                    finish_outcome
                        .supervisor_errors
                        .push(format!("retained completion: {error}"));
                    serde_json::json!({
                        "schema": "mmmm-retained-game-completion/1",
                        "status": "release_unconfirmed",
                        "error": storage_error_report(&error),
                        "game_removal_attempted": false,
                        "build_lease_release_attempted": false,
                    })
                }
            }
        };
        completion_report["preservation"] =
            serde_json::json!(preservation.as_ref().map(RetainedPreservation::report));
        let completion_export = if preservation.is_some() {
            write_new_json_with_checkpoint(
                &build.paths().evidence.join("game-completion.json"),
                &completion_report,
                &mut preservation_checkpoint,
            )
        } else {
            write_new_json(
                &build.paths().evidence.join("game-completion.json"),
                &completion_report,
            )
        };
        if let Err(error) = completion_export {
            finish_outcome.evidence_exported = false;
            finish_outcome
                .supervisor_errors
                .push(format!("retained completion evidence export: {error}"));
            // 실제 complete 반환 사실은 남기되 receipt 내구성 실패를 lease 복구로 바꾸지 않는다.
            completion_report["status"] = "release_unconfirmed".into();
            completion_report["receipt_exported"] = false.into();
            completion_report["receipt_export_error"] = error.to_string().into();
            eprintln!(
                "retained completion evidence export: {error}; completion: {completion_report}"
            );
        } else {
            completion_report["receipt_exported"] = true.into();
        }
        game_completion = Some(completion_report);
    }
    drop(retained);
    let mut finalization = serde_json::json!({
        "schema": "mmmm-build-finalization-input/1",
        "command_exit": finish_outcome.command_exit,
        "drained": finish_outcome.drained,
        "evidence_exported": finish_outcome.evidence_exported,
        "supervisor_errors": finish_outcome.supervisor_errors,
    });
    if let Some(completion) = game_completion {
        finalization["retained_game"] = completion;
    }
    if let Some(preservation) = &preservation {
        finalization["retained_preservation"] = preservation.report();
        let finalization_export = write_new_json_with_checkpoint(
            &build.paths().evidence.join("finalization-input.json"),
            &finalization,
            &mut preservation_checkpoint,
        );
        if let Err(error) = finalization_export {
            // 남은 보존 기한을 넘겨 파일 작업을 재시도하지 않는다. 원 실패와 정리 실패를 분리해 출력한다.
            eprintln!(
                "retained finalization evidence export: {error}; finalization: {finalization}"
            );
            return Err(error);
        }
    } else {
        write_new_json(
            &build.paths().evidence.join("finalization-input.json"),
            &finalization,
        )?;
    }
    // retained borrow는 complete 또는 보존 실패로 끝난 뒤에만 build finish로 이동한다.
    let receipt = build.finish(finish_outcome)?;
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
    fn retained_options_reject_invalid_combinations_before_storage_admission() {
        let root = std::env::current_dir().unwrap();
        let root_text = root.to_str().unwrap();
        let mut generic = BTreeMap::new();
        assert!(
            retained_run_options(
                &mut generic,
                "fixture",
                process::TailPolicy::TerminateForBuild,
                1200,
            )
            .unwrap()
            .is_none()
        );
        assert!(generic.is_empty());
        for (purpose, tail, root_value, stop, timeout) in [
            ("jvm", process::TailPolicy::Reject, None, Some("1"), 2),
            (
                "fixture",
                process::TailPolicy::Reject,
                Some(root_text),
                None,
                2,
            ),
            (
                "jvm",
                process::TailPolicy::TerminateForBuild,
                Some(root_text),
                None,
                2,
            ),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some("relative-game-root"),
                None,
                2,
            ),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some(root_text),
                Some("0"),
                2,
            ),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some(root_text),
                Some("3601"),
                3600,
            ),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some(root_text),
                Some("2"),
                2,
            ),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some(root_text),
                Some("invalid"),
                2,
            ),
        ] {
            let mut flags = BTreeMap::new();
            if let Some(root) = root_value {
                flags.insert("--retained-game-root".into(), root.into());
            }
            if let Some(stop) = stop {
                flags.insert("--minecraft-stop-after-seconds".into(), stop.into());
            }
            assert!(retained_run_options(&mut flags, purpose, tail, timeout).is_err());
        }
        for stop in [None, Some("1")] {
            let mut flags = BTreeMap::from([("--retained-game-root".into(), root_text.into())]);
            if let Some(stop) = stop {
                flags.insert("--minecraft-stop-after-seconds".into(), stop.into());
            }
            let options = retained_run_options(&mut flags, "jvm", process::TailPolicy::Reject, 2)
                .unwrap()
                .unwrap();
            assert_eq!(options.root, root);
            assert!(options.launch_directory.is_none());
            assert_eq!(options.stop_after, stop.map(|_| Duration::from_secs(1)));
            assert!(flags.is_empty());
        }
        for (purpose, tail, root_value, launch_directory) in [
            ("jvm", process::TailPolicy::Reject, None, root_text),
            (
                "jvm",
                process::TailPolicy::Reject,
                Some(root_text),
                "relative-game-directory",
            ),
            (
                "fixture",
                process::TailPolicy::Reject,
                Some(root_text),
                root_text,
            ),
            (
                "jvm",
                process::TailPolicy::TerminateForBuild,
                Some(root_text),
                root_text,
            ),
        ] {
            let mut flags = BTreeMap::from([(
                "--retained-game-launch-directory".into(),
                launch_directory.into(),
            )]);
            if let Some(root) = root_value {
                flags.insert("--retained-game-root".into(), root.into());
            }
            assert!(retained_run_options(&mut flags, purpose, tail, 2).is_err());
            assert!(flags.is_empty());
        }
        let launch_directory = root.join("game");
        let mut flags = BTreeMap::from([
            ("--retained-game-root".into(), root_text.into()),
            (
                "--retained-game-launch-directory".into(),
                launch_directory.to_str().unwrap().into(),
            ),
        ]);
        let options = retained_run_options(&mut flags, "jvm", process::TailPolicy::Reject, 2)
            .unwrap()
            .unwrap();
        assert_eq!(options.root, root);
        assert_eq!(options.launch_directory, Some(launch_directory));
        assert!(options.stop_after.is_none());
        assert!(flags.is_empty());
    }

    #[test]
    fn minecraft_stop_schedule_waits_for_running_and_preserves_first_request_time() {
        let mut schedule = MinecraftStopSchedule {
            handle: process::MinecraftStopHandle::new(),
            after: Duration::from_secs(1),
            requested_at_elapsed_ms: None,
        };
        schedule
            .request_if_due(process::ObservationPhase::PreSpawn, Duration::from_secs(5))
            .unwrap();
        schedule
            .request_if_due(
                process::ObservationPhase::Running,
                Duration::from_millis(999),
            )
            .unwrap();
        assert_eq!(schedule.requested_at_elapsed_ms, None);
        schedule
            .request_if_due(
                process::ObservationPhase::Running,
                Duration::from_millis(5100),
            )
            .unwrap();
        schedule
            .request_if_due(process::ObservationPhase::Running, Duration::from_secs(8))
            .unwrap();
        assert_eq!(schedule.requested_at_elapsed_ms, Some(5100));
        let report = schedule.report(Duration::from_secs(5));
        assert_eq!(report["exact_spawn_clock"], false);
        assert_eq!(report["observation_interval_ms"], 5000);
        assert_eq!(report["requested_at_elapsed_ms"], 5100);
        assert_eq!(report["acknowledgement"], "not_observed");
    }

    #[test]
    fn process_and_retained_projection_preserves_original_failures_and_final_budget() {
        // 상대 실행 파일은 validate에서 거절되어 child, pipe, log를 만들지 않는다.
        let root = std::env::current_dir().unwrap();
        let spec = process::ProcessSpec::new(
            "relative-program".into(),
            root.clone(),
            root.join("unused-stdout"),
            root.join("unused-stderr"),
        );
        assert!(spec.minecraft_stop.is_none() && spec.absolute_deadline.is_none());
        let mut error = process::supervise(&spec, &AtomicBool::new(false), || Ok(())).unwrap_err();
        let generic = process_error_report(&error);
        assert_eq!(
            generic,
            serde_json::json!({
                "kind": error.kind, "message": error.message, "drained": error.drained,
            })
        );
        let original_display = error.to_string();
        // 아래 값은 직렬화 경계용 자료다. native 쓰기나 게임 처리 성공의 증거를 발급하지 않는다.
        error.minecraft_stop = Some(Box::new(process::MinecraftStopEvidence {
            requested: true,
            request_observed: true,
            control_closed: true,
            writer_available: true,
            writer_closed: true,
            write_attempts: 1,
            would_block: 0,
            last_would_block: None,
            bytes_written: 2,
            write_error: Some(process::MinecraftStopIoError {
                kind: "BrokenPipe".into(),
                raw_os_error: Some(109),
            }),
            close_error: None,
            pipe_capacity_bytes: Some(4096),
            write_mode: "projection_fixture",
            acknowledgement: "not_observed",
        }));
        let report = process_error_report(&error);
        assert_eq!(report["kind"], generic["kind"]);
        assert_eq!(report["message"], generic["message"]);
        assert_eq!(report["drained"], generic["drained"]);
        assert_eq!(error.to_string(), original_display);
        assert_eq!(report["minecraft_stop"]["bytes_written"], 2);
        assert_eq!(
            report["minecraft_stop"]["write_error"]["kind"],
            "BrokenPipe"
        );
        assert_eq!(report["minecraft_stop"]["write_error"]["raw_os_error"], 109);
        assert_eq!(report["minecraft_stop"]["acknowledgement"], "not_observed");
        let mut completion = storage::retained_game::RetainedCompletion {
            lease_released: true,
            game_retained: true,
            observed_before_release: storage::retained_game::RetainedMeasurement {
                game_bytes: 1,
                retained_bytes: 3,
                build_slot_bytes: 4,
                build_catalog_bytes: 5,
                combined_slot_bytes: 7,
                combined_catalog_bytes: 8,
                within_budget: true,
            },
        };
        let mut finish = storage::FinishOutcome {
            command_exit: Some(0),
            supervisor_errors: Vec::new(),
            drained: true,
            evidence_exported: true,
        };
        let admitted = retained_completion_report(&completion, &mut finish.supervisor_errors);
        assert_eq!(admitted["status"], "released");
        assert!(finish.supervisor_errors.is_empty());
        completion.observed_before_release.within_budget = false;
        let rejected = retained_completion_report(&completion, &mut finish.supervisor_errors);
        assert_eq!(rejected["status"], "released_over_budget");
        assert_eq!(rejected["completion"]["lease_released"], true);
        assert_eq!(
            rejected["completion"]["observed_before_release"]["within_budget"],
            false
        );
        assert_eq!(rejected["error"]["kind"], "resource_budget");
        // build finish와 전체 성공 gate가 공유하는 원 supervisor_errors에 남는다.
        assert_eq!(finish.supervisor_errors.len(), 1);
        assert!(finish.supervisor_errors[0].starts_with("resource_budget:"));
        assert!(finish.drained && finish.evidence_exported);
    }

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
