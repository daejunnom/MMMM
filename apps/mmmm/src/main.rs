use mmmm_coordinator::{
    daemon::DaemonError,
    native_entry::{self, EntryError},
    stdio_io::{self, NativeStdioPort, StdioLimits},
};
use std::{fmt, path::PathBuf, sync::Arc};

mod command_io;
mod mcp;

const USAGE: &str = "Usage:\n\
  mmmm init --data-root <absolute root> --name <name> --target-profile <profile>\n\
  mmmm start --data-root <absolute root> --project <projectId>\n\
  mmmm daemon --data-root <absolute root> --project <projectId> [--lifetime-seconds <1..1800>]\n\
  mmmm host-setup --data-root <absolute root> --project <projectId> --host-jar <absolute jar> --output <absolute config> --scope-json <json>\n\
  mmmm source-import --data-root <absolute root> --project <projectId> --expected-revision <sha256> --document <prefab|instance|clip>:<JSON> [--document <kind>:<JSON> ...]\n\
    Source import is a cold native management command: 1..256 documents, each <=8 MiB, total <=32 MiB; actual OS argv limits may be smaller.\n\
    Prefab and Clip references can share a batch. The data root must contain an initialized Project and have no active daemon owner; referenced resource bytes must already be retained.\n\
  mmmm call <function.name> --data-root <absolute root> [--json|--summary] < request.json\n\
  mmmm mcp --data-root <absolute root>\n\
  mmmm --version\n";

#[derive(Debug)]
enum CliError {
    Arguments,
    Native(EntryError),
    Command(command_io::CommandIoError),
    Mcp(mcp::FacadeError),
    Diagnostic {
        primary: Box<CliError>,
        delivery: command_io::CommandIoError,
    },
}
impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments => write!(f, "CLI arguments are invalid.\n{USAGE}"),
            Self::Native(error) => PublicEntryError(error).fmt(f),
            Self::Command(error) => error.fmt(f),
            Self::Mcp(error) => error.fmt(f),
            Self::Diagnostic { delivery, .. } => {
                write!(f, "CLI failure diagnostic delivery failed: {delivery}")
            }
        }
    }
}
impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Arguments => None,
            Self::Native(error) => Some(error),
            Self::Command(error) => Some(error),
            Self::Mcp(error) => Some(error),
            Self::Diagnostic { primary, .. } => Some(primary.as_ref()),
        }
    }
}

/// Caller DTOs and server messages are retained in typed errors, never copied
/// into stderr. Public committed locators and fixed native error codes remain
/// available even when result delivery or shutdown failed.
struct PublicEntryError<'a>(&'a EntryError);
impl fmt::Display for PublicEntryError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            EntryError::Daemon(error) => PublicDaemonError(error).fmt(f),
            EntryError::Output(error) => write!(f, "Native result delivery failed: {error}"),
            EntryError::OutputDrain { primary, cleanup } => write!(
                f,
                "Native result output failed: {}; output drain failed: {}",
                PublicEntryError(primary),
                PublicEntryError(cleanup)
            ),
            EntryError::Shutdown { primary, cleanup } => {
                if let Some(primary) = primary {
                    write!(f, "{}; ", PublicEntryError(primary))?;
                }
                write!(f, "Coordinator shutdown is unresolved: {cleanup}")
            }
            EntryError::Initialized {
                project,
                revision,
                delivery,
            } => write!(
                f,
                "Project {project} at revision {revision} was initialized and retained; result delivery failed: {}",
                PublicEntryError(delivery)
            ),
            EntryError::SourcesCommitted { receipt, delivery } => write!(
                f,
                "Project {} advanced from {} to {} with committed sources retained; result delivery failed: {}",
                receipt.project_id,
                receipt.base_revision,
                receipt.project_revision,
                PublicEntryError(delivery)
            ),
            // EntryError's other diagnostics contain fixed text, public pins,
            // or static native-operation codes with bounded numeric metadata.
            error => error.fmt(f),
        }
    }
}
struct PublicDaemonError<'a>(&'a DaemonError);
impl fmt::Display for PublicDaemonError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            DaemonError::Application(error) => write!(
                f,
                "{}: Native daemon application admission failed",
                error.code
            ),
            DaemonError::AfterInitialization {
                project,
                revision,
                source,
            } => write!(
                f,
                "Project {project} at revision {revision} was initialized and retained; daemon composition failed: {}",
                PublicDaemonError(source)
            ),
            error => error.fmt(f),
        }
    }
}

fn main() {
    let primary = match run() {
        Ok(()) => std::process::exit(0),
        Err(error) => error,
    };
    // A failed diagnostic has one separate finite attempt. Keep its cause and
    // original command error together until exit; no recursive stderr owner.
    let failure = match command_io::diagnostic(&primary) {
        Ok(()) => primary,
        Err(delivery) => CliError::Diagnostic {
            primary: Box::new(primary),
            delivery,
        },
    };
    let exit = if matches!(&failure, CliError::Diagnostic { .. }) {
        3
    } else {
        2
    };
    std::process::exit(exit);
}

fn run() -> Result<(), CliError> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| CliError::Arguments))
        .collect::<Result<Vec<_>, _>>()?;
    // The inherited helper must run before native command parsing or any
    // facade initialization. Its private protocol has no application output.
    if args.first().map(String::as_str) == Some(stdio_io::WORKER_COMMAND) {
        stdio_io::worker_entry_exit(&args[1..]);
    }
    if native_entry::dispatch(&args).map_err(CliError::Native)? {
        return Ok(());
    }
    match args.as_slice() {
        [command] if command == "--version" => command_io::public_output(
            format!(
                "MMMM {} (contract {})\n",
                env!("CARGO_PKG_VERSION"),
                mmmm_contracts::CONTRACT_VERSION
            )
            .as_bytes(),
        )
        .map_err(CliError::Command),
        [command] if matches!(command.as_str(), "--help" | "help") => {
            command_io::public_output(USAGE.as_bytes()).map_err(CliError::Command)
        }
        [command, option, root] if command == "mcp" && option == "--data-root" => {
            let root = absolute_root(root)?;
            let native = NativeStdioPort::spawn_current(StdioLimits::default())
                .map_err(command_io::CommandIoError::Stdio)
                .map_err(CliError::Command)?;
            mcp::run_with_io(&root.join("runtime"), Arc::new(native)).map_err(CliError::Mcp)
        }
        [command, method, option, root] if command == "call" && option == "--data-root" => {
            command_io::call(method, &absolute_root(root)?, false).map_err(CliError::Command)
        }
        [command, method, option, root, mode]
            if command == "call"
                && option == "--data-root"
                && matches!(mode.as_str(), "--json" | "--summary") =>
        {
            command_io::call(method, &absolute_root(root)?, mode == "--summary")
                .map_err(CliError::Command)
        }
        _ => Err(CliError::Arguments),
    }
}

fn absolute_root(raw: &str) -> Result<PathBuf, CliError> {
    let root = PathBuf::from(raw);
    if root.is_absolute() {
        Ok(root)
    } else {
        Err(CliError::Arguments)
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn static_session_failure_code_and_original_typed_cause_survive_public_formatting() {
        let authentication = EntryError::Daemon(DaemonError::Coordinator(
            mmmm_coordinator::lifecycle::CoordinatorError::Authentication(
                mmmm_coordinator::auth::AuthError::InvalidPolicy,
            ),
        ));
        assert!(
            PublicEntryError(&authentication)
                .to_string()
                .contains("INVALID_SESSION_POLICY")
        );
        assert!(
            std::error::Error::source(match &authentication {
                EntryError::Daemon(DaemonError::Coordinator(error)) => error,
                _ => unreachable!(),
            })
            .unwrap()
            .is::<mmmm_coordinator::auth::AuthError>()
        );
    }
}
