use mmmm_contracts::{JsonLimits, encode_json, parse_json_with_limits};
use mmmm_coordinator::CoordinatorClient;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    sync::Arc,
};
mod mcp;

fn main() {
    let exit = match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(exit);
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    if command == mmmm_coordinator::stdio_io::WORKER_COMMAND {
        // This owned helper handles inherited external stdio only. Its channel
        // bootstrap is private; stdout cannot contain application diagnostics.
        let remaining: Vec<_> = args.collect();
        mmmm_coordinator::stdio_io::worker_entry_exit(&remaining);
    }
    if command == "--version" {
        println!(
            "MMMM {} (contract {})",
            env!("CARGO_PKG_VERSION"),
            mmmm_contracts::CONTRACT_VERSION
        );
        return Ok(());
    }
    if command == "mcp" {
        if args.next().as_deref() != Some("--data-root") {
            return usage();
        }
        let data_root = PathBuf::from(args.next().ok_or("A local data root is required")?);
        if !data_root.is_absolute() || args.next().is_some() {
            return usage();
        }
        let native = mmmm_coordinator::stdio_io::NativeStdioPort::spawn_current(
            mmmm_coordinator::stdio_io::StdioLimits::default(),
        )?;
        mcp::run_with_io(&data_root.join("runtime"), Arc::new(native))?;
        return Ok(());
    }
    if command != "call" {
        return usage();
    }
    let method = args.next().ok_or("A canonical function name is required")?;
    if args.next().as_deref() != Some("--data-root") {
        return usage();
    }
    let data_root = PathBuf::from(args.next().ok_or("A local data root is required")?);
    let mode = args.next().unwrap_or_else(|| "--json".to_owned());
    if !matches!(mode.as_str(), "--json" | "--summary") || args.next().is_some() {
        return usage();
    }
    // Only explicit stdin contains the function DTO. No environment secret,
    // arbitrary config file, key file, shell, or direct live-path write is read.
    let mut input = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut input)?;
    let value = parse_json_with_limits(
        &input,
        JsonLimits {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            max_nodes: 4096,
        },
    )?;
    let client = CoordinatorClient::discover_peer(&data_root.join("runtime"))?;
    let output = client.call(&method, &value)?;
    if mode == "--json" {
        io::stdout().write_all(&encode_json(&output)?)?;
        io::stdout().write_all(b"\n")?;
    } else {
        // Human summaries retain actual operation status rather than declaring
        // completion because an HTTP request succeeded.
        if let Some(status) = output.get("status").and_then(serde_json::Value::as_str) {
            println!("{method}: {status}");
        } else if let Some(state) = output.get("state").and_then(serde_json::Value::as_str) {
            println!("{method}: {state}");
        } else {
            println!("{method}: 응답을 받았습니다. 전체 결과는 --json으로 확인하세요.");
        }
    }
    Ok(())
}
fn usage() -> Result<(), Box<dyn std::error::Error>> {
    Err("Usage: mmmm call <function.name> --data-root <absolute local root> [--json|--summary] < request.json; mmmm mcp --data-root <absolute local root>".into())
}
