//! `sayso-ops`: the command the repository's scheduled workflow runs.
//!
//!     sayso-ops plan    <owner.json>
//!     sayso-ops harvest <owner.json> <vault-dir>   (ntfy poll output on stdin)
//!     sayso-ops expire  <owner.json> <vault-dir>
//!
//! `plan` prints the URLs to poll, one per line. `harvest` and `expire` print
//! a one-line summary. Set `SAYSO_NOW` (Unix seconds) to run against a fixed
//! clock.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, io};

use sayso_ops::{Config, Limits};

fn now() -> u64 {
    env::var("SAYSO_NOW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: sayso-ops plan <owner.json> | harvest <owner.json> <vault> | expire <owner.json> <vault>";
    let (command, manifest) = match args {
        [command, manifest, ..] => (command.as_str(), manifest),
        _ => return Err(usage.into()),
    };
    let config = Config::from_owner(&fs::read(manifest)?)?;
    match (command, args.get(2)) {
        ("plan", None) => {
            for url in config.poll_urls() {
                println!("{url}");
            }
        }
        ("harvest", Some(vault)) => {
            let report = sayso_ops::harvest(
                &config,
                io::stdin().lock(),
                Path::new(vault),
                now(),
                Limits::default(),
            )?;
            println!("{report}");
        }
        ("expire", Some(vault)) => {
            let removed = sayso_ops::expire(&config, Path::new(vault), now())?;
            println!("expired={}", removed.len());
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sayso-ops: {err}");
            ExitCode::FAILURE
        }
    }
}
