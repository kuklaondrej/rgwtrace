use anyhow::{bail, Result};

use crate::{cli::Cli, collector::TraceDocument, dwarf_json::DwarfInfo};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub fn run(cli: &Cli, dwarf: &DwarfInfo) -> Result<TraceDocument> {
    linux::run(cli, dwarf)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_cli: &Cli, _dwarf: &DwarfInfo) -> Result<TraceDocument> {
    bail!("live tracing requires Linux")
}
