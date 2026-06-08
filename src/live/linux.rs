use anyhow::{bail, Result};

use crate::{cli::Cli, collector::TraceDocument, dwarf_json::DwarfInfo};

pub fn run(_cli: &Cli, _dwarf: &DwarfInfo) -> Result<TraceDocument> {
    bail!("Linux BPF loader is not wired yet")
}
