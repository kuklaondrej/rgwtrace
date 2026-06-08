mod events;

mod cli;
mod dwarf_json;

use anyhow::Result;
use clap::Parser;

use crate::{cli::Cli, dwarf_json::DwarfInfo};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dwarf = DwarfInfo::from_path(&cli.import_json)?;

    println!("{}", serde_json::to_string_pretty(&dwarf.summary())?);
    Ok(())
}
