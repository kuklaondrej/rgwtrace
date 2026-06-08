mod events;

mod classify;
mod cli;
mod collector;
mod dwarf_json;
mod live;
mod otel;

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::{Cli, OutputMode},
    collector::Collector,
    dwarf_json::DwarfInfo,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dwarf = DwarfInfo::from_path(&cli.import_json)?;
    let trace = if cli.dry_run {
        Collector::default().into_trace_document(cli.service_name.clone())
    } else {
        live::run(&cli, &dwarf)?
    };

    match cli.output {
        OutputMode::Json => {
            let output = serde_json::json!({
                "dwarf": dwarf.summary(),
                "trace": trace,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputMode::Otlp => {
            otel::export_otlp_http(&cli.otlp_endpoint, &trace)?;
        }
    }

    Ok(())
}
