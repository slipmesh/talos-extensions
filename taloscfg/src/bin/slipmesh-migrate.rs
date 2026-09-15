//! `slipmesh-migrate`: moves `mesh.yaml` and the hand-edited patch files to `slipmesh.yaml` and
//! `slipmesh-secrets.yaml`, once. It writes the two new files and touches nothing else; the patch
//! files are regenerated from them afterwards by `slipmesh-taloscfg generate`.

use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::path::PathBuf;
use taloscfg::migrate::migrate;

#[derive(Parser)]
#[command(
    name = "slipmesh-migrate",
    version,
    about = "Moves mesh.yaml and hand-edited patch files to slipmesh.yaml and slipmesh-secrets.yaml"
)]
struct Cli {
    #[arg(long, default_value = "mesh.yaml")]
    mesh: PathBuf,
    /// Where the patch files are read from: their keys, and the documents written into them by
    /// hand.
    #[arg(long, default_value = "patches")]
    patches_dir: PathBuf,
    #[arg(long, default_value = "slipmesh.yaml")]
    out: PathBuf,
    #[arg(long, default_value = "slipmesh-secrets.yaml")]
    out_secrets: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    for path in [&cli.out, &cli.out_secrets] {
        ensure!(
            !path.exists(),
            "{} already exists - a migration writes it from scratch and would replace it",
            path.display()
        );
    }

    let mesh = std::fs::read_to_string(&cli.mesh)
        .with_context(|| format!("reading {}", cli.mesh.display()))?;
    let migration = migrate(&mesh, &cli.patches_dir)?;
    for route in &migration.minted {
        eprintln!(
            "warning: {route} is in neither {} nor {} and was minted - if it existed before, this \
             is a new identity",
            cli.mesh.display(),
            cli.patches_dir.display()
        );
    }

    std::fs::write(&cli.out, &migration.slipmesh)
        .with_context(|| format!("writing {}", cli.out.display()))?;
    std::fs::write(&cli.out_secrets, &migration.secrets)
        .with_context(|| format!("writing {}", cli.out_secrets.display()))?;
    println!(
        "wrote {} and {} - `slipmesh-taloscfg generate --diff` shows what they regenerate",
        cli.out.display(),
        cli.out_secrets.display()
    );
    Ok(())
}
