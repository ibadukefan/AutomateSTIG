//! Protected transition and signing utility.
//!
//! This binary is absent unless the explicit non-default `transition` feature
//! is enabled. The analyst-facing `automatestig` binary never exposes these
//! state-transition or private-key operations.

#[path = "../commands/mod.rs"]
#[allow(dead_code)]
mod commands;
#[path = "../ui.rs"]
#[allow(dead_code)]
mod ui;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "automatestig-transition",
    version,
    about = "Protected AutomateSTIG transition, migration, and handoff-signing utility"
)]
pub(crate) struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    pub(crate) db: Option<String>,
    #[arg(long, global = true)]
    pub(crate) library: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[cfg(test)]
impl Cli {
    fn command_test_fixture(library: String, db: String) -> Self {
        Self {
            verbose: false,
            library: Some(library),
            db: Some(db),
            command: Commands::Migration {
                action: MigrationAction::Inventory { output: None },
            },
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect, export, or explicitly bind retained pre-cutover scanner runs.
    Migration {
        #[command(subcommand)]
        action: MigrationAction,
    },
    /// Protected handoff producer-key operations.
    Scanner {
        #[command(subcommand)]
        action: ScannerAction,
    },
}

#[derive(Debug, Subcommand)]
enum MigrationAction {
    /// Produce a read-only attribution and migration inventory as JSON.
    Inventory {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Create a new, private transition ZIP without changing local state.
    Export {
        #[arg(short, long)]
        output: String,
    },
    /// Bind one retained run to an exact, operator-confirmed destination.
    #[command(name = "bind-run")]
    BindRun(Box<BindRunOptions>),
}

#[derive(Debug, Args)]
struct BindRunOptions {
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    api_url: String,
    #[arg(long)]
    token_url: String,
    #[arg(long)]
    client_id: String,
    #[arg(long, default_value = "AUTOMATESTIG_STIGMAN_CLIENT_SECRET")]
    client_secret_env: String,
    #[arg(long, value_delimiter = ',', required = true)]
    destination_allowlist: Vec<String>,
    #[arg(long)]
    collection_id: String,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    operator_source: String,
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ScannerAction {
    /// Sign a semantically verified handoff on a protected host.
    #[command(name = "sign-handoff")]
    SignHandoff {
        zip: String,
        #[arg(long)]
        signing_key: String,
        #[arg(short, long)]
        output: String,
    },
    /// Explicitly create a dedicated external handoff-signing key pair.
    #[command(name = "generate-signing-key")]
    GenerateSigningKey {
        #[arg(long)]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    let result = match &cli.command {
        Commands::Migration { action } => match action {
            MigrationAction::Inventory { output } => {
                commands::migration::inventory(output.as_deref(), &cli)
            }
            MigrationAction::Export { output } => commands::migration::export(output, &cli),
            MigrationAction::BindRun(args) => commands::migration::bind_run(
                commands::migration::BindRunArgs {
                    run_id: args.run_id.clone(),
                    api_url: args.api_url.clone(),
                    token_url: args.token_url.clone(),
                    client_id: args.client_id.clone(),
                    client_secret_env: args.client_secret_env.clone(),
                    destination_allowlist: args.destination_allowlist.clone(),
                    collection_id: args.collection_id.clone(),
                    asset_id: args.asset_id.clone(),
                    operator_source: args.operator_source.clone(),
                    output: args.output.clone(),
                },
                &cli,
            ),
        },
        Commands::Scanner { action } => match action {
            ScannerAction::SignHandoff {
                zip,
                signing_key,
                output,
            } => commands::handoff::sign_handoff(zip, signing_key, output, &cli),
            ScannerAction::GenerateSigningKey { output } => {
                commands::handoff::generate_signing_key(output, &cli)
            }
        },
    };
    if let Err(error) = result {
        ui::error(&format!("{error:#}"));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{CommandFactory, Parser};

    #[test]
    fn protected_help_exposes_transition_and_signing_routes() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("migration"));
        assert!(help.contains("scanner"));
        assert!(
            Cli::try_parse_from(["automatestig-transition", "migration", "inventory",]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "automatestig-transition",
            "migration",
            "bind-run",
            "--run-id",
            "run",
            "--api-url",
            "https://stigman.example.test/api",
            "--token-url",
            "https://id.example.test/token",
            "--client-id",
            "automatestig",
            "--destination-allowlist",
            "stigman.example.test,id.example.test",
            "--collection-id",
            "collection",
            "--asset-id",
            "asset",
            "--operator-source",
            "approved-migration-ticket",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig-transition",
            "scanner",
            "sign-handoff",
            "run.zip",
            "--signing-key",
            "producer.key",
            "--output",
            "run.zip.signature.json",
        ])
        .is_ok());
    }
}
