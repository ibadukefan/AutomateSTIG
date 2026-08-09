//! AutomateSTIG CLI — difficult-device STIG scanning and evidence handoff.
//!
//! Usage:
//!   automatestig collect --stig <STIG_ID> --host <HOST> --username <USER> --output <EVIDENCE_JSON>
//!   automatestig evaluate --stig <STIG_ID> (--evidence <FILE> | --config <FILE>) [--output <OUTPUT>]
//!   automatestig scanner verify-handoff <HANDOFF_ZIP>
//!   automatestig migration inventory [--output <REPORT_JSON>]
//!   automatestig migration export --output <TRANSITION_ZIP>

mod commands;
mod ui;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "automatestig",
    version,
    about = "AutomateSTIG — difficult-device STIG scanner and evidence handoff",
    long_about = "AutomateSTIG is a deterministic, air-gapped-first scanner and evidence producer that supplements STIG Manager.\n\
                   Its v0.3 scanner targets are NetApp ONTAP 9.x and FreeBSD over\n\
                   plan-bound SSH evidence, plus Cisco IOS-XE Router NDM running configs.\n\n\
                   Changed reviews use a verified selected-run handoff; connected verification records only an exact remote no-op.\n\n\
                   Evaluation is deterministic and reproducible."
)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Database path (default: ~/.automatestig/data.db).
    #[arg(long, global = true)]
    db: Option<String>,

    /// STIG library path (default: ~/.automatestig/library).
    #[arg(long, global = true)]
    library: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Collect versioned evidence from a remote device over SSH.
    Collect {
        /// STIG benchmark ID whose check pack defines the collection plan.
        #[arg(short, long)]
        stig: String,

        /// Remote host name or address (without username).
        #[arg(long)]
        host: String,

        /// Corroborating endpoint identity; when supplied, must equal --host.
        #[arg(long)]
        hostname: Option<String>,

        /// SSH username.
        #[arg(short, long)]
        username: String,

        /// SSH port.
        #[arg(long, default_value_t = 22)]
        port: u16,

        /// Private-key file; when absent, password is read from --password-env.
        #[arg(long)]
        key: Option<String>,

        /// Environment variable containing the SSH password.
        #[arg(long, default_value = "AUTOMATESTIG_SSH_PASSWORD")]
        password_env: String,

        /// Environment variable containing the private-key passphrase.
        #[arg(long, default_value = "AUTOMATESTIG_SSH_KEY_PASSPHRASE")]
        passphrase_env: String,

        /// Per-command wall-clock and inactivity timeout.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,

        /// Evidence JSON path, or '-' for stdout.
        #[arg(short, long)]
        output: String,

        /// Enroll an unknown server key for this collection only.
        #[arg(long)]
        trust_on_first_use: bool,
    },

    /// Evaluate a STIG against a device evidence transcript or running configuration.
    Evaluate {
        /// STIG benchmark ID to evaluate.
        #[arg(short, long)]
        stig: String,

        /// Evidence v2 JSON file collected from the target device.
        #[arg(long, required_unless_present = "config", conflicts_with = "config")]
        evidence: Option<String>,

        /// Transition-only: unsafely assume marker-based v1 evidence commands succeeded.
        #[arg(long, requires = "evidence", conflicts_with = "config", hide = true)]
        allow_legacy_evidence: bool,

        /// Device running-config file (e.g. show running-config output) evaluated via config_line check packs.
        #[arg(
            long,
            required_unless_present = "evidence",
            conflicts_with = "evidence"
        )]
        config: Option<String>,

        /// Signed organization-policy JSON for organization-defined Cisco controls.
        #[arg(long, requires = "organization_policy_signature")]
        organization_policy: Option<String>,

        /// Detached Ed25519 signature for --organization-policy.
        #[arg(long, requires = "organization_policy")]
        organization_policy_signature: Option<String>,

        /// Transition-only path(s) to legacy answer files.
        #[arg(short, long, hide = true)]
        answer: Vec<String>,

        /// Target hostname (auto-detected from evidence if not specified).
        #[arg(long)]
        host: Option<String>,

        /// Output file path (.ckl, .cklb, or .json).
        #[arg(short, long)]
        output: Option<String>,

        /// Output format override (ckl, cklb, json).
        #[arg(short, long)]
        format: Option<String>,

        /// Transition-only merge with a previous local checklist.
        #[arg(long, hide = true)]
        merge: Option<String>,
    },

    /// Import a .stigpack content pack into the STIG library.
    #[command(hide = true)]
    Import {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Verify a .stigpack file without importing.
    #[command(hide = true)]
    Verify {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Manage the STIG library.
    #[command(hide = true)]
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },

    /// Convert between checklist formats.
    #[command(hide = true)]
    Convert {
        /// Input file path.
        #[arg(short, long)]
        input: String,

        /// Output file path.
        #[arg(short, long)]
        output: String,

        /// Output format (ckl, cklb, json, stig-manager).
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Show summary of a checklist.
    #[command(hide = true)]
    Summary {
        /// Input file path (.ckl, .cklb, or .json).
        #[arg(short, long)]
        input: String,

        /// Show only open findings.
        #[arg(long)]
        open_only: bool,

        /// Filter by severity (high, medium, low).
        #[arg(long)]
        severity: Option<String>,
    },

    /// Generate an answer file template from an existing checklist.
    #[command(name = "gen-answer", hide = true)]
    GenAnswer {
        /// Input checklist file.
        #[arg(short, long)]
        input: String,

        /// Output answer file path (.json or .yaml).
        #[arg(short, long)]
        output: String,

        /// Include Not_Reviewed findings in template.
        #[arg(long)]
        include_unreviewed: bool,
    },

    /// Export checklist to external formats.
    #[command(hide = true)]
    Export {
        /// Input checklist file.
        #[arg(short, long)]
        input: String,

        /// Output file path.
        #[arg(short, long)]
        output: String,

        /// Export format (stig-manager).
        #[arg(short, long)]
        format: String,

        /// Collection name (for STIG-Manager export).
        #[arg(long)]
        collection: Option<String>,
    },

    /// Explicitly create a new external content-signing key pair.
    #[command(name = "generate-signing-key", hide = true)]
    GenerateSigningKey {
        /// Output path for the private key; the public key uses `.pub`.
        #[arg(long)]
        output: String,
    },

    /// Sign an organization-policy artifact on an isolated signing host.
    #[command(name = "sign-organization-policy", hide = true)]
    SignOrganizationPolicy {
        /// Exact organization-policy JSON bytes to sign.
        #[arg(long)]
        policy: String,

        /// Existing external raw 32-byte Ed25519 private key.
        #[arg(long)]
        signing_key: String,

        /// Create-new detached signature output.
        #[arg(short, long)]
        output: String,
    },

    /// Build a .stigpack content pack.
    #[command(name = "build-pack", hide = true)]
    BuildPack {
        /// Pack ID.
        #[arg(long)]
        id: String,

        /// Pack name.
        #[arg(long)]
        name: String,

        /// Pack version.
        #[arg(long)]
        version: String,

        /// Directory containing benchmarks/ and other pack content.
        #[arg(short, long)]
        source: String,

        /// Output .stigpack file path.
        #[arg(short, long)]
        output: String,

        /// Existing external raw 32-byte Ed25519 signing key.
        ///
        /// The matching public key must exist at the same path with a `.pub`
        /// extension. AutomateSTIG never creates either key during pack build.
        #[arg(long)]
        signing_key: String,
    },

    /// Import DISA STIG content directly from XCCDF files or ZIP archives.
    #[command(name = "disa-import", hide = true)]
    DisaImport {
        /// Path to DISA STIG ZIP archive or XCCDF XML file.
        #[arg(short, long)]
        input: String,
    },

    /// Validate rule-by-rule coverage manifests.
    #[command(hide = true)]
    Coverage {
        #[command(subcommand)]
        action: CoverageAction,
    },

    /// Inspect or export preserved local data during the scanner-first transition.
    Migration {
        #[command(subcommand)]
        action: MigrationAction,
    },

    /// Inspect scanner artifacts exchanged with an existing STIG Manager workflow.
    Scanner {
        #[command(subcommand)]
        action: ScannerAction,
    },

    /// Show application version and library status.
    Status,
}

#[derive(Subcommand)]
enum CoverageAction {
    /// Validate a coverage manifest JSON file.
    Validate {
        /// Path to coverage manifest JSON.
        #[arg(short, long)]
        manifest: String,
    },
}

#[derive(Subcommand)]
enum MigrationAction {
    /// Produce a read-only attribution and migration inventory as JSON.
    Inventory {
        /// Report path, or '-' for stdout (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Create a new, private transition ZIP without changing local state.
    Export {
        /// Create-new ZIP path outside AutomateSTIG-managed state.
        #[arg(short, long)]
        output: String,
    },
}

#[derive(Subcommand)]
enum ScannerAction {
    /// Verify a selected-run handoff ZIP without importing or changing local state.
    #[command(name = "verify-handoff")]
    VerifyHandoff {
        /// Selected-run handoff ZIP downloaded from AutomateSTIG.
        zip: String,

        /// Detached signature sidecar created on a protected signing host.
        #[arg(long)]
        signature: Option<String>,

        /// Dedicated directory of trusted handoff-producer `.pub` keys.
        #[arg(long, requires = "signature")]
        trust_dir: Option<String>,
    },

    /// Sign a semantically verified handoff on a protected CLI host.
    #[command(name = "sign-handoff")]
    SignHandoff {
        /// Selected-run handoff ZIP downloaded from AutomateSTIG.
        zip: String,

        /// Existing external raw 32-byte Ed25519 private key.
        #[arg(long)]
        signing_key: String,

        /// Create-new detached signature sidecar path.
        #[arg(short, long)]
        output: String,
    },

    /// Explicitly create a dedicated external handoff-signing key pair.
    #[command(name = "generate-signing-key")]
    GenerateSigningKey {
        /// Create-new private key path; the public key uses `.pub`.
        #[arg(long)]
        output: String,
    },
}

#[derive(Subcommand)]
enum LibraryAction {
    /// List all available STIG benchmarks.
    List,

    /// Show details of a specific benchmark.
    Show {
        /// Benchmark ID.
        id: String,
    },

    /// Initialize a new STIG library.
    Init,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging.
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    let result = match &cli.command {
        Commands::Collect {
            stig,
            host,
            hostname,
            username,
            port,
            key,
            password_env,
            passphrase_env,
            timeout_secs,
            output,
            trust_on_first_use,
        } => commands::collect::run(
            commands::collect::CollectArgs {
                stig_id: stig.clone(),
                host: host.clone(),
                hostname: hostname.clone(),
                username: username.clone(),
                port: *port,
                key: key.clone(),
                password_env: password_env.clone(),
                passphrase_env: passphrase_env.clone(),
                timeout_secs: *timeout_secs,
                output: output.clone(),
                trust_on_first_use: *trust_on_first_use,
            },
            &cli,
        ),
        Commands::Evaluate {
            ref stig,
            ref evidence,
            allow_legacy_evidence,
            ref config,
            ref organization_policy,
            ref organization_policy_signature,
            ref answer,
            ref host,
            ref output,
            ref format,
            ref merge,
        } => commands::evaluate::run(
            commands::evaluate::EvaluateArgs {
                stig_id: stig.clone(),
                evidence: evidence.clone(),
                allow_legacy_evidence: *allow_legacy_evidence,
                config: config.clone(),
                organization_policy: organization_policy.clone(),
                organization_policy_signature: organization_policy_signature.clone(),
                answer_paths: answer.clone(),
                host: host.clone(),
                output: output.clone(),
                format: format.clone(),
                merge: merge.clone(),
            },
            &cli,
        ),
        Commands::Import { ref pack } => commands::import::run(pack, &cli),
        Commands::Verify { ref pack } => commands::verify::run(pack),
        Commands::Library { ref action } => match action {
            LibraryAction::List => commands::library::list(&cli),
            LibraryAction::Show { ref id } => commands::library::show(id, &cli),
            LibraryAction::Init => commands::library::init(&cli),
        },
        Commands::Convert {
            ref input,
            ref output,
            ref format,
        } => commands::convert::run(input, output, format.as_deref(), &cli),
        Commands::Summary {
            ref input,
            open_only,
            ref severity,
        } => commands::summary::run(input, *open_only, severity.as_deref()),
        Commands::GenAnswer {
            ref input,
            ref output,
            include_unreviewed,
        } => commands::gen_answer::run(input, output, *include_unreviewed, &cli),
        Commands::Export {
            ref input,
            ref output,
            ref format,
            ref collection,
        } => commands::export::run(input, output, format, collection.as_deref(), &cli),
        Commands::GenerateSigningKey { ref output } => {
            commands::build_pack::generate_signing_key(output)
        }
        Commands::SignOrganizationPolicy {
            ref policy,
            ref signing_key,
            ref output,
        } => commands::evaluate::sign_organization_policy(policy, signing_key, output),
        Commands::BuildPack {
            ref id,
            ref name,
            ref version,
            ref source,
            ref output,
            ref signing_key,
        } => commands::build_pack::run(id, name, version, source, output, signing_key),
        Commands::DisaImport { ref input } => commands::disa_import::run(input, &cli),
        Commands::Coverage { ref action } => match action {
            CoverageAction::Validate { ref manifest } => commands::coverage::validate(manifest),
        },
        Commands::Migration { ref action } => match action {
            MigrationAction::Inventory { ref output } => {
                commands::migration::inventory(output.as_deref(), &cli)
            }
            MigrationAction::Export { ref output } => commands::migration::export(output, &cli),
        },
        Commands::Scanner { ref action } => match action {
            ScannerAction::VerifyHandoff {
                ref zip,
                ref signature,
                ref trust_dir,
            } => commands::handoff::run(zip, signature.as_deref(), trust_dir.as_deref()),
            ScannerAction::SignHandoff {
                ref zip,
                ref signing_key,
                ref output,
            } => commands::handoff::sign_handoff(zip, signing_key, output, &cli),
            ScannerAction::GenerateSigningKey { ref output } => {
                commands::handoff::generate_signing_key(output, &cli)
            }
        },
        Commands::Status => commands::status::run(&cli),
    };

    if let Err(e) = result {
        ui::error(&format!("{:#}", e));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{error::ErrorKind, CommandFactory, Parser};

    #[test]
    fn product_help_exposes_scanning_handoff_and_migration_not_manager_duplicates() {
        let help = Cli::command().render_long_help().to_string();
        for command in ["collect", "evaluate", "scanner", "migration", "status"] {
            assert!(help.contains(command), "missing scanner command {command}");
        }
        for retired in [
            "gen-answer",
            "convert",
            "summary",
            "disa-import",
            "library",
            "export",
        ] {
            let command_is_listed = help.lines().any(|line| {
                line.trim_start()
                    .strip_prefix(retired)
                    .is_some_and(|suffix| suffix.chars().next().is_some_and(char::is_whitespace))
            });
            assert!(
                !command_is_listed,
                "manager-duplicate command leaked: {retired}"
            );
        }
    }

    #[test]
    fn evaluate_requires_exactly_one_primary_input() {
        let missing = match Cli::try_parse_from(["automatestig", "evaluate", "--stig", "example"]) {
            Err(error) => error,
            Ok(_) => panic!("an evaluation without an input must be rejected"),
        };
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);

        let mixed = match Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--evidence",
            "evidence.json",
            "--config",
            "running-config.txt",
        ]) {
            Err(error) => error,
            Ok(_) => panic!("evidence and config must be mutually exclusive"),
        };
        assert_eq!(mixed.kind(), ErrorKind::ArgumentConflict);

        assert!(Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--evidence",
            "evidence.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--config",
            "running-config.txt",
        ])
        .is_ok());
    }

    #[test]
    fn legacy_override_is_valid_only_with_evidence() {
        let result = Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--config",
            "running-config.txt",
            "--allow-legacy-evidence",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn migration_cli_separates_inventory_from_create_new_export() {
        assert!(Cli::try_parse_from(["automatestig", "migration", "inventory"]).is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "migration",
            "inventory",
            "--output",
            "inventory.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["automatestig", "migration", "export"]).is_err());
        assert!(Cli::try_parse_from([
            "automatestig",
            "migration",
            "export",
            "--output",
            "transition.zip",
        ])
        .is_ok());
    }

    #[test]
    fn scanner_handoff_verification_uses_a_positional_read_only_artifact() {
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
            "--signature",
            "selected-run.zip.signature.json",
            "--trust-dir",
            "/approved/handoff-keys",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
            "--trust-dir",
            "/approved/handoff-keys",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["automatestig", "scanner", "verify-handoff"]).is_err());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "sign-handoff",
            "selected-run.zip",
            "--signing-key",
            "/protected/producer.key",
            "--output",
            "selected-run.zip.signature.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "generate-signing-key",
            "--output",
            "/protected/producer.key",
        ])
        .is_ok());
    }
}
