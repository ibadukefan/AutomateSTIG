//! AutomateSTIG CLI — STIG evaluation and compliance automation.
//!
//! Usage:
//!   automatestig evaluate --stig <STIG_ID> (--evidence <FILE> | --config <FILE>) [--answer <FILE>] [--output <OUTPUT>]
//!   automatestig import --pack <STIGPACK_FILE>
//!   automatestig library list
//!   automatestig convert --input <FILE> --format <ckl|cklb|json>
//!   automatestig verify --pack <STIGPACK_FILE>
//!   automatestig summary --input <CKL_FILE>

mod commands;
mod ui;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "automatestig",
    version,
    about = "AutomateSTIG — Cross-platform STIG evaluation and compliance automation",
    long_about = "AutomateSTIG is a deterministic, air-gapped-first STIG evaluation platform.\n\
                   Its v0.3 scanner targets are NetApp ONTAP 9.x and FreeBSD over\n\
                   plan-bound SSH evidence, plus Cisco IOS-XE Router NDM running configs.\n\n\
                   All operations are 100% deterministic and reproducible."
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

        /// Hostname recorded in evidence (defaults to --host).
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

        /// Unsafely assume marker-based v1 evidence commands succeeded.
        #[arg(long, requires = "evidence", conflicts_with = "config")]
        allow_legacy_evidence: bool,

        /// Device running-config file (e.g. show running-config output) evaluated via config_line check packs.
        #[arg(
            long,
            required_unless_present = "evidence",
            conflicts_with = "evidence"
        )]
        config: Option<String>,

        /// Path(s) to answer file(s) (JSON/YAML).
        #[arg(short, long)]
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

        /// Merge with previous checklist (preserves manual entries).
        #[arg(long)]
        merge: Option<String>,
    },

    /// Import a .stigpack content pack into the STIG library.
    Import {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Verify a .stigpack file without importing.
    Verify {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Manage the STIG library.
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },

    /// Convert between checklist formats.
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
    #[command(name = "gen-answer")]
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
    #[command(name = "generate-signing-key")]
    GenerateSigningKey {
        /// Output path for the private key; the public key uses `.pub`.
        #[arg(long)]
        output: String,
    },

    /// Build a .stigpack content pack.
    #[command(name = "build-pack")]
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
    #[command(name = "disa-import")]
    DisaImport {
        /// Path to DISA STIG ZIP archive or XCCDF XML file.
        #[arg(short, long)]
        input: String,
    },

    /// Validate rule-by-rule coverage manifests.
    Coverage {
        #[command(subcommand)]
        action: CoverageAction,
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
        } => commands::convert::run(input, output, format.as_deref()),
        Commands::Summary {
            ref input,
            open_only,
            ref severity,
        } => commands::summary::run(input, *open_only, severity.as_deref()),
        Commands::GenAnswer {
            ref input,
            ref output,
            include_unreviewed,
        } => commands::gen_answer::run(input, output, *include_unreviewed),
        Commands::Export {
            ref input,
            ref output,
            ref format,
            ref collection,
        } => commands::export::run(input, output, format, collection.as_deref()),
        Commands::GenerateSigningKey { ref output } => {
            commands::build_pack::generate_signing_key(output)
        }
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
    use clap::{error::ErrorKind, Parser};

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
}
